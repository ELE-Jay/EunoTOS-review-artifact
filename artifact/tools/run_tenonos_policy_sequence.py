#!/usr/bin/env python3
"""Collect state-linked Tenon configuration histories on leon; no optimizer."""
import argparse
import contextlib
import copy
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

from audit_tenonos_tasks import configuration
from audit_tenonos_paper_tasks import guest_outcome
from run_tenonos_paper_tasks import admitted_gates, evaluate_pi, prepare_runtime_helpers, retain_runtime_transfer
from tenonos_config_validation import verify_sources
from tenonos_kvm_reproduce import save, sha, utc
from tenonos_model_service import DEEPSEEK_KEY
from tenonos_paper_orchestrator import RECONSTRUCTION, generate

ROOT = Path(__file__).resolve().parents[1]


def round_task(base, parent_config, graph, feedback, index):
    actual = configuration(parent_config)
    tlsf, buddy = "LIBUKBOOT_INITTLSF", "LIBUKBOOT_INITBBUDDY"
    if (actual.get(tlsf, "n"), actual.get(buddy, "n")) not in (("y", "n"), ("n", "y")):
        raise ValueError("Retained parent has no unique supported allocator")
    target = buddy if actual.get(tlsf) == "y" else tlsf
    task = copy.deepcopy(base)
    task["id"] = "R" + str(index)
    task["required_options"].update({tlsf: "y" if target == tlsf else "n", buddy: "y" if target == buddy else "n"})
    kinds = {n["name"]: n["type"] for n in graph["nodes"] if n["kind"] == "config"}
    names = set(base["starting_options"]) | set(base["fixed_options"]) | set(base["candidate_controls"])
    task["starting_options"] = {n: actual.get(n, "n") for n in sorted(names)
                                if n in actual or kinds[n] in ("bool", "tristate")}
    task["preserve_reference"]["sha256"] = sha(parent_config)
    task["preserve_reference"]["config"] = "starting-reference.config"
    task["objective"] = (
        "Change the retained runtime's default allocator to " + ("TLSF" if target == tlsf else "binary buddy") +
        ". Preserve priority scheduling, same-priority preemption, the 1000-Hz tick and all unrelated options. "
        "All six unchanged RTOS cases must complete. Return only allocator changes. "
        "Prior configuration-check feedback: " + json.dumps(feedback, sort_keys=True))
    task["sequence_round"] = index
    task["target_allocator_option"] = target
    return task


def configuration_feedback(gates, accepted, evaluation):
    return {"accepted": accepted, "gates": gates,
            "required_configuration": [{k: row[k] for k in ("option", "required", "actual", "pass")}
                                       for row in evaluation.get("required_checks", [])],
            "preserved_unrelated_configuration": next((r["pass"] for r in evaluation.get("runtime_checks", [])
                                                        if r["gate"] == "preserve_unrelated_configuration"), None)}


def boot_parent(folder, parent_build, ssh, host, socket, pi_workspace, helper_directory, remote):
    if Path(remote).parent != Path("/dev/shm") or not Path(remote).name.startswith("iotos-tenon-v4-"):
        raise ValueError("Unsafe temporary parent path")
    folder.mkdir(parents=True, exist_ok=False)
    built = folder / "build"
    built.mkdir()
    original = json.loads((parent_build / "build-result.json").read_text())
    if sha(parent_build / "runtime-image") != original["image_sha256"] or sha(parent_build / ".config") != original["config_sha256"]:
        raise ValueError("Retained parent bytes changed")
    for name in ("runtime-image", ".config"):
        shutil.copyfile(parent_build / name, built / name)
    shutil.copyfile(parent_build / "build-result.json", built / "origin-build-result.json")
    save(built / "build-result.json", {**original, "image": remote + "/build/runtime-image"})
    save(folder / "image-rebinding.json", {"origin_sha256": sha(built / "origin-build-result.json"),
         "runtime_sha256": original["image_sha256"], "change": "Temporary image pathname only; no rebuild"})
    subprocess.run([*ssh, shlex.join(["mkdir", "-m", "700", remote])], check=True, timeout=20)
    subprocess.run([*ssh, shlex.join(["mkdir", remote + "/build"])], check=True, timeout=20)
    subprocess.run(["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes",
                    *[str(p) for p in built.iterdir()], host + ":" + remote + "/build/"], check=True, timeout=30)
    argv = ["timeout", "--kill-after=10", "950", "env", "PYTHONPATH=" + pi_workspace + "/python-deps", "python3",
            helper_directory + "/tenonos_kvm_reproduce.py", "boot", "--workspace", pi_workspace,
            "--build-dir", remote + "/build", "--output", remote + "/boots", "--accelerator", "kvm"]
    with (folder / "remote.stdout").open("xb") as out, (folder / "remote.stderr").open("xb") as err:
        subprocess.run([*ssh, shlex.join(argv)], check=True, stdout=out, stderr=err, timeout=980)
    subprocess.run(["rsync", "-a", "-e", shlex.join(ssh[:-1]), host + ":" + remote + "/boots/", str(folder / "boots") + "/"],
                   check=True, timeout=120)
    code = "import pathlib,hashlib,json;r=pathlib.Path(" + repr(remote) + ");print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob('*') if p.is_file() and not p.is_symlink()}))"
    manifest = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])], universal_newlines=True, timeout=30))
    retain_runtime_transfer(folder, manifest, remote, 0)
    result = json.loads((folder / "boots/boot-result.json").read_text())
    if not result["all_three_pass"] or result["image_sha256"] != original["image_sha256"]:
        raise ConnectionError("Retained parent failed fresh runtime checks; stop the history")
    for i in (1, 2, 3):
        step = json.loads((folder / ("boots/boot%d.json" % i)).read_text())
        if not guest_outcome((folder / ("boots/boot%d.stdout" % i)).read_text(),
                             (folder / ("boots/boot%d.stderr" % i)).read_text(), step["returncode"])["complete"]:
            raise ConnectionError("Retained parent raw output failed replay")
    subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", remote])], check=True, timeout=20)
    return {"image_sha256": original["image_sha256"], "fresh_guest_boots": 3, "passed": True}


def run(plan_path, workspace, graph_path, index, output, socket, host, pi_workspace):
    if output.exists():
        raise ValueError("Existing history must be inspected, not restarted")
    plan = json.loads(plan_path.read_text())
    bank_path = ROOT / plan["task_bank"]
    bank = json.loads(bank_path.read_text())
    if sha(bank_path) != plan["task_bank_sha256"] or (plan["maximum_model_calls"], plan["maximum_completion_tokens"]) != (24, 4608) or \
            (plan["histories_per_method"], plan["rounds_per_history"], plan["attempts_per_round"]) != (3, 2, 1) or \
            plan["methods"] != ["direct", "graph"]:
        raise ValueError("Sequence protocol or authorization limits differ")
    base = next(t for t in bank["tasks"] if t["id"] == plan["source_task"])
    if (plan["generation_budget_s"], plan["maximum_output_tokens_per_round"],
            plan["per_round_decision_budget_s"], plan["per_history_budget_s"],
            plan["candidate_guest_boots"], plan["parent_check_guest_boots"]) != (180, 384, 1800, 3600, 3, 3) or \
            (plan["model"], plan["service"], plan["thinking"], plan["temperature"]) != ("deepseek-v4-pro", "deepseek", "disabled", 0):
        raise ValueError("Frozen model or sequence timing differs")
    for task in bank["tasks"]:
        for item in task["reference_files"]:
            if sha(ROOT / item["path"]) != item["sha256"]:
                raise ValueError("Feasible reference changed")
    for name in ("initial_reference", "alternate_feasible_reference"):
        for i in (1, 2, 3):
            prefix = ROOT / plan[name] / "boots" / ("boot" + str(i))
            step = json.loads(prefix.with_suffix(".json").read_text())
            if not guest_outcome(prefix.with_suffix(".stdout").read_text(), prefix.with_suffix(".stderr").read_text(), step["returncode"])["complete"]:
                raise ValueError("Feasible reference raw outputs incomplete")
    graph = json.loads(graph_path.read_text())
    verify_sources(graph, graph_path, workspace)
    graph_hash, index_hash = sha(graph_path), sha(index / "run.json")
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", host]
    helpers, source_ids = prepare_runtime_helpers(ssh, host, socket, pi_workspace)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(plan_path, output / "protocol.json")
    shutil.copyfile(bank_path, output / "task-bank.json")
    (output / "sources").mkdir()
    names = ["run_tenonos_policy_sequence.py", "run_tenonos_paper_tasks.py", "tenonos_paper_orchestrator.py",
             "tenonos_config_validation.py", "tenonos_lib_graph.py", "tenonos_lightrag_runtime.py", "tenonos_model_service.py",
             "tenonos_kvm_reproduce.py", "tenonos_orchestrator.py", "audit_tenonos_paper_tasks.py",
             "audit_tenonos_tasks.py", "import_iotos_subjects.py", "iotos_task_benchmark.py"]
    hashes = {}
    for name in names:
        source = ROOT / "tools" / name
        hashes[name] = sha(source)
        shutil.copyfile(source, output / "sources" / name)
    save(output / "registration.json", {"registered_utc": utc(), "plan_sha256": sha(plan_path),
         "bank_sha256": sha(bank_path), "source_sha256": hashes, "source_commits": source_ids,
         "graph_sha256": graph_hash, "index_run_sha256": index_hash, "reconstruction": RECONSTRUCTION,
         "model": plan["model"], "service": plan["service"], "maximum_model_calls": 24, "maximum_completion_tokens": 4608,
         "temporary_helpers": helpers, "author_engine": False, "rsi": False})
    histories, calls, tokens = [], 0, 0
    campaign = {"status": "incomplete", "started_utc": utc(), "histories": histories, "model_calls": 0, "completion_tokens": 0}
    save(output / "campaign.json", campaign)
    for number in range(1, 4):
        for method in (("direct", "graph") if number % 2 else ("graph", "direct")):
            history = {"id": "H%d-%s" % (number, method), "method": method, "rounds": []}
            directory = output / history["id"]
            directory.mkdir()
            parent = ROOT / plan["initial_reference"] / "build"
            started = time.monotonic()
            with (directory / "initial.log").open("x") as log, contextlib.redirect_stdout(log):
                history["initial_check"] = boot_parent(directory / "initial", parent, ssh, host, socket, pi_workspace,
                                                       helpers, "/dev/shm/iotos-tenon-v4-" + output.name + "-" + history["id"] + "-initial")
            history["initialization_wall_s"] = time.monotonic() - started
            history["initial_image_sha256"] = sha(parent / "runtime-image")
            histories.append(history)
            feedback, history_clock = {"accepted": None, "gates": None, "required_configuration": []}, time.monotonic()
            for round_index in (1, 2):
                if any(sha(ROOT / "tools" / n) != h for n, h in hashes.items()) or \
                        sha(graph_path) != graph_hash or sha(index / "run.json") != index_hash:
                    raise ValueError("Registered sequence source changed")
                verify_sources(graph, graph_path, workspace)
                if calls + (1 if method == "direct" else 3) > 24 or tokens + 384 > 4608:
                    raise ValueError("Sequence authorization budget exhausted")
                folder = directory / ("R" + str(round_index))
                folder.mkdir()
                clock, before_parent = time.monotonic(), parent
                task = round_task(base, parent / ".config", graph, feedback, round_index)
                save(folder / "task.json", task)
                record = {"round": round_index, "started_utc": utc(), "parent_build": str(parent.relative_to(ROOT)),
                          "parent_image_sha256": sha(parent / "runtime-image"), "parent_config_sha256": sha(parent / ".config"),
                          "target_allocator_option": task["target_allocator_option"], "feedback": feedback, "accepted": False,
                          "gates": {k: False for k in ("generated", "built", "booted", "functional", "constraints")}}
                history["rounds"].append(record)
                save(folder / "round.json", record)
                with (folder / "generation.log").open("x") as log, contextlib.redirect_stdout(log):
                    generated = generate(folder / "task.json", graph_path, index, workspace, folder / "candidate",
                                         plan["model"], "deepseek", 42, 384, DEEPSEEK_KEY, method, "deepseek")
                calls += len(generated["model_calls"])
                tokens += generated["completion_tokens"]
                record.update(generation_wall_s=generated["generation_wall_s"], preflight_wall_s=generated["preflight_wall_s"],
                              model_calls=len(generated["model_calls"]), completion_tokens=generated["completion_tokens"])
                record["gates"]["generated"] = generated["valid_candidate"]
                if not generated["valid_candidate"]:
                    record["failure"] = generated.get("failure")
                evaluation = {}
                if generated["valid_candidate"]:
                    shutil.copyfile(parent / ".config", folder / "candidate/starting-reference.config")
                    with (folder / "runtime.log").open("x") as log, contextlib.redirect_stdout(log):
                        checked = evaluate_pi(folder, ssh, host, socket, pi_workspace,
                            "/dev/shm/iotos-tenon-v4-" + output.name + "-" + history["id"] + "-R" + str(round_index),
                            lambda: 1800 - (time.monotonic() - clock), helpers)
                    record["raw_gates"] = {k: checked[k] for k in record["gates"]}
                    record["gates"] = admitted_gates(record["raw_gates"])
                    path = folder / "candidate/evaluation.json"
                    evaluation = json.loads(path.read_text()) if path.exists() else {}
                    if checked.get("failure"):
                        record["failure"] = checked["failure"]
                record["decision_wall_s"] = time.monotonic() - clock
                record["accepted"] = all(record["gates"].values()) and record["decision_wall_s"] <= 1800
                if record["accepted"]:
                    parent = folder / "evaluation/build"
                else:
                    recovery_clock = time.monotonic()
                    with (folder / "recovery.log").open("x") as log, contextlib.redirect_stdout(log):
                        record["recovery"] = boot_parent(folder / "recovery", parent, ssh, host, socket, pi_workspace,
                            helpers, "/dev/shm/iotos-tenon-v4-" + output.name + "-" + history["id"] + "-R" + str(round_index) + "-recovery")
                    record["recovery_wall_s"] = time.monotonic() - recovery_clock
                record.update(retained_build=str(parent.relative_to(ROOT)), retained_image_sha256=sha(parent / "runtime-image"),
                              retained_config_sha256=sha(parent / ".config"), observed_wall_s=time.monotonic() - clock,
                              finished_utc=utc(), policy_changed=configuration(parent / ".config") != configuration(before_parent / ".config"))
                feedback = configuration_feedback(record["gates"], record["accepted"], evaluation)
                record["next_feedback"] = feedback
                save(folder / "round.json", record)
                campaign.update(model_calls=calls, completion_tokens=tokens)
                save(output / "campaign.json", campaign)
                print(json.dumps({"history": history["id"], "round": round_index, "accepted": record["accepted"],
                                  "observed_wall_s": record["observed_wall_s"], "model_calls_so_far": calls}), flush=True)
            history.update(final_image_sha256=sha(parent / "runtime-image"), final_config_sha256=sha(parent / ".config"),
                           total_round_wall_s=time.monotonic() - history_clock)
            history["within_history_budget"] = history["total_round_wall_s"] <= 3600
            save(output / "campaign.json", campaign)
    campaign.update(status="collection_complete", completed_utc=utc())
    save(output / "campaign.json", campaign)
    subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", helpers])], check=True, timeout=20)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "workspace", "graph", "index", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--socket", default="/tmp/iotos-pi-api.sock")
    parser.add_argument("--host", default="pi@192.168.31.76")
    parser.add_argument("--pi-workspace", default="/home/pi/tenonos-benchmark-v1")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Collect histories and retain all evidence on leon")
    with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(args.plan.resolve(), args.workspace.resolve(), args.graph.resolve(), args.index.resolve(),
            args.output.resolve(), args.socket, args.host, args.pi_workspace)
