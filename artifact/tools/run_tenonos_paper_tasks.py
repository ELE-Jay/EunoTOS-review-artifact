#!/usr/bin/env python3
"""Run paired trials from leon, retaining Pi's native build/guest records on leon."""
import argparse
import contextlib
import fcntl
import json
import math
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

from iotos_task_benchmark import summarize_accounting
from tenonos_config_validation import verify_sources
from tenonos_kvm_reproduce import save, sha, utc
from tenonos_model_service import DEEPSEEK_KEY
from tenonos_orchestrator import check_resolved
from tenonos_paper_orchestrator import RECONSTRUCTION, generate


def planned_trials(tasks, repetitions):
    rows = []
    for repeat in range(1, repetitions + 1):
        for task in tasks:
            for method in (("direct", "graph") if repeat % 2 else ("graph", "direct")):
                rows.append({"id": task["id"] + "-" + str(repeat) + "-" + method,
                             "task": task["id"], "repeat": repeat, "method": method})
    return rows


def admitted_gates(raw):
    gates, preceding = {}, True
    for name in ("generated", "built", "booted", "functional", "constraints"):
        gates[name] = preceding and raw[name] is True
        preceding = gates[name]
    return gates


def retain_runtime_transfer(folder, manifest, remote_path, returncode, remote_evaluation=None):
    overrides, reconciled = {}, None
    for name, expected in manifest.items():
        local = (folder / name).resolve()
        local.relative_to(folder.resolve())
        if sha(local) == expected:
            continue
        if name != "candidate/evaluation.json" or remote_evaluation is None or \
                json.loads(local.read_bytes()) != json.loads(remote_evaluation):
            raise ConnectionError("Returned runtime evidence differs: " + name)
        original = folder / "runtime-transfer-repair/remote-evaluation.json"
        original.parent.mkdir(exist_ok=True)
        with original.open("xb") as stream:
            stream.write(remote_evaluation)
        if sha(original) != expected:
            raise ConnectionError("Returned evaluator original differs")
        overrides[name] = str(original.relative_to(folder))
        reconciled = {"kind": "json_serialization_order_only", "structured_equal": True,
                      "local_replay_sha256": sha(local), "remote_original_sha256": expected}
    receipt = {"remote_temporary_path": remote_path, "files": manifest, "all_equal": True,
               "file_overrides": overrides, "serialization_reconciliation": reconciled,
               "omitted_regenerable_subtrees": ["evaluation/build/build"], "remote_returncode": returncode}
    save(folder / "runtime-transfer-check.json", receipt)
    return receipt


def evaluate_pi(folder, ssh, host, socket, pi_workspace, remote_path, remaining, helper_directory=None):
    if Path(remote_path).parent != Path("/dev/shm") or not Path(remote_path).name.startswith("iotos-tenon-v4-"):
        raise ValueError("Temporary operation path is outside the dedicated prefix")
    candidate = folder / "candidate"
    names = ["task.json", "generation.json", "candidate.defconfig"]
    if (candidate / "starting-reference.config").exists():
        names.append("starting-reference.config")
    with (folder / "transfer.stdout").open("wb") as out, (folder / "transfer.stderr").open("wb") as err:
        subprocess.run([*ssh, shlex.join(["mkdir", "-m", "700", remote_path])], check=True,
                       stdout=out, stderr=err, timeout=20)
        subprocess.run([*ssh, shlex.join(["mkdir", remote_path + "/candidate"])], check=True,
                       stdout=out, stderr=err, timeout=20)
        subprocess.run(["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes",
                        *[str(candidate / n) for n in names], host + ":" + remote_path + "/candidate/"],
                       check=True, stdout=out, stderr=err, timeout=30)
    limit = math.floor(remaining())
    if limit <= 0:
        raise TimeoutError("Task budget exhausted before runtime evaluation")
    argv = ["timeout", "--kill-after=10", str(limit), "env", "PYTHONPATH=" + pi_workspace + "/python-deps",
            "python3", (helper_directory or pi_workspace) + "/tenonos_orchestrator.py", "evaluate", "--workspace", pi_workspace,
            "--candidate-dir", remote_path + "/candidate", "--output", remote_path + "/evaluation"]
    with (folder / "remote-evaluation.stdout").open("wb") as out, (folder / "remote-evaluation.stderr").open("wb") as err:
        result = subprocess.run([*ssh, shlex.join(argv)], stdout=out, stderr=err, timeout=limit + 20)
    if result.returncode == 255:
        raise ConnectionError("Pi SSH disconnected; inspect the same temporary operation before resuming")
    with (folder / "retrieve.stdout").open("wb") as out, (folder / "retrieve.stderr").open("wb") as err:
        subprocess.run(["rsync", "-a", "--exclude=/build/build/", "-e", shlex.join(ssh[:-1]), host + ":" + remote_path + "/evaluation/",
                        str(folder / "evaluation") + "/"], check=True, stdout=out, stderr=err, timeout=120)
    pipeline = json.loads((folder / "evaluation/pipeline.json").read_text())
    if (folder / "evaluation/boots/boot-result.json").exists():
        checked = check_resolved(candidate, folder / "evaluation/build", folder / "evaluation/boots")
        if any(checked[k] != pipeline[k] for k in ("generated", "built", "booted", "functional", "constraints")):
            raise ValueError("Pi and leon runtime verdicts differ")
        pipeline["local_replay_equal"] = True
    # Keep the original harness's retained ELF/config/logs; omit only rebuildable object intermediates.
    manifest_code = "import pathlib,hashlib,json; r=pathlib.Path(" + repr(remote_path) + "); print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob('*') if p.is_file() and not p.is_symlink() and p.relative_to(r).parts[:3]!=('evaluation','build','build')}))"
    manifest = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", manifest_code])],
                                                 timeout=30, universal_newlines=True))
    original = None
    if "candidate/evaluation.json" in manifest and sha(candidate / "evaluation.json") != manifest["candidate/evaluation.json"]:
        original = subprocess.check_output([*ssh, shlex.join(["cat", "--", remote_path + "/candidate/evaluation.json"])], timeout=20)
    retain_runtime_transfer(folder, manifest, remote_path, result.returncode, original)
    subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", remote_path])], check=True, timeout=20)
    return pipeline


def prepare_runtime_helpers(ssh, host, socket, pi_workspace):
    helpers = [Path(__file__).with_name(n) for n in ("tenonos_kvm_reproduce.py", "tenonos_orchestrator.py")]
    helper_directory = "/dev/shm/iotos-tenon-v4-helpers-" + "-".join(sha(p)[:10] for p in helpers)
    subprocess.run([*ssh, shlex.join(["mkdir", "-m", "700", helper_directory])], check=True, timeout=20)
    subprocess.run(["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes",
                    *[str(p) for p in helpers], host + ":" + helper_directory + "/"], check=True, timeout=30)
    code = "import sys,pathlib,json; w=pathlib.Path(" + repr(pi_workspace) + ");h=pathlib.Path(" + repr(helper_directory) + ");sys.path.insert(0,str(h));from tenonos_kvm_reproduce import sources,sha;print(json.dumps({'source_commits':sources(w,True,'abi'),'helper_sha256':{n:sha(h/n) for n in ['tenonos_kvm_reproduce.py','tenonos_orchestrator.py']}}))"
    source_ids = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])],
                                                  timeout=30, universal_newlines=True))
    for name, expected in source_ids["helper_sha256"].items():
        if sha(Path(__file__).with_name(name)) != expected:
            raise ValueError("Pi runtime helper differs: " + name)
    return helper_directory, source_ids


def run(bank_path, workspace, graph_path, index, output, socket, host, pi_workspace):
    root = Path(__file__).resolve().parents[1]
    bank = json.loads(bank_path.read_text())
    if (bank["maximum_output_tokens"], bank["generation_budget_s"], bank["attempts_per_trial"],
            bank["independent_guest_boots_per_candidate"]) != (384, 180, 1, 3):
        raise ValueError("Frozen task budgets differ")
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", host]
    if output.exists():
        raise ValueError("Existing campaign must be reconciled, not overwritten")
    helper_directory, source_ids = prepare_runtime_helpers(ssh, host, socket, pi_workspace)
    graph = json.loads(graph_path.read_text())
    verify_sources(graph, graph_path, workspace)
    for task in bank["tasks"]:
        for item in task["reference_files"]:
            if sha(root / item["path"]) != item["sha256"]:
                raise ValueError("Frozen feasible reference changed")
    output.mkdir(parents=True, exist_ok=False)
    task_dir = output / "tasks"
    task_dir.mkdir()
    for task in bank["tasks"]:
        save(task_dir / (task["id"] + ".json"), {**task, "protocol_id": bank["id"], "bank_sha256": sha(bank_path)})
    code = ["run_tenonos_paper_tasks.py", "tenonos_paper_orchestrator.py", "tenonos_model_service.py",
            "tenonos_config_validation.py", "tenonos_lib_graph.py", "tenonos_lightrag_runtime.py",
            "tenonos_kvm_reproduce.py", "tenonos_orchestrator.py", "iotos_task_benchmark.py", "import_iotos_subjects.py"]
    source_dir = output / "sources"
    source_dir.mkdir()
    hashes = {}
    for name in code:
        p = Path(__file__).with_name(name)
        hashes[name] = sha(p)
        shutil.copyfile(p, source_dir / name)
    registration = {"protocol_id": "tenon-paper-v4-paired-v2", "registered_utc": utc(),
        "historical_task_bank_sha256": sha(bank_path), "source_sha256": hashes, "source_commits": source_ids,
        "task_sha256": {t["id"]: sha(task_dir / (t["id"] + ".json")) for t in bank["tasks"]},
        "graph_sha256": sha(graph_path), "index_run_sha256": sha(index / "run.json"),
        "service": "deepseek", "model": "deepseek-v4-pro", "thinking": "disabled", "seed_supported": False,
        "temporary_pi_helpers": helper_directory,
        "temperature": 0, "aggregate_completion_tokens_per_trial": 384, "generation_budget_s": 180,
        "wall_budget_s": bank["wall_budget_s"], "attempts_per_trial": 1, "reconstruction": RECONSTRUCTION,
        "trials": planned_trials(bank["tasks"], len(bank["seeds"])),
        "statistics": "Three fresh calls per task and method; median/range, no P95; retain all failures.",
        "scope": "Independent paper reconstruction versus matched direct prompting; not author code, V3, MCU performance or RSI."}
    save(output / "registration.json", registration)
    records = []
    for trial in registration["trials"]:
        verify_sources(graph, graph_path, workspace)
        if any(sha(Path(__file__).with_name(n)) != digest for n, digest in hashes.items()):
            raise ValueError("Campaign source changed; no additional requests permitted")
        if sha(graph_path) != registration["graph_sha256"] or sha(index / "run.json") != registration["index_run_sha256"]:
            raise ValueError("Graph/index changed; no additional requests permitted")
        task = next(t for t in bank["tasks"] if t["id"] == trial["task"])
        folder = output / trial["id"]
        folder.mkdir()
        before = time.monotonic()
        record = {"id": trial["id"], "task_id": task["id"], "method": trial["method"],
            "family": task["family"], "started_utc": utc(), "applicable": True, "infrastructure_invalid": False,
            "timed_out": False, "budget_wall_s": bank["wall_budget_s"],
            "gates": {name: False for name in ("generated", "built", "booted", "functional", "constraints")}}
        save(folder / "trial.json", record)
        try:
            with (folder / "generation.log").open("x") as log, contextlib.redirect_stdout(log):
                generated = generate(task_dir / (task["id"] + ".json"), graph_path, index, workspace,
                    folder / "candidate", "deepseek-v4-pro", "deepseek", 42, 384, DEEPSEEK_KEY, trial["method"], "deepseek")
            record["gates"]["generated"] = generated["valid_candidate"]
            if not generated["valid_candidate"]:
                record["failure"] = generated.get("failure")
            else:
                if task.get("preserve_reference"):
                    shutil.copyfile(root / task["starting_reference_file"], folder / "candidate/starting-reference.config")
                remaining = lambda: bank["wall_budget_s"] - (time.monotonic() - before)
                remote_path = "/dev/shm/iotos-tenon-v4-" + output.name + "-" + trial["id"]
                with (folder / "boot-check.log").open("x") as log, contextlib.redirect_stdout(log):
                    checked = evaluate_pi(folder, ssh, host, socket, pi_workspace, remote_path, remaining, helper_directory)
                record["raw_gates"] = {k: checked[k] for k in record["gates"]}
                record["gates"] = admitted_gates(record["raw_gates"])
                if (folder / "candidate/evaluation.json").exists():
                    record["external_check_sha256"] = sha(folder / "candidate/evaluation.json")
                if checked.get("failure"):
                    record["failure"] = checked["failure"]
        except (ConnectionError, subprocess.CalledProcessError) as error:
            record.update(infrastructure_invalid=True, failure=type(error).__name__ + ": " + str(error))
        except Exception as error:
            record["failure"] = type(error).__name__ + ": " + str(error)
        finally:
            record.update(finished_utc=utc(), observed_wall_s=time.monotonic() - before, benchmark_trial=True)
            record["timed_out"] = record["observed_wall_s"] > bank["wall_budget_s"]
            record["end_to_end_pass"] = all(record["gates"].values()) and not record["timed_out"]
            save(folder / "trial.json", record)
            records.append(record)
            save(output / "results.json", {"protocol_id": registration["protocol_id"], "records": records,
                "accounting": {m: summarize_accounting([r for r in records if r["method"] == m]) for m in ("direct", "graph")},
                "finished": len(records) == len(registration["trials"])})
            print(json.dumps({k: record[k] for k in ("id", "gates", "observed_wall_s", "end_to_end_pass")}), flush=True)
        if record["infrastructure_invalid"]:
            raise RuntimeError("Infrastructure stopped; inspect the recorded remote operation before resuming")
    subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", helper_directory])], check=True, timeout=20)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bank", "workspace", "graph", "index", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--socket", default="/tmp/iotos-pi-api.sock")
    parser.add_argument("--host", default="pi@192.168.31.76")
    parser.add_argument("--pi-workspace", default="/home/pi/tenonos-benchmark-v1")
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run the campaign and retain its evidence on leon")
    with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(args.bank.resolve(), args.workspace.resolve(), args.graph.resolve(), args.index.resolve(),
            args.output.resolve(), args.socket, args.host, args.pi_workspace)
