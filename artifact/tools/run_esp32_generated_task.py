#!/usr/bin/env python3
"""Run frozen configuration tasks with the independent Kconfig baseline."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shutil
import statistics
import tempfile

from build_esp32_evolution_candidate import audit_candidate, build
from import_iotos_subjects import config_text
from run_esp32_followup import Board
from audit_esp32_tm_basic import audit as original_audit
from audit_esp32_tm_reboots import require_self_check, require_cpu2_interrupt
from iotos_task_benchmark import constraint_oracle

ROOT = Path(__file__).resolve().parents[1]
SUBJECT = "Independent-Kconfig-Qwen/Zephyr"
MAC = "34:98:7a:a2:85:28"
MODEL = "qwen2.5-1.5b-instruct-q4_k_m"
SEEDS = (42, 43, 44)
CODE = ("run_esp32_generated_task.py", "tenonos_orchestrator.py", "tenonos_kvm_reproduce.py",
        "build_esp32_evolution_candidate.py", "import_iotos_subjects.py", "run_esp32_followup.py",
        "capture_esp32_uart.py", "audit_esp32_tm_basic.py", "audit_esp32_tm_reboots.py",
        "iotos_task_benchmark.py")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def task_cells(folder, run, task):
    for i, case in enumerate(task["workloads"]):
        bundle = folder / ("task" if i == 0 else "task-" + case)
        cell = run if len(task["workloads"]) == 1 else run / case
        yield case, bundle, cell


def prepare(folder, kernel, task_id="B1", generate_on_collect=False):
    """Freeze inputs before inference; retain the original task bank unchanged."""
    import kconfiglib as kc
    bank = ROOT / "registry/iotos_tasks_v1.json"
    admitted = ROOT / "artifacts/reports/iotos-task-bank-v1.json"
    task = next(t for t in json.loads(bank.read_text())["tasks"] if t["id"] == task_id)
    if task["workloads"][0] != "message_processing" or set(task["workloads"]) - {
            "message_processing", "synchronization_processing", "interrupt_processing"}:
        raise ValueError("This recorder supports the frozen queue, semaphore and real-IRQ workloads")
    qualification = json.loads(admitted.read_text())
    if qualification["bank_sha256"] != sha(bank) or not next(
            t for t in qualification["tasks"] if t["id"] == task_id)["admitted"]:
        raise ValueError("The frozen task lacks a feasible reference")
    folder.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT / "artifacts/reports/esp32-evolution-build-control-v1/task", folder / "task")
    for case in task["workloads"][1:]:
        source = ROOT / "artifacts/reports/esp32-task-reference-b1-v1/C2" / case / "task"
        destination = folder / ("task-" + case)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            from iotos_evolution import audited_inventory, prepare_mcu
            prepare_mcu(audited_inventory(), destination, case)
    shutil.copyfile(kernel, folder / "kernel.Kconfig")
    shutil.copyfile(bank, folder / "task-bank.json")
    shutil.copyfile(admitted, folder / "reference-qualification.json")
    interpretation = ROOT / "registry/iotos_kconfig_native_resolution_v1.json"
    if interpretation.is_file():
        shutil.copyfile(interpretation, folder / "native-config-semantics.json")
    shutil.copyfile(ROOT / "artifacts/reports/tenonos-rpi4-v1/local-model-1.5b.json", folder / "model.json")
    (folder / "tools").mkdir()
    for name in CODE:
        shutil.copyfile(ROOT / "tools" / name, folder / "tools" / name)
    # Parse the two complete native choice blocks, not hand-written descriptions.
    source = kernel.read_text()
    blocks = [re.search(r"^choice " + name + r"\n.*?^endchoice[^\n]*", source, re.M | re.S).group()
              for name in ("SCHED_ALGORITHM", "WAITQ_ALGORITHM")]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Kconfig"
        path.write_text("\n\n".join(blocks) + "\n")
        parsed = kc.Kconfig(str(path), warn_to_stderr=False)
        job = json.loads((folder / "task/job.json").read_text())
        controls = [n.removeprefix("CONFIG_") for n in job["execution"]["zephyr_candidate_controls"]]
        nodes = []
        for name in controls:
            symbol = parsed.syms[name]
            nodes.append({"name": name, "type": kc.TYPE_TO_STR[symbol.type],
                "prompt": " ".join(n.prompt[0] for n in symbol.nodes if n.prompt),
                "help": "\n".join(n.help for n in symbol.nodes if n.help),
                "depends": kc.expr_str(symbol.direct_dep),
                "references": sorted(s.name for s in symbol.referenced if s.name in controls)})
    save(folder / "graph.json", {"nodes": nodes, "source": "Zephyr v3.7.0 kernel/Kconfig",
        "source_sha256": sha(kernel), "parser": "kconfiglib 14.1.0",
        "fixed_external_dependency": {"SCHED_DEADLINE": "n"}})
    throughput_requirement = ""
    if "minimum_reference_throughput_ratio" in task["constraints"]:
        throughput_requirement = "The required original throughput is at least 90% of 17453974 counts per 30 seconds. "
        if len(task["workloads"]) > 1:
            references = {case: json.loads((bundle / "job.json").read_text())["reference"]["median"]
                          for case, bundle, _ in task_cells(folder, folder, task)}
            throughput_requirement = "Each original throughput must retain 90% of its own reference count/30s: " + json.dumps(references) + ". "
    model_task = {"id": task_id, "subject": SUBJECT, "target_system": "Zephyr ESP32 runtime",
        "objective": task["requirements"] + " The platform, application, adapter, 240-MHz clock, "
        "one core, periodic 100-Hz tick and GCC13.2/-Os are frozen outside your output. "
        "Choose only the provided native ready-queue and wait-queue options. "
        "The fixed reference uses SCHED_DUMB=y and WAITQ_DUMB=y. " +
        throughput_requirement + "Do not change the application or its self-checks.",
        "fixed_options": {}, "candidate_controls": controls, "generation_budget_s": 180}
    save(folder / "model-task.json", model_task)
    registration = {"schema": "esp32-generated-" + task_id.lower() + "-v1", "subject": SUBJECT,
        "author_orchestrator": False, "registered_utc": utc(), "task": task,
        "extension": "User-authorized independent Kconfig baseline, adapted from the frozen Tenon prototype. "
        "The original task bank, workload and thresholds are unchanged; this is not TenonOS or RSI.",
        "trials": [{"id": task_id + "-" + str(i), "seed": seed} for i, seed in enumerate(SEEDS, 1)],
        "model": MODEL, "temperature": 0, "maximum_output_tokens": 384,
        "generation_attempts": 1, "wall_budget_s": 1800, "independent_resets_per_artifact": 3,
        "feedback": "No runtime feedback, automatic repairs, retries or prompt/model tuning.",
        "board_mac": MAC, "profile": "B1/240MHz/one-core/100Hz/GCC13.2/-Os",
        "statistics": "Three registered deterministic calls; report counts and median/range, not P95 or population success probability.",
        "completion_time": "Task receipt through final required raw-capture validation; includes queued calls/builds and Flash backup, excludes subsequent restoration and offline replay.",
        "energy_measured": False, "whole_ram_peak_measured": False,
        "online_oracle": True,
        "inputs": {p.relative_to(folder).as_posix(): sha(p) for p in folder.rglob("*") if p.is_file()}}
    if generate_on_collect:
        registration["dispatch"] = "generate_each_trial_immediately_before_its_build_and_capture"
    save(folder / "registration.json", registration)
    return registration


def registered(folder):
    registration = json.loads((folder / "registration.json").read_text())
    for name, digest in registration["inputs"].items():
        if sha(folder / name) != digest:
            raise ValueError("Frozen experiment input changed: " + name)
    bank = json.loads((folder / "task-bank.json").read_text())
    task = next(t for t in bank["tasks"] if t["id"] == registration["task"]["id"])
    if registration["task"] != task or registration["trials"] != [
            {"id": task["id"] + "-" + str(i), "seed": seed} for i, seed in enumerate(SEEDS, 1)] or \
            registration["wall_budget_s"] != bank["budget"]["max_wall_s"] or \
            registration["generation_attempts"] != bank["budget"]["max_generation_attempts"] or \
            registration["independent_resets_per_artifact"] != bank["statistics"]["independent_resets_per_artifact"]:
        raise ValueError("Registered task, attempts or budget differs from the frozen bank")
    return registration


def generate(folder, endpoint):
    from tenonos_orchestrator import generate as public_model_call
    registration = registered(folder)
    if registration.get("dispatch"):
        raise ValueError("This batch dispatches generation during acquisition, not in advance")
    for trial in registration["trials"]:
        start = datetime.now(timezone.utc)
        if start <= datetime.fromisoformat(registration["registered_utc"]):
            raise ValueError("Generation predates registration")
        destination = folder / trial["id"]
        destination.mkdir()
        public_model_call(folder / "graph.json", folder / "model-task.json", destination / "candidate",
                          endpoint, MODEL, trial["seed"])


def measured_capture(folder, index, case="message_processing"):
    rows = [json.loads(line) for line in (folder / ("reset%d.jsonl" % index)).read_text().splitlines()]
    if case == "interrupt_processing":
        require_cpu2_interrupt(rows)
    else:
        require_self_check(rows, "queue" if case == "message_processing" else "semaphore")
    resets = [r for r in rows if r["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
        raise ValueError("Missing independent physical reset")
    return original_audit(folder / ("reset%d.jsonl" % index), "Zephyr", case)


def online_task_checks(folder, run, task):
    sizes, counts, references, configs = {}, {}, {}, {}
    for case, bundle, cell in task_cells(folder, run, task):
        sizes[case] = (cell / "build/application.bin").stat().st_size
        counts[case] = [json.loads((cell / "captures" / ("result%d.json" % i)).read_text())["original_window_totals"][0]
                        for i in (1, 2, 3)]
        references[case] = json.loads((bundle / "job.json").read_text())["reference"]["values"]
        configs[case], _ = config_text((cell / "build/config").read_text())
    return constraint_oracle(task, sizes, counts, references, resolved_configs=configs)


def collect(folder, root, port, endpoint=None):
    registration = registered(folder)
    campaign = {"registered_sha256": sha(folder / "registration.json"), "started_utc": utc(),
        "status": "incomplete", "original_flash_restored": False, "board_mac": MAC, "trials": []}
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        board = Board(root, folder, MAC, port)
        backed_up = False
        try:
            for trial in registration["trials"]:
                run = folder / trial["id"]
                if registration.get("dispatch"):
                    if endpoint is None:
                        raise ValueError("Registered serial dispatch requires the local-model endpoint")
                    from tenonos_orchestrator import generate as public_model_call
                    run.mkdir()
                    public_model_call(folder / "graph.json", folder / "model-task.json", run / "candidate",
                                      endpoint, MODEL, trial["seed"])
                generated = json.loads((run / "candidate/generation.json").read_text())
                result = {"id": trial["id"], "built": False, "runtime_collected": False,
                          "infrastructure_invalid": False}
                campaign["trials"].append(result)
                if not generated["valid_candidate"]:
                    result.update(completed_utc=utc(), failure="generation")
                    continue
                try:
                    for case, bundle, cell in task_cells(folder, run, registration["task"]):
                        cell.mkdir(parents=True, exist_ok=True)
                        build(bundle, cell / "build", root, run / "candidate/candidate.defconfig")
                        save(cell / "build-audit.json", audit_candidate(bundle, cell / "build"))
                    result["built"] = True
                except Exception as exc:
                    result.update(completed_utc=utc(), failure="build: " + str(exc))
                    continue
                try:
                    if not backed_up:
                        board.backup()
                        backed_up = True
                    for case, _, cell in task_cells(folder, run, registration["task"]):
                        captures = cell / "captures"
                        captures.mkdir()
                        pairs = board.flash(captures, cell / "build")
                        for i in (1, 2, 3):
                            board.capture(captures, i, 95, capture_script=folder / "tools/capture_esp32_uart.py")
                            save(captures / ("result%d.json" % i), measured_capture(captures, i, case))
                            board.verify(pairs, captures / ("verify-run%d.log" % i))
                            print(trial["id"], case, "physical reset", i, "complete", flush=True)
                        board.verify(pairs, captures / "verify-after.log")
                    if registration.get("online_oracle"):
                        checks = online_task_checks(folder, run, registration["task"])
                        save(run / "task-checks.json", {"validated_utc": utc(), "result": checks})
                    result.update(runtime_collected=True, completed_utc=utc())
                except ValueError as exc:
                    result.update(completed_utc=utc(), failure="runtime checks: " + str(exc))
                except Exception as exc:
                    result.update(infrastructure_invalid=True, completed_utc=utc(), failure=str(exc))
                    raise
                finally:
                    save(run / "collection.json", result)
            campaign["status"] = "collection_complete"
        finally:
            try:
                if backed_up:
                    board.restore()
                    campaign["original_flash_restored"] = True
            finally:
                campaign["completed_utc"] = utc()
                save(folder / "campaign.json", campaign)


def audit(folder):
    from run_esp32_followup import verified
    from run_esp32_followup import read_raw_capture
    from tenonos_orchestrator import options_from_response
    registration = registered(folder)
    campaign = json.loads((folder / "campaign.json").read_text())
    if campaign["registered_sha256"] != sha(folder / "registration.json") or campaign["status"] != "collection_complete":
        raise ValueError("Incomplete acquisition")
    if [r["id"] for r in campaign["trials"]] != [r["id"] for r in registration["trials"]]:
        raise ValueError("A registered attempt was dropped")
    if any(r["runtime_collected"] for r in campaign["trials"]):
        if not campaign["original_flash_restored"]:
            raise ValueError("Original full Flash was not restored")
        restore = (folder / "restore-verify.log").read_text()
        if "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in restore or \
                "verify OK (digest matched)" not in restore or set(re.findall(r"^MAC: ([0-9a-f:]+)$", restore, re.M)) != {MAC}:
            raise ValueError("Full-Flash restoration evidence differs")
    graph = json.loads((folder / "graph.json").read_text())
    task = registration["task"]
    previous, results = None, []
    for trial, collection in zip(registration["trials"], campaign["trials"]):
        run = folder / trial["id"]
        generated = json.loads((run / "candidate/generation.json").read_text())
        request = json.loads((run / "candidate/request.json").read_text())
        if generated["subject"] != SUBJECT or generated["model"] != MODEL or \
                generated["task_sha256"] != sha(folder / "model-task.json") or \
                generated["graph_sha256"] != sha(folder / "graph.json") or \
                generated["generator_code_sha256"] != registration["inputs"]["tools/tenonos_orchestrator.py"] or \
                request["model"] != MODEL or request["temperature"] != 0 or request["seed"] != trial["seed"] or \
                request["max_tokens"] != 384 or request["messages"][0]["role"] != "system":
            raise ValueError("Generation identity/budget changed")
        started = datetime.fromisoformat(generated["started_utc"])
        if started <= datetime.fromisoformat(registration["registered_utc"]):
            raise ValueError("Task run predates registration")
        if registration.get("dispatch") and previous is not None and started <= previous:
            raise ValueError("Serial task generation predates the previous acquisition")
        gates = {"generated": generated["valid_candidate"], "built": False,
                 "booted": False, "functional": False, "constraints": False}
        result = {"id": trial["id"], "gates": gates, "failure": collection.get("failure"),
            "generation_wall_s": generated["generation_wall_s"],
            "observed_wall_s": (datetime.fromisoformat(collection["completed_utc"]) - started).total_seconds(),
            "infrastructure_invalid": collection["infrastructure_invalid"], "success": False}
        if generated["valid_candidate"]:
            response = json.loads((run / "candidate/response.json").read_text())
            options = options_from_response(response["choices"][0]["message"]["content"], graph)
            expected = "\n".join("CONFIG_" + k + "=" + v for k, v in options.items()) + "\n"
            if options != generated["options"] or (run / "candidate/candidate.defconfig").read_text() != expected or \
                    sha(run / "candidate/candidate.defconfig") != generated["candidate_sha256"]:
                raise ValueError("Candidate differs from the actual model response")
            result["options"] = options
        if collection["built"]:
            boot_markers = []
            for case, bundle, cell in task_cells(folder, run, task):
                proof = audit_candidate(bundle, cell / "build")
                if proof != json.loads((cell / "build-audit.json").read_text()) or \
                        sha(cell / "build/candidate.conf") != generated["candidate_sha256"]:
                    raise ValueError("Build did not consume this generated artifact")
                first = cell / "captures/reset1.jsonl"
                lines = [json.loads(line)["line"] for line in first.read_text().splitlines()] if first.exists() else []
                boot_markers.append(sum("Thread-Metric Zephyr ESP32 boot" in line for line in lines) == 1)
            gates["built"] = True
            gates["booted"] = all(boot_markers)
        if collection["runtime_collected"]:
            workloads, sizes, counts, references, configs = [], {}, {}, {}, {}
            for case, bundle, cell in task_cells(folder, run, task):
                captures, built = cell / "captures", cell / "build"
                verified(captures, built, MAC)
                values = []
                for i in (1, 2, 3):
                    rows = read_raw_capture(captures, i)
                    actual = measured_capture(captures, i, case)
                    if actual != json.loads((captures / ("result%d.json" % i)).read_text()):
                        raise ValueError("Derived original count changed")
                    verified(captures, built, MAC, logs=("verify-run%d.log" % i,))
                    begin, end = (datetime.fromisoformat(rows[n]["utc"]) for n in (0, -1))
                    if begin <= started or previous is not None and begin <= previous:
                        raise ValueError("Physical reset chronology overlaps")
                    previous = end
                    values.append(actual["original_window_totals"][0])
                config, _ = config_text((built / "config").read_text())
                source_job = json.loads((bundle / "job.json").read_text())
                sizes[case], counts[case], references[case], configs[case] = (
                    (built / "application.bin").stat().st_size, values, source_job["reference"]["values"], config)
                workloads.append({"case": case, "values": values, "median_count_30s": statistics.median(values),
                    "image_bytes": sizes[case], "throughput_ratio": statistics.median(values)/source_job["reference"]["median"]})
            checks = constraint_oracle(task, sizes, counts, references, resolved_configs=configs)
            if registration.get("online_oracle"):
                online = json.loads((run / "task-checks.json").read_text())
                validated = datetime.fromisoformat(online["validated_utc"])
                if online["result"] != checks or not previous <= validated <= datetime.fromisoformat(collection["completed_utc"]):
                    raise ValueError("Online task validator differs from source replay or completion time")
                previous = validated
            gates.update(booted=True, functional=True, constraints=checks["pass"])
            if len(workloads) == 1:
                result.update(values=workloads[0]["values"], median_count_30s=workloads[0]["median_count_30s"],
                    image_bytes=workloads[0]["image_bytes"], constraint_checks=checks,
                    throughput_ratio=workloads[0]["throughput_ratio"])
            else:
                result.update(workloads=workloads, constraint_checks=checks)
        result["success"] = all(gates.values()) and not result["infrastructure_invalid"] and \
            0 <= result["observed_wall_s"] <= registration["wall_budget_s"]
        results.append(result)
    successful = [r["observed_wall_s"] for r in results if r["success"]]
    return {"audit": "pass", "subject": SUBJECT, "task_id": task["id"], "board_mac": MAC,
        "registered_trials": len(results), "successes": sum(r["success"] for r in results),
        "stage_counts": {k: sum(r["gates"][k] for r in results) for k in results[0]["gates"]},
        "trials": results, "successful_completion_median_s": statistics.median(successful) if successful else None,
        "successful_completion_range_s": [min(successful), max(successful)] if successful else None,
        "unique_candidates": len({sha(folder / t["id"] / "candidate/candidate.defconfig")
            for t in registration["trials"] if (folder / t["id"] / "candidate/candidate.defconfig").exists()}),
        "original_flash_restored": campaign["original_flash_restored"], "energy_measured": False,
        "whole_ram_peak_measured": False, "p95_s": None,
        "boundary": "Three repeated calls on one original ESP32 task; no author TenonOS, RSI, population success probability or cross-platform ranking."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "generate", "collect", "audit"))
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--task-id", choices=("A1", "A2", "B1", "B2", "C1", "C2"), default="B1")
    parser.add_argument("--generate-on-collect", action="store_true")
    parser.add_argument("--endpoint", default="http://127.0.0.1:18089/v1")
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    folder = args.folder.resolve()
    if args.command == "prepare":
        result = prepare(folder, args.kernel, args.task_id, args.generate_on_collect)
    elif args.command == "generate":
        result = generate(folder, args.endpoint)
    elif args.command == "collect":
        result = collect(folder, args.root, args.port, args.endpoint)
    else:
        result = audit(folder)
        save(folder / "audit.json", result)
    if result is not None:
        print(json.dumps(result, indent=2))
