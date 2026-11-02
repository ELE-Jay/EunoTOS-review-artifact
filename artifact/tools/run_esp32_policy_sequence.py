#!/usr/bin/env python3
"""Acquire and replay prospective, state-linked public-model configuration updates."""
import argparse
from datetime import datetime
import fcntl
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from build_esp32_evolution_candidate import audit_candidate, build
from import_iotos_subjects import config_text
from run_esp32_followup import Board
from run_esp32_generated_task import (CODE, MAC, MODEL, ROOT, SUBJECT, measured_capture,
    online_task_checks, prepare as prepare_task, registered as registered_task, save, sha, task_cells, utc)
from tenonos_orchestrator import generate, options_from_response, request_payload


def load(path):
    return json.loads(path.read_text())


def choice_state(config, plan):
    resolved, _ = config_text(config)
    return {name: resolved.get("CONFIG_" + name, "n") for name in plan["initial_config"]}


def model_task(base, state, feedback, task_id):
    task = dict(base)
    task["starting_options"] = dict(state)
    task["objective"] = ("Update the currently deployed OS configuration. " + base["objective"] +
        " This is round " + task_id + " of a prescribed policy-update sequence. "
        "The starting options below describe the actual retained parent; where the original task "
        "mentions a fixed start, use this current parent instead. Prior external validation: " +
        json.dumps(feedback, sort_keys=True) + ". Do not change the test, constraints or evaluator.")
    return task


def prepare(folder, kernel):
    folder.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT / "registry/iotos_policy_sequence_v1.json", folder / "protocol.json")
    plan = load(folder / "protocol.json")
    (folder / "tasks").mkdir()
    for task_id in plan["rounds"]:
        prepare_task(folder / "tasks" / task_id, kernel, task_id, True)
    source = ROOT / "artifacts/reports/esp32-generated-a1-v1"
    if load(source / "audit.json")["audit"] != "pass":
        raise ValueError("Initial artifact lacks the retained original audit")
    baseline = folder / "baseline"
    baseline.mkdir()
    shutil.copytree(source / "task", baseline / "task")
    shutil.copytree(source / "A1-1/build", baseline / "build",
                    ignore=shutil.ignore_patterns("build", "__pycache__"))
    proof = audit_candidate(baseline / "task", baseline / "build")
    if choice_state((baseline / "build/config").read_text(), plan) != plan["initial_config"]:
        raise ValueError("Initial deployed policy is not the frozen DUMB configuration")
    save(baseline / "build-audit.json", proof)
    save(baseline / "reuse.json", {"source": "esp32-generated-a1-v1/A1-1", "audit_sha256": sha(source / "audit.json"),
        "image_sha256": sha(baseline / "build/application.bin"), "new_generation": False,
        "prior_values": load(source / "audit.json")["trials"][0]["values"],
        "boundary": "Reused initial artifact only; each new history physically activates and checks it."})
    (folder / "tools").mkdir()
    for name in (*CODE, Path(__file__).name):
        shutil.copyfile(ROOT / "tools" / name, folder / "tools" / name)
    save(folder / "registration.json", {"schema": "esp32-policy-sequence-registration-v1",
        "registered_utc": utc(), "protocol": plan, "model": MODEL,
        "temperature": 0, "maximum_output_tokens": 384, "board_mac": MAC,
        "profile": "B1/240MHz/one-core/100Hz/GCC13.2/-Os",
        "inputs": {p.relative_to(folder).as_posix(): sha(p) for p in folder.rglob("*") if p.is_file()}})


def registered(folder):
    registration = load(folder / "registration.json")
    plan = load(folder / "protocol.json")
    if registration["protocol"] != plan or registration["board_mac"] != MAC or registration["model"] != MODEL:
        raise ValueError("Registered sequence identity changed")
    for name, digest in registration["inputs"].items():
        path = (folder / name).resolve()
        path.relative_to(folder.resolve())
        if sha(path) != digest:
            raise ValueError("Frozen sequence input changed: " + name)
    for task_id in plan["rounds"]:
        task = registered_task(folder / "tasks" / task_id)
        if sha(folder / "tasks" / task_id / "task-bank.json") != plan["task_bank_sha256"] or \
                task["wall_budget_s"] != plan["per_round_wall_budget_s"]:
            raise ValueError("Sequence changed the original task or per-round budget")
    return registration, plan


def capture_program(board, cell, built, case, indices, script):
    cell.mkdir(parents=True)
    pairs = board.flash(cell, built)
    for i in indices:
        board.capture(cell, i, 95, capture_script=script)
        save(cell / ("result%d.json" % i), measured_capture(cell, i, case))
        board.verify(pairs, cell / ("verify-run%d.log" % i))
    board.verify(pairs, cell / "verify-after.log")


def feedback_for(round_record):
    return {"task": round_record["task"], "accepted": round_record["accepted"],
        "gates": round_record["gates"], "failure": round_record.get("failure"),
        "constraint_checks": round_record.get("constraint_checks"),
        "original_counts_30s": round_record.get("counts", {})}


def collect(folder, root, port, endpoint):
    registration, plan = registered(folder)
    campaign = {"registered_sha256": sha(folder / "registration.json"), "started_utc": utc(),
        "status": "incomplete", "original_flash_restored": False, "histories": []}
    save(folder / "campaign.json", campaign)
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        board = Board(root, folder, MAC, port)
        backed_up = False
        try:
            board.backup()
            backed_up = True
            for history in plan["histories"]:
                directory = folder / history["id"]
                directory.mkdir()
                init_start, init_clock = utc(), time.monotonic()
                parent = "baseline/build"
                state, feedback = dict(plan["initial_config"]), {"task": None, "accepted": None}
                capture_program(board, directory / "initial", folder / parent, "message_processing", (1,),
                                folder / "tools/capture_esp32_uart.py")
                record = {"id": history["id"], "initialization": {"started_utc": init_start,
                    "completed_utc": utc(), "wall_s": time.monotonic() - init_clock}, "rounds": []}
                campaign["histories"].append(record)
                for task_id in plan["rounds"]:
                    run = directory / task_id
                    run.mkdir()
                    started, clock = utc(), time.monotonic()
                    round_record = {"task": task_id, "started_utc": started, "parent_build": parent,
                        "parent_image_sha256": sha(folder / parent / "application.bin"), "starting_options": state,
                        "feedback": feedback, "gates": dict.fromkeys(("generated", "built", "booted", "functional", "constraints"), False),
                        "accepted": False, "costs": {k: 0.0 for k in ("generation_s", "build_s", "deploy_s", "evaluation_s")}}
                    record["rounds"].append(round_record)
                    source = folder / "tasks" / task_id
                    board.verify(["0x1000", str(folder / parent / "application.bin")], run / "verify-parent.log")
                    task = load(source / "registration.json")["task"]
                    save(run / "model-task.json", model_task(load(source / "model-task.json"), state, feedback, task_id))
                    generated = generate(source / "graph.json", run / "model-task.json", run / "candidate",
                                         endpoint, MODEL, history["seed"])
                    round_record["gates"]["generated"] = generated["valid_candidate"]
                    round_record["costs"]["generation_s"] = generated["generation_wall_s"]
                    usage = generated.get("usage") or {}
                    round_record["costs"].update(input_tokens=usage.get("prompt_tokens"), output_tokens=usage.get("completion_tokens"))
                    try:
                        if not generated["valid_candidate"]:
                            raise ValueError("generation: " + generated.get("failure", "invalid candidate"))
                        stage = time.monotonic()
                        try:
                            for case, bundle, cell in task_cells(source, run, task):
                                cell.mkdir(parents=True, exist_ok=True)
                                build(bundle, cell / "build", root, run / "candidate/candidate.defconfig")
                                save(cell / "build-audit.json", audit_candidate(bundle, cell / "build"))
                        finally:
                            round_record["costs"]["build_s"] += time.monotonic() - stage
                        round_record["gates"]["built"] = True
                        for case, _, cell in task_cells(source, run, task):
                            captures = cell / "captures"
                            captures.mkdir()
                            stage = time.monotonic()
                            pairs = board.flash(captures, cell / "build")
                            round_record["costs"]["deploy_s"] += time.monotonic() - stage
                            stage = time.monotonic()
                            try:
                                for i in (1, 2, 3):
                                    board.capture(captures, i, 95, capture_script=folder / "tools/capture_esp32_uart.py")
                                    save(captures / ("result%d.json" % i), measured_capture(captures, i, case))
                                    board.verify(pairs, captures / ("verify-run%d.log" % i))
                                    print(history["id"], task_id, case, "reset", i, "complete", flush=True)
                                board.verify(pairs, captures / "verify-after.log")
                            finally:
                                round_record["costs"]["evaluation_s"] += time.monotonic() - stage
                        stage = time.monotonic()
                        checks = online_task_checks(source, run, task)
                        round_record["costs"]["evaluation_s"] += time.monotonic() - stage
                        save(run / "task-checks.json", {"validated_utc": utc(), "result": checks})
                        round_record["constraint_checks"] = checks
                        round_record["counts"] = {case: [load(cell / "captures" / ("result%d.json" % i))["original_window_totals"][0]
                            for i in (1, 2, 3)] for case, _, cell in task_cells(source, run, task)}
                        round_record["gates"].update(booted=True, functional=True, constraints=checks["pass"])
                        round_record["accepted"] = checks["pass"] and time.monotonic() - clock <= plan["per_round_wall_budget_s"]
                    except (ValueError, subprocess.CalledProcessError) as exc:
                        round_record["failure"] = str(exc)
                    round_record["decision_utc"] = utc()
                    round_record["decision_wall_s"] = time.monotonic() - clock
                    round_record["within_round_budget"] = round_record["decision_wall_s"] <= plan["per_round_wall_budget_s"]
                    if round_record["accepted"]:
                        # Restore the queue executable as the actual parent of the next round.
                        queue = next(cell for case, _, cell in task_cells(source, run, task) if case == "message_processing")
                        parent = (queue / "build").relative_to(folder).as_posix()
                        stage = time.monotonic()
                        activation = run / "accepted-activation"
                        activation.mkdir()
                        board.flash(activation, folder / parent)
                        board.verify(["0x1000", str(folder / parent / "application.bin")], activation / "verify-after.log")
                        round_record["costs"]["deploy_s"] += time.monotonic() - stage
                        state = choice_state((folder / parent / "config").read_text(), plan)
                    else:
                        stage = time.monotonic()
                        capture_program(board, run / "recovery", folder / parent, "message_processing", (1,),
                                        folder / "tools/capture_esp32_uart.py")
                        round_record["costs"]["evaluation_s"] += time.monotonic() - stage
                    round_record.update(completed_utc=utc(), observed_wall_s=time.monotonic() - clock,
                        retained_build=parent, retained_options=state)
                    feedback = feedback_for(round_record)
                    save(run / "round.json", round_record)
                    save(folder / "campaign.json", campaign)
                    print(history["id"], task_id, "accepted", round_record["accepted"], flush=True)
                record.update(final_build=parent, final_options=state, completed_utc=utc())
                save(folder / "campaign.json", campaign)
            campaign["status"] = "collection_complete"
        finally:
            try:
                if backed_up:
                    board.restore()
                    campaign["original_flash_restored"] = True
            finally:
                campaign["completed_utc"] = utc()
                save(folder / "campaign.json", campaign)


def verify_program(captures, built, case, indices, previous):
    from run_esp32_followup import verified
    from audit_esp32_zephyr_thread import read_raw_capture
    verified(captures, built, MAC)
    counts = []
    for i in indices:
        actual = measured_capture(captures, i, case)
        if actual != load(captures / ("result%d.json" % i)):
            raise ValueError("Original observation changed")
        verified(captures, built, MAC, logs=("verify-run%d.log" % i,))
        rows = read_raw_capture(captures, i)
        begin, end = (datetime.fromisoformat(rows[n]["utc"]) for n in (0, -1))
        if begin <= previous or end < begin:
            raise ValueError("Physical chronology differs")
        previous = end
        counts.append(actual["original_window_totals"][0])
    return counts, previous


def audit(folder):
    from run_esp32_followup import verified
    registration, plan = registered(folder)
    campaign = load(folder / "campaign.json")
    if campaign["registered_sha256"] != sha(folder / "registration.json") or \
            campaign["status"] != "collection_complete" or not campaign["original_flash_restored"] or \
            [h["id"] for h in campaign["histories"]] != [h["id"] for h in plan["histories"]]:
        raise ValueError("Incomplete or reordered sequence")
    restore = (folder / "restore-verify.log").read_text()
    if "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in restore or \
            "verify OK (digest matched)" not in restore or set(re.findall(r"^MAC: ([0-9a-f:]+)$", restore, re.M)) != {MAC}:
        raise ValueError("Full Flash restoration missing")
    proof = audit_candidate(folder / "baseline/task", folder / "baseline/build")
    if proof != load(folder / "baseline/build-audit.json"):
        raise ValueError("Initial artifact changed")
    previous = datetime.fromisoformat(registration["registered_utc"])
    histories, resets = [], 0
    for history, specification in zip(campaign["histories"], plan["histories"]):
        directory = folder / history["id"]
        _, previous = verify_program(directory / "initial", folder / "baseline/build", "message_processing", (1,), previous)
        parent, state = "baseline/build", dict(plan["initial_config"])
        feedback, results = {"task": None, "accepted": None}, []
        if [r["task"] for r in history["rounds"]] != plan["rounds"]:
            raise ValueError("Registered round missing or reordered")
        for record in history["rounds"]:
            task_id, run = record["task"], directory / record["task"]
            source = folder / "tasks" / task_id
            started = datetime.fromisoformat(record["started_utc"])
            if record != load(run / "round.json") or started <= previous or record["parent_build"] != parent or \
                    record["parent_image_sha256"] != sha(folder / parent / "application.bin") or \
                    record["starting_options"] != state or record["feedback"] != feedback:
                raise ValueError("Wrong actual deployed parent or feedback chronology")
            verified(run, folder / parent, MAC, logs=("verify-parent.log",))
            task = load(source / "registration.json")["task"]
            expected_task = model_task(load(source / "model-task.json"), state, feedback, task_id)
            generated, request = load(run / "candidate/generation.json"), load(run / "candidate/request.json")
            if load(run / "model-task.json") != expected_task or load(run / "candidate/task.json") != expected_task or \
                    generated["task_sha256"] != sha(run / "model-task.json") or \
                    generated["graph_sha256"] != sha(source / "graph.json") or generated["subject"] != SUBJECT or \
                    generated["model"] != MODEL or generated["generator_code_sha256"] != registration["inputs"]["tools/tenonos_orchestrator.py"] or \
                    request["seed"] != specification["seed"] or request["model"] != MODEL or request["temperature"] != 0 or request["max_tokens"] != 384 or \
                    request != request_payload(load(source / "graph.json"), expected_task, MODEL, specification["seed"]) or \
                    not started <= datetime.fromisoformat(generated["started_utc"]):
                raise ValueError("Generation identity or state-conditioned input changed")
            previous = datetime.fromisoformat(generated["finished_utc"])
            gates = dict.fromkeys(record["gates"], False)
            gates["generated"] = generated["valid_candidate"]
            if gates["generated"]:
                options = options_from_response(load(run / "candidate/response.json")["choices"][0]["message"]["content"], load(source / "graph.json"))
                expected = "\n".join("CONFIG_" + k + "=" + v for k, v in {**state, **options}.items()) + "\n"
                if options != generated["options"] or (run / "candidate/candidate.defconfig").read_text() != expected or \
                        sha(run / "candidate/candidate.defconfig") != generated["candidate_sha256"]:
                    raise ValueError("Candidate is not the public model output applied to its parent")
            if record["gates"]["built"]:
                for _, bundle, cell in task_cells(source, run, task):
                    if audit_candidate(bundle, cell / "build") != load(cell / "build-audit.json") or \
                            sha(cell / "build/candidate.conf") != generated["candidate_sha256"]:
                        raise ValueError("Generated source-to-firmware binding differs")
                gates["built"] = True
            if record["gates"]["functional"]:
                counts = {}
                for case, _, cell in task_cells(source, run, task):
                    counts[case], previous = verify_program(cell / "captures", cell / "build", case, (1, 2, 3), previous)
                    resets += 3
                checks = online_task_checks(source, run, task)
                online = load(run / "task-checks.json")
                if checks != record["constraint_checks"] or counts != record["counts"] or online["result"] != checks or \
                        not previous <= datetime.fromisoformat(online["validated_utc"]) <= datetime.fromisoformat(record["decision_utc"]):
                    raise ValueError("External checks differ from the physical observations")
                gates.update(booted=True, functional=True, constraints=checks["pass"])
            decision = (datetime.fromisoformat(record["decision_utc"]) - started).total_seconds()
            ended = datetime.fromisoformat(record["completed_utc"])
            if abs(decision - record["decision_wall_s"]) > 0.05 or \
                    abs((ended - started).total_seconds() - record["observed_wall_s"]) > 0.05 or \
                    record["within_round_budget"] != (decision <= plan["per_round_wall_budget_s"]) or \
                    record["accepted"] != (all(gates.values()) and record["within_round_budget"]) or record["gates"] != gates:
                raise ValueError("Acceptance, failed attempt or timing was changed")
            if record["accepted"]:
                queue = next(cell for case, _, cell in task_cells(source, run, task) if case == "message_processing")
                parent = (queue / "build").relative_to(folder).as_posix()
                state = choice_state((folder / parent / "config").read_text(), plan)
                verified(run / "accepted-activation", folder / parent, MAC)
            else:
                _, previous = verify_program(run / "recovery", folder / parent, "message_processing", (1,), previous)
            if record["retained_build"] != parent or record["retained_options"] != state or ended < previous:
                raise ValueError("Actual retained/rolled-back state differs")
            costs = record["costs"]
            usage = generated.get("usage") or {}
            if costs["generation_s"] != generated["generation_wall_s"] or \
                    costs["input_tokens"] != usage.get("prompt_tokens") or costs["output_tokens"] != usage.get("completion_tokens") or \
                    any(costs[k] < 0 for k in ("generation_s", "build_s", "deploy_s", "evaluation_s")) or \
                    sum(costs[k] for k in costs if k.endswith("_s")) > record["observed_wall_s"] + 0.05:
                raise ValueError("All-attempt cost accounting differs")
            previous, feedback = ended, feedback_for(record)
            results.append({"task": task_id, "accepted": record["accepted"], "gates": gates,
                "original_counts_30s": record.get("counts", {}), "observed_wall_s": record["observed_wall_s"],
                "decision_wall_s": record["decision_wall_s"], "costs": costs, "retained_options": state,
                "failure": record.get("failure"), "retained_build": parent})
        wall = sum(r["observed_wall_s"] for r in results)
        if history["final_build"] != parent or history["final_options"] != state:
            raise ValueError("Final state is not the last accepted deployment")
        histories.append({"id": history["id"], "rounds": results, "total_round_wall_s": wall,
            "within_history_budget": wall <= plan["per_history_wall_budget_s"],
            "initialization_s": history["initialization"]["wall_s"], "final_options": state})
    return {"audit": "pass", "subject": SUBJECT, "registered_histories": len(histories),
        "registered_model_calls": sum(len(h["rounds"]) for h in histories), "histories": histories,
        "generated_physical_resets": resets, "initial_state_captures": len(histories),
        "recovery_state_captures": sum(not r["accepted"] for h in histories for r in h["rounds"]),
        "original_flash_restored": True, "energy_measured": False, "whole_ram_peak_measured": False,
        "rsi": False, "held_out": False, "author_tenon_engine": False,
        "boundary": plan["interpretation"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "collect", "audit"))
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    parser.add_argument("--endpoint", default="http://127.0.0.1:18089/v1")
    args = parser.parse_args()
    folder = args.folder.resolve()
    if args.command == "prepare":
        prepare(folder, args.kernel)
    elif args.command == "collect":
        collect(folder, args.root, args.port, args.endpoint)
    else:
        result = audit(folder)
        save(folder / "audit.json", result)
        print(json.dumps(result, indent=2))
