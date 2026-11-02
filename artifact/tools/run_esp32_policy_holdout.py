#!/usr/bin/env python3
"""Freeze an external workload before new policy histories; evaluate it afterward."""
import argparse
from datetime import datetime
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

import run_esp32_policy_sequence as sequence
from build_esp32_evolution_candidate import audit_candidate, build
from run_esp32_followup import Board
from run_esp32_generated_task import MAC, ROOT, save, sha, task_cells, utc


def load(path):
    return json.loads(path.read_text())


def policies(folder, sequence_result):
    inner = folder / "sequence"
    plan = load(inner / "protocol.json")
    sources = [("initial", inner / "baseline/build")]
    for history in sequence_result["histories"]:
        for record in history["rounds"]:
            if record["gates"]["built"]:
                task = load(inner / "tasks" / record["task"] / "registration.json")["task"]
                for case, _, cell in task_cells(inner / "tasks" / record["task"],
                        inner / history["id"] / record["task"], task):
                    sources.append((history["id"] + "/" + record["task"] + "/" + case, cell / "build"))
        sources.append((history["id"] + "/retained", inner / history["rounds"][-1]["retained_build"]))
    groups = {}
    for alias, source in sources:
        state = sequence.choice_state((source / "config").read_text(), plan)
        key = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
        group = groups.setdefault(key, {"id": key, "options": state, "aliases": []})
        group["aliases"].append({"alias": alias, "build": source.relative_to(folder).as_posix(),
                                 "config_sha256": sha(source / "config")})
    return list(groups.values())


def prepare(folder, kernel):
    source = ROOT / "artifacts/reports/esp32-generated-a2-v2"
    reference = source / "A2-1/interrupt_processing/build"
    bundle = source / "task-interrupt_processing"
    proof = audit_candidate(bundle, reference)
    if proof["case"] != "interrupt_processing":
        raise ValueError("Wrong original held-out workload")
    folder.mkdir(parents=True, exist_ok=False)
    sequence.prepare(folder / "sequence", kernel)
    shutil.copyfile(ROOT / "registry/iotos_policy_holdout_v1.json", folder / "protocol.json")
    shutil.copytree(bundle, folder / "task")
    save(folder / "source-proof.json", proof)
    shutil.copyfile(__file__, folder / "runner.py")
    save(folder / "registration.json", {"schema": "esp32-policy-holdout-registration-v1",
        "registered_utc": utc(), "board_mac": MAC, "protocol": load(folder / "protocol.json"),
        "sequence_registration_sha256": sha(folder / "sequence/registration.json"),
        "inputs": {p.relative_to(folder).as_posix(): sha(p) for p in folder.rglob("*") if p.is_file()}})


def registered(folder):
    registration = load(folder / "registration.json")
    plan = load(folder / "protocol.json")
    if registration["board_mac"] != MAC or registration["protocol"] != plan or \
            registration["sequence_registration_sha256"] != sha(folder / "sequence/registration.json"):
        raise ValueError("Frozen held-out registration changed")
    for name, digest in registration["inputs"].items():
        path = (folder / name).resolve()
        path.relative_to(folder.resolve())
        if sha(path) != digest:
            raise ValueError("Frozen held-out input changed: " + name)
    _, sequence_plan = sequence.registered(folder / "sequence")
    if plan["histories"] != [h["id"] for h in sequence_plan["histories"]] or plan["rounds"] != sequence_plan["rounds"] or \
            plan["held_out_case"] != "interrupt_processing" or plan["independent_resets_per_unique_policy"] != 3 or \
            plan["capture_seconds"] != 95:
        raise ValueError("Original workloads, reset protocol or histories changed")
    return registration, plan


def collect(folder, root, port, endpoint):
    registration, plan = registered(folder)
    if (folder / "sequence/campaign.json").exists() or (folder / "campaign.json").exists():
        raise ValueError("Refusing to restart or overwrite an existing acquisition")
    sequence.collect(folder / "sequence", root, port, endpoint)
    result = sequence.audit(folder / "sequence")
    save(folder / "sequence/audit.json", result)
    collect_registered_policies(folder, root, port, result)


def resume_held_out(folder, root, port):
    """Resume only the not-yet-started stage after a restored, complete history."""
    registered(folder)
    if (folder / "campaign.json").exists():
        raise ValueError("Refusing to overwrite or restart a held-out acquisition")
    result = sequence.audit(folder / "sequence")
    saved = folder / "sequence/audit.json"
    if saved.exists() and load(saved) != result:
        raise ValueError("Completed sequence audit differs")
    if not saved.exists():
        save(saved, result)
    receipt = folder / "post-sequence-recovery.json"
    if receipt.exists():
        raise ValueError("A prior recovery must be inspected before any repeat")
    save(receipt, {"started_utc": utc(), "registration_sha256": sha(folder / "registration.json"),
        "original_runner_sha256": sha(folder / "runner.py"), "recovery_runner_sha256": sha(Path(__file__)),
        "sequence_audit_sha256": sha(saved), "new_model_calls": 0,
        "reason": "Complete restored histories retained; only previously unstarted held-out stage is continued"})
    collect_registered_policies(folder, root, port, result)


def collect_registered_policies(folder, root, port, result):
    registration, plan = registered(folder)
    if (folder / "campaign.json").exists():
        raise ValueError("Refusing to overwrite or restart a held-out acquisition")
    groups = policies(folder, result)
    campaign = {"registered_sha256": sha(folder / "registration.json"), "started_utc": utc(),
                "status": "incomplete", "original_flash_restored": False, "policies": []}
    save(folder / "campaign.json", campaign)
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        board = Board(root, folder, MAC, port)
        backed_up = False
        try:
            board.backup()
            backed_up = True
            for group in groups:
                cell = folder / group["id"]
                cell.mkdir()
                record = {**group, "started_utc": utc(), "build_pass": False, "functional_pass": False}
                campaign["policies"].append(record)
                clock = time.monotonic()
                fragment = cell / "policy.conf"
                fragment.write_text("".join("CONFIG_" + k + "=" + v + "\n" for k, v in group["options"].items()))
                try:
                    build(folder / "task", cell / "build", root, fragment)
                    save(cell / "build-audit.json", audit_candidate(folder / "task", cell / "build"))
                    record["build_pass"] = True
                    sequence.capture_program(board, cell / "captures", cell / "build", plan["held_out_case"],
                        (1, 2, 3), folder / "sequence/tools/capture_esp32_uart.py")
                    record["functional_pass"] = True
                except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                    record["failure"] = str(exc)
                finally:
                    record.update(completed_utc=utc(), observed_wall_s=time.monotonic() - clock)
                    save(cell / "result.json", record)
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


def audit(folder):
    registration, plan = registered(folder)
    result = sequence.audit(folder / "sequence")
    sequence_campaign = load(folder / "sequence/campaign.json")
    if not datetime.fromisoformat(registration["registered_utc"]) < datetime.fromisoformat(sequence_campaign["started_utc"]):
        raise ValueError("Workload was not frozen before the new histories")
    campaign = load(folder / "campaign.json")
    if campaign["status"] != "collection_complete" or not campaign["original_flash_restored"]:
        raise ValueError("Held-out campaign is incomplete or unrestored")
    for name in ("identity-before.log", "identity-restore.log", "restore-verify.log"):
        text = (folder / name).read_text()
        if set(re.findall(r"^MAC: ([0-9a-f:]+)$", text, re.M)) != {MAC}:
            raise ValueError("Held-out board identity differs")
    restore = (folder / "restore-verify.log").read_text()
    if "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in restore or "verify OK (digest matched)" not in restore:
        raise ValueError("Full Flash restoration is not witnessed")
    if campaign["registered_sha256"] != sha(folder / "registration.json") or \
            not datetime.fromisoformat(sequence_campaign["completed_utc"]) < datetime.fromisoformat(campaign["started_utc"]):
        raise ValueError("Held-out evaluation preceded deployment decisions")
    expected = policies(folder, result)
    if len(campaign["policies"]) != len(expected):
        raise ValueError("A unique policy was omitted")
    previous = datetime.fromisoformat(campaign["started_utc"])
    observations = []
    for group, record in zip(expected, campaign["policies"]):
        cell = folder / group["id"]
        if any(record[k] != group[k] for k in group) or record != load(cell / "result.json"):
            raise ValueError("Policy aliases or decision record changed")
        started, ended = map(datetime.fromisoformat, (record["started_utc"], record["completed_utc"]))
        if started < previous or ended < started or abs((ended - started).total_seconds() - record["observed_wall_s"]) > 0.05:
            raise ValueError("Held-out costs or chronology differ")
        if record["build_pass"]:
            if audit_candidate(folder / "task", cell / "build") != load(cell / "build-audit.json") or \
                    sequence.choice_state((cell / "build/config").read_text(), load(folder / "sequence/protocol.json")) != group["options"]:
                raise ValueError("Held-out image changed the resolved policy")
        counts = []
        if record["functional_pass"]:
            if not record["build_pass"]:
                raise ValueError("Functional result without a build")
            counts, previous = sequence.verify_program(cell / "captures", cell / "build", plan["held_out_case"], (1, 2, 3), started)
            if previous > ended:
                raise ValueError("Runtime occurred after the recorded endpoint")
        elif not record.get("failure"):
            raise ValueError("Failed evaluation has no retained reason")
        previous = ended
        observations.append({**group, "build_pass": record["build_pass"], "functional_pass": record["functional_pass"],
                             "original_counts_30s": counts, "observed_wall_s": record["observed_wall_s"], "failure": record.get("failure")})
    return {"audit": "pass", "sequence": result, "held_out": True, "case": plan["held_out_case"],
            "policies": observations, "physical_resets": sum(3 for p in observations if p["functional_pass"]),
            "original_flash_restored": True, "rsi": False, "boundary": plan["interpretation"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "collect", "resume-held-out", "audit"))
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    parser.add_argument("--endpoint", default="http://127.0.0.1:18089/v1")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.folder.resolve(), args.kernel)
    elif args.command == "collect":
        collect(args.folder.resolve(), args.root, args.port, args.endpoint)
    elif args.command == "resume-held-out":
        resume_held_out(args.folder.resolve(), args.root, args.port)
    else:
        result = audit(args.folder.resolve())
        save(args.folder / "audit.json", result)
        print(json.dumps(result, indent=2))
