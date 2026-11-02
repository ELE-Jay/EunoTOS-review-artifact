#!/usr/bin/env python3
"""Repeat admitted original Thread-Metric workloads on B1, then replay evidence."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import shutil
import statistics

from run_esp32_followup import Board, sha

ROOT = Path(__file__).resolve().parents[1]
CASE = "message_processing"
CASES = ("cooperative_scheduling", "preemptive_scheduling", CASE,
         "synchronization_processing", "interrupt_processing", "interrupt_preemption_processing",
         "basic_processing", "memory_allocation")
SOURCES = {
    "FreeRTOS": ("tm-freertos-native-aligned-v1/message_processing", {
        "iotosbench_tm.elf": "application.elf", "iotosbench_tm.bin": "application.bin",
        "bootloader.bin": "bootloader.bin", "partition-table.bin": "partitions.bin"}),
    "Zephyr": ("zephyr-gcc13-align/message_processing", {
        "zephyr.elf": "application.elf", "zephyr.bin": "application.bin"}),
    "NuttX": ("tm-nuttx-native-aligned-v1/message_processing", {
        "nuttx": "application.elf", "nuttx.bin": "application.bin",
        "bootloader-esp32.bin": "bootloader.bin", "partition-table-esp32.bin": "partitions.bin"}),
}
SCHEDULE = (tuple(SOURCES), ("NuttX", "FreeRTOS", "Zephyr"), ("Zephyr", "NuttX", "FreeRTOS"))


def sources(case):
    if case not in CASES:
        raise ValueError("Unknown admitted original workload")
    result = {}
    for system, (directory, images) in SOURCES.items():
        if case.startswith("interrupt_") and system != "FreeRTOS":
            directory = "tm-irq-cpu2-v1/" + system.lower() + "/" + case
        elif case == "cooperative_scheduling" and system == "NuttX":
            directory = "tm-cooperative-native-nuttx-v1"
        else:
            directory = directory.replace(CASE, case)
        result[system] = directory, images
    return result


def window_durations(result):
    times = result["host_window_seconds"]
    if len(times) != 3:
        raise ValueError("Incomplete original report timestamps")
    # The retained parser returns cumulative host arrival times, not durations.
    return [times[0]] + [b - a for a, b in zip(times, times[1:])]


def source_proof(system, case=CASE):
    from audit_esp32_report import audit_zephyr_image
    from audit_esp32_tm_irq_match import audit_image
    directory, images = sources(case)[system]
    source = ROOT / "artifacts/reports" / directory
    if system == "Zephyr" and not case.startswith("interrupt_"):
        audit_zephyr_image(source, case)
    else:
        audit_image(source, system, case, require_flash=False, uniform=system == "FreeRTOS")
    return {"source": directory, "images": {name: sha(source / name) for name in images},
            "config_sha256": sha(source / "config"), "case": case}


def audit(directory):
    from audit_esp32_followup import envelope, verified
    from audit_esp32_tm_basic import audit as original
    from audit_esp32_tm_reboots import require_self_check, require_cpu2_interrupt
    from audit_esp32_report import require_memory_pool_metadata
    from audit_esp32_zephyr_thread import read_raw_capture
    campaign = envelope(directory)
    case = campaign.get("case", CASE)
    systems = campaign.get("systems", list(SOURCES))
    if len(systems) < 2 or len(set(systems)) != len(systems) or not set(systems) <= set(SOURCES):
        raise ValueError("Invalid native comparison subset")
    schedule = [[s for s in order if s in systems] for order in SCHEDULE]
    if campaign["mode"] not in ("message-cohort", "kernel-cohort") or campaign["schedule"] != schedule:
        raise ValueError("Unexpected workload or acquisition order")
    cells, intervals = [], []
    for system, (_, images) in sources(case).items():
        if system not in systems:
            continue
        folder = directory / system
        proof = source_proof(system, case)
        if proof != json.loads((folder / "source-proof.json").read_text()):
            raise ValueError("Source/configuration proof changed")
        build = folder / "build"
        if {p.name for p in build.iterdir()} != set(images.values()) or any(
                sha(build / saved) != proof["images"][name] for name, saved in images.items()):
            raise ValueError("Installed candidate does not match the admitted image")
        values, evidence = [], []
        for index in (1, 2, 3):
            capture = folder / ("run%d" % index)
            verified(capture, build, campaign["board_mac"])
            rows = read_raw_capture(capture, 1)
            resets = [r for r in rows if r["line"].startswith("rst:0x")]
            if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
                raise ValueError("Missing independent early physical reset")
            if case in (CASE, "synchronization_processing"):
                require_self_check(rows, "queue" if case == CASE else "semaphore")
            if case.startswith("interrupt_"):
                require_cpu2_interrupt(rows)
            if case == "memory_allocation" and system == "FreeRTOS":
                require_memory_pool_metadata(rows)
            result = original(capture / "reset1.jsonl", system, case)
            if len(result["original_window_totals"]) != 3 or any(
                    not 25 < v < 40 for v in window_durations(result)):
                raise ValueError("Incomplete original thirty-second windows")
            values.append(result["original_window_totals"][0])
            intervals.append((*tuple(datetime.fromisoformat(rows[i]["utc"]) for i in (0, -1)), system, index))
            evidence.append({"path": str((capture / "reset1.jsonl").relative_to(directory)),
                             "sha256": sha(capture / "reset1.jsonl")})
        cells.append({"os": system, "case": case, "values": values, "median": statistics.median(values),
                      "range": [min(values), max(values)], "unit": "count/30s", "captures": evidence,
                      "independent_resets": 3, "comparison_eligible": True})
        if case == "memory_allocation":
            cells[-1].update(comparison_eligible=system != "FreeRTOS",
                comparison_group="private general heap" if system == "FreeRTOS" else "four fixed 128-byte blocks",
                allocator={"FreeRTOS": "ESP-IDF multi_heap, 4096-byte arena and portMUX",
                           "Zephyr": "k_mem_slab, four 128-byte blocks, no wait",
                           "NuttX": "mempool, four 128-byte blocks, no expansion or wait"}[system])
        if case == "basic_processing":
            cells[-1]["role"] = "CPU/compiler control, not a kernel service score"
    intervals.sort()
    if any(a[1] >= b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("Physical acquisition intervals overlap")
    if [(r[2], r[3]) for r in intervals] != [(system, i) for i, order in enumerate(schedule, 1) for system in order]:
        raise ValueError("Actual acquisition chronology differs from the declared order")
    return {"audit": "pass", "board": "B1", "board_mac": campaign["board_mac"], "case": case,
            "cells": cells, "independent_resets": 3 * len(systems), "same_board_comparison": True,
            "profile": "240 MHz / one core / 100 Hz / GCC 13.2 / " + ("original same-thread 4-slot 16-byte copying queue" if case == CASE else "original " + case),
            "six_case_index": None, "energy_measured": False, "historical_cohort_modified": False,
            "external_independent_replication": False}


def audit_failed_cooperative(directory):
    from audit_esp32_followup import envelope, verified
    from audit_esp32_tm_basic import audit as original, cooperative_balanced
    from audit_esp32_zephyr_thread import read_raw_capture
    campaign = envelope(directory, allow_incomplete=True)
    if campaign["status"] != "incomplete" or campaign["case"] != "cooperative_scheduling":
        raise ValueError("Not the retained interrupted cooperative campaign")
    folder = directory / "FreeRTOS"
    proof = source_proof("FreeRTOS", "cooperative_scheduling")
    if proof != json.loads((folder / "source-proof.json").read_text()):
        raise ValueError("Failed image source proof differs")
    for name, saved in sources("cooperative_scheduling")["FreeRTOS"][1].items():
        if sha(folder / "build" / saved) != proof["images"][name]:
            raise ValueError("Failed capture bound to a different image")
    verified(folder / "run1", folder / "build", campaign["board_mac"])
    rows = read_raw_capture(folder / "run1", 1)
    import re
    counters = [int(m[1]) for r in rows if (m := re.fullmatch(r"tm_cooperative_thread_[0-4]_counter:\s*(\d+)", r["line"]))]
    if len(counters) != 15 or cooperative_balanced(counters[-5:]) or not any(
            r["line"].startswith("ERROR: Invalid counter value(s).") for r in rows):
        raise ValueError("Retained original correctness failure differs")
    try:
        original(folder / "run1/reset1.jsonl", "FreeRTOS", "cooperative_scheduling")
    except ValueError:
        pass
    else:
        raise ValueError("An incorrect original workload was admitted")
    return {"audit": "pass", "result": "original_correctness_failure", "board": "B1",
        "board_mac": campaign["board_mac"], "os": "FreeRTOS", "case": "cooperative_scheduling",
        "attempted_resets": 1, "third_report_counters": counters[-5:], "comparison_eligible": False,
        "six_case_index": None, "original_flash_restored": True,
        "reason": "Original floor-average +/-1 worker predicate fails in the third report; no successful window is selected around it",
        "root_cause": "native ready-list/preemption interaction under investigation; not established by this capture"}


def collect(root, output, mac, port, case=CASE, systems=None):
    import subprocess
    device = subprocess.check_output(["udevadm", "info", "-q", "property", "-n", port]).decode()
    if not {"ID_VENDOR_ID=1a86", "ID_MODEL_ID=7523", "ID_USB_DRIVER=ch341"} <= set(device.splitlines()):
        raise ValueError("Wrong serial bridge")
    if mac != "34:98:7a:a2:85:28" or shutil.disk_usage(root).free < 32 * 1024 ** 2:
        raise ValueError("Unexpected B1 identity or insufficient evidence/backup space")
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        systems = list(SOURCES) if systems is None else systems
        if len(systems) < 2 or len(set(systems)) != len(systems) or not set(systems) <= set(SOURCES):
            raise ValueError("At least two distinct native systems required")
        selected = {s: item for s, item in sources(case).items() if s in systems}
        schedule = [[s for s in order if s in systems] for order in SCHEDULE]
        proofs = {system: source_proof(system, case) for system in selected}
        output.mkdir(parents=True, exist_ok=False)
        (output / "device.log").write_text(device)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        for system, (source, images) in selected.items():
            folder = output / system
            (folder / "build").mkdir(parents=True)
            for name, saved in images.items():
                origin = root / "downloads" / source / name
                if sha(origin) != proofs[system]["images"][name]:
                    raise ValueError("Remote candidate image differs from source audit")
                shutil.copyfile(origin, folder / "build" / saved)
            (folder / "source-proof.json").write_text(json.dumps(proofs[system], indent=2))
        board = Board(root, output, mac, port)
        report = {"mode": "message-cohort" if case == CASE else "kernel-cohort", "case": case,
                  "status": "incomplete", "board_mac": mac,
                  "started_utc": datetime.now(timezone.utc).isoformat(), "schedule": schedule,
                  "original_flash_restored": False, "old_cohort_modified": False,
                  "energy_measured": False, "external_independent_replication": False}
        if set(systems) != set(SOURCES):
            report["systems"] = systems
        try:
            board.backup()
            try:
                for index, order in enumerate(schedule, 1):
                    for system in order:
                        folder = output / system / ("run%d" % index)
                        folder.mkdir()
                        pairs = board.flash(folder, output / system / "build")
                        board.capture(folder, 1, 95, send="iotosbench" if system == "NuttX" else None)
                        board.verify(pairs, folder / "verify-after.log")
                        from audit_esp32_tm_basic import audit as original
                        result = original(folder / "reset1.jsonl", system, case)
                        print(system, index, result["original_window_totals"][0], flush=True)
                report["status"] = "collection_complete_audit_pending"
            finally:
                board.restore()
                report["original_flash_restored"] = True
        finally:
            report["completed_utc"] = datetime.now(timezone.utc).isoformat()
            report["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*")
                               if p.is_file() and p.name != "campaign.json"}
            (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "audit"))
    parser.add_argument("--case", choices=CASES, default=CASE)
    parser.add_argument("--systems", nargs="+", choices=tuple(SOURCES))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mac", default="34:98:7a:a2:85:28")
    parser.add_argument("--port", default="/dev/ttyUSB0")
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.root.resolve(), args.output.resolve(), args.mac, args.port, args.case, args.systems)
    else:
        result = audit(args.output.resolve())
        (args.output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
