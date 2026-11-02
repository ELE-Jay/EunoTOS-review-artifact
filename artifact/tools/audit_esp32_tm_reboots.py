#!/usr/bin/env python3
"""Audit separate ESP32 Thread-Metric boot captures without ranking them."""

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path

from audit_esp32_tm_basic import CASES, audit


def require_cpu2_interrupt(rows):
    marker = "Thread-Metric interrupt source=CPU_FROM_CPU2 peripheral=26 level=1 context=ISR"
    matches = [index for index, row in enumerate(rows) if row["line"].strip() == marker]
    report = next((index for index, row in enumerate(rows)
                   if row["line"].startswith("**** Thread-Metric")), len(rows))
    if len(matches) != 1 or matches[0] >= report:
        raise ValueError("expected one CPU_FROM_CPU2 interrupt marker before measurements")


def require_self_check(rows, kind):
    marker = f"Thread-Metric {kind} self-check PASS"
    matches = [index for index, row in enumerate(rows) if row["line"].strip() == marker]
    report = next((index for index, row in enumerate(rows)
                   if row["line"].startswith("**** Thread-Metric")), len(rows))
    if len(matches) != 1 or matches[0] >= report:
        raise ValueError(f"expected one {kind} self-check PASS before measurements")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("os", choices=("FreeRTOS", "Zephyr", "NuttX", "RIOT", "AliOS-Rhino"))
    parser.add_argument("case", choices=CASES)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--require-queue-self-check", action="store_true")
    parser.add_argument("--require-semaphore-self-check", action="store_true")
    parser.add_argument("--require-memory-self-check", action="store_true")
    parser.add_argument("--require-cpu2-interrupt", action="store_true")
    args = parser.parse_args()
    if args.require_queue_self_check and args.case != "message_processing":
        parser.error("queue self-check applies only to message_processing")
    if args.require_semaphore_self_check and args.case != "synchronization_processing":
        parser.error("semaphore self-check applies only to synchronization_processing")
    if args.require_memory_self_check and args.case != "memory_allocation":
        parser.error("memory self-check applies only to memory_allocation")
    if args.require_cpu2_interrupt and args.case not in ("interrupt_processing", "interrupt_preemption_processing"):
        parser.error("CPU_FROM_CPU2 check applies only to interrupt cases")
    if len(args.captures) < 3 or len(set(args.captures)) != len(args.captures):
        parser.error("provide at least three different capture files")

    results = []
    for path in args.captures:
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        resets = [row for row in rows if row["line"].startswith("rst:0x")]
        if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
            raise ValueError(f"{path}: expected one early ESP32 ROM reset line")
        if args.require_queue_self_check:
            require_self_check(rows, "queue")
        if args.require_semaphore_self_check:
            require_self_check(rows, "semaphore")
        if args.require_memory_self_check:
            require_self_check(rows, "memory")
        if args.require_cpu2_interrupt:
            require_cpu2_interrupt(rows)
        result = audit(path, args.os, args.case)
        if not 25 < result["host_window_seconds"][0] < 40:
            raise ValueError(f"{path}: first 30-second window is not near 30 seconds")
        result["file"] = str(path)
        result["reset"] = resets[0]["line"]
        result["started_utc"] = rows[0]["utc"]
        results.append(result)

    starts = [datetime.fromisoformat(result["started_utc"]) for result in results]
    if any(later <= earlier for earlier, later in zip(starts, starts[1:])):
        raise ValueError("capture start times are not strictly increasing")
    first_windows = [result["original_window_totals"][0] for result in results]
    print(json.dumps({
        "audit": "pass", "os": args.os, "case": args.case,
        "reboot_count": len(results), "runs": results,
        "first_window_median": statistics.median(first_windows),
        "first_window_min": min(first_windows),
        "first_window_max": max(first_windows),
        "ranking_eligible": False,
    }, indent=2))


if __name__ == "__main__":
    main()
