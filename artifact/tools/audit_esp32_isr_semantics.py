#!/usr/bin/env python3
"""Check original ISR timestamps separately from interrupt-entry latency."""
import json
from pathlib import Path
import statistics

from audit_esp32_zephyr_thread import audit as native
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = {"FreeRTOS": ("freertos", "zephyr-isr-freertos-v1"),
           "NuttX": ("nuttx", "zephyr-isr-nuttx-v3")}
TAGS = ("isr.resume.interrupted.thread.kernel", "isr.resume.different.thread.kernel")


def audit():
    results, proof = {}, {}
    for system, (short, name) in FOLDERS.items():
        folder = ROOT / "artifacts/reports" / name
        result = native(folder, short, isr_subset=True)
        if result["audit"] != "pass" or tuple(result["metrics"]) != TAGS or any(result[k] != v for k, v in
                {"clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "13.2.0",
                 "original_iterations": 1000, "worker_stack_bytes": 1792, "resets": 3}.items()):
            raise ValueError("ISR original source/control/profile differs")
        results[system] = result
        names = ("image.sha256", "capture.sha256", "port.c", "config", "compiler.txt", "disassembly.txt")
        paths = [folder / n for n in names] + list((folder / "source").glob("*")) + [
            folder / ("reset%d.%s" % (i, suffix)) for i in (1, 2, 3) for suffix in ("jsonl", "raw")]
        proof[system] = {p.relative_to(ROOT).as_posix(): sha(p) for p in paths if p.is_file()}
    values = {system: result["metrics"][TAGS[1]]["means_ns"] for system, result in results.items()}
    medians = {system: statistics.median(v) for system, v in values.items()}
    return {"audit": "pass", "schema": "esp32-isr-semantics-v1", "board": "B0",
        "board_mac": "84:1f:e8:8f:55:dc", "proof": proof,
        "profile": "240 MHz / one core / 1 Hz / GCC13.2 / -Os / 1792 B worker stacks",
        "original_suite": "Zephyr 3.7.0 latency_measure int_to_thread.c",
        "interrupt": "CPU_FROM_CPU2 peripheral 26, level 1; real hardware handler; deferred ISR-exit scheduling",
        "cells": [{"metric": TAGS[1], "values_ns": values, "median_ns": medians,
            "order": sorted(medians, key=medians.get), "comparison_eligible": True,
            "endpoint": "timestamp inside ISR after semaphore give, to first timestamp after high-priority blocked take returns",
            "scope": "original adapter-inclusive ISR-exit-to-thread mean; excludes interrupt entry and the give itself",
            "statistic": "original mean of 1000 iterations; median of three independent boot means"}],
        "native_only": {"metric": TAGS[0],
            "values_ns": {system: result["metrics"][TAGS[0]]["means_ns"] for system, result in results.items()},
            "comparison_eligible": False,
            "reason": "interrupted-thread endpoint occurs after irq_offload returns; NuttX's guard/poll and both ports' validation execute inside this interval",
            "missing": "match the timed offload shim or separately bound its return-check cost before attributing this value to native ISR return"},
        "metadata_correction": "legacy generic auditor labels this ISR subset as thread lifecycle; the frozen numbers are retained and this source-bound view supplies the actual ISR scope",
        "overhead": "preserve original single adjustment on accumulated 1000-sample sum; not a per-sample subtraction",
        "new_measurements": False, "included_in_thread_metric_index": False, "energy_measured": False}


if __name__ == "__main__":
    result = audit()
    (ROOT / "artifacts/reports/esp32-isr-semantics-v1.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"audit": "pass", "comparable_original_metrics": len(result["cells"]),
                      "native_only_metrics": 1, "new_measurements": False}))
