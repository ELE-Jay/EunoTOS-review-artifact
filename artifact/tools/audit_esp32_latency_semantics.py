#!/usr/bin/env python3
"""Admit only the source-bound, same-board original synchronization subset."""
import json
from pathlib import Path
import statistics

from audit_esp32_zephyr_latency_freertos import audit as freertos, TAGS, SOURCES
from audit_esp32_zephyr_latency_nuttx import audit as nuttx
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "artifacts/reports"
FOLDERS = {"FreeRTOS": "zephyr-latency-freertos-v2", "NuttX": "zephyr-latency-nuttx-v2"}
ENDPOINTS = (
    "1000 gives from count 0 to 1000, no waiter; timestamps outside the loop",
    "1000 no-wait takes from count 1000 to 0; timestamps outside the loop",
    "before high-priority blocking take to low-priority peer timestamp before give",
    "peer timestamp before give to high-priority blocked take returning",
    "1000 recursive acquisitions by one owner; first acquisition included",
    "1000 recursive releases by the same owner; final release included",
)


def audit():
    results = {"FreeRTOS": freertos(EVIDENCE / FOLDERS["FreeRTOS"]),
               "NuttX": nuttx(EVIDENCE / FOLDERS["NuttX"])}
    cells, proof = [], {}
    for system, result in results.items():
        folder = EVIDENCE / FOLDERS[system]
        if result["audit"] != "pass" or tuple(result["metrics"]) != TAGS or any(
                result[k] != v for k, v in {"clock_mhz": 240, "cores": 1, "tick_hz": 1,
                "original_iterations": 1000, "worker_stack_bytes": 1792, "resets": 3}.items()):
            raise ValueError("Original subset conditions differ")
        commands = (folder / ("compile_commands.json" if system == "FreeRTOS" else "build.log")).read_text()
        if "13.2.0" not in (folder / "compiler.txt").read_text() or "-Os" not in commands:
            raise ValueError("Compiler/optimization qualification differs")
        paths = [folder / "port.c", folder / "config", folder / "compiler.txt", folder / "image.sha256",
                 folder / "capture.sha256", *(folder / "source" / n for n in SOURCES),
                 *(folder / ("reset%d.%s" % (i, ext)) for i in (1, 2, 3) for ext in ("jsonl", "raw"))]
        proof[system] = {p.relative_to(ROOT).as_posix(): sha(p) for p in paths}
    for tag, endpoint in zip(TAGS, ENDPOINTS):
        values = {system: result["metrics"][tag]["means_ns"] for system, result in results.items()}
        medians = {system: statistics.median(ns) for system, ns in values.items()}
        corrected = ".blocking." in tag or ".wake+ctx." in tag
        cells.append({"metric": tag, "values_ns": values, "median_ns": medians,
            "order": sorted(medians, key=medians.get), "direction": "lower", "endpoint": endpoint,
            "statistic": "original integer mean over 1000 iterations; median of three independent reset means",
            "timestamp_overhead_subtracted": corrected, "comparison_eligible": True})
    return {"audit": "pass", "schema": "esp32-latency-semantics-v1", "board": "B0",
        "board_mac": "84:1f:e8:8f:55:dc", "profile": "240 MHz / one core / 1 Hz / GCC 13.2 / -Os / 1792 B worker stacks",
        "original_suite": "Zephyr 3.7.0 latency_measure", "cells": cells, "proof": proof,
        "scope": "original synchronization operations through each native adapter, including its timed wrapper costs; not kernel-only latency",
        "semaphore_contract": "unowned counting, no PI; original count remains within 0..1000; NuttX does not enforce the general limit outside this subset",
        "mutex_contract": "owned recursive mutex with PI enabled; original has no contending owner, so PI efficacy is not evaluated",
        "preparation": "same original operation order, timestamp calibration and priority relationships; no cache flush requested by original; native cache/layout costs retained",
        "excluded": {"Zephyr": "clock/core/1-Hz tick/GCC13 match, but its retained full-suite run executes other operations before synchronization; the selected-subset preparation/order has not been matched",
            "RIOT": "native tickless instead of 1 Hz; GCC12 instead of GCC13",
            "AliOS-Rhino": "GCC5 instead of GCC13; SDK/ROM ABI alignment unresolved"},
        "new_measurements": False, "included_in_thread_metric_index": False, "energy_measured": False}


if __name__ == "__main__":
    result = audit()
    (EVIDENCE / "esp32-latency-semantics-v1.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"audit": result["audit"], "original_metrics": len(result["cells"]),
                      "measured_os": list(FOLDERS), "board": result["board"]}))
