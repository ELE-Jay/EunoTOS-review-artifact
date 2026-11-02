#!/usr/bin/env python3
"""Pair measured joules with the unchanged original Thread-Metric period totals."""
import argparse
import json
import math
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from audit_esp32_powerz import audit
from audit_esp32_tm_reboots import require_cpu2_interrupt, require_self_check
from host.energy import measurement_sha256
from run_esp32_tm_energy import CASES, OSES, make_plan

WORK_UNITS = {
    "basic_processing": "one original sweep updating 1024 array entries; CPU/compiler control",
    "cooperative_scheduling": "one worker counter increment, summed across the five yielding workers",
    "preemptive_scheduling": "one worker counter increment, summed across the five priority-resume/suspend workers",
    "message_processing": "one completed original 16-byte self send/receive cycle",
    "synchronization_processing": "one completed original semaphore get/put pair; no contention",
    "memory_allocation": "one original 128-byte allocate/free pair; native allocator families differ",
    "interrupt_processing": "one original real interrupt handled and return to the triggering worker",
    "interrupt_preemption_processing": "one original real interrupt handled with higher-priority worker activation",
}
PRIMARY = ("FreeRTOS", "Zephyr", "NuttX")
COMPARABLE = tuple(case for case in CASES if case not in ("basic_processing", "memory_allocation"))


def comparison_order(case, group):
    ordered = sorted(group, key=lambda cell: cell["medians"]["joules_per_original_count"])
    median_order = [cell["os"] for cell in ordered]
    round_orders = []
    for reset in (1, 2, 3):
        values = [(cell["os"], next(run["joules_per_original_count"] for run in cell["runs"]
                                   if run["reset"] == reset)) for cell in group]
        round_orders.append([name for name, value in sorted(values, key=lambda pair: pair[1])])
    consistent = all(order == median_order for order in round_orders)
    separated = all(first["ranges"]["joules_per_original_count"][1] <
                    second["ranges"]["joules_per_original_count"][0]
                    for first, second in zip(ordered, ordered[1:]))
    eligible = consistent and separated
    return {"case": case, "median_arithmetic_order": median_order,
            "lower_energy_first": median_order if eligible else None,
            "repeat_orders": round_orders, "repeat_consistent": consistent,
            "observed_repeat_ranges_separated": separated, "observed_order_eligible": eligible,
            "definition": "order of three-reset per-run E/N medians, requiring the same order in all rounds and disjoint observed ranges; not statistical significance",
            "scope": "these configured systems and this original active workload only"}


def check_native_workload(capture, os_name, case):
    rows = [json.loads(line) for line in (Path(capture) / "uart.jsonl").read_text(encoding="utf-8").splitlines()]
    check_native_rows(rows, os_name, case)


def check_native_rows(rows, os_name, case):
    if os_name not in OSES.values() or case not in CASES:
        raise ValueError("unknown native workload profile")
    kind = {"message_processing": "queue", "synchronization_processing": "semaphore"}.get(case)
    # The archived Zephyr/NuttX pool ports use the original test's error checks,
    # not the additional exhaustion self-check implemented by the other ports.
    if case == "memory_allocation" and os_name in ("FreeRTOS", "RIOT", "AliOS-Rhino"):
        kind = "memory"
    if kind:
        require_self_check(rows, kind)
    if case.startswith("interrupt_"):
        require_cpu2_interrupt(rows)
    if any("BENCH_RAM" in row["line"] for row in rows):
        raise ValueError("RAM-instrumented firmware must not replace the uninstrumented energy workload")
    if os_name in ("RIOT", "AliOS-Rhino"):
        timer = "timer=tickless" if os_name == "RIOT" else "tick_hz=100"
        marker = f"Thread-Metric conditions cpu_hz=240000000 cores=1 {timer} scheduler=priority-fifo"
        if sum(row["line"] == marker for row in rows) != 1:
            raise ValueError("missing native runtime condition witness")


def paired_energy(result):
    totals = result["original_workload"]["original_window_totals"]
    windows = result["steady_report_intervals"]
    if len(totals) != 3 or len(windows) != 2:
        raise ValueError("energy normalization requires all three original totals and both steady intervals")
    if any(not 29.5 < window["duration_s"] < 30.5 for window in windows):
        raise ValueError("not an original 30-second steady interval")
    pairs = []
    # A heading's original total covers the preceding interval, not all elapsed time.
    for window, count in zip(windows, totals[1:]):
        if type(count) is not int or count <= 0 or not math.isfinite(window["energy_j"]) or window["energy_j"] <= 0:
            raise ValueError("invalid completed work or measured energy")
        pairs.append(dict(window, completed_original_counts=count,
                          joules_per_original_count=window["energy_j"] / count))
    energy = sum(window["energy_j"] for window in pairs)
    duration = sum(window["duration_s"] for window in pairs)
    count = sum(totals[1:])
    return {"paired_intervals": pairs, "steady_energy_j": energy, "steady_duration_s": duration,
            "steady_average_power_w": energy / duration, "completed_original_counts": count,
            "original_counts_per_s": count / duration, "joules_per_original_count": energy / count,
            "energy_per_original_count_uj": energy / count * 1e6}


def audit_suite(directory):
    directory = Path(directory)
    plan = json.loads((directory / "plan.json").read_text(encoding="utf-8"))
    if plan != make_plan():
        raise ValueError("changed or incomplete interleaved 40-cell/120-reset acquisition schedule")
    status = json.loads((directory / "status.json").read_text(encoding="utf-8"))
    if status.get("status") != "capture_complete_requires_independent_audit" or \
            status.get("completed_resets") != 120 or status.get("expected_resets") != 120:
        raise ValueError("capture driver has not completed the full eight-case/five-OS matrix")
    acquisition_names = ("run_esp32_tm_energy.py", "capture_esp32_powerz.py")
    for name in acquisition_names:
        if (directory / name).read_bytes() != (Path(__file__).parent / name).read_bytes():
            raise ValueError("changed acquisition source: " + name)
    actual = {str(path.relative_to(directory)) for path in directory.glob("*/*/reset*/capture")}
    expected = {step["directory"] + "/capture" for step in plan["schedule"]}
    if actual != expected:
        raise ValueError("missing or extra capture in original-workload matrix")
    setup_sha = measurement_sha256(directory / "operator-setup.json")
    setup = json.loads((directory / "operator-setup.json").read_text(encoding="utf-8"))
    previous_end, runs = None, {}
    for step in plan["schedule"]:
        capture = directory / step["directory"] / "capture"
        flash_lines = (capture.parent / "flash.log").read_text(encoding="utf-8").splitlines()
        if sum(line.strip() == "MAC: " + setup["board_mac"] for line in flash_lines) != 1:
            raise ValueError("installed board MAC differs from the retained supply confirmation")
        check_native_workload(capture, step["os"], step["case"])
        result = audit(capture, tm_os=step["os"], tm_case=step["case"],
                       whole_board_evidence=capture / "supply-evidence.json")
        if result.get("operator_setup_sha256") != setup_sha:
            raise ValueError("capture supply statement differs from the prior cohort confirmation")
        metadata = json.loads((capture / "metadata.json").read_text(encoding="utf-8"))
        start = datetime.fromisoformat(metadata["started_utc"])
        if start.utcoffset() is None or previous_end is not None and start <= previous_end:
            raise ValueError("overlapping captures or timezone-free acquisition")
        if metadata.get("usb_id") != "5fc9:0063" or metadata.get("port") != "/dev/ttyUSB0":
            raise ValueError("different instrument or board UART")
        previous_end = start + timedelta(seconds=metadata["duration_actual_s"])
        rows = [json.loads(line) for line in (capture / "uart.jsonl").read_text(encoding="utf-8").splitlines()]
        reset = next(row for row in rows if row["line"].startswith("rst:0x"))
        if reset["elapsed_s"] > 2 or not 25 < result["original_workload"]["host_window_seconds"][0] < 40:
            raise ValueError("not an early independent reset followed by original reporting")
        result.update(paired_energy(result), reset=step["reset"], started_utc=metadata["started_utc"],
                      evidence=str(capture.relative_to(directory)), work_unit=WORK_UNITS[step["case"]])
        runs.setdefault((step["case"], step["os"]), []).append(result)
    cells = []
    for case in CASES:
        for system, name in OSES.items():
            group = sorted(runs[case, name], key=lambda row: row["reset"])
            if [row["reset"] for row in group] != [1, 2, 3]:
                raise ValueError("incomplete independent repeats")
            fields = ("steady_average_power_w", "steady_energy_j", "original_counts_per_s",
                      "joules_per_original_count", "energy_per_original_count_uj")
            reason = ("CPU/compiler baseline, not an OS mechanism rank" if case == "basic_processing" else
                      "native fixed-block/variable-arena allocators differ" if case == "memory_allocation" else
                      "GCC12/native tickless cohort" if name == "RIOT" else
                      "GCC5/legacy SDK cohort" if name == "AliOS-Rhino" else
                      "same named original workload; 240 MHz/one core/GCC13 application/100-Hz FIFO profiles")
            cells.append({"os": name, "case": case, "work_unit": WORK_UNITS[case],
                          "independent_resets": 3, "whole_board_eligible": True,
                          "scoped_energy_comparison_eligible": case in COMPARABLE and name in PRIMARY,
                          "comparison_scope": reason, "ranking_eligible": False,
                          "medians": {field: statistics.median(row[field] for row in group) for field in fields},
                          "ranges": {field: [min(row[field] for row in group), max(row[field] for row in group)]
                                     for field in fields},
                          "voltage_v_full_trace": {"min": min(row["voltage_v"]["min"] for row in group),
                                                   "max": max(row["voltage_v"]["max"] for row in group)},
                          "runs": group})
    comparisons = []
    for case in COMPARABLE:
        group = [cell for cell in cells if cell["case"] == case and cell["os"] in PRIMARY]
        comparisons.append(comparison_order(case, group))
    eligible_cases = [row["case"] for row in comparisons if row["observed_order_eligible"]]
    for cell in cells:
        cell["observed_order_eligible"] = cell["os"] in PRIMARY and cell["case"] in eligible_cases
    return {"audit": "pass", "case_count": 8, "os_profiles": 5, "cells_count": 40,
            "independent_resets": 120, "whole_board_eligible": True, "ranking_eligible": False,
            "scoped_energy_comparison_eligible": True, "comparisons": comparisons, "cells": cells,
            "observed_order_cases": eligible_cases,
            "raw_sample_count": sum(run["sample_count"] for group in runs.values() for run in group),
            "operator_setup_sha256": setup_sha, "completed_utc": previous_end.isoformat(),
            "started_utc": min(run["started_utc"] for group in runs.values() for run in group),
            "acquisition_source_sha256": {name: measurement_sha256(directory / name) for name in acquisition_names},
            "archived_capture_checker_sha256": measurement_sha256(directory / "audit_esp32_tm_energy.py"),
            "independent_audit_source_sha256": measurement_sha256(Path(__file__)),
            "normalization": "sum measured E over 30->60 and 60->90 / sum corresponding original period totals, then median of three resets",
            "boundary": "operator-confirmed whole development-board input, includes downstream lead losses",
            "timing": "host UART receipt and POWER-Z query midpoint; no calibrated device conversion delay",
            "calibration": "instrument default, no external calibration or close-rank significance claim",
            "workload_scope": "unchanged Thread-Metric active workload; no idle/deep-sleep/network or official energy-score claim"}


def render_tables(suite):
    from audit_esp32_report import TM

    if suite.get("audit") != "pass" or suite.get("cells_count") != 40 or suite.get("independent_resets") != 120:
        raise ValueError("cannot render results for an incomplete or unaudited energy matrix")
    labels = {case: label for case, label, _ in TM}
    cells = {(cell["case"], cell["os"]): cell for cell in suite["cells"]}
    rows = []
    for heading, prefix, field, multiplier, format_spec in (
            ("Steady Board-Input Power (mW)", "Board power", "steady_average_power_w", 1000, ".1f"),
            ("Energy per Original Operation (microjoules)", "Energy per operation", "energy_per_original_count_uj", 1, ".3g")):
        rows += ["#### " + heading, "", "| Original test | " + " | ".join(OSES.values()) + " |",
                 "| --- | " + " | ".join("---:" for _ in OSES) + " |"]
        for case in CASES:
            values = []
            for name in OSES.values():
                cell = cells[case, name]
                median = format(cell["medians"][field] * multiplier, format_spec)
                bounds = "-".join(format(value * multiplier, format_spec) for value in cell["ranges"][field])
                values.append(median + " [" + bounds + "]")
            rows.append("| " + prefix + " / " + labels[case] + " | " + " | ".join(values) + " |")
        rows.append("")
    rows += ["#### Scoped Energy Comparison", "", "| Original test | Observed lower-energy-first order |",
             "| --- | --- |"]
    for comparison in suite["comparisons"]:
        order = (" < ".join(comparison["lower_energy_first"]) if comparison["observed_order_eligible"]
                 else "Not rank-qualified (" + ("repeat order changes" if not comparison["repeat_consistent"]
                                                else "observed repeat ranges overlap") + ")")
        rows.append("| Energy order / " + labels[comparison["case"]] + " | " +
                    order + " |")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", action="store_true", help="render independently replayed result tables")
    args = parser.parse_args()
    suite = audit_suite(args.directory)
    result = render_tables(suite) if args.markdown else json.dumps(suite, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
