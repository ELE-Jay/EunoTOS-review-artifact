#!/usr/bin/env python3
"""Explain original Rhealstone subtraction from already audited captures."""
import argparse
import json

from audit_esp32_rhealstone import CASES, ROOT, SOURCE, digest, original_formula

SYSTEMS = ("freertos", "zephyr", "riot", "nuttx", "alios")
SEMANTICS = {
    "taskswitch": ("Task switch", "Empty loops and one no-peer yield",
        "Increment above no-peer yield; not complete context-switch time"),
    "taskpreempt": ("Task Preempt", "Empty loop and one initial self-suspend/task return",
        "Resume/preempt/suspend-cycle difference; not isolated preemption entry"),
    "semshuffle": ("Semaphore Shuffle", "Whole two-task yield-only run",
        "Added obtain/release pair and changed handoff path per original shuffle"),
    "mlatency": ("Intertask Message Latency", "Empty loop and one prefilled nonblocking receive",
        "Blocking receive/send/wakeup difference; not full 16-byte transfer latency"),
    "deadlockbrk": ("Deadlock Break", "Whole suspend/resume baseline and one uncontended obtain",
        "Priority-inheritance contention-cycle difference; not general deadlock recovery"),
}
API_BOUNDARIES = {
    "freertos": "Native yield/suspend/resume; PI mutex also used for no-PI shuffle; copied queue",
    "zephyr": "Native yield/suspend/resume; k_mutex always PI; copied queue",
    "riot": "Native yield/sleep/wakeup; shuffle non-PI and break PI modules; mailbox plus adapter payload buffer",
    "nuttx": "Native yield; SIGSTOP/SIGCONT job control; configured non-PI/PI pthread mutex; POSIX copied queue",
    "alios": "Native yield/suspend/resume; global PI mutex also used for no-PI shuffle; copied buffer queue",
}


def audit(ports):
    # The unified caller first replays each image/source/native path and UART.
    if set(ports) != set(SYSTEMS):
        raise ValueError("baseline review requires all five audited native ports")
    originals = {name: digest(SOURCE / name) for name in (*[case + ".c" for case in CASES], "timesys.h")}
    cells = []
    for system in SYSTEMS:
        port = ports[system]
        directory = ROOT / "artifacts/reports" / ("rhealstone-" + system + "-calibrated-" +
            ("v2" if system == "riot" else "v1"))
        proof = json.loads((directory / "original-source-proof.json").read_text())
        if any(sum(row["name"] == name and row["sha256"] == sha for row in proof) != 1
                for name, sha in originals.items()):
            raise ValueError("original baseline/program/formula identity differs")
        if port["audit"] != "pass" or port["independent_boots"] != 15 or port["ranking_eligible"] or \
                not port["original_timer_overhead_contract_restored"] or \
                {row["case"] for row in port["cells"]} != set(CASES) or len(port["cells"]) != 5:
            raise ValueError("calibrated baseline evidence coverage or qualification differs")
        for cell in port["cells"]:
            case = cell["case"]
            _, _, count, indices = CASES[case]
            if cell["resets"] != 3 or len(cell["captures"]) != 3 or cell["measurement_eligible"] or cell["ranking_eligible"]:
                raise ValueError("baseline review cannot promote an unqualified cell")
            total, baseline, directive = indices
            inputs = []
            for capture in cell["captures"]:
                values = capture["timer_reads_cycles"]
                if len(values) != (2 if case == "semshuffle" else 3) or \
                        any(type(value) is not int or not 0 <= value <= 0xffffffff for value in values) or \
                        capture["original_iterations"] != count or capture["measurement_eligible"] or \
                        original_formula(values, count, indices) != capture["raw_original_cycles"]:
                    raise ValueError("original baseline formula or eligibility differs")
                first_difference = values[total] - values[baseline]
                quotient = (first_difference & 0xffffffff) // count
                overhead = values[directive] if directive is not None else 0
                inputs.append({"total_cycles": values[total], "loop_or_baseline_cycles": values[baseline],
                    "directive_cycles": overhead, "iterations": count,
                    "original_output_cycles": capture["raw_original_cycles"],
                    "total_subtraction_unsigned_wrap": first_difference < 0,
                    "directive_subtraction_unsigned_wrap": quotient < overhead,
                    "capture_jsonl_sha256": capture["uart_sha256"]})
            if cell["raw_original_cycles"] != [row["original_output_cycles"] for row in inputs]:
                raise ValueError("baseline capture outputs differ from audited cell")
            label, removed, interpretation = SEMANTICS[case]
            cells.append({"system": system, "case": case, "original_label": label,
                "original_source_sha256": originals[case + ".c"],
                "binary_sha256": cell["binary_sha256"], "removed_baseline": removed,
                "interpretation": interpretation, "native_api_boundary": API_BOUNDARIES[system],
                "formula_inputs": inputs, "measurement_eligible": False, "ranking_eligible": False})
    return {"audit": "pass", "scope": "interpretation of original calibrated Rhealstone subtractions",
        "original_revision": "acb78c0c8c76f4ae12c60b729948e541c1e3930c",
        "source_sha256": originals, "existing_program_cells_reviewed": 25,
        "existing_boots_reviewed": 75, "new_board_boots": 0, "new_benchmark_metrics": 0,
        "original_formula": "uint32(total-baseline) / iterations - directive; printed as int32",
        "cells": cells, "ranking_eligible": False, "composite_score": None,
        "boundary": "source-level baseline meaning resolved; machine-path/source/UART qualification inherited from calibrated auditors; API differences, cold/warm cache/layout, calibration sample perturbation and complete-operation latency remain unqualified; no new workload, corrected formula, measurement or score"}


def render_table(result):
    if result["audit"] != "pass" or len(result["cells"]) != 25 or result["ranking_eligible"]:
        raise ValueError("baseline interpretation table lacks audited unranked coverage")
    return "\n".join(["| Original Rhealstone metric | Original baseline removed | Meaning of retained output |",
        "| --- | --- | --- |", *["| Baseline review / " + " | ".join(SEMANTICS[case]) + " |" for case in CASES]])


if __name__ == "__main__":
    from audit_esp32_rhealstone_calibrated import audit as calibrated
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    args = parser.parse_args()
    ports = {system: calibrated(ROOT / "artifacts/reports" / ("rhealstone-" + system +
        "-calibrated-" + ("v2" if system == "riot" else "v1")), system) for system in SYSTEMS}
    value = json.dumps(audit(ports), indent=2) + "\n"
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(value, encoding="utf-8")
    else:
        print(value, end="")
