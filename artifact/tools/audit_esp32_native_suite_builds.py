#!/usr/bin/env python3
"""Audit remaining GCC13 images as build-only artifacts, never as measurements."""
import json
import argparse
from pathlib import Path
import re
import statistics
from elftools.elf.elffile import ELFFile

from audit_esp32_rhino_gcc13 import build as rhino
from audit_esp32_riot_startup import build as riot
from audit_esp32_alios_tm_irq import native_calls
from run_esp32_followup import sha
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_tm_basic import audit as original, CASES as CASE_LABELS
from audit_esp32_tm_reboots import require_self_check, require_cpu2_interrupt
from audit_esp32_alios_tm import check_conditions

ROOT = Path(__file__).resolve().parents[1]
CASES = ("basic_processing", "cooperative_scheduling", "preemptive_scheduling",
         "synchronization_processing", "memory_allocation", "interrupt_processing",
         "interrupt_preemption_processing")


def audit():
    cells = []
    for system, family in (("RIOT", "riot"), ("AliOS-Rhino", "rhino")):
        base = ROOT / "artifacts/reports" / ("esp32-" + family + "-gcc13-suite-build-v1")
        for case in CASES:
            folder = base / case
            proof = riot(folder, False) if family == "riot" else rhino(folder, case)
            text = (folder / "build.log").read_text()
            selected = set(re.findall(r"-DTM_TEST_(\w+)=1\b", text))
            if selected != {case}:
                raise ValueError("Wrong compiled original case: " + system + " " + case)
            with (folder / "application.elf").open("rb") as stream:
                names = {s.name for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()
                         if s["st_shndx"] != "SHN_UNDEF"}
            if "tm_" + case + "_initialize" not in names:
                raise ValueError("Original initialization not linked")
            if case.startswith("interrupt_") and not {"software_isr", "tm_cause_interrupt"} <= names:
                raise ValueError("Native interrupt adapter not linked")
            if family == "rhino" and case.startswith("interrupt_"):
                for name, digest in (("k_sys.c", "54832be1c042d9dcc5ebc0ab04a5c01e91892236e15dfb20c227bc9f143a5593"),
                                     ("espos_scheduler.c", "138ca7d75019cb469fd7939c09e123976f3009aa5ef12035d2f645440f538f36")):
                    if sha(folder / "native-source" / name) != digest:
                        raise ValueError("Pinned native ISR source changed")
                proof["irq_machine_control"] = native_calls(folder, case, gcc13_blocks=True)
            cells.append({"os": system, "case": case, "evidence": folder.relative_to(ROOT).as_posix(),
                          "status": "build_pass_not_measured", "board_resets": 0,
                          "ranking_eligible": False, "proof": proof})
    return {"audit": "pass", "built_os_case_cells": len(cells), "cells": cells,
            "board_resets": 0, "new_measured_results": 0, "ranking_eligible": False,
            "remaining": ["three physical resets per original case with original correctness checks",
                          "runtime ISR entry/exit and deferred dispatch checks for GCC13 IRQ images",
                          "Rhino background service activity and RIOT native tickless comparison contract"],
            "boundary": "cross-build, pinned source/configuration, C ABI and linked original case only; no successful boot or runtime IRQ semantics inferred"}


def audit_campaign(folder):
    campaign = envelope(folder)
    proof = audit()
    if campaign["mode"] != "native-suite" or campaign["board_mac"] != "34:98:7a:a2:85:28" or \
            not campaign["requested_cases"] or not set(campaign["requested_cases"]) <= set(CASES) or \
            proof != json.loads((folder / "build-proof.json").read_text()):
        raise ValueError("Wrong native suite acquisition/source proof")
    cells, sequence = [], []
    checks = {"synchronization_processing": "semaphore", "memory_allocation": "memory"}
    from datetime import datetime
    for case in campaign["requested_cases"]:
        for system in ("RIOT", "AliOS-Rhino"):
            cell = next(r for r in proof["cells"] if r["os"] == system and r["case"] == case)
            base = folder / system / case
            build, capture = base / "build", base / "captures"
            if any(sha(build / n) != digest for n, digest in cell["proof"]["images"].items()):
                raise ValueError("Native measured image differs from source")
            verified(capture, build, campaign["board_mac"])
            runs = []
            for index, rows in enumerate(independent_captures(capture), 1):
                if system == "AliOS-Rhino":
                    check_conditions(rows)
                elif sum(r["line"] == "Thread-Metric conditions cpu_hz=240000000 cores=1 timer=tickless scheduler=priority-fifo" for r in rows) != 1:
                    raise ValueError("Native RIOT timer/profile differs")
                if case in checks:
                    require_self_check(rows, checks[case])
                if case.startswith("interrupt_"):
                    require_cpu2_interrupt(rows)
                parsed = original(capture / ("reset%d.jsonl" % index), system, case)
                if parsed != json.loads((capture / ("result%d.json" % index)).read_text()):
                    raise ValueError("Original reports differ from independent replay")
                sequence.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
                runs.append(parsed)
            values = [r["original_window_totals"][0] for r in runs]
            cells.append({"os": system, "case": case, "case_label": CASE_LABELS[case],
                          "values": values, "median": statistics.median(values),
                          "unit": "count/30s", "runs": runs, "independent_resets": 3,
                          "ranking_eligible": False, "source": cell["evidence"]})
    if any(a[1] >= b[0] for a, b in zip(sequence, sequence[1:])):
        raise ValueError("Native independent captures overlap or acquisition order differs")
    return {"audit": "pass", "board": "B1", "cells": cells, "independent_resets": len(sequence),
            "ranking_eligible": False, "energy_measured": False, "original_flash_restored": True,
            "boundary": "RIOT native tickless and GCC12 newlib; Rhino 100 Hz and legacy SDK libc; original native configurations, no cross-OS index"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path)
    args = parser.parse_args()
    result = audit_campaign(args.campaign) if args.campaign else audit()
    destination = args.campaign / "audit.json" if args.campaign else ROOT / "artifacts/reports/esp32-native-suite-builds-v1.json"
    destination.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "cells"}, indent=2))
