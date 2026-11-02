#!/usr/bin/env python3
"""Replay replacement-board followups without changing historical qualifications."""
import argparse
from datetime import datetime
import hashlib
import importlib
import json
from pathlib import Path
import re
import statistics

from audit_esp32_alios_tm import check_conditions, check_compilation, check_native_port
from audit_esp32_alios_tm_irq import native_calls
from audit_esp32_resources import audit_elf_image
from audit_esp32_tm_basic import audit as tm_audit
from audit_esp32_tm_reboots import require_cpu2_interrupt
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import CANDIDATES, RAMS, verified


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def envelope(directory, allow_incomplete=False, *, allow_energy=False):
    data = json.loads((directory / "campaign.json").read_text())
    allowed = ("collection_complete_audit_pending", "incomplete") if allow_incomplete else ("collection_complete_audit_pending",)
    if data["status"] not in allowed or not data["original_flash_restored"] or \
            data["old_cohort_modified"] or data["energy_measured"] is not allow_energy or data["external_independent_replication"]:
        raise ValueError("Incomplete, unrestored, or incorrectly qualified campaign")
    for name, digest in data["files"].items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or not path.is_file() or sha(path) != digest:
            raise ValueError("Campaign artifact changed or escapes directory: " + name)
    if set(data["files"]) != {p.relative_to(directory).as_posix() for p in directory.rglob("*")
                              if p.is_file() and p not in (directory / "campaign.json", directory / "audit.json")}:
        raise ValueError("Unaccounted campaign files")
    for name in ("identity-before.log", "identity-restore.log", "restore-verify.log"):
        text = (directory / name).read_text()
        if set(re.findall(r"^MAC: ([0-9a-f:]+)$", text, re.M)) != {data["board_mac"]}:
            raise ValueError("Board identity mismatch")
    text = (directory / "restore-verify.log").read_text()
    if "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in text or "verify OK (digest matched)" not in text:
        raise ValueError("Original full Flash restoration is not witnessed")
    return data


def independent_captures(folder, indices=(1, 2, 3)):
    captures = [read_raw_capture(folder, i) for i in indices]
    previous = None
    for index, rows in zip(indices, captures):
        resets = [r for r in rows if r["line"].startswith("rst:0x")]
        start, end = (datetime.fromisoformat(rows[n]["utc"]) for n in (0, -1))
        if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or previous is not None and start <= previous:
            raise ValueError("Independent physical reset chronology differs")
        previous = end
        text = (folder / ("verify-run%d.log" % index)).read_text()
        if "digest matched" not in text or re.search(r"fatal error|digest mismatch", text, re.I):
            raise ValueError("Per-reset image verification missing")
    return captures


def retained_build_proof(computed, recorded, directory, campaign):
    fields = {"capture_recorder_sha256", "prepared_raw_uart_recorder_sha256"}
    selected = fields & (computed.keys() | recorded.keys())
    bound = dict(computed)
    if selected:
        recorder = sha(directory / "capture_esp32_uart.py")
        if campaign["files"].get("capture_esp32_uart.py") != recorder or any(
                recorded.get(key) != recorder or key not in computed for key in selected):
            raise ValueError("Retained recorder differs from acquisition manifest or build proof")
        # Replaying an old acquisition binds its archived recorder, not today's tool.
        bound.update({key: recorder for key in selected})
    if bound != recorded:
        raise ValueError("Static original/native qualification changed")
    return bound


def candidates(directory, campaign):
    cells, failed, all_times = [], [], []
    requested = campaign.get("requested_candidates", [n for _, _, n in CANDIDATES])
    if not requested or not set(requested) <= {n for _, _, n in CANDIDATES}:
        raise ValueError("Unknown or empty planned candidate set")
    for kind, system, name in CANDIDATES:
        if name not in requested:
            continue
        folder = directory / name
        recorded = json.loads((folder / "result.json").read_text())
        if recorded["status"] != "pass":
            failed.append({"original": name, "reason": recorded["error"]})
            continue
        module = importlib.import_module("audit_esp32_riot_" + kind + "_" + system)
        # Some retained build audits also inspect sibling failed-build archives.
        reference = Path(__file__).resolve().parents[1] / "artifacts/reports" / name
        proof = module.audit(reference)
        frozen = {p.relative_to(folder / "build").as_posix(): sha(p)
                  for p in (folder / "build").rglob("*") if p.is_file()}
        if any(not (reference / n).is_file() or sha(reference / n) != digest for n, digest in frozen.items()):
            raise ValueError("Collected build snapshot differs from the admitted original build")
        proof = retained_build_proof(proof, json.loads((folder / "build-proof.json").read_text()), directory, campaign)
        captures = folder / "captures"
        if sha(captures / "application.elf") != sha(folder / "build/application.elf"):
            raise ValueError("Capture parser is bound to a different ELF")
        verified(captures, folder / "build", campaign["board_mac"])
        aligned = proof["machine_control"].get("aligned_peer_storage_bytes")
        runs = [module.capture(captures, i, aligned) if aligned is not None else module.capture(captures, i)
                for i in (1, 2, 3)]
        if runs != recorded["captures"] or recorded["ranking_eligible"] or recorded["energy_measured"]:
            raise ValueError("Original statistics or qualification differs")
        times = [(datetime.fromisoformat(r["start_utc"]), datetime.fromisoformat(r["end_utc"])) for r in runs]
        if any(a[1] >= b[0] for a, b in zip(times, times[1:])):
            raise ValueError("Independent captures overlap")
        all_times += times
        values = [r["original_count"] for r in runs]
        cells.append({"os": proof["os"], "original": name, "values": values,
            "median": statistics.median(values), "range": [min(values), max(values)],
            "independent_resets": 3, "ranking_eligible": False, "original_test_body_unchanged": True,
            "profile": {k: proof[k] for k in ("clock_mhz", "cores", "tick_hz", "compiler", "optimization")}})
    all_times.sort()
    if any(a[1] >= b[0] for a, b in zip(all_times, all_times[1:])):
        raise ValueError("Cross-case physical captures overlap")
    return {"audit": "pass", "cells": cells, "failed_candidates": failed,
            "completed_cells": len(cells), "independent_resets": len(cells) * 3,
            "ranking_eligible": False, "new_raw_metrics": False}


def interrupts(directory, campaign, prepared):
    build = json.loads((prepared / "build.json").read_text())
    if build != json.loads((directory / "build.json").read_text()) or build["status"] != "build_pass_not_measured":
        raise ValueError("IRQ build identity differs")
    original = Path(__file__).resolve().parents[1] / "artifacts/source_snapshots/thread-metric-6.2.1-rel"
    images, cell_rows, time_rows = {}, [], []
    controls = ("main.c", "test.c", "tm_override.h", "config", "sdkconfig.h", "k_config.h",
                "compiler.txt", "rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S", "app-aos.mk")
    for case in ("interrupt_processing", "interrupt_preemption_processing"):
        baseline = prepared / "images/legacy" / case
        counts = {}
        for variant in ("legacy", "corrected", "replica"):
            item = next(r for r in build["builds"] if r["case"] == case and r["variant"] == variant)
            source = prepared / item["directory"]
            if any(sha(source / n) != digest for n, digest in item["images"].items()):
                raise ValueError("Prepared IRQ image changed")
            if any((source / n).read_bytes() != (baseline / n).read_bytes() for n in controls) or \
                    (source / ("tm_" + case + "_test.c")).read_bytes() != (original / ("tm_" + case + "_test.c")).read_bytes():
                raise ValueError("Controlled configuration/original program differs")
            if variant != "legacy" and (baseline / "port.c").read_text().replace(
                    "    krhino_intrpt_enter();\n", "").replace("    krhino_intrpt_exit();\n", "") != (source / "port.c").read_text():
                raise ValueError("Adapter intervention exceeds two nesting calls")
            check_compilation(source, case)
            check_native_port(source)
            native_calls(source, case, legacy_ablation=variant == "legacy")
            audit_elf_image(source / "application.elf", source / "application.bin")
            images[variant, case] = item["images"]
            values = []
            for index in (1, 2, 3):
                folder = directory / variant / case / ("run%d" % index)
                verified(folder, source, campaign["board_mac"])
                rows = read_raw_capture(folder, 1)
                check_conditions(rows)
                require_cpu2_interrupt(rows)
                result = tm_audit(folder / "reset1.jsonl", "AliOS-Rhino", case)
                recorded = json.loads((folder / "result.json").read_text())
                if result["original_window_totals"] != recorded["original_window_totals"] or \
                        recorded["images"] != item["images"] or not 25 < result["host_window_seconds"][0] < 40:
                    raise ValueError("IRQ source/window/record differs")
                values.append(result["original_window_totals"][0])
                time_rows.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
            counts[variant] = values
        if images["corrected", case] != images["replica", case]:
            # ELF may embed build paths, but installed segments must reproduce exactly.
            if any(images["corrected", case][n] != images["replica", case][n]
                   for n in ("application.bin", "bootloader.bin", "partitions.bin")):
                raise ValueError("Clean-build replica installed segments differ")
        cell_rows.append({"case": case, "original_counts_30s": counts,
            "medians": {v: statistics.median(n) for v, n in counts.items()},
            "relative_change_percent": (statistics.median(counts["corrected"]) / statistics.median(counts["legacy"]) - 1) * 100,
            "installed_images_reproduced": True, "legacy_is_invalid_performance_baseline": True})
    time_rows.sort()
    if any(a[1] >= b[0] for a, b in zip(time_rows, time_rows[1:])):
        raise ValueError("IRQ/reproduction captures overlap")
    return {"audit": "pass", "cells": cell_rows, "independent_resets": 18,
            "single_adapter_intervention": True, "same_board": True,
            "replication_scope": "fresh source directory and build; same lab/host/operator/physical board",
            "external_independent_replication": False, "ranking_eligible": False, "energy_measured": False}


def ram(directory, campaign):
    from audit_esp32_hartstone_series import audit as series
    cells, intervals = [], []
    for system, source_name in RAMS:
        module = importlib.import_module("audit_esp32_hartstone_ram_" +
                                        ("nuttx_freelist" if system == "nuttx" else "alios"))
        reference = Path(__file__).resolve().parents[1] / "artifacts/reports" / source_name
        folder, captures = directory / system, directory / system / "captures"
        proof = module.audit(reference) if system == "nuttx" else module.build(reference)
        if system == "alios":
            proof["machine_control"] = module.machine(reference)
        if json.loads(json.dumps(proof)) != json.loads((folder / "build-proof.json").read_text()):
            raise ValueError("RAM original/native/observer build qualification differs")
        for p in (folder / "build").rglob("*"):
            if p.is_file() and sha(p) != sha(reference / p.relative_to(folder / "build")):
                raise ValueError("RAM build snapshot differs from static qualification")
        if sha(captures / "application.elf") != sha(reference / "application.elf"):
            raise ValueError("RAM capture parser is bound to a different image")
        verified(captures, folder / "build", campaign["board_mac"])
        for index in (1, 2, 3):
            rows = read_raw_capture(captures, index)
            resets = [r for r in rows if "rst:0x" in r["line"]]
            if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
                raise ValueError("RAM run lacks exactly one early physical reset")
            intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
        os_name = "NuttX" if system == "nuttx" else "AliOS-Rhino"
        old_series = [series(module.REFERENCE / ("reset%d.jsonl" % i), os_name, 4, high_resolution=True) for i in (1, 2, 3)]
        if system == "nuttx":
            result = module.observations(captures, proof, proof["machine_control"], old_series)
        else:
            runs = [module.capture(captures, i, proof) for i in (1, 2, 3)]
            if any(datetime.fromisoformat(a["completed_utc"]) >= datetime.fromisoformat(b["started_utc"])
                   for a, b in zip(runs, runs[1:])):
                raise ValueError("RAM independent resets overlap")
            result = {"measured": True, "runs": runs,
                "observed_software_ram_bytes": [proof["static_footprint"]["static_sram_bytes"] + r["dynamic_heap_peak_bytes"] for r in runs],
                "reference_worker_cohort_covered": all(r["observed_hartstone_series"]["first_loss_step"] >=
                    max(s["first_loss_step"] for s in old_series) for r in runs)}
        cells.append({"os": os_name, "board_mac": campaign["board_mac"], "result": result,
            "scope": "instrumented application entry through complete original first loss; allocated bytes, not live stack bytes",
            "historical_reference_scope": "B0 worker-count coverage only, not a same-board performance comparison",
            "ranking_eligible": False, "full_lifetime_live_ram_measured": False})
    intervals.sort()
    if any(a[1] >= b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("RAM physical capture intervals overlap")
    return {"audit": "pass", "cells": cells, "independent_resets": 6,
            "energy_measured": False, "ranking_eligible": False, "external_independent_replication": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--prepared", type=Path)
    args = parser.parse_args()
    data = envelope(args.directory.resolve())
    if data["mode"] == "candidates":
        result = candidates(args.directory, data)
    elif data["mode"] == "interrupts":
        result = interrupts(args.directory, data, args.prepared)
    elif data["mode"] == "ram":
        result = ram(args.directory, data)
    else:
        raise ValueError("Unknown acquisition mode")
    print(json.dumps(result, indent=2))
