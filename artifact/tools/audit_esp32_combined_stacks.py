#!/usr/bin/env python3
"""Join same-image C-boundary and native-transition stack observations."""
import argparse
import json
from pathlib import Path
import sys

from run_esp32_followup import sha


def join_contexts(boundary, native):
    identity = ("kind", "index", "low", "high", "generation", "tcb")
    # Peak snapshots occur at different instants; compare lifecycle identities instead.
    owners = lambda value: sorted(tuple(row[k] for k in identity)
                                   for row in value["contexts"] if row["kind"] in (0, 1))
    b, n = boundary["summary"], native["summary"]
    if owners(boundary) != owners(native) or any(b[k] != n[k] for k in ("generations", "retired")):
        raise ValueError("Combined observers disagree on task generations or physical storage")
    if any(s[k] for s in (b, n) for k in ("unknown", "bad", "invalid")) or any(
            value["whole_live_ram_peak_bytes"] is not None or value["ranking_eligible"] for value in (boundary, native)):
        raise ValueError("Incomplete boundary observations cannot establish a whole-RAM peak")
    return {"boundary_observations": b["total"], "native_observations": n["total"],
            "boundary_joint_stack_bytes": b["joint_peak"], "native_joint_stack_bytes": n["joint_peak"],
            "boundary_peak_allocation_event": b["peak_event"], "native_peak_allocation_event": n["peak_event"],
            "generations": b["generations"], "retired": b["retired"],
            "same_task_storage_and_generations": True, "peaks_added_together": False}


def audit(folder, source):
    from measure_esp32_boot_handoff_ram import audit as main_audit
    from replay_esp32_message_boundaries import replay as boundary_replay
    from replay_esp32_native_sp import replay as native_replay
    main = main_audit(folder, source)
    boundary, native = boundary_replay(folder), native_replay(folder)
    build = main["build"]["application"]
    if not build.get("compiler_boundary_stack_trace") or not build.get("native_assembly_sp_trace"):
        raise ValueError("Combined observation requires both probes in the measured image")
    measured = [main["application"]["separate_validation"]] + main["application"]["runs"]
    rows = []
    for index, (value, separate_b, separate_n) in enumerate(zip(measured, boundary["runs"], native["runs"], strict=True)):
        if separate_b["validation"] != (index == 0) or separate_n["validation"] != (index == 0) or \
                value["boundary_stack"] != separate_b["boundary_stack"] or value["native_sp"] != separate_n["native_sp"]:
            raise ValueError("Combined observation differs from independent raw-byte replay")
        row = {"validation": index == 0, **join_contexts(value["boundary_stack"], value["native_sp"])}
        if index:
            if value["software_reserved_and_allocated_peak_bytes"] != build["static_sram_bytes"] + value["heap_peak_bytes"]:
                raise ValueError("Stack reservations were added more than once")
            row.update(heap_peak_bytes=value["heap_peak_bytes"],
                       static_and_allocated_peak_bytes=value["software_reserved_and_allocated_peak_bytes"],
                       original_counts_30s=value["original_message"]["original_window_totals"])
        rows.append(row)
    if len(rows) != 6 or len(measured) != 6:
        raise ValueError("Combined observation requires five resets and one finite validation")
    return {"audit": "pass", "runs": rows, "independent_resets": 5, "separate_validation_resets": 1,
            "static_sram_bytes": build["static_sram_bytes"], "profile": build["profile"],
            "original_flash_restored": main["original_flash_restored"],
            "source_manifest_sha256": sha(source / "build.json"), "campaign_sha256": sha(folder / "campaign.json"),
            "auditor_sha256": sha(Path(__file__)), "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
            "new_board_captures_during_audit": 0,
            "scope": "Same-image task generations and storage across function/allocation and native assembly boundaries. "
                     "Separate peak instants are not added, and stacks already belong to static/heap reservations. "
                     "No continuous instruction, ROM or unmanaged-memory peak is inferred."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("campaign", "source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Audit real evidence on leon")
    result = audit(args.campaign, args.source)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("audit", "independent_resets", "separate_validation_resets", "whole_live_ram_peak_bytes")}))
