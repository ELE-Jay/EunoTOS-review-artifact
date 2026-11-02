#!/usr/bin/env python3
"""Bind continuous SP contexts to the original native allocation lifetimes."""
import argparse
import json
from pathlib import Path
import sys

from measure_esp32_message_steps import MAC, step_observations, reusable_validation
from measure_esp32_boot_handoff_ram import build_proof
from run_esp32_followup import monotonic_interval, read_raw_capture, sha, verified
from run_esp32_tm_ram_lifetimes import EVENT, POOL, read_run, replay_events


def bind_contexts(lines, step, proof):
    events = [tuple(map(int, m.groups())) for s in lines if (m := EVENT.fullmatch(s))]
    pools = [tuple(map(int, m.groups())) for s in lines if (m := POOL.fullmatch(s))]
    creations = []
    for i, e in enumerate(events):
        if e[1] == 5:
            if i + 1 == len(events) or events[i + 1][1] != 6 or events[i + 1][2] != e[2]:
                raise ValueError("Native task generation pair is incomplete")
            creations.append({"tcb": e[3], "low": events[i + 1][3], "span": events[i + 1][4], "cursor": i + 2})
    summary = step["summary"]
    if step["unclassified_sp_observations"] or not summary.get("reconstructed", 0) or \
            len(creations) != summary["generations"] or not 0 < summary["peak_event"] <= len(events):
        raise ValueError("Continuous trace has missing context coverage or generations")
    for kind in (0, 2):
        rows = [r for r in step["contexts"] if r["kind"] == kind]
        if any(a["low"] < b["high"] and b["low"] < a["high"] for i, a in enumerate(rows) for b in rows[i + 1:]):
            raise ValueError("Simultaneous context reservations overlap")
    final = replay_events(events, pools)
    at_peak = replay_events(events[:summary["peak_event"]], pools, require_terminal=False)
    irq = proof["interrupt_stack"]
    for r in step["contexts"]:
        if r["kind"] != 1 and r["index"] == 16:
            if (r["low"], r["high"] - r["low"], r["tcb"], r["generation"]) != (irq["address"], irq["reserved_bytes"], 0, 0):
                raise ValueError("Observed IRQ span differs from the linked native stack")
            continue
        if not 1 <= r["generation"] <= len(creations):
            raise ValueError("Unknown task SP generation")
        native = creations[r["generation"] - 1]
        if (r["tcb"], r["low"], r["high"] - r["low"]) != (native["tcb"], native["low"], native["span"]):
            raise ValueError("SP context differs from its native allocation generation")
        if r["kind"] in (0, 2):
            allocation = final if r["kind"] == 0 else at_peak
            if native["cursor"] > (len(events) if r["kind"] == 0 else summary["peak_event"]) or \
                    r["low"] not in allocation["blocks"] or r["tcb"] not in allocation["blocks"]:
                raise ValueError("SP context has no simultaneous native reservation")
            if r["kind"] == 2 and any(n["tcb"] == r["tcb"] and n["cursor"] <= summary["peak_event"]
                    for n in creations[r["generation"]:]):
                raise ValueError("Peak context reused a retired task generation")
    return {"native_generations": len(creations), "peak_event_cursor": summary["peak_event"],
        "stack_reservations_not_added_again_to_heap": True, "full_live_ram_peak_bytes": None}


def audit(source, folder):
    from audit_esp32_followup import envelope
    state, proof = envelope(folder), build_proof(source)
    application = proof["application"]
    recorded_plan = json.loads((folder / "plan.json").read_text())
    reused = recorded_plan.get("reused_validation", False)
    expected = {"resets": 5, "separate_validation_resets": 1, "seconds": 150, "validation_seconds": 30,
        "board_mac": MAC, "build_manifest_sha256": sha(source / "build.json"), "step": application["step_observer"],
        "scope": "continuous instruction-boundary SPs from app workload entry through original third report; early boot remains separate",
        "chronology": "host-boot-scoped-monotonic-ns-v1",
        **({"reused_validation": True, "reused_campaign_sha256": sha(folder / "reused-validation-source/campaign.json")} if reused else {})}
    if state["mode"] != "message-continuous-step-stacks" or state["board_mac"] != MAC or \
            state["independent_resets"] != 5 or state["separate_validation_resets"] != 1 or \
            recorded_plan != expected:
        raise ValueError("Continuous trace campaign/protocol incomplete")
    if reused:
        original = folder / "reused-validation-source"
        reusable_validation(original, source, proof)
        expected_files = {p.relative_to(original / "validation").as_posix(): sha(p) for p in (original / "validation").rglob("*") if p.is_file()}
        actual_files = {p.relative_to(folder / "validation").as_posix(): sha(p) for p in (folder / "validation").rglob("*") if p.is_file()}
        if expected_files != actual_files or state.get("reused_validation_resets") != 1:
            raise ValueError("Reused validation bytes or physical-reset count differ")
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
        if sha(folder / "build" / name) != sha(source / name):
            raise ValueError("Continuous capture image differs from its qualified source")
    verified(folder / "captures", folder / "build", MAC)
    output, previous = [], None
    for name, i, validation in [("validation", 1, True)] + [("captures", i, False) for i in range(1, 6)]:
        captures = folder / name
        verified(captures, folder / "build", MAC, logs=("verify-run%d.log" % i,))
        rows = read_raw_capture(captures, i)
        clock = monotonic_interval(rows)
        if sum(r["line"].startswith("rst:0x") for r in rows) != 1 or previous is not None and \
                (clock["host_boot_id"] != previous["host_boot_id"] or clock["start_ns"] <= previous["end_ns"]):
            raise ValueError("Continuous physical capture intervals overlap")
        previous = clock
        lines = [r["line"] for r in rows]
        native = read_run(captures, i, application, validation=validation)
        step = step_observations(lines)
        saved = json.loads((captures / ("result%d.json" % i)).read_text())
        if json.loads(json.dumps({"native": native, "steps": step})) != saved:
            raise ValueError("Stored continuous result differs from original bytes")
        output.append({"validation": validation, "native": native, "continuous_stack": step,
            "allocation_binding": bind_contexts(lines, step, application)})
    return {"audit": "pass", "board_mac": MAC, "independent_resets": 5, "separate_validation_resets": 1,
        "runs": output, "reused_validation_resets": int(reused), "new_board_captures": 6 - int(reused),
        "original_flash_restored": True, "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "context_span_definition": "native usable stack reservation upper bound minus observed/saved SP; not an additional heap charge or an uninstrumented estimate",
        "scope": "observer-image continuous instruction-boundary task/ordinary-IRQ context spans; early boot/unmanaged ranges remain open"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "campaign", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux": parser.error("Audit experimental evidence on leon only")
    result = audit(args.source, args.campaign)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("audit", "independent_resets", "separate_validation_resets", "whole_live_ram_peak_bytes")}))
