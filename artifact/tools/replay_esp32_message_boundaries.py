#!/usr/bin/env python3
"""Independent raw-byte and allocation-prefix replay for boundary SP records."""
import argparse
import json
from pathlib import Path
import sys

from replay_esp32_followup import campaign, raw_rows, require


def decode(lines):
    records, summaries, events = [], [], []
    for line in lines:
        if line.startswith(("BOUNDARY_RAM total=", "BOUNDARY_RAM slot ")):
            slot = line.startswith("BOUNDARY_RAM slot ")
            pairs = [part.split("=") for part in line.split()[2 if slot else 1:]]
            require(all(len(p) == 2 and p[1].isdigit() for p in pairs) and
                    len({p[0] for p in pairs}) == len(pairs), "Malformed boundary fields")
            (records if slot else summaries).append({k: int(v) for k, v in pairs})
        elif line.startswith("TM_RAM event="):
            pairs = [part.split("=") for part in line.split()[1:]]
            require(all(len(p) == 2 for p in pairs), "Malformed native event")
            events.append({k: int(v) for k, v in pairs})
    require(len(summaries) == lines.count("BOUNDARY_RAM END") == 1 and
            lines.count("BOUNDARY_RAM ARM domain=function-boundary-plus-allocation observer=included") == 1,
            "Incomplete boundary interval")
    s = summaries[0]
    require(set(s) == {"total", "unknown", "bad", "invalid", "refreshes", "switches", "joint_peak", "peak_event", "peak_heap", "peak_irq", "retired", "generations"} and
            0 < s["total"] < 2**32 and 0 < s["refreshes"] <= s["total"] and
            all(s[k] == 0 for k in ("unknown", "bad", "invalid")), "Boundary coverage is incomplete")
    require(len({(r["kind"], r["index"]) for r in records}) == len(records), "Repeated context")
    for r in records:
        require(set(r) == {"kind", "index", "low", "high", "generation", "tcb", "samples", "minimum", "last", "min_pc"} and
                r["kind"] in (0, 1, 2) and 0x3ffae000 <= r["low"] <= r["minimum"] <= r["last"] <= r["high"] < 0x40000000,
                "Context physical interval differs")
    live = [r for r in records if r["kind"] == 0]
    dead = [r for r in records if r["kind"] == 1]
    peak = [r for r in records if r["kind"] == 2]
    require(len(dead) == s["retired"] and sum(r["samples"] for r in live + dead) == s["total"] and
            sorted(r["generation"] for r in live + dead if r["generation"]) == list(range(1, s["generations"] + 1)),
            "Task generations or samples lost")
    require(len([r for r in live if r["index"] == 16 and r["samples"] > 0 and r["high"] - r["low"] == 1536]) == 1,
            "Ordinary IRQ context absent")
    for group in (live, peak):
        ranges = sorted((r["low"], r["high"]) for r in group)
        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "Physical contexts overlap")
    require(s["peak_irq"] in (0, 1) and sum(r["high"] - r["last"] for r in peak) == s["joint_peak"],
            "Joint observation arithmetic differs")
    if events:
        require([e["event"] for e in events] == list(range(len(events))) and
                0 < s["peak_event"] <= len(events) and
                sum(e["delta"] for e in events[:s["peak_event"]] if e["kind"] < 5) == s["peak_heap"],
                "Joint observation is not bound to the native event prefix")
    extra = {}
    skipped = [line for line in lines if line.startswith("BOUNDARY_RAM fast_skipped=")]
    if skipped:
        require(len(skipped) == 1 and skipped[0].split("=")[1].isdigit(), "Malformed depth pruning count")
        extra["fast_skipped"] = int(skipped[0].split("=")[1])
    return {"summary": s, "contexts": records, **extra, "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


def replay(folder):
    state = campaign(folder)
    require(state["mode"] == "tm-message-lifetimes" and state["board_mac"] == "34:98:7a:a2:85:28" and
            state["independent_resets"] == 5, "Incomplete boundary reset plan")
    result, previous = [], None
    for directory, index in [("validation", 1)] + [("captures", n) for n in range(1, 6)]:
        rows = raw_rows(folder / directory / ("reset%d.jsonl" % index))
        clock = rows[0]["host_boot_id"], rows[0]["capture_started_monotonic_ns"], rows[-1]["clock_read_after_ns"]
        require(sum(r["line"].startswith("rst:0x") for r in rows) == 1 and clock[1] < clock[2] and
                (previous is None or previous[0] == clock[0] and previous[1] < clock[1]), "Resets are not independently ordered")
        previous = clock[0], clock[2]
        result.append({"validation": directory == "validation", "boundary_stack": decode([r["line"] for r in rows])})
    return {"replay": "pass", "independent_resets": 5, "separate_validation_resets": 1, "runs": result,
        "original_flash_restored": True, "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if sys.platform != "linux": p.error("Replay on leon only")
    result = replay(a.directory)
    with a.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print("Boundary raw-byte replay passed")
