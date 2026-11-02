#!/usr/bin/env python3
"""Independent original-byte arithmetic for continuous context observations."""
import argparse
import json
from pathlib import Path
import sys

from replay_esp32_followup import campaign, raw_rows, require


def decode(lines):
    summaries, contexts = [], []
    for line in lines:
        if line.startswith("STEP_RAM total=") or line.startswith("STEP_RAM slot "):
            parts = line.split()[2:] if line.startswith("STEP_RAM slot ") else line.split()[1:]
            pairs = [p.split("=") for p in parts]
            require(all(len(p) == 2 and p[1].isdigit() for p in pairs) and
                    len({p[0] for p in pairs}) == len(pairs), "Malformed continuous record")
            target = contexts if line.startswith("STEP_RAM slot ") else summaries
            target.append({k: int(v) for k, v in pairs})
    require(len(summaries) == lines.count("STEP_RAM END") == 1 and
            lines.count("STEP_RAM ARM domain=instruction-boundary ordinary_irqs=enabled") == 1, "Incomplete continuous interval")
    s = summaries[0]
    require(set(s) == {"total", "unknown", "reconstructed", "bad", "invalid", "limit", "unknown_min", "unknown_max", "unknown_pc", "joint_peak", "peak_pc", "peak_irq", "peak_event", "retired", "generations"},
            "Different continuous schema")
    require(0 < s["total"] < 1200000000 and 0 <= s["reconstructed"] <= s["total"] and
            all(s[k] == 0 for k in ("unknown", "bad", "invalid", "limit", "unknown_max", "unknown_pc")) and
            s["unknown_min"] == 4294967295, "Continuous observer has a hole or exhausted budget")
    require(len({(r["kind"], r["index"]) for r in contexts}) == len(contexts), "Duplicate context")
    for r in contexts:
        require(set(r) == {"kind", "index", "low", "high", "generation", "tcb", "samples", "minimum", "last", "min_pc"} and
                r["kind"] in (0, 1, 2) and 0x3ffae000 <= r["low"] <= r["minimum"] <= r["last"] <= r["high"] < 0x40000000,
                "Context has invalid physical bounds")
    current = [r for r in contexts if r["kind"] == 0]
    retired = [r for r in contexts if r["kind"] == 1]
    peak = [r for r in contexts if r["kind"] == 2]
    require(len(retired) == s["retired"] and sum(r["samples"] for r in current + retired) == s["total"] and
            sorted(r["generation"] for r in current + retired if r["generation"]) == list(range(1, s["generations"] + 1)),
            "Samples or generations disappeared")
    require(len([r for r in current if r["index"] == 16 and r["samples"] > 0 and r["high"] - r["low"] == 1536]) == 1,
            "Ordinary IRQ stack was not observed")
    for group in (current, peak):
        ranges = sorted((r["low"], r["high"]) for r in group)
        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "Simultaneous context reservations overlap")
    require(s["peak_irq"] in (0, 1) and sum(r["high"] - r["last"] for r in peak if r["index"] != 16 or s["peak_irq"]) == s["joint_peak"],
            "Same-instant context sum differs")
    return {"summary": s, "contexts": contexts, "unclassified_sp_observations": 0, "whole_live_ram_peak_bytes": None}


def replay(folder):
    state = campaign(folder)
    require(state["mode"] == "message-continuous-step-stacks" and state["board_mac"] == "34:98:7a:a2:85:28" and
            state["independent_resets"] == 5 and state["separate_validation_resets"] == 1, "Incomplete planned reset set")
    output, previous = [], None
    for name, i, finite in [("validation", 1, True)] + [("captures", i, False) for i in range(1, 6)]:
        rows = raw_rows(folder / name / ("reset%d.jsonl" % i))
        boot, start, end = rows[0]["host_boot_id"], rows[0]["capture_started_monotonic_ns"], rows[-1]["clock_read_after_ns"]
        require(sum(r["line"].startswith("rst:0x") for r in rows) == 1 and start < end and
                (previous is None or previous[0] == boot and previous[1] < start), "Resets are not independent and ordered")
        previous = boot, end
        output.append({"validation": finite, "continuous_stack": decode([r["line"] for r in rows])})
    return {"replay": "pass", "independent_resets": 5, "separate_validation_resets": 1, "runs": output,
        "original_flash_restored": True, "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "scope": "separate byte and aggregate-counter implementation; native allocation semantics checked by the primary audit"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux": parser.error("Replay evidence on leon only")
    result = replay(args.directory)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("replay", "independent_resets", "separate_validation_resets")}))
