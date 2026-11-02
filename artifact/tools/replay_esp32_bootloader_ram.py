#!/usr/bin/env python3
"""Separate stdlib replay of boot-stage UART fields and original heap history."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from replay_esp32_followup import campaign, raw_rows, require
from replay_esp32_freertos_message import history


def boot_rows(lines):
    found = []
    expected = {"phase", "entry_sp", "low", "paint_end", "painted", "verified", "sp", "spare", "touched", "invalid", "guard", "stages"}
    for line in lines:
        if not line.startswith("BOOT_RAM "):
            continue
        pairs = [word.split("=", 1) for word in line.split()[1:]]
        require(len(pairs) == len(expected) and {p[0] for p in pairs} == expected, "Boot field inventory differs")
        r = {key: int(value) for key, value in pairs}
        require(r["phase"] == len(found) and r["invalid"] == 0 and r["stages"] == 2 and r["guard"] == 64 and
                r["low"] == 0x3ffe0440 and r["low"] + 64 < r["entry_sp"] <= 0x3ffe3f20 and r["entry_sp"] % 16 == 0,
                "Boot phase/state differs")
        require(r["low"] <= r["sp"] < r["entry_sp"] and r["paint_end"] + 64 == r["entry_sp"] and
                r["painted"] == r["verified"] == r["paint_end"] - r["low"] and
                0 <= r["spare"] <= r["painted"] and 0 <= r["touched"] <= r["painted"] and
                r["spare"] + r["touched"] == r["painted"] and r["touched"] % 4 == r["spare"] % 4 == 0,
                "Boot marked-range arithmetic differs")
        found.append(r)
    require(len(found) == 2 and found[1]["touched"] >= found[0]["touched"], "Boot cumulative phases differ")
    return found


def handoff_row(lines, address):
    markers = [s for s in lines if s.startswith("FREERTOS_BOOT_HANDOFF ")]
    require(len(markers) == 1, "Boot handoff count differs")
    pairs = [word.split("=", 1) for word in markers[0].split()[1:]]
    names = {"source", "entry_sp", "low", "paint_end", "painted", "verified", "app_sp", "spare", "touched", "invalid", "guard", "stages"}
    require(len(pairs) == len(names) and {p[0] for p in pairs} == names, "Boot handoff fields differ")
    r = {k: int(v) for k, v in pairs}
    prior = boot_rows(lines)[1]
    require(all(r[k] == prior[k] for k in ("entry_sp", "low", "paint_end", "painted", "verified", "guard", "stages")),
            "Boot state changed between stages")
    require(r["source"] == address and r["invalid"] == 0 and r["app_sp"] % 16 == 0 and
            r["low"] + 64 < r["app_sp"] <= 0x3ffe3f20 and 0 <= r["spare"] <= r["painted"] and
            prior["touched"] <= r["touched"] <= r["painted"] and r["spare"] + r["touched"] == r["painted"] and
            r["spare"] % 4 == r["touched"] % 4 == 0, "Boot handoff arithmetic differs")
    return r


def replay(folder):
    state = campaign(folder)
    require(state["mode"] == "boot-stage-ram" and state["board_mac"] == "34:98:7a:a2:85:28" and
            state["independent_resets"] == 5, "Incomplete boot-stage capture")
    previous, runs = None, []
    for index in range(1, 6):
        rows = raw_rows(folder / "captures" / ("reset%d.jsonl" % index))
        lines = [r["line"] for r in rows]
        start, end = (datetime.fromisoformat(rows[i]["utc"]) for i in (0, -1))
        require(start < end and (previous is None or previous < start), "Reset chronology overlaps")
        previous = end
        require(sum(s.startswith("rst:0x") for s in lines) == 1 and
                lines.count("Thread-Metric queue self-check PASS") == 1 and
                not re.search(r"panic|abort|Guru Meditation|Exception|ASSERT|FATAL|watchdog", "\n".join(lines), re.I),
                "Original boot or workload validation differs")
        boot = boot_rows(lines)
        values = history(lines)
        totals = [int(m[1]) for s in lines if (m := re.fullmatch(r"Time Period Total:\s*(\d+)", s))]
        require(len(totals) == 3 and min(totals) > 0 and lines[-1] ==
                "TM_RAM END events=%d invalid=0 original_reports=3" % values["events"], "Original reports incomplete")
        runs.append({"boot_stages": boot, "events": values["events"], "heap_peak_bytes": values["heap_peak_bytes"],
            "heap_final_bytes": values["heap_final_bytes"], "original_counts": totals})
    return {"replay": "pass", "independent_resets": 5, "runs": runs, "original_flash_restored": True,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = replay(args.campaign)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
