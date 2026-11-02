#!/usr/bin/env python3
"""Replay all retained raw UART pairs; this is evidence validation, not a metric."""
import argparse
import json
from pathlib import Path
from audit_esp32_report import ROOT
from audit_esp32_riot_original import digest
from audit_esp32_zephyr_thread import read_raw_capture, check_uart_chronology


def audit(directory=ROOT / "artifacts/reports", *, manifest=None):
    checked, legacy, skipped = [], [], 0
    paths = sorted(directory.rglob("*.jsonl"))
    if manifest is not None:
        snapshot = json.loads(manifest.read_text())
        entries = snapshot["captures"] + snapshot["clock_only_legacy_captures"]
        paths = sorted(directory / r["path"] for r in entries)
        if len(set(paths)) != len(paths):
            raise ValueError("Duplicate raw UART snapshot entry")
        for row in entries:
            path = directory / row["path"]
            if not path.resolve().is_relative_to(directory.resolve()) or digest(path) != row["uart_sha256"] or \
                    digest(path.with_suffix(".raw")) != row["raw_sha256"]:
                raise ValueError("Historical raw UART snapshot changed: " + row["path"])
    for path in paths:
        raw = path.with_suffix(".raw")
        if not raw.is_file(): continue
        first = path.read_text().splitlines()
        if not first:
            raise ValueError("empty raw capture: " + str(path))
        rows = [json.loads(line) for line in first]
        if not all({"line", "utc", "elapsed_s"} <= row.keys() for row in rows):
            if any({"line", "utc", "elapsed_s", "raw_bytes", "raw_sha256"} & row.keys() for row in rows):
                raise ValueError("partial raw capture schema: " + str(path))
            skipped += 1
            continue
        evidence = {"path": str(path.relative_to(directory)), "uart_sha256": digest(path), "raw_sha256": digest(raw)}
        if not any("raw_bytes" in row or "raw_sha256" in row for row in rows):
            check_uart_chronology(rows)
            legacy.append({**evidence, "per_line_byte_binding_verified": False})
            continue
        read_raw_capture(path.parent, "", prefix=path.stem)
        checked.append(evidence)
    if not checked:
        raise ValueError("no raw UART evidence pairs found")
    return {"audit": "pass", "checked_raw_uart_files": len(checked), "checked_legacy_uart_clock_files": len(legacy),
        "unsupported_raw_pair_schemas_skipped": skipped,
        "per_row_utc_monotonic_tolerance_s": 0.1, "new_board_boots": 0, "new_metric_created": False,
        "captures": checked, "clock_only_legacy_captures": legacy}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "artifacts/reports")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output: args.output.write_text(content)
    else: print(content, end="")
