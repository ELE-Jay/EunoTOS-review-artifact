#!/usr/bin/env python3
"""Inspect vendor-ignored ISR diagnostics without disabling original assertions."""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re
from audit_esp32_report import ROOT, audit_flash
from audit_esp32_freertos_original_performance import audit as original_app
from audit_esp32_riot_original import digest
from audit_esp32_iperf_original import ANSI


def capture(path, name, elf_sha):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [float(row["elapsed_s"]) for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid acquisition chronology")
    if sum("2nd stage bootloader" in line for line in lines) != 1 or sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
            sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or not any(
            "ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines):
        raise ValueError("missing original-image independent reboot/frequency binding")
    if lines.count("Running " + name + "...") != 1:
        raise ValueError("wrong original case selection")
    outcome = re.fullmatch(r"1 Tests ([01]) Failures ([01]) Ignored", lines[-1])
    if outcome is None or outcome[2] != "0" or any(re.search(
            r"Guru Meditation|panic|Brownout|Ignoring performance test", line) for line in lines):
        raise ValueError("incomplete original diagnostic or disabled performance assertions")
    values = {}
    for label in ("ISR_ENTER_CYCLES", "ISR_EXIT_CYCLES"):
        selected = [int(m[1]) for line in lines if (m := re.fullmatch(r"\[Performance\]\[" + label + r"\]: (\d+) cycles", line))]
        if len(selected) > 1:
            raise ValueError("duplicate original average")
        values[label] = selected[0] if selected else None
    failed = int(outcome[1]) != 0
    heap_checks = []
    for line in lines:
        m = re.fullmatch(r"MALLOC_CAP_(8BIT|32BIT): Before (\d+) bytes free, After (\d+) bytes free \(delta (-?\d+)\)", line)
        if m:
            before, after, delta = map(int, m.groups()[1:])
            if after - before != delta:
                raise ValueError("native memory-check arithmetic does not reproduce")
            heap_checks.append({"capability": m[1], "before_free_bytes": before, "after_free_bytes": after, "delta_free_bytes": delta})
    if not failed and (None in values.values() or [row["capability"] for row in heap_checks] != ["8BIT", "32BIT"] or
                       not any(line.endswith(":" + name + ":PASS") for line in lines)):
        raise ValueError("passing outcome lacks original averages/memory checks")
    errors = [line for line in lines if ":FAIL" in line]
    if failed and not errors:
        raise ValueError("failing original outcome has no failure record")
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "uart_sha256": digest(path),
            "original_average_cycles": values, "original_unity_pass": not failed,
            "native_heap_checks": heap_checks,
            "native_failure_records": errors, "measurement_eligible": False,
            "reason": "vendor-ignored source; uninitialized yield flag, unreleased semaphores and trigger semantics require a corrected original-method port"}


def audit(directory):
    reference = directory / "reference"
    original_app(reference)
    archived = ROOT / "artifacts/reports/freertos-original-performance-v1"
    for name in ("freertos_test.elf", "freertos_test.bin", "bootloader.bin", "partition-table.bin", "config"):
        if (reference / name).read_bytes() != (archived / name).read_bytes():
            raise ValueError("native diagnostic differs from unchanged original application")
    commands = json.loads((reference / "compile_commands.json").read_text())
    selected = [row for row in commands if Path(row["file"]).name == "test_isr_latency.c"]
    if len(selected) != 1 or "freertos-original-performance-source/performance/" not in selected[0]["file"]:
        raise ValueError("original ignored ISR source not compiled")
    audit_flash(directory, "flash.log", 3)
    written = re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())
    if [(int(size), int(address, 16)) for size, address in written] != [
            ((reference / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("freertos_test.bin", 0x10000))]:
        raise ValueError("installed diagnostic image differs from archived segments")
    groups = {}
    for case, suffix in (("no-parameter", "no parameter"), ("parameter", "parameter")):
        name = "isr latency test vport-yield-from-isr with " + suffix
        runs = [capture(directory / case / f"reset{i}.jsonl", name, digest(reference / "freertos_test.elf")) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
            raise ValueError("diagnostic independent resets overlap")
        groups[case] = runs
    if groups["no-parameter"][-1]["end_utc"] >= groups["parameter"][0]["start_utc"]:
        raise ValueError("case windows overlap")
    return {"audit": "pass", "diagnostic_boot_captures": 6, "groups": groups,
            "original_samples_per_case": 10000, "original_statistic": "arithmetic average rounded to integer cycles",
            "measurement_eligible": False, "ranking_eligible": False,
            "boundary": "CPU software-interrupt trigger to ISR; ISR tail to continuing triggering task, not GPIO-entry or blocked-task wake",
            "source_issues": ["vendor [ignore] tags preserved", "higher-priority-woken local is not initialized before GiveFromISR",
                              "original source does not delete the two created semaphores"],
            "binary_sha256": digest(reference / "freertos_test.bin")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
