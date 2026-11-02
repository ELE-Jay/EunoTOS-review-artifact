#!/usr/bin/env python3
"""Replay original Rhealstone arithmetic; preserve invalid negative results."""
import argparse
import hashlib
import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "artifacts/source_snapshots/rhealstone-rtems-acb78c0"
CASES = {
    "taskswitch": ("RHTASKSWITCH", "Task switch", 99999, (2, 0, 1)),
    "taskpreempt": ("RHTASKPREEMPT", "Task Preempt", 49999, (2, 0, 1)),
    "semshuffle": ("RHSEMSHUFFLE", "Semaphore Shuffle", 100000, (1, 0, None)),
    "mlatency": ("RHMLATENCY", "Intertask Message Latency", 49999, (2, 0, 1)),
    "deadlockbrk": ("RHDEADLOCKBRK", "Deadlock Break", 20000, (2, 1, 0)),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def original_formula(values, count, indices):
    total, loop, overhead = indices
    raw = ((((values[total] - values[loop]) & 0xffffffff) // count) -
           (values[overhead] if overhead is not None else 0)) & 0xffffffff
    return raw if raw < 0x80000000 else raw - 0x100000000


def audit_capture(path, case, os="FreeRTOS", tick=100):
    name, label, count, indices = CASES[case]
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    marker = f"RHEALSTONE BEGIN {name} {os} clock=240 cores=1 tick={tick} timer=ccount unit=cycles"
    if lines.count(marker) != 1 or lines.count("RHEALSTONE END") != 1 or lines[-1] != "RHEALSTONE END":
        raise ValueError("missing original case/native completion")
    if sum("rst:0x" in line for line in lines) != 1 or any(re.search(
            r"RHEALSTONE FAIL|Guru Meditation|panic|ASSERT|Exception|task_wdt", line) for line in lines):
        raise ValueError("reset/native error")
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("invalid UTC chronology")
    elapsed = [float(row["elapsed_s"]) for row in rows]
    if any(not math.isfinite(t) or t < 0 for t in elapsed) or any(
            b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid acquisition chronology")
    measured = [int(match.group(1)) for line in lines if (match := re.fullmatch(
        r"Rhealstone: " + re.escape(label) + r" - (-?\d+)", line))]
    diagnostic = [line for line in lines if line.startswith("RHEALSTONE TIMER_READS ")]
    if len(measured) != 1 or len(diagnostic) != 1:
        raise ValueError("missing original result/timer inputs")
    match = re.fullmatch(r"RHEALSTONE TIMER_READS count=(\d+)((?: value\d+=\d+)+)", diagnostic[0])
    if not match:
        raise ValueError("malformed timer trace")
    reads = [(int(i), int(v)) for i, v in re.findall(r"value(\d+)=(\d+)", match.group(2))]
    n = 2 if case == "semshuffle" else 3
    if int(match.group(1)) != n or [i for i, _ in reads] != list(range(n)):
        raise ValueError("wrong timer trace length/order")
    values = [v for _, v in reads]
    if any(v < 0 or v > 0xffffffff for v in values) or original_formula(values, count, indices) != measured[0]:
        raise ValueError("original arithmetic does not reproduce")
    total, loop, _ = indices
    valid = measured[0] > 0 and values[total] > values[loop]
    reason = "positive original calculation"
    if values[total] <= values[loop]:
        reason = "measured duration does not exceed baseline; original unsigned subtraction wraps or is zero; no score"
    elif measured[0] <= 0:
        reason = "original overhead subtraction gives nonpositive latency; no clamping or score"
    return {"raw_original_cycles": measured[0], "timer_reads_cycles": values,
            "original_iterations": count, "measurement_eligible": valid,
            "measurement_reason": reason,
            "start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "uart_sha256": digest(path)}


def audit(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "freertos":
        raise ValueError("unsupported native port/case")
    for line in (directory / "image.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = directory / name.lstrip("*")
        if not path.resolve().is_relative_to(directory.resolve()) or digest(path) != expected:
            raise ValueError(("manifest mismatch", name))
    for name in (case + ".c", "timesys.h"):
        if (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError(("original source/formula altered", name))
    if (directory / "port.c").read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/freertos/port.c").read_bytes():
        raise ValueError("native adapter is not the inspected diagnostic port")
    for name in ("tmacros.h", "rtems/btimer.h", "rtems/confdefs.h"):
        if (directory / "include" / name).read_bytes() != (
                ROOT / "firmware/bsp/esp32/rhealstone/include" / name).read_bytes():
            raise ValueError(("native API contract altered", name))
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_UNICORE=y", "CONFIG_FREERTOS_HZ=100"):
        if setting not in config:
            raise ValueError(("native configuration mismatch", setting))
    header = (directory / "FreeRTOSConfig.h").read_text()
    if not re.search(r"#define configUSE_PREEMPTION\s+1", header) or not re.search(
            r"#define configUSE_TIME_SLICING\s+0", header):
        raise ValueError("native scheduler mismatch")
    commands = json.loads((directory / "compile_commands.json").read_text())
    applications = [row for row in commands if Path(row["file"]).name == case + ".c"]
    if len(applications) != 1 or "rhealstone-original" not in applications[0]["file"]:
        raise ValueError("original body absent from compile commands")
    if "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("wrong compiler")
    flash = (directory / "flash.log").read_text()
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3:
        raise ValueError("missing board/three verified Flash segments")
    sizes = re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)
    if [(int(size), int(address, 16)) for size, address in sizes] != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("rhealstone.bin", 0x10000))]:
        raise ValueError("written segments do not bind archived images")
    captures = [audit_capture(directory / f"reset{i}.jsonl", case) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("reset intervals overlap")
    values = [row["raw_original_cycles"] for row in captures]
    valid = all(row["measurement_eligible"] for row in captures)
    return {"audit": "pass", "case": case, "os": "FreeRTOS/ESP-IDF 5.2.5", "resets": 3,
            "original_revision": "RTEMS acb78c0c8c76f4ae12c60b729948e541c1e3930c",
            "raw_original_cycles": values, "measurement_eligible": valid,
            "median_us": statistics.median(values) / 240 if valid else None,
            "range_us": [min(values) / 240, max(values) / 240] if valid else None,
            "ranking_eligible": False,
            "ranking_reason": "native mutex/overhead calibration and unmatched native profiles require semantic review",
            "captures": captures, "binary_sha256": digest(directory / "rhealstone.bin")}


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
