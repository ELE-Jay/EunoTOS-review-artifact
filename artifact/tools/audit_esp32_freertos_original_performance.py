#!/usr/bin/env python3
"""Audit the original 1023-sample native FreeRTOS scheduling median."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.request import urlopen
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_iperf_original import ANSI

UPSTREAM = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/components/freertos/test_apps/freertos/"


def capture(path, elf_sha):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or any(
            not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid capture chronology")
    if sum("2nd stage bootloader" in line for line in lines) != 1 or sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
            sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or not any(
            "ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines):
        raise ValueError("missing native independent boot/frequency/ELF binding")
    if lines[-1] != "1 Tests 0 Failures 0 Ignored" or lines.count("Running scheduling time test...") != 1 or \
            not any(line.endswith(":scheduling time test:PASS") for line in lines) or any(
            re.search(r"Guru Meditation|panic|:FAIL|Assertion.*failed|Ignoring performance test|Brownout", line) for line in lines):
        raise ValueError("original correctness/performance check failed or incomplete")
    values = [int(m[1]) for line in lines if (m := re.fullmatch(r"\[Performance\]\[SCHEDULING_TIME\]: (\d+) cycles", line))]
    if len(values) != 1 or values[0] <= 0 or sum("(delta 0)" in line for line in lines) != 2:
        raise ValueError("missing original median or memory checks")
    return {"original_median_cycles": values[0], "microseconds": values[0] / 240,
            "start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "uart_sha256": digest(path),
            "reset_evidence": "native second-stage boot, app initialization and archived ELF fingerprint"}


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    source = directory / "source"
    files = {p.relative_to(source).as_posix(): p for p in source.rglob("*") if p.is_file() and p.name != "dependencies.lock"}
    provenance_path = directory / "official-source.json"
    if verify_upstream:
        records = []
        for relative, path in sorted(files.items()):
            with urlopen(UPSTREAM + relative, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(path):
                raise ValueError(("original test application changed", relative))
            records.append({"path": relative, "url": UPSTREAM + relative, "sha256": sha})
        provenance_path.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance_path.read_text())
    if len(records) != len(files) or {row["path"] for row in records} != set(files) or any(
            row["url"] != UPSTREAM + row["path"] or digest(files[row["path"]]) != row["sha256"] for row in records):
        raise ValueError("original-source provenance incomplete or changed")
    config = (directory / "config").read_text().splitlines()
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1000", "CONFIG_FREERTOS_UNICORE=y"} <= set(config) or \
            "CONFIG_UNITY_IGNORE_PERFORMANCE_TESTS=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("wrong original native profile/performance assertions disabled")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for name in ("test_freertos_scheduling_time.c", "test_freertos_main.c"):
        selected = [row for row in commands if Path(row["file"]).name == name]
        if len(selected) != 1 or "freertos-original-performance-source" not in selected[0]["file"]:
            raise ValueError("unchanged original native test/main not compiled")
    flash = (directory / "flash.log").read_text()
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or [
            (int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)
    ] != [((directory / name).stat().st_size, address) for name, address in
          (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("freertos_test.bin", 0x10000))]:
        raise ValueError("native Flash segments/board binding missing")
    captures = [capture(directory / f"reset{i}.jsonl", digest(directory / "freertos_test.elf")) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent reset windows overlap")
    return {"audit": "pass", "os": "FreeRTOS/ESP-IDF 5.2.5", "benchmark": "scheduling time test",
            "original_samples_per_reset": 1023, "original_statistic": "median", "resets": 3,
            "captures": captures, "source_files": len(files), "configured_clock_mhz": 240, "cores": 1,
            "tick_hz": 1000, "ranking_eligible": False,
            "ranking_reason": "different original method/statistic/profile from Zephyr averages; other matching ports unmeasured",
            "binary_sha256": digest(directory / "freertos_test.bin")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
