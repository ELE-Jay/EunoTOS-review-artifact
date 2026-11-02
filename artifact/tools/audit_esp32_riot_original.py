#!/usr/bin/env python3
"""Replay RIOT original benchmarks, preserving optimized-away invalid metrics."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import statistics
from datetime import datetime
from urllib.request import urlopen

REVISION = "dd06b3727c41c2c44bf93f47ff7831fdd501d68b"
UPSTREAM = f"https://raw.githubusercontent.com/RIOT-OS/RIOT/{REVISION}/"
CASES = ("runtime_coreapis", "msg_pingpong", "thread_yield_pingpong", "mutex_pingpong", "thread_flags_pingpong")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest(directory, name):
    for line in (directory / name).read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        path = (directory / relative.lstrip("*")).resolve()
        if not path.is_relative_to(directory.resolve()) or digest(path) != expected:
            raise ValueError(("manifest mismatch", relative))


def capture(path, case, expected):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(
            b < a for a, b in zip(times, times[1:])) or any(
            not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid capture chronology")
    if sum("rst:0x" in line for line in lines) != 1 or lines.count("START") != 1 or lines.count(
            "main(): This is RIOT! (Version: 2024.10-devel)") != 1 or lines.count("Single core mode") != 1:
        raise ValueError("missing native reset/version/interactive start")
    if any(re.search(r"Guru Meditation|panic|Assertion.*failed|FAILED|Exception", line) for line in lines):
        raise ValueError("native failure")
    values = {}
    if case == "runtime_coreapis":
        if lines[-1] != "[SUCCESS]" or lines.count("[SUCCESS]") != 1:
            raise ValueError("incomplete original suite")
        for line in lines:
            match = re.fullmatch(r"\s*(.+?):\s*(\d+)us\s+---\s+(\d+\.\d{3})us per call\s+---\s+(\d+) calls per sec", line)
            if match:
                name, total, average, rate = match.groups()
                name = name.strip()
                total = int(total)
                if name in values or total <= 0 or int(round(float(average) * 1000)) != total // 1000 or \
                        int(rate) != (1000000000000 // total) & 0xffffffff:
                    raise ValueError("original runtime arithmetic/duplicate mismatch")
                # The original inline repeated initialization is one store after optimization.
                valid = name != "mutex_init()"
                values[name] = {"total_us": total, "displayed_us_per_call": average,
                    "raw_calls_per_second": int(rate), "measurement_eligible": valid,
                    "reason": "original elapsed-time loop" if valid else
                    "repeated inline initialization optimized away; original uint32 rate wraps"}
        if set(values) != expected:
            raise ValueError("missing/extra original runtime metric")
    else:
        result = json.loads(lines[-1])
        if set(result) != {"result", "ticks"} or any(type(v) is not int or v <= 0 for v in result.values()) or \
                result["ticks"] != 240000000 // result["result"]:
            raise ValueError("original duration/count/ticks arithmetic mismatch")
        if elapsed[-1] - next(row["elapsed_s"] for row in rows if row["line"] == "main starting") < 0.95:
            raise ValueError("original one-second window shortened")
        values[case] = {"original_count": result["result"], "original_ticks": result["ticks"],
                        "duration_us": 1000000, "measurement_eligible": True,
                        "reason": "original whole ping-pong iteration, not an isolated API latency"}
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "uart_sha256": digest(path), "metrics": values}


def audit(directory, verify_upstream=False):
    case = directory.name
    if case not in CASES:
        raise ValueError("unsupported original RIOT benchmark")
    check_manifest(directory, "image.sha256")
    originals = {p.relative_to(directory).as_posix(): "tests/bench/" + case + "/" + p.relative_to(
        directory / "source").as_posix() for p in (directory / "source").rglob("*") if p.is_file()}
    originals.update({"benchmark.h": "sys/include/benchmark.h", "benchmark.c": "sys/benchmark/benchmark.c",
                      "Makefile.bench_common": "tests/bench/Makefile.bench_common"})
    provenance_path = directory / "official-source.json"
    if verify_upstream:
        provenance = []
        for relative, official in sorted(originals.items()):
            with urlopen(UPSTREAM + official, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / relative) != sha:
                raise ValueError(("original source differs", relative))
            provenance.append({"path": relative, "url": UPSTREAM + official, "sha256": sha})
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    provenance = json.loads(provenance_path.read_text())
    if len(provenance) != len(originals) or {row["path"] for row in provenance} != set(originals):
        raise ValueError("incomplete upstream source proof")
    for row in provenance:
        if row["url"] != UPSTREAM + originals[row["path"]] or digest(directory / row["path"]) != row["sha256"]:
            raise ValueError("changed source/provenance")
    config = (directory / "config.h").read_text()
    if "#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240 1" not in config or \
            "#define CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE 1" not in config or \
            "12.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("wrong native clock/core/compiler profile")
    reproduction = directory / "reproduction"
    check_manifest(reproduction, "reproduction.sha256")
    if (directory / "application.bin").read_bytes() != (reproduction / "application.bin").read_bytes() or \
            (reproduction / "measured-stripped.elf").read_bytes() != (reproduction / "rebuilt-stripped.elf").read_bytes():
        raise ValueError("measured BIN/debug-stripped ELF does not reproduce")
    commands = [shlex.split(line) for line in (reproduction / "build.log").read_text().replace(
        "\\\n", " ").splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line and
        f"/tests/bench/{case}/main.c" in line]
    if len(commands) != 1 or any("-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1" not in command or
            "-Os" not in command or any(re.match(r"-D(?:BENCH_RUNS|TEST_DURATION)", value) for value in command)
            for command in commands):
        raise ValueError("original compile conditions missing/altered")
    flash = (directory / "flash.log").read_text()
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or [
            (int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)
    ] != [((directory / name).stat().st_size, address) for name, address in
          (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native Flash/MAC binding missing")
    expected = set(re.findall(r'BENCHMARK_FUNC\("([^"]+)"', (directory / "source/main.c").read_text()))
    captures = [capture(directory / f"reset{i}.jsonl", case, expected) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent reset intervals overlap")
    metrics = {}
    for name in captures[0]["metrics"]:
        values = [row["metrics"][name] for row in captures]
        valid = all(row["measurement_eligible"] for row in values)
        field = "total_us" if case == "runtime_coreapis" else "original_count"
        raw = [row[field] for row in values]
        metrics[name] = {"measurement_eligible": valid, "raw_resets": values,
                         "median_" + field: statistics.median(raw) if valid else None,
                         "range_" + field: [min(raw), max(raw)] if valid else None}
    return {"audit": "pass", "benchmark": case, "os": "RIOT 2024.10-devel", "revision": REVISION,
            "cores": 1, "configured_clock_mhz": 240, "compiler": "GCC12.2", "resets": 3,
            "source_files": len(originals), "metric_count": len(metrics), "metrics": metrics,
            "captures": captures, "ranking_eligible": False,
            "ranking_reason": "different original benchmark/API semantics; other OS ports unmeasured",
            "binary_sha256": digest(directory / "application.bin"),
            "reproduction_scope": "BIN and debug-stripped ELF byte-identical; unstripped DWARF can differ"}


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
