#!/usr/bin/env python3
"""Replay complete, unchanged Zephyr 3.7.0 latency/sys_kernel board suites."""
import argparse
import hashlib
import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen

BENCHMARKS = ("latency_measure", "sys_kernel")
UPSTREAM = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/tests/benchmarks/"
LATENCY = re.compile(r"^([\w.+]+)\s+-\s+(.+?)\s*:\s*(\d+) cycles\s*,\s*(\d+) ns\s*:\s*$")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_metrics(source, benchmark):
    if benchmark == "latency_measure":
        text = (source / "README.rst").read_text().split(
            "Sample output of the benchmark (with userspace enabled)")[0]
        return set(re.findall(r"^\s+([\w.+]+)\s+-.* cycles", text, re.M))
    return set(re.findall(r"^TEST CASE: (.+)$", (source / "README.txt").read_text(), re.M))


def parse_capture(path, benchmark, expected):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(not math.isfinite(t) or t < 0 for t in elapsed) or any(
            b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid capture timestamps")
    utc = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(t.utcoffset() is None for t in utc) or any(b < a for a, b in zip(utc, utc[1:])):
        raise ValueError("invalid UTC chronology")
    if sum("rst:0x" in line for line in lines) != 1 or sum(
            "*** Booting Zephyr OS build 3.7.0 ***" in line for line in lines) != 1:
        raise ValueError("missing independent reset/Zephyr version")
    if lines.count("PROJECT EXECUTION SUCCESSFUL") != 1 or lines[-1] != "PROJECT EXECUTION SUCCESSFUL":
        raise ValueError("incomplete original suite")
    if any(re.search(r"FAILED|PARTIAL|FATAL|PANIC|ASSERTION|Exception|Guru Meditation|Error:|timer tick happened", line)
           for line in lines):
        raise ValueError("failed original correctness/timing check")
    values, description = {}, {}
    if benchmark == "latency_measure":
        for line in lines:
            match = LATENCY.match(line)
            if match:
                tag, label, cycles, ns = match.groups()
                if tag in values:
                    raise ValueError("duplicate metric")
                cycles, ns = int(cycles), int(ns)
                if abs(ns - cycles * 1000 / 240) > 5:
                    raise ValueError("cycles/ns do not agree with 240-MHz timing")
                values[tag] = ns
                description[tag] = label
    else:
        current, successful = None, False
        for line in lines:
            if line.startswith("TEST CASE: "):
                if current is not None:
                    raise ValueError("unfinished test case")
                current, successful = line[11:], False
                if current in values:
                    raise ValueError("duplicate metric")
            elif line == "TEST RESULT: SUCCESSFUL":
                successful = True
            elif line.startswith("DETAILS: Average time for 1 iteration: "):
                match = re.fullmatch(r"DETAILS: Average time for 1 iteration: (\d+) nSec", line)
                if not match or current is None or not successful:
                    raise ValueError("unbound iteration result")
                values[current] = int(match.group(1))
            elif line == "END TEST CASE":
                if current not in values or not successful:
                    raise ValueError("test case lacks successful measurement")
                current = None
        if current is not None:
            raise ValueError("unfinished test case")
    if set(values) != expected:
        raise ValueError(("incomplete original metrics", sorted(expected - values.keys()), sorted(values.keys() - expected)))
    return {"values_ns": values, "description": description, "start_utc": utc[0].isoformat(),
            "end_utc": utc[-1].isoformat(), "uart_sha256": digest(path)}


def audit(directory, verify_upstream=False):
    source = directory / "source"
    benchmark = directory.name
    if benchmark not in BENCHMARKS:
        raise ValueError("unknown original benchmark")
    for line in (directory / "image.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = directory / name.lstrip("*")
        if not path.resolve().is_relative_to(directory.resolve()) or digest(path) != expected:
            raise ValueError(("source/image manifest mismatch", name))
    provenance_path = directory / "official-source.json"
    if verify_upstream:
        provenance = []
        for path in sorted(source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(source).as_posix()
                url = UPSTREAM + benchmark + "/" + relative
                with urlopen(url, timeout=30) as response:
                    official_sha = hashlib.sha256(response.read()).hexdigest()
                if digest(path) != official_sha:
                    raise ValueError(("not original upstream source", relative))
                provenance.append({"path": relative, "url": url, "sha256": official_sha})
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    provenance = json.loads(provenance_path.read_text())
    files = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    if len(provenance) != len(files) or {row["path"] for row in provenance} != files:
        raise ValueError("incomplete original-source provenance")
    for row in provenance:
        if row["url"] != UPSTREAM + benchmark + "/" + row["path"] or digest(source / row["path"]) != row["sha256"]:
            raise ValueError("changed original source/provenance")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_SYS_CLOCK_TICKS_PER_SEC=1",
                    "CONFIG_MP_MAX_NUM_CPUS=1"):
        if setting not in config:
            raise ValueError(("wrong native configuration", setting))
    if "CONFIG_SMP=y" in config or "CONFIG_USERSPACE=y" in config:
        raise ValueError("native kernel-only single-core profile changed")
    if benchmark == "latency_measure" and "CONFIG_BENCHMARK_NUM_ITERATIONS=1000" not in config:
        raise ValueError("original latency iteration count changed")
    compiler = (directory / "compiler.txt").read_text()
    if "13.2.0" not in compiler or "xtensa-esp-elf-gcc" not in compiler:
        raise ValueError("wrong compiler")
    commands = json.loads((directory / "compile_commands.json").read_text())
    compiled = {Path(row["file"]).name for row in commands if
                f"/tests/benchmarks/{benchmark}/src/" in row["file"]}
    if compiled != {p.name for p in (source / "src").glob("*.c")}:
        raise ValueError("original C sources absent from actual compile commands")
    flash = (directory / "flash.log").read_text()
    if "84:1f:e8:8f:55:dc" not in flash or "Hash of data verified." not in flash:
        raise ValueError("missing board/verified Flash binding")
    written = re.findall(r"Wrote (\d+) bytes .* at 0x00001000", flash)
    if written != [str((directory / "zephyr.bin").stat().st_size)]:
        raise ValueError("installed native image size/address mismatch")
    captures = [parse_capture(directory / f"reset{i}.jsonl", benchmark, expected_metrics(source, benchmark))
                for i in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
           for a, b in zip(captures, captures[1:])):
        raise ValueError("reset intervals overlap")
    metrics = {name: {"median_ns": statistics.median(values := [c["values_ns"][name] for c in captures]),
                      "range_ns": [min(values), max(values)], "resets_ns": values}
               for name in sorted(captures[0]["values_ns"])}
    return {"audit": "pass", "benchmark": benchmark, "os": "Zephyr 3.7.0", "resets": 3,
            "metric_count": len(metrics), "clock_mhz": 240, "tick_hz": 1, "cores": 1,
            "original_source_files": len(files), "ranking_eligible": False,
            "ranking_reason": "original native Zephyr suite; other OS ports not yet measured",
            "image_sha256": digest(directory / "zephyr.bin"), "flash_log_sha256": digest(directory / "flash.log"),
            "captures": captures, "metrics": metrics}


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
