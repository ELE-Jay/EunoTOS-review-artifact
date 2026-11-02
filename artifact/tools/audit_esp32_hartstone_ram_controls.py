#!/usr/bin/env python3
"""Replay calibration controls as diagnostics, never benchmark scores."""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re
import shlex
import statistics
from audit_esp32_report import ROOT, audit_flash, audit_image_manifest
from audit_esp32_riot_original import digest

CAL = re.compile(r"HARTSTONE PH CAL status=PASS workload_kwi=10000 elapsed_us=(\d+) kwips=(\d+) clock_hz=240000000")
CLOCK = "BENCH_RAM lifecycle clock cpu_mhz=240 source=1 source_freq_mhz=480 div=2"


def prefix(path, mode=None, early=False, lifecycle=False):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [float(row["elapsed_s"]) for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid diagnostic acquisition chronology")
    if sum("rst:0x" in line for line in lines) != 1 or any(re.search(
            r"Guru Meditation|panic|ASSERT|Exception|task_wdt|HARTSTONE .*FAIL", line) for line in lines):
        raise ValueError("missing single native reboot or native failure")
    boot = "HARTSTONE PH SERIES boot target=ESP32 os=FreeRTOS experiment=4"
    timer = "HARTSTONE PH TIMER backend=ESP_TIMER quantum_us=10 callback=TASK"
    matches = [(i, m) for i, line in enumerate(lines) if (m := CAL.fullmatch(line))]
    if lines.count(boot) != 1 or lines.count(timer) != 1 or len(matches) != 1 or matches[0][0] != len(lines) - 1 or \
            not lines.index(boot) < lines.index(timer) < matches[0][0] or any("HARTSTONE PH TRIAL " in line for line in lines):
        raise ValueError("not a complete original calibration-only prefix")
    us, kwips = map(int, matches[0][1].groups())
    if us <= 0 or kwips != 10000000000 // us:
        raise ValueError("original calibration arithmetic does not reproduce")
    counters = None
    if lifecycle or early:
        if lines.count(CLOCK) != 1 or lines.index(CLOCK) >= lines.index(boot):
            raise ValueError("missing actual clock-register witness")
    if mode is not None:
        tag = "RAM_EARLY_CONTROL" if early else "RAM_CONTROL"
        selected = f"{tag} selected enabled={mode}" + ("" if early else " cpu_mhz=240")
        if mode not in (0, 1) or lines.count(selected) != 1 or lines.count(f"{tag} ready select=0/1") != 1:
            raise ValueError("wrong runtime selection")
        before = [int(m[1]) for line in lines if (m := re.fullmatch(
            r"BENCH_RAM lifecycle sample phase=application-start occupied=\d+ peak=\d+ observations=(\d+)" if early else
            r"RAM_CONTROL before-calibration observations=(\d+)", line))]
        after = [int(m[1]) for line in lines if (m := re.fullmatch(tag + r" after-calibration observations=(\d+)", line))]
        if len(before) != 1 or before != after:
            raise ValueError("observer performed counted work inside the calibration")
        if not early and before != [mode]:
            raise ValueError("unexpected runtime initial observation count")
        if early and before[0] < 1:
            raise ValueError("missing application-start observation")
        counters = {"before": before[0], "after": after[0]}
    return {"uart_sha256": digest(path), "start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "elapsed_us": us, "raw_kwips": kwips, "mode": mode, "observation_counts": counters,
            "benchmark_score_eligible": False}


def image(directory, component=None):
    required = {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "series.c", "small_whetstone.c"}
    if component:
        required |= {"compile_commands.json", "compiler.txt", "base-observer.c", "freertos.c",
                     "observer-CMakeLists.txt", "observer-app-CMakeLists.txt", "FreeRTOSConfig.h", "FreeRTOSConfig-stock.h"}
        if component != "hartstone_lifecycle_control":
            required.add("lifecycle-observer.c")
        if component.endswith("_iram"):
            required |= {"observer-linker.lf", "symbols.txt"}
    audit_image_manifest(directory, required)
    reference = ROOT / "artifacts/reports/hartstone-native-us-fifo-v1/freertos/ph4"
    for name in ("config", "series.c", "small_whetstone.c"):
        if (directory / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError(("original workload/profile changed", name))
    if component:
        observer = ROOT / "firmware/bsp/esp32/resource_census"
        bindings = [("base-observer.c", observer / "freertos.c"),
                    ("freertos.c", observer / component / "freertos.c"),
                    ("observer-CMakeLists.txt", observer / component / "CMakeLists.txt"),
                    ("observer-app-CMakeLists.txt", observer / component / "app/CMakeLists.txt")]
        if component != "hartstone_lifecycle_control":
            bindings.append(("lifecycle-observer.c", observer / "hartstone_lifecycle/freertos.c"))
        if component.endswith("_iram"):
            bindings.append(("observer-linker.lf", observer / component / "linker.lf"))
        for name, reviewed in bindings:
            if (directory / name).read_bytes() != reviewed.read_bytes():
                raise ValueError(("unreviewed diagnostic source", name))
        for name in ("FreeRTOSConfig.h", "FreeRTOSConfig-stock.h"):
            if (directory / name).read_bytes() != (reference / name).read_bytes():
                raise ValueError("native scheduler control changed")
        if "13.2.0" not in (directory / "compiler.txt").read_text():
            raise ValueError("compiler changed")
        commands = json.loads((directory / "compile_commands.json").read_text())
        for name in ("series.c", "small_whetstone.c"):
            selected = [row for row in commands if Path(row["file"]).name == name and "/hartstone_freertos/main/" in row["file"]]
            if len(selected) != 1:
                raise ValueError("missing original compilation")
            flags = shlex.split(selected[0]["command"])
            if [arg for arg in flags if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or not {
                    "-DPH_EXPERIMENT=4", "-DPH_HIGH_RES=1", "-fno-fast-math", "-ffp-contract=off"} <= set(flags):
                raise ValueError("original compiler semantics changed")
    return {"elf_sha256": digest(directory / "application.elf"), "binary_sha256": digest(directory / "application.bin")}


def flashed(directory, name):
    audit_flash(directory, name, 3)
    written = re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", (directory / name).read_text())
    expected = [(str((directory / file).stat().st_size), hex(offset)) for file, offset in
                (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]
    if [(size, hex(int(addr, 16))) for size, addr in written] != expected:
        raise ValueError("verified written segments do not bind the archived images")


def summarize(rows):
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(rows, rows[1:])):
        raise ValueError("diagnostic independent reset windows overlap")
    values = [row["elapsed_us"] for row in rows]
    return {"captures": rows, "median_elapsed_us": statistics.median(values),
            "range_elapsed_us": [min(values), max(values)]}


def audit():
    evidence = ROOT / "artifacts/reports"
    paired = evidence / "ram-hartstone-lifecycle-controls-v1"
    pairs, chronological = {}, []
    for variant in ("reference", "observed"):
        directory = paired / variant
        binding = image(directory)
        source = evidence / ("hartstone-native-us-fifo-v1/freertos/ph4" if variant == "reference" else "ram-hartstone-lifecycle-v2/freertos/ph4")
        for target, original in (("application.elf", "iotosbench_esp32_hartstone.elf" if variant == "reference" else "application.elf"),
                                 ("application.bin", "iotosbench_esp32_hartstone.bin" if variant == "reference" else "application.bin"),
                                 ("bootloader.bin", "bootloader.bin"),
                                 ("partitions.bin", "partition-table.bin" if variant == "reference" else "partitions.bin")):
            if (directory / target).read_bytes() != (source / original).read_bytes():
                raise ValueError("interleaved control not the archived original image")
        rows = []
        for run in (1, 2, 3):
            flashed(directory, f"flash-{run}.log")
            rows.append(prefix(directory / f"reset{run}.jsonl", lifecycle=variant == "observed"))
        pairs[variant] = {**binding, **summarize(rows)}
    for run in range(3):
        chronological.extend(pairs[variant]["captures"][run] for variant in ("reference", "observed"))
    summarize(chronological)
    groups = {"interleaved_archived_images": pairs}
    for name, cohort, component, early in (
            ("runtime_counting", "ram-hartstone-runtime-control-v1", "hartstone_lifecycle_control", False),
            ("early_counting", "ram-hartstone-early-control-v1", "hartstone_lifecycle_early_control", True)):
        directory = evidence / cohort / "freertos/ph4"
        binding = image(directory, component)
        flashed(directory, "flash.log")
        modes, chronological = {}, []
        for mode in (0, 1):
            rows = [prefix(directory / f"mode{mode}-reset{run}.jsonl", mode, early) for run in (1, 2, 3)]
            modes[str(mode)] = summarize(rows)
        for run in range(3):
            chronological.extend(modes[str(mode)]["captures"][run] for mode in (0, 1))
        summarize(chronological)
        groups[name] = {**binding, "modes": modes, "same_image": True}
    directory = evidence / "ram-hartstone-iram-control-v1/freertos/ph4"
    binding = image(directory, "hartstone_lifecycle_iram")
    flashed(directory, "calibration-flash.log")
    symbols = (directory / "symbols.txt").read_text()
    for name in ("__wrap_app_main", "__wrap_fputs", "__wrap_heap_caps_init", "__wrap_multi_heap_malloc"):
        entries = re.findall(r"^([0-9a-f]+) [0-9a-f]+ T " + name + r"$", symbols, re.M)
        if len(entries) != 1 or not 0x40080000 <= int(entries[0], 16) < 0x400a0000:
            raise ValueError("observer placement is not native instruction RAM")
    rows = [prefix(directory / f"calibration-reset{run}.jsonl", lifecycle=True) for run in (1, 2, 3)]
    groups["observer_in_iram"] = {**binding, **summarize(rows)}
    return {"audit": "pass", "diagnostic_prefix_captures": 21, "groups": groups,
            "benchmark_score_eligible": False, "reference_workload_ram_completed": False,
            "conclusion": "counting toggles do not explain the calibration change; IRAM placement restores the fast calibration",
            "unresolved": "specific cache/layout mechanism and complete instrumented workload coverage"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
