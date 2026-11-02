#!/usr/bin/env python3
"""Replay separate lifecycle RAM observations, never Hartstone speed scores."""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re
import shlex
import statistics
from audit_esp32_report import audit_image_manifest, ROOT
from audit_esp32_resources import audit_cell
from audit_esp32_ram_census import region_accounting
from audit_esp32_hartstone_series import audit as hartstone
from audit_esp32_riot_original import digest


def capture(path, sections):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or any(
            not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid lifecycle chronology")
    if lines.count("BENCH_RAM lifecycle clock cpu_mhz=240 source=1 source_freq_mhz=480 div=2") != 1:
        raise ValueError("missing actual native clock-register witness")
    starts = [(i, m) for i, line in enumerate(lines) if (m := re.fullmatch(
        r"BENCH_RAM lifecycle begin os=FreeRTOS family=native-multi-heap window=heap-ready-through-first-loss initialized=1 initial_occupied=(\d+)", line))]
    if len(starts) != 1 or lines[-1] != "BENCH_RAM lifecycle complete":
        raise ValueError("missing initialized lifecycle start or complete endpoint")
    regions = [tuple(map(int, m.groups())) for line in lines if
               (m := re.fullmatch(r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if len(regions) != 6:
        raise ValueError("missing native registered heap regions")
    capacity = region_accounting(sections, regions, False)
    pattern = re.compile(r"BENCH_RAM lifecycle sample phase=(\S+) occupied=(\d+) peak=(\d+) observations=(\d+)")
    samples = [(i, m[1], *map(int, m.groups()[1:])) for i, line in enumerate(lines) if (m := pattern.fullmatch(line))]
    if [row[1] for row in samples] != ["application-start", "application-return", "series-end"]:
        raise ValueError("missing or duplicate lifecycle sample phases")
    previous_peak, previous_count = int(starts[0][1][1]), 0
    if not 0 < previous_peak <= capacity or starts[0][0] >= samples[0][0]:
        raise ValueError("invalid initial native occupancy or phase order")
    for index, phase, occupied, peak, count in samples:
        if not 0 <= occupied <= peak <= capacity or peak < previous_peak or count <= previous_count:
            raise ValueError("impossible or regressing native RAM observation")
        previous_peak, previous_count = peak, count
    original = hartstone(path, "FreeRTOS", 4, high_resolution=True)
    boot = lines.index("HARTSTONE PH SERIES boot target=ESP32 os=FreeRTOS experiment=4")
    calibration = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH CAL "))
    trial = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH TRIAL "))
    terminal = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
    if not samples[0][0] < boot < calibration < samples[1][0] < trial < terminal < samples[2][0] or \
            original["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("RAM phases do not enclose the complete observed original series")
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "uart_sha256": digest(path),
            "initial_heap_occupied_bytes": int(starts[0][1][1]), "heap_regions": regions,
            "dynamic_heap_peak_bytes": previous_peak, "samples": [row[1:] for row in samples],
            "observed_hartstone_series": original, "not_an_uninstrumented_performance_score": True}


def audit(directory, component="hartstone_lifecycle"):
    if component not in ("hartstone_lifecycle", "hartstone_lifecycle_iram"):
        raise ValueError("unsupported observation framework")
    reference = ROOT / "artifacts/reports/hartstone-native-us-fifo-v1/freertos/ph4"
    required = {"series.c", "small_whetstone.c", "small_whetstone.h", "ph_esp_timer.h", "ph_us_schedule.h",
                "config", "compiler.txt", "compile_commands.json", "symbols.txt", "disassembly.txt",
                "freertos.c", "base-observer.c", "observer-CMakeLists.txt", "observer-app-CMakeLists.txt",
                "FreeRTOSConfig.h", "FreeRTOSConfig-stock.h", "CMakeLists.txt", "main-CMakeLists.txt"}
    if component == "hartstone_lifecycle_iram":
        required |= {"observer-linker.lf", "lifecycle-observer.c"}
    audit_image_manifest(directory, required)
    for name in required & {"series.c", "small_whetstone.c", "small_whetstone.h", "ph_esp_timer.h",
                            "ph_us_schedule.h", "config", "FreeRTOSConfig.h", "FreeRTOSConfig-stock.h",
                            "CMakeLists.txt", "main-CMakeLists.txt"}:
        if (directory / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError(("original workload/profile changed", name))
    observer = ROOT / "firmware/bsp/esp32/resource_census"
    bindings = [("base-observer.c", observer / "freertos.c"),
                ("freertos.c", observer / component / "freertos.c"),
                ("observer-CMakeLists.txt", observer / component / "CMakeLists.txt"),
                ("observer-app-CMakeLists.txt", observer / component / "app/CMakeLists.txt")]
    if component == "hartstone_lifecycle_iram":
        bindings.extend([("observer-linker.lf", observer / component / "linker.lf"),
                         ("lifecycle-observer.c", observer / "hartstone_lifecycle/freertos.c")])
    for name, reviewed in bindings:
        if (directory / name).read_bytes() != reviewed.read_bytes():
            raise ValueError(("unreviewed native observation framework", name))
    if "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("changed native compiler")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for filename, fragment in (("series.c", "/hartstone_freertos/main/"),
                               ("small_whetstone.c", "/hartstone_freertos/main/"),
                               ("freertos.c", "/resource_census/" + component + "/")):
        selected = [row for row in commands if Path(row["file"]).name == filename and fragment in row["file"]]
        if len(selected) != 1:
            raise ValueError("missing reviewed original/observer compilation")
        args = shlex.split(selected[0]["command"])
        if [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or "-c" not in args:
            raise ValueError("original optimization changed")
        if filename != "freertos.c" and not {"-DPH_EXPERIMENT=4", "-DPH_HIGH_RES=1", "-fno-fast-math", "-ffp-contract=off"} <= set(args):
            raise ValueError("original selection/timer/math semantics changed")
    symbols = (directory / "symbols.txt").read_text()
    for name in ("app_main", "heap_caps_init", "heap_caps_enable_nonos_stack_heaps", "fputs",
                 "multi_heap_malloc", "multi_heap_free", "multi_heap_realloc"):
        if not re.search(r"\bT __wrap_" + name + r"$", symbols, re.M):
            raise ValueError(("missing compiled native observation hook", name))
    disassembly = (directory / "disassembly.txt").read_text()
    addresses = dict((name, address) for address, name in
                     re.findall(r"^([0-9a-f]+) [0-9a-f]+ T (\S+)$", symbols, re.M))
    if component == "hartstone_lifecycle_iram" and any(
            not 0x40080000 <= int(addresses["__wrap_" + name], 16) < 0x400a0000 for name in
            ("app_main", "heap_caps_init", "heap_caps_enable_nonos_stack_heaps", "fputs", "multi_heap_malloc", "multi_heap_free", "multi_heap_realloc")):
        raise ValueError("observer escaped reviewed instruction-RAM placement")
    callers, caller = [], None
    for line in disassembly.splitlines():
        header = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if header:
            caller = header[1]
        if re.search(r"\bcall\w*\s+[^<]*<multi_heap_aligned_free>", line):
            callers.append(caller)
    if addresses.get("multi_heap_aligned_free") != addresses.get("multi_heap_free") or \
            not callers or set(callers) != {"__wrap_multi_heap_free"} or "multi_heap_aligned_alloc_offs" in addresses:
        raise ValueError("native aligned allocation/free bypasses the reviewed observation hooks")
    for name in ("__wrap_app_main", "__wrap_heap_caps_init", "__wrap_heap_caps_enable_nonos_stack_heaps", "__wrap_fputs"):
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native observation hook not called", name))
    resource = audit_cell(directory, "FreeRTOS", "hartstone_ph4_lifecycle_observation", observation=True)
    runs = [capture(directory / f"reset{i}.jsonl", resource["ram_sections"]) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("independent reset windows overlap")
    peaks = [resource["static_sram_bytes"] + row["dynamic_heap_peak_bytes"] for row in runs]
    baseline = [hartstone(reference / f"reset{i}.jsonl", "FreeRTOS", 4, high_resolution=True) for i in (1, 2, 3)]
    worker_coverage = all(row["observed_hartstone_series"]["first_loss_step"] == max(
        trial["first_loss_step"] for trial in baseline) for row in runs)
    return {"audit": "pass", "os": "FreeRTOS", "resets": 3, "source": "unchanged SEI-derived PH4 C workload",
            "window": "after native heap registration through the instrumented series endpoint",
            "static_sram_bytes": resource["static_sram_bytes"], "observed_software_ram_peak_bytes": peaks,
            "median_observed_peak_bytes": statistics.median(peaks), "range_observed_peak_bytes": [min(peaks), max(peaks)],
            "runs": runs, "reference_original_series": baseline,
            "observer_component": component, "reference_worker_cohort_covered": worker_coverage,
            "instrumented_reference_worker_cohort_peak_eligible": worker_coverage,
            "reference_workload_peak_eligible": False, "ranking_eligible": False,
            "reason": "covers the reference maximum worker cohort, but includes observer code/state and does not prove zero timing perturbation" if worker_coverage else
                "instrumented calibration/first-loss differ; does not cover the original maximum worker cohort",
            "excluded": ["ROM/pre-heap initialization", "allocator-internal transient peaks", "uninstrumented performance scores"],
            "resources": resource}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--component", choices=("hartstone_lifecycle", "hartstone_lifecycle_iram"), default="hartstone_lifecycle")
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.component), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
