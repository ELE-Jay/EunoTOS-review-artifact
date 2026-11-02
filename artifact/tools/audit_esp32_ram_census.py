#!/usr/bin/env python3
"""Replay native RAM census and static/heap disjointness, never performance rank."""
import argparse
import hashlib
import json
import re
import shlex
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from audit_esp32_resources import audit_cell, physical_intervals, union_bytes, RAM, primary_directory
from audit_esp32_report import audit_image_manifest
from audit_esp32_tm_basic import CASES, audit
from audit_esp32_tm_reboots import require_cpu2_interrupt, require_self_check

FAMILIES = {"FreeRTOS": "native-multi-heap", "Zephyr": "static-native-heaps",
            "NuttX": "native-region-heap", "RIOT": "native-newlib-multi-region",
            "AliOS-Rhino": "native-rhino-region-heap"}
WRAPS = {
    "FreeRTOS": ["multi_heap_malloc", "multi_heap_free", "multi_heap_aligned_free",
                 "multi_heap_realloc", "multi_heap_aligned_alloc_offs"],
    "Zephyr": ["sys_heap_init"], "NuttX": ["mm_unlock"],
    "RIOT": ["_sbrk_r", "__malloc_unlock"],
    "AliOS-Rhino": [],
}
ROOT = Path(__file__).resolve().parents[1]
MESSAGE_PROFILES = (("FreeRTOS", "ram-census-v2/freertos"), ("Zephyr", "ram-census-v1/zephyr"),
                    ("NuttX", "ram-census-v2/nuttx"), ("RIOT", "ram-census-v1/riot"),
                    ("AliOS-Rhino", "ram-census-v2/alios"))
LEGACY_OBSERVERS = {
    "Zephyr": "5346b1e4b6835161a3d89285e47a7fa4165c1c9de08b8b5a2334eed56536a4b4",
    "NuttX": "32232802a7192145e481be7bf0b1a8e9eac2fcc21444a8a703f48f8bf4cac450",
}


def check_observation_build(directory, os, case="message_processing"):
    if case not in CASES:
        raise ValueError("unknown original Thread-Metric RAM case")
    if os == "AliOS-Rhino":
        return  # The native Rhino source/compiler/port checks below cover this profile.
    app = ROOT / "firmware/bsp/esp32" / f"{os.lower()}_thread_metric"
    if os in ("FreeRTOS", "Zephyr"):
        app /= "main" if os == "FreeRTOS" else "src"
    names = ("port.c", "test.c", "tm_override.h",
             "iotosbench_main.c" if os == "NuttX" else "main.c")
    audit_image_manifest(directory, {"config", "compiler.txt", "build.log", *names})
    for name in names:
        if (directory / name).read_bytes() != (app / name).read_bytes():
            raise ValueError(f"RAM observation changed the reviewed native adapter: {name}")
    reference = (ROOT / "artifacts/reports/riot-native-gcc12-v3" / case
                 if os == "RIOT" else primary_directory(os, case))
    config_name = "config.h" if os == "RIOT" else "config"
    if (directory / "config").read_bytes() != (reference / config_name).read_bytes():
        raise ValueError("RAM observation changed the reference core/clock/kernel configuration")
    version = "12.2.0" if os == "RIOT" else "13.2.0"
    if version not in (directory / "compiler.txt").read_text() or \
            '#pragma GCC optimize("O0")' not in (directory / "test.c").read_text():
        raise ValueError("RAM observation changed the compiler or original timed-body optimization")
    if os == "RIOT":
        from audit_esp32_riot_tm import check_compilation
        if (directory / "Makefile").read_bytes() != (
                ROOT / "firmware/bsp/esp32/resource_census/riot.Makefile").read_bytes():
            raise ValueError("unreviewed RIOT observer link recipe")
        check_compilation(directory, case, workspace="ram-riot-work-v1",
                          sources=("main.c", "port.c", "test.c", "census.c"))
        return
    if os == "NuttX":
        recipe = (directory / "Makefile").read_bytes()
        digest = hashlib.sha256(recipe).hexdigest()
        legacy = ((case == "message_processing" and digest ==
                   "15161555110618192e08d8e3c9bf7da516e5006e9ff25a42c795531c7a7bff76") or
                  (not case.startswith("interrupt_") and case != "memory_allocation" and digest ==
                   "78a04072a31afcbc0f73ea19b2d6b3dc2f0e3cb917bfbbe8a3518c89deaa40ad"))
        if not legacy and recipe != (
                ROOT / "firmware/bsp/esp32/resource_census/nuttx.Makefile").read_bytes():
            raise ValueError("unreviewed NuttX observer link recipe")
        commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    else:
        audit_image_manifest(directory, {"compile_commands.json"})
        commands = [shlex.split(row["command"]) for row in
                    json.loads((directory / "compile_commands.json").read_text())]
    sources = {"port.c", "test.c", names[-1]}
    observer = "census.c" if os == "NuttX" else f"{os.lower()}.c"
    selected = []
    compiled = []
    for args in commands:
        source = [Path(arg).name for arg in args if arg.endswith(".c")]
        macros = [arg for arg in args if arg.startswith("-DTM_TEST_")]
        if len(source) == 1 and (source[0] == observer or source[0] in sources and macros):
            selected.append(args)
            compiled.extend(source)
            if macros and macros != [f"-DTM_TEST_{case}=1"]:
                raise ValueError("RAM compilation selected a different original case")
            if macros and ([arg for arg in args if arg.startswith("-DTM_IRQ_FROM_CPU2")]
                           != (["-DTM_IRQ_FROM_CPU2=1"] if case.startswith("interrupt_") else [])):
                raise ValueError("RAM compilation changed the matched interrupt path")
    if sorted(compiled) != sorted((*sources, observer)) or any("-c" not in args or
            not any(Path(arg).name == "xtensa-esp32-elf-gcc" for arg in args) or
            [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]
            for args in selected):
        raise ValueError("RAM native application/observer compile commands are incomplete or changed")


def region_accounting(sections, regions, static_heaps):
    static = [interval for section in sections for interval in
              physical_intervals(int(section["address"], 16), section["bytes"])]
    heap = []
    for start, size in regions:
        if size <= 0 or not any(low <= start < start + size <= high for low, high in RAM):
            raise ValueError("heap region outside known internal SRAM")
        heap.extend(physical_intervals(start, size))
    if union_bytes(heap) != sum(size for _, size in regions):
        raise ValueError("heap regions physically overlap")
    overlap = union_bytes(static) + union_bytes(heap) - union_bytes(static + heap)
    if static_heaps and overlap != union_bytes(heap):
        raise ValueError("Zephyr heap is not fully included in static SRAM")
    if not static_heaps and overlap:
        raise ValueError("dynamic heap overlaps static SRAM; would double count")
    return union_bytes(heap)


def audit_capture(path, os, sections, case="message_processing"):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    lines = [row["line"] for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
        raise ValueError("expected one early board reset")
    begin = f"BENCH_RAM begin os={os} family={FAMILIES[os]} window=application-through-reports"
    if lines.count(begin) != 1:
        raise ValueError("missing or duplicate native RAM census identity")
    regions = [tuple(map(int, match.groups())) for line in lines if
               (match := re.fullmatch(r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if not regions or (os == "RIOT" and len(regions) != 4) or (os == "AliOS-Rhino" and len(regions) != 2):
        raise ValueError("missing native heap regions")
    region_size = region_accounting(sections, regions, os == "Zephyr")
    sample_re = re.compile(r"BENCH_RAM sample occupied=(\d+) peak=(\d+) observations=(\d+)(?: invalid=(\d+))?")
    samples = [(index, tuple(int(value or 0) for value in match.groups()))
               for index, line in enumerate(lines) if (match := sample_re.fullmatch(line))]
    headings = [index for index, line in enumerate(lines)
                if line.startswith("**** Thread-Metric")]
    if len(samples) != 3 or len(headings) != 3:
        raise ValueError("expected three original reports and three census samples")
    previous_peak = previous_count = 0
    for run, (index, (occupied, peak, count, invalid)) in enumerate(samples):
        if not (0 <= occupied <= peak <= region_size and peak >= previous_peak and
                count >= previous_count and count > 0 and invalid == 0):
            raise ValueError("invalid global native heap census")
        if not (headings[run - 1] < index if run else True) or index >= headings[run]:
            raise ValueError("RAM sample not paired with original report")
        if os == "Zephyr" and (occupied or peak or count != len(regions)):
            raise ValueError("static heap profile changed during observation")
        previous_peak, previous_count = peak, count
    original = audit(path, os, case)
    checks = {"message_processing": "queue", "synchronization_processing": "semaphore",
              "memory_allocation": "memory"}
    if case in checks:
        require_self_check(rows, checks[case])
    if case.startswith("interrupt_"):
        require_cpu2_interrupt(rows)
    if os == "RIOT" and lines.count(
            "Thread-Metric conditions cpu_hz=240000000 cores=1 timer=tickless scheduler=priority-fifo") != 1:
        raise ValueError("RAM observation lacks effective native RIOT conditions")
    if os == "FreeRTOS" and (sum("cpu_start: cpu freq: 240000000 Hz" in line for line in lines) != 1 or
                             sum("cpu_start: Single core mode" in line for line in lines) != 1):
        raise ValueError("RAM observation lacks effective native FreeRTOS core/clock boot witness")
    started = datetime.fromisoformat(rows[0]["utc"]) - timedelta(seconds=rows[0]["elapsed_s"])
    return {"capture_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "started_utc": started.isoformat(),
            "completed_utc": (started + timedelta(seconds=rows[-1]["elapsed_s"])).isoformat(),
            "regions": regions,
            "dynamic_heap_peak_bytes": samples[-1][1][1],
            "native_observations": samples[-1][1][2],
            "original_test_execution": original,
            "not_an_uninstrumented_performance_score": True}


def audit_census(directory, os, case="message_processing", *, irq_vector_corrected=False):
    if case not in CASES:
        raise ValueError("unknown original Thread-Metric RAM case")
    if irq_vector_corrected:
        from audit_esp32_alios_tm import check_irq_adapter_correction
        if os != "AliOS-Rhino":
            raise ValueError("native vector correction is specific to the reviewed Rhino IRQ pair")
        check_irq_adapter_correction(case)
    required = {"census.c", "symbols.txt", "disassembly.txt", f"tm_{case}_test.c"}
    if os == "AliOS-Rhino":
        required |= {"alios-k_mm.c", "k_mm.h", "app-aos.mk", "soc_impl.c", "heap_wrapper.c",
                     "sdkconfig.h", "k_config.h", "main.c", "port.c", "test.c", "tm_override.h"}
    if os in LEGACY_OBSERVERS and case == "memory_allocation":
        required.add("pool_check.h")
    audit_image_manifest(directory, required)
    check_observation_build(directory, os, case)
    result = audit_cell(directory, os, f"{case}_observation", observation=True)
    resumed = []
    for index in (2, 3):
        verify_path = directory / f"resume-image-verify-{index}.log"
        if verify_path.exists():
            log = verify_path.read_text()
            verified = [(int(size), int(offset, 16)) for size, offset in re.findall(
                r"Verifying 0x[0-9a-f]+ \((\d+)\) bytes @ (0x[0-9a-f]+)", log)]
            expected_segments = [(segment["bytes"], int(segment["offset"], 16))
                                 for segment in result["segments"]]
            if (sorted(verified) != sorted(expected_segments) or
                    log.count("-- verify OK (digest matched)") != len(expected_segments) or
                    log.count("MAC: 84:1f:e8:8f:55:dc") != 1):
                raise ValueError("resumed captures lack same-board full-image digest verification")
            resumed.append({"first_reset": index, "log_sha256": hashlib.sha256(verify_path.read_bytes()).hexdigest(),
                            "verified_segments": verified})
    if resumed:
        result["resume_flash_verification"] = resumed
    source_name = "alios.c" if os == "AliOS-Rhino" else f"{os.lower()}.c"
    expected = ROOT / "firmware/bsp/esp32/resource_census" / source_name
    observer = (directory / "census.c").read_bytes()
    legacy = (case != "memory_allocation" and
              hashlib.sha256(observer).hexdigest() == LEGACY_OBSERVERS.get(os))
    if observer != expected.read_bytes() and not legacy:
        raise ValueError("observer source differs from independently reviewed version")
    if os in LEGACY_OBSERVERS and case == "memory_allocation" and (
            directory / "pool_check.h").read_bytes() != (
            ROOT / "firmware/bsp/esp32/resource_census/pool_check.h").read_bytes():
        raise ValueError("unreviewed native memory pool self-check")
    original = ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / f"tm_{case}_test.c"
    if (directory / original.name).read_bytes() != original.read_bytes():
        raise ValueError("original workload body changed")
    symbols = (directory / "symbols.txt").read_text()
    disassembly = (directory / "disassembly.txt").read_text()
    mandatory = ["tm_main", "tm_thread_sleep", *WRAPS[os]]
    if os in LEGACY_OBSERVERS and case == "memory_allocation":
        mandatory.append("tm_memory_pool_create")
    if os == "FreeRTOS":
        addresses = {name: address for address, name in
                     re.findall(r"^([0-9a-f]+) [0-9a-f]+ T (\S+)$", symbols, re.M)}
        callers = []
        caller = None
        for line in disassembly.splitlines():
            header = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
            if header:
                caller = header[1]
            if re.search(r"\bcall\w*\s+[^<]*<multi_heap_aligned_free>", line):
                callers.append(caller)
        # GCC labels the free implementation by its same-address aligned alias.
        alias_covered = (addresses.get("multi_heap_aligned_free") == addresses.get("multi_heap_free")
                         and callers and set(callers) <= {"__wrap_multi_heap_free"})
        if alias_covered:
            mandatory.remove("multi_heap_aligned_free")
        if "multi_heap_aligned_alloc_offs" not in addresses:
            mandatory.remove("multi_heap_aligned_alloc_offs")
    for symbol in mandatory:
        if not re.search(r"\bT __wrap_" + re.escape(symbol) + r"$", symbols, re.M):
            raise ValueError(f"missing compiled observer wrapper: {symbol}")
    if os == "AliOS-Rhino":
        from audit_esp32_alios_tm import check_conditions, check_native_port, check_compilation
        result["native_port_profile"] = check_native_port(directory)
        if not result["native_port_profile"].startswith("historical"):
            check_compilation(directory, case)
        for name in ("main.c", "port.c", "test.c", "tm_override.h"):
            expected = ROOT / "firmware/bsp/esp32/alios_thread_metric_irq/port.c" if irq_vector_corrected and name == "port.c" else \
                ROOT / "firmware/bsp/esp32/alios_thread_metric" / name
            if (directory / name).read_bytes() != expected.read_bytes():
                raise ValueError("RAM observer changed the native original-test adapter")
        for name in ("sdkconfig.h", "k_config.h"):
            if (directory / name).read_bytes() != (
                    ROOT / "firmware/bsp/esp32/alios_board/esp32bench" / name).read_bytes():
                raise ValueError("RAM observation clock/kernel profile differs")
        for name in ("alios-k_mm.c", "alios-aos.mk"):
            archived = "app-aos.mk" if name.endswith("aos.mk") else name
            if (directory / archived).read_bytes() != (
                    ROOT / "firmware/bsp/esp32/resource_census" / name).read_bytes():
                raise ValueError("unreviewed native whole-heap observation hook")
        if not re.search(r"\bT bench_ram_observe$", symbols, re.M):
            raise ValueError("native allocator commit observer missing from ELF")
        if "<bench_ram_observe>" not in disassembly:
            raise ValueError("compiled native allocator observer not witnessed")
        observed_callers = set()
        caller = None
        for line in disassembly.splitlines():
            header = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
            if header:
                caller = header[1]
            if re.search(r"\bcall\w*\s+[^<]*<bench_ram_observe>", line):
                observed_callers.add(caller)
        if not {"k_mm_alloc", "k_mm_free", "k_mm_realloc"} <= observed_callers:
            raise ValueError("not all native Rhino allocator commit paths call the observer")
        for reset in (1, 2, 3):
            check_conditions([json.loads(line) for line in
                              (directory / f"reset{reset}.jsonl").read_text().splitlines()])
    runs = [audit_capture(directory / f"reset{index}.jsonl", os, result["ram_sections"], case)
            for index in (1, 2, 3)]
    starts = [datetime.fromisoformat(run["started_utc"]) for run in runs]
    ends = [datetime.fromisoformat(run["completed_utc"]) for run in runs]
    if not all(right > left for left, right in zip(ends, starts[1:])):
        raise ValueError("independent reset capture intervals overlap")
    if any(run["regions"] != runs[0]["regions"] for run in runs):
        raise ValueError("native heap layout differs between resets")
    native_control_bytes = 0
    if os == "NuttX":
        from audit_esp32_nuttx_ram_context import account_context
        context = account_context(directory, case, result["ram_sections"], runs)
        native_control_bytes = context["native_heap_control_bytes"]
        result["native_heap_control"] = context
        result["historical_static_plus_managed_heap_median_bytes"] = statistics.median(
            result["static_sram_bytes"] + run["dynamic_heap_peak_bytes"] for run in runs)
    peaks = [result["static_sram_bytes"] + run["dynamic_heap_peak_bytes"] + native_control_bytes for run in runs]
    result.update({"status": "PASS", "runs": runs,
                   "native_adapter_configuration_compilation": "audited, original test body unchanged",
                   "original_case": case,
                   "runtime_whole_ram_peak_bytes": statistics.median(peaks),
                   "runtime_whole_ram_peak_min_bytes": min(peaks),
                   "runtime_whole_ram_peak_max_bytes": max(peaks),
                   "runtime_peak_status": "measured at native allocator commit boundaries",
                   "definition": "instrumented firmware static physical SRAM union plus simultaneous occupied native heaps outside that union" +
                       (" plus separately reserved native heap-control context" if native_control_bytes else ""),
                   "window": "benchmark-entry snapshot before original tm_main through the RAM snapshot immediately preceding the original 90-second report",
                   "excludes": ["earlier boot/application-setup transient peak", "hardware cache/ROM-private reserved buffers",
                                "allocator-internal transient states between observed commit boundaries"],
                   "ranking_eligible": False})
    if irq_vector_corrected:
        result["native_irq_vector_duplicate_nesting_removed"] = True
    return result


def audit_suite(directory):
    cells = []
    for os, message_folder in MESSAGE_PROFILES:
        name = "alios" if os == "AliOS-Rhino" else os.lower()
        for case in CASES:
            folder = (ROOT / "artifacts/reports" / message_folder if case == "message_processing"
                      else Path(directory) / name / case)
            if os in LEGACY_OBSERVERS and case == "memory_allocation":
                folder = Path(directory) / name / "memory_allocation-selfcheck-v2"
            if os == "NuttX" and case == "cooperative_scheduling":
                folder = Path(directory) / name / "cooperative_scheduling-console-v2"
            cells.append(audit_census(folder, os, case))
    return {"status": "PASS", "original_cases_per_os": len(CASES),
            "os_profiles": len(MESSAGE_PROFILES), "observation_cells": len(cells),
            "independent_resets": sum(len(cell["runs"]) for cell in cells),
            "cells": cells, "ranking_eligible": False,
            "scope": "eight original Thread-Metric workloads; separate instrumented images; benchmark entry through the snapshot before the 90-second report; excludes earlier boot and Hartstone workloads"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("os", choices=FAMILIES, nargs="?")
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--case", choices=CASES, default="message_processing")
    parser.add_argument("--all", action="store_true", help="Audit the five explicitly included observation profiles")
    parser.add_argument("--suite", type=Path, help="Audit all eight original cases per OS, reusing retained message observations")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.suite:
        if args.os or args.directory or args.all:
            parser.error("--suite does not take a single-profile OS/directory or --all")
        result = audit_suite(args.suite)
    elif args.all:
        if args.os or args.directory:
            parser.error("--all does not take a single-profile OS/directory")
        cells = [audit_census(ROOT / "artifacts/reports" / folder, os) for os, folder in MESSAGE_PROFILES]
        result = {"status": "PASS", "independent_resets": sum(len(cell["runs"]) for cell in cells),
                  "cells": cells, "ranking_eligible": False}
    else:
        if not args.os or not args.directory:
            parser.error("provide an OS and evidence directory, or --all")
        result = audit_census(args.directory, args.os, args.case)
    content = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
