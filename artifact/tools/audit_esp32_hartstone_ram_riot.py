#!/usr/bin/env python3
"""Replay native RIOT heap-commit observations around unchanged PH4 work."""
import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
import statistics
import struct
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_image_manifest
from audit_esp32_resources import audit_cell, audit_elf_image, static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_hartstone_series import audit as hartstone
from audit_esp32_riot_original import UPSTREAM, digest, check_manifest
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_hartstone_ram_riot_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/ram-hartstone-riot-v1/riot/ph4"
REFERENCE = ROOT / "artifacts/reports/hartstone-riot-native-v4/ph4"
PORT = ROOT / "firmware/bsp/esp32/resource_census/hartstone_lifecycle_riot"
ORIGINAL = ("main.c", "workload.c", "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h")
NATIVE = ("sys/newlib_syscalls_default/syscalls.c", "cpu/esp_common/syscalls.c",
    "cpu/esp_common/esp-xtensa/thread_arch.c", "cpu/esp_common/vendor/xtensa/portasm.S",
    "core/thread.c", "core/sched.c", "sys/sema/sema.c")
SDK = "1329b19fe494500aeb79d19b27cfd99b40c37aec"
SDK_FILES = ("components/esp_hw_support/esp_clk.c", "components/esp_hw_support/include/esp_private/esp_clk.h")


def symbol_bytes(elf, symbols, name, size):
    rows = symbols.get_symbol_by_name(name) or []
    if len(rows) != 1 or rows[0]["st_size"] != size:
        raise ValueError("native/observer memory layout differs: " + name)
    symbol = rows[0]
    section = elf.get_section(symbol["st_shndx"])
    offset = symbol["st_value"] - section["sh_addr"]
    return section.data()[offset:offset + size]


def build(directory, verify_upstream=False):
    audit_image_manifest(directory, {"application.elf", "application.bin", "bootloader.bin", "partitions.bin",
        "config", "reference-config", "compiler.txt", "census.c", "base-observer.c", "Makefile", "original-Makefile",
        "build-script.sh", "newlib-libc.a", "sdk-package-Makefile", *ORIGINAL,
        *("native-source/" + name for name in NATIVE), *("native-source/sdk/" + name for name in SDK_FILES)}, allow_nested=True)
    for name in ORIGINAL:
        if (directory / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("changed original PH4 workload/helper: " + name)
    for name, expected in (("census.c", PORT / "riot.c"), ("base-observer.c", PORT.parent / "riot.c"),
            ("Makefile", PORT / "Makefile"), ("original-Makefile", REFERENCE / "Makefile"),
            ("build-script.sh", ROOT / "tools/build_esp32_hartstone_ram_riot.sh")):
        if (directory / name).read_bytes() != expected.read_bytes():
            raise ValueError("unreviewed original/observation recipe: " + name)
    for name in ("application.elf", "application.bin"):
        if (directory / name).read_bytes() != (directory / "failed-archive-path" / name).read_bytes():
            raise ValueError("source archive recovery changed the measured image")
    if (directory / "config").read_bytes() != (REFERENCE / "config.h").read_bytes() or \
            (directory / "reference-config").read_bytes() != (REFERENCE / "config.h").read_bytes():
        raise ValueError("changed native core, clock, timer or scheduler configuration")
    config = (directory / "config").read_text()
    if "12.2.0" not in (directory / "compiler.txt").read_text() or "#define MODULE_NEWLIB_NANO 1" not in config or \
            "MODULE_ESP_IDF_HEAP" in config or "MODULE_SCHED_ROUND_ROBIN" in config:
        raise ValueError("changed native compiler, allocator or FIFO scheduler")
    official = [(name, UPSTREAM + name, directory / "native-source" / name) for name in NATIVE]
    official += [("sdk/" + name, "https://raw.githubusercontent.com/espressif/esp-idf/" + SDK + "/" + name,
                  directory / "native-source/sdk" / name) for name in SDK_FILES]
    official.append(("sdk-package-Makefile", UPSTREAM + "pkg/esp32_sdk/Makefile", directory / "sdk-package-Makefile"))
    proof = directory / "official-native-source.json"
    expected = [{"path": name, "url": url, "sha256": digest(path)} for name, url, path in official]
    if verify_upstream:
        for name, url, path in official:
            if urlopen(url, timeout=60).read() != path.read_bytes():
                raise ValueError("native file differs from fixed official source: " + name)
        proof.write_text(json.dumps(expected, indent=2) + "\n")
    if not proof.exists() or json.loads(proof.read_text()) != expected:
        raise ValueError("native official-source verification missing or changed")
    log = (directory / "failed-archive-path/build.log").read_text().replace("\\\n", " ")
    commands = [shlex.split(line) for line in log.splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    selected = []
    for fragment in ("/app/main.c", "/app/workload.c", "/app/census.c", "/core/thread.c", "/core/sched.c",
            "/sys/newlib_syscalls_default/syscalls.c", "/cpu/esp_common/syscalls.c", "/sys/sema/sema.c",
            "/cpu/esp_common/esp-xtensa/thread_arch.c", "/components/esp_hw_support/esp_clk.c"):
        rows = [args for args in commands if any(arg.endswith(fragment) for arg in args)]
        if len(rows) != 1 or [arg for arg in rows[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("missing original/observer/native compile or changed optimization: " + fragment)
        if not {"-DPH_EXPERIMENT=4", "-DPH_HIGH_RES=1", "-fno-fast-math", "-ffp-contract=off",
                "-DTHREAD_PRIORITY_MAIN=14", "-DMAXTHREADS=48", "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1"} <= set(rows[0]):
            raise ValueError("changed original math/clock/thread/timer compilation")
        selected.append(fragment)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    footprint = static_footprint(directory / "application.elf")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        starts = [symbols.get_symbol_by_name("_sheap" + suffix)[0]["st_value"] for suffix in ("", "1", "2", "3")]
        ends = [symbols.get_symbol_by_name("_eheap" + suffix)[0]["st_value"] for suffix in ("", "1", "2", "3")]
        regions = list(zip(starts, [b - a for a, b in zip(starts, ends)]))
        if list(struct.unpack("<12I", symbol_bytes(elf, symbols, "regions", 48))) != [
                value for start, end in zip(starts, ends) for value in (start, end, start)] or \
                list(struct.unpack("<8I", symbol_bytes(elf, symbols, "heaps", 32))) != [
                value for pair in zip(starts, ends) for value in pair] or \
                list(struct.unpack("<4I", symbol_bytes(elf, symbols, "heap_top", 16))) != starts:
            raise ValueError("observer heap ranges/tops differ from actual native sbrk arrays")
        region_accounting(footprint["ram_sections"], regions, False)
        for name, size in (("tasks", 45 * 28), ("stacks", 45 * 4), ("pids", 45 * 2), ("gates", 45 * 12)):
            if symbols.get_symbol_by_name(name)[0]["st_size"] != size:
                raise ValueError("original persistent-worker slots changed: " + name)
    return {"official_native_files_checked": len(official), "compiled_units_checked": selected,
        "original_files_checked": list(ORIGINAL), "native_heap_regions": regions, "static_footprint": footprint,
        "archive_recovery_image_unchanged": True}


def machine(directory):
    check_manifest(directory, "ram-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "ram-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "capture.sha256", "ram-control-flow.txt", "executed-ram-control.py",
            "flash.log", "application.map", "libg_nano.a", "official-native-library.json",
            "pilot-reset1.jsonl", "pilot-reset1.raw", "flash-pilot.log", "run-script-pilot.sh"}:
        raise ValueError("RAM machine supplement coverage differs")
    if (directory / "executed-ram-control.py").read_text() != collector_source(
            (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("changed entry-driven RAM decoder")
    library = ROOT / "artifacts/reports/zephyr-heap-riot-v1"
    if (directory / "libg_nano.a").read_bytes() != (library / "libg_nano.a").read_bytes() or \
            (directory / "official-native-library.json").read_bytes() != (library / "official-native-library.json").read_bytes():
        raise ValueError("actual native Newlib-nano archive differs from vendor-verified payload")
    mapped = (directory / "application.map").read_text()
    for member in ("malloc", "mlock", "nano-mallocr", "nano-freer", "nano-mallinfor"):
        if "libg_nano.a(lib_a-" + member + ".o)" not in mapped:
            raise ValueError("actual link does not use the captured native allocator member")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "ram-control-flow.txt").read_text(), "HARTSTONE RAM CONTROL",
                                    elf, symbols, set(FUNCTIONS))
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                encoding, target = int(match[1], 16), int(match[2], 16)
                offset = encoding >> 6
                if offset & (1 << 17): offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != target or not any(
                        item["st_value"] == target for item in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("actual native allocator call differs from encoding")
                calls[name, match[3]] += 1
        for caller, target, count in (("main_trampoline", "__wrap_main", 1), ("__wrap_main", "main", 1),
            ("__wrap_main", "report", 2), ("report", "observe", 1), ("observe", "_mallinfo_r", 1),
            ("__wrap__sbrk_r", "_sbrk_r", 1), ("__wrap___malloc_unlock", "__malloc_unlock", 2),
            ("__wrap___malloc_unlock", "observe", 1), ("malloc", "_malloc_r", 1),
            ("_mallinfo_r", "__wrap___malloc_unlock", 1), ("_malloc_r", "__wrap___malloc_unlock", 2),
            ("_free_r", "__wrap___malloc_unlock", 1), ("main", "malloc", 1),
            ("main", "thread_create", 1), ("thread_create", "thread_stack_init", 1),
            ("worker", "hartstone_small_whetstone", 1)):
            if calls[caller, target] != count:
                raise ValueError("native allocation/original/observer call coverage differs: " + caller + " -> " + target)
        if literal_word(elf, control["main"][0x400d0642], 14) != symbols.get_symbol_by_name("worker")[0]["st_value"] or \
                literal_word(elf, control["main"][0x400d05dc], 2) != symbols.get_symbol_by_name("stacks")[0]["st_value"] or \
                "117740 slli\ta7, a7, 12" not in control["main"][0x400d0613] or \
                not re.search(r"movi\.n\s+a7, 1$", control["main"][0x400d0611]):
            raise ValueError("actual original callback/stack pointer/4096-byte operand differs")
        if literal_word(elf, control["_sbrk_r"][0x40083245], 11) != symbols.get_symbol_by_name("heap_top")[0]["st_value"] or \
                literal_word(elf, control["_sbrk_r"][0x40083248], 9) != symbols.get_symbol_by_name("heaps")[0]["st_value"] or \
                not re.search(r"4d0c movi\.n\s+a13, 4$", control["_sbrk_r"][0x40083251]):
            raise ValueError("actual native sbrk arrays/four-region loop differs")
        if literal_word(elf, control["observe"][0x400d004c], 8) != symbols.get_symbol_by_name("regions")[0]["st_value"] or \
                literal_word(elf, control["_mallinfo_r"][0x400d468c], 4) != symbols.get_symbol_by_name("__malloc_free_list")[0]["st_value"]:
            raise ValueError("actual native free-list/observer region-array binding differs")
        for name, address, pattern in (("observe", 0x400d004a, r"81b8 l32i\.n\s+a11, a1, 32$"),
            ("observe", 0x400d0051, r"490c movi\.n\s+a9, 4$"),
            ("observe", 0x400d005c, r"c0aa30 sub\s+a10, a10, a3$"),
            ("observe", 0x400d005f, r"22aa add\.n\s+a2, a2, a10$"),
            ("observe", 0x400d006f, r"c022b0 sub\s+a2, a2, a11$"),
            ("_mallinfo_r", 0x400d469a, r"99aa add\.n\s+a9, a9, a10$"),
            ("_mallinfo_r", 0x400d46a9, r"8499 s32i\.n\s+a9, a4, 32$")):
            if not re.search(pattern, control[name][address]):
                raise ValueError("actual four-region commit/free-list subtraction differs: " + name)
    return {"reachable_functions_checked": len(control), "encoded_direct_calls_checked": sum(calls.values()),
        "native_allocator": "vendor-precompiled Newlib-nano, not source rebuilt",
        "initial_default_libc_archive_not_used_for_native_link_proof": True}


def capture(directory, index, footprint, expected_regions):
    rows = read_raw_capture(directory, index)
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(time.utcoffset() is None for time in times) or any(b < a for a, b in zip(times, times[1:])) or \
            sum(line.startswith("rst:0x") for line in lines) != 1 or lines.count("Single core mode") != 1 or \
            lines[-1] != "BENCH_RAM lifecycle complete" or any(re.search(
                r"Guru Meditation|panic|assert failed|Brownout|watchdog|status=FAIL", line, re.I) for line in lines):
        raise ValueError("incomplete or failed native RAM window/reset/clock/core")
    begin = "BENCH_RAM lifecycle begin os=RIOT family=native-newlib-multi-region window=application-through-first-loss clock_hz=240000000"
    if lines.count(begin) != 1 or lines.count("BENCH_RAM lifecycle result=0") != 1 or next(
            row["elapsed_s"] for row in rows if row["line"].startswith("rst:0x")) > 2:
        raise ValueError("native RAM window or clock/return witness differs")
    regions = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if regions != [tuple(row) for row in expected_regions]:
        raise ValueError("printed regions do not match actual native heap bounds")
    capacity = region_accounting(footprint["ram_sections"], regions, False)
    samples = [(i, m[1], *map(int, m.groups()[1:])) for i, line in enumerate(lines) if (m := re.fullmatch(
        r"BENCH_RAM lifecycle sample phase=(\S+) occupied=(\d+) peak=(\d+) observations=(\d+) invalid=(\d+)", line))]
    if [row[1] for row in samples] != ["application-start", "series-return"]:
        raise ValueError("missing original lifecycle sample phases")
    previous_peak = previous_count = 0
    for position, phase, occupied, peak, count, invalid in samples:
        if not 0 < occupied <= peak <= capacity or count <= previous_count or peak < previous_peak or invalid:
            raise ValueError("impossible/regressing native heap sample")
        previous_peak, previous_count = peak, count
    original = hartstone(directory / f"reset{index}.jsonl", "RIOT", 4, high_resolution=True)
    if original["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("partial pilot cannot establish RAM at complete first loss")
    boot = lines.index("HARTSTONE PH SERIES boot target=ESP32 os=RIOT experiment=4")
    terminal = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
    if not lines.index(begin) < samples[0][0] < boot < terminal < samples[1][0] < lines.index("BENCH_RAM lifecycle result=0"):
        raise ValueError("RAM window does not enclose the unchanged original work")
    workers = 5 + original["first_loss_step"]
    if samples[1][2] - samples[0][2] < workers * 4096:
        raise ValueError("heap occupation cannot hold all retained original worker stacks")
    return {"started_utc": times[0].isoformat(), "completed_utc": times[-1].isoformat(),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw"),
        "dynamic_heap_peak_bytes": previous_peak, "observations": previous_count,
        "samples": [row[1:] for row in samples], "heap_regions": regions, "active_original_workers": workers,
        "observed_hartstone_series": original, "not_an_uninstrumented_performance_score": True}


def audit(directory=DIRECTORY, verify_upstream=False, build_only=False):
    result = build(directory, verify_upstream)
    if build_only:
        return {"audit": "build-only-pass", "measured": False, **result}
    check_manifest(directory, "capture.sha256")
    if (directory / "run-script-full.sh").read_bytes() != (ROOT / "tools/run_esp32_hartstone_ram_riot.sh").read_bytes() or \
            (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes() or \
            (directory / "flash.log").read_bytes() != (directory / "flash-full.log").read_bytes():
        raise ValueError("changed physical capture recipe or resource flash alias")
    resources = audit_cell(directory, "RIOT", "hartstone_ph4_lifecycle_observation", observation=True, recursive_manifest=True)
    control = machine(directory)
    runs = [capture(directory, index, resources, result["native_heap_regions"]) for index in (1, 2, 3)]
    if any(a["completed_utc"] >= b["started_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("independent reset windows overlap")
    baseline = [hartstone(REFERENCE / f"reset{index}.jsonl", "RIOT", 4, high_resolution=True) for index in (1, 2, 3)]
    covered = all(row["observed_hartstone_series"]["first_loss_step"] >= max(item["first_loss_step"] for item in baseline) for row in runs)
    peaks = [resources["static_sram_bytes"] + row["dynamic_heap_peak_bytes"] for row in runs]
    pilot = read_raw_capture(directory, 1, prefix="pilot-reset")
    if any(row["line"] == "BENCH_RAM lifecycle complete" or row["line"].startswith("HARTSTONE PH SERIES status=") for row in pilot) or \
            datetime.fromisoformat(pilot[-1]["utc"]) >= datetime.fromisoformat(runs[0]["started_utc"]) or \
            (directory / "run-script-pilot.sh").read_bytes() != (directory / "run-script-full.sh").read_bytes():
        raise ValueError("bounded pilot was promoted or its chronology/recipe differs")
    return {"audit": "pass", "os": "RIOT", "resets": 3, **result, "machine_control": control, "resources": resources,
        "runs": runs, "reference_original_series": baseline, "observed_software_ram_peak_bytes": peaks,
        "median_observed_peak_bytes": statistics.median(peaks), "reference_worker_cohort_covered": covered,
        "window": "application entry through complete first loss, native allocator commit boundaries",
        "instrumented_reference_worker_cohort_peak_eligible": covered, "uninstrumented_peak_measured": False,
        "stack_live_bytes_high_water_measured": False, "pre_kernel_transient_peak_measured": False,
        "allocator_internal_transient_peak_measured": False, "energy_measured": False, "ranking_eligible": False,
        "clock_witness": "official HAL CPU tick-scale getter, not an independent PLL-register measurement",
        "comparison_boundary": "includes observer and allocated stack reservation; OS-specific first-loss worker cohorts are not equal-load memory ranks",
        "new_metric_created": False, "excluded_capture_attempts": [{"path": "pilot-reset1.jsonl", "board_reset_prefixes": 1,
            "complete_series": False, "raw_bytes_saved": True, "uart_sha256": digest(directory / "pilot-reset1.jsonl"),
            "reason": "bounded setup check, not a complete first-loss result"}]}


def render_table(result):
    rows = ["| PH4 native heap RAM observation | RIOT |", "| --- | --- |",
        "| RIOT independent complete resets | 3 |",
        "| Static physical software SRAM, observer image | " + str(result["resources"]["static_sram_bytes"]) + " B |",
        "| Simultaneously occupied native heap peak | " + " / ".join(str(row["dynamic_heap_peak_bytes"]) for row in result["runs"]) + " B |",
        "| Observed software RAM peak, including observer | " + " / ".join(map(str, result["observed_software_ram_peak_bytes"])) + " B |",
        "| RIOT observed first-loss steps, not performance scores | " + " / ".join(str(row["observed_hartstone_series"]["first_loss_step"]) for row in result["runs"]) + " |",
        "| RIOT stack live-byte high water / uninstrumented peak | Not measured |"]
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args.directory, args.verify_upstream, args.build_only), indent=2) + "\n"
    if args.output: args.output.write_text(text)
    else: print(text, end="")
