#!/usr/bin/env python3
"""Audit the unchanged PH4 workload and its static-ownership RAM observation."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_image_manifest
from audit_esp32_riot_original import digest
from audit_esp32_zephyr_condvar import check_manifest
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_ram_census import region_accounting
from audit_esp32_resources import audit_cell, audit_elf_image, static_footprint
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_hartstone_series import audit as hartstone
from collect_esp32_hartstone_ram_zephyr_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/ram-hartstone-zephyr-v1/zephyr/ph4"
REFERENCE = ROOT / "artifacts/reports/hartstone-native-us-v1/zephyr/ph4"
PORT = ROOT / "firmware/bsp/esp32/resource_census/hartstone_lifecycle_zephyr"
ORIGINAL = ("series.c", "math_compat.h", "errno_bridge.c", "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h")
NATIVE = ("kernel/init.c", "kernel/thread.c", "kernel/sched.c", "kernel/kheap.c", "lib/heap/heap.c",
    "lib/libc/common/source/stdlib/malloc.c", "include/zephyr/kernel.h", "include/zephyr/kernel/thread_stack.h",
    "include/zephyr/sys/sys_heap.h")
HAL = "87e7902d7184a8280b4d13bce79801a723f4ddd8"


def build(directory, verify_upstream=False):
    required = {"application.elf", "application.bin", "config", "reference-config", "compiler.txt",
                "compile_commands.json", "symbols.txt", "disassembly.txt", "zephyr.c", "CMakeLists.txt",
                "west.yml", "VERSION", "build-script.sh", *("source/" + name for name in ORIGINAL),
                *("native-source/" + name for name in NATIVE)}
    audit_image_manifest(directory, required, allow_nested=True)
    for name in ORIGINAL:
        if (directory / "source" / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("changed original Hartstone source: " + name)
    for name in ("zephyr.c", "CMakeLists.txt"):
        if (directory / name).read_bytes() != (PORT / name).read_bytes():
            raise ValueError("unreviewed lifecycle observer")
    if (directory / "build-script.sh").read_bytes() != (ROOT / "tools/build_esp32_hartstone_ram_zephyr.sh").read_bytes():
        raise ValueError("changed census build recipe")
    for name in ("application.elf", "application.bin"):
        if (directory / name).read_bytes() != (directory / "failed-config-archive" / name).read_bytes():
            raise ValueError("archive recovery unexpectedly changed the built image")
    if (directory / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes():
        raise ValueError("changed reference profile")
    config = (directory / "config").read_text()
    normalize = lambda text: re.sub(r"^CONFIG_TAINT(?:_BLOBS)?=y\n", "", text, flags=re.M)
    if normalize(config) != normalize((REFERENCE / "config").read_text()):
        raise ValueError("changed core, clock, tick, heap or workload profile")
    if "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("changed compiler")
    official = [(name, "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/" + name,
                 directory / "native-source" / name) for name in NATIVE]
    official += [(name, "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/" + name,
                  directory / name) for name in ("west.yml", "VERSION")]
    official += [("hal/" + name, "https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL + "/" + name,
                  directory / "native-source/hal" / name) for name in
                 ("components/esp_hw_support/esp_clk.c", "components/esp_hw_support/include/esp_private/esp_clk.h")]
    proof = directory / "official-native-source.json"
    if verify_upstream:
        evidence = []
        for name, url, path in official:
            if urlopen(url, timeout=60).read() != path.read_bytes():
                raise ValueError("native file differs from fixed upstream: " + name)
            evidence.append({"path": name, "url": url, "sha256": digest(path)})
        proof.write_text(json.dumps(evidence, indent=2) + "\n")
    if not proof.is_file() or json.loads(proof.read_text()) != [
            {"path": name, "url": url, "sha256": digest(path)} for name, url, path in official]:
        raise ValueError("native source verification missing or changed")
    commands = json.loads((directory / "compile_commands.json").read_text())
    selected = []
    for fragment in ("/hartstone_zephyr/src/series.c", "/hartstone_zephyr/src/errno_bridge.c",
            "/hartstone_freertos/main/small_whetstone.c", "/hartstone_lifecycle_zephyr/zephyr.c",
            "/zephyr/kernel/init.c", "/zephyr/kernel/thread.c", "/zephyr/kernel/sched.c",
            "/zephyr/kernel/kheap.c", "/zephyr/lib/heap/heap.c", "/zephyr/lib/libc/common/source/stdlib/malloc.c",
            "/components/esp_hw_support/esp_clk.c"):
        rows = [row for row in commands if row["file"].endswith(fragment)]
        if len(rows) != 1:
            raise ValueError("missing original/observer/native compilation: " + fragment)
        args = shlex.split(rows[0]["command"])
        if "-c" not in args or [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("changed native compile optimization")
        if "/hartstone_" in fragment and not {"-DPH_EXPERIMENT=4", "-DPH_HIGH_RES=1", "-fno-fast-math", "-ffp-contract=off"} <= set(args):
            raise ValueError("changed original experiment/timer/math compilation")
        selected.append(rows[0]["file"])
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    footprint = static_footprint(directory / "application.elf")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        for name, size in (("stacks", 37 * 4096), ("threads", 37 * 96), ("tasks", 37 * 32), ("kheap__system_heap", 4096)):
            rows = symbols.get_symbol_by_name(name) or []
            if len(rows) != 1 or rows[0]["st_size"] != size:
                raise ValueError("static worker/heap reservation differs: " + name)
            symbol = rows[0]
            section = elf.get_section(symbol["st_shndx"])
            if not section["sh_flags"] & 2 or section["sh_type"] != "SHT_NOBITS" or not any(
                    int(row["address"], 16) <= symbol["st_value"] < symbol["st_value"] + size <= int(row["address"], 16) + row["bytes"]
                    for row in footprint["ram_sections"]):
                raise ValueError("worker/heap reservation missing from physical static SRAM")
        for name in ("malloc_arena", "z_malloc_heap", "k_thread_stack_alloc", "esp_wifi_init"):
            if any(row["st_shndx"] != "SHN_UNDEF" for row in symbols.get_symbol_by_name(name) or []):
                raise ValueError("unaccounted dynamic/externally allocated memory linked: " + name)
        heap = symbols.get_symbol_by_name("kheap__system_heap")[0]
        heap_region = (heap["st_value"], heap["st_size"])
    return {"official_native_files_checked": len(official), "compiled_units_checked": selected,
            "original_files_checked": list(ORIGINAL), "static_footprint": footprint,
            "native_heap_region": heap_region}


def machine(directory):
    check_manifest(directory, "ram-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "ram-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "capture.sha256", "ram-control-flow.txt", "executed-ram-control.py"}:
        raise ValueError("RAM control manifest coverage differs")
    expected = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text())
    if (directory / "executed-ram-control.py").read_text() != expected:
        raise ValueError("changed entry-driven RAM decoder")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        rows = read_control_rows((directory / "ram-control-flow.txt").read_text(), "HARTSTONE RAM CONTROL", elf, symbols, set(FUNCTIONS))
        calls = []
        for name, body in rows.items():
            for row in body.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                address, encoding, target = (int(value, 16) for value in match.groups()[:3])
                offset = encoding >> 6
                if offset & (1 << 17): offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != target or not any(
                        item["st_value"] == target for item in symbols.get_symbol_by_name(match[4]) or []):
                    raise ValueError("native census encoded call differs")
                calls.append((name, match[4]))
        for caller, target, count in (("bg_thread_main", "__wrap_main", 1), ("__wrap_main", "main", 1),
            ("__wrap_main", "esp_clk_cpu_freq", 1), ("statics_init", "k_heap_init", 1),
            ("k_heap_init", "__wrap_sys_heap_init", 1), ("__wrap_sys_heap_init", "sys_heap_init", 1),
            ("main", "z_impl_k_thread_create", 1), ("z_impl_k_thread_create", "z_setup_new_thread", 1),
            ("z_setup_new_thread", "arch_new_thread", 1), ("worker", "hartstone_small_whetstone", 1)):
            if calls.count((caller, target)) != count:
                raise ValueError("census/original/native call path differs: " + caller + " -> " + target)
        if literal_word(elf, rows["main"][0x400d0777], 13) != symbols.get_symbol_by_name("worker")[0]["st_value"] or \
                literal_word(elf, rows["main"][0x400d0766], 8) != symbols.get_symbol_by_name("stacks")[0]["st_value"] or \
                literal_word(elf, rows["main"][0x400d0744], 7) != symbols.get_symbol_by_name("threads")[0]["st_value"] or \
                "11cc40 slli\ta12, a12, 12" not in rows["main"][0x400d0782]:
            raise ValueError("actual original worker/stack/TCB/4096-byte literal binding differs")
        if any(target in ("malloc", "k_malloc", "k_heap_alloc", "k_heap_aligned_alloc", "k_thread_stack_alloc")
               for caller, target in calls if caller in ("main", "worker", "z_impl_k_thread_create", "z_setup_new_thread", "arch_new_thread")):
            raise ValueError("original static worker creation unexpectedly allocates a heap")
    return {"reachable_functions_checked": len(rows), "encoded_direct_calls_checked": len(calls),
            "observer_outside_original_calibration_and_work_loops": True}


def capture(directory, index, sections, expected_region):
    rows = read_raw_capture(directory, index)
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(time.utcoffset() is None for time in times) or any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("invalid lifecycle chronology")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or lines[-1] != "BENCH_RAM lifecycle complete":
        raise ValueError("missing physical reset or complete endpoint")
    if next(row["elapsed_s"] for row in rows if row["line"].startswith("rst:0x")) > 2 or any(
            word in line.lower() for line in lines for word in ("guru meditation", "panic", "assert", "ram port fail")):
        raise ValueError("late reset or native lifecycle failure")
    begin = "BENCH_RAM lifecycle begin os=Zephyr family=static-native-heaps window=application-through-first-loss clock_hz=240000000"
    first = "BENCH_RAM lifecycle sample phase=application-start regions=1 invalid=0"
    final = "BENCH_RAM lifecycle sample phase=series-return regions=1 invalid=0 initial_regions=1 result=0"
    if any(lines.count(line) != 1 for line in (begin, first, final)):
        raise ValueError("native static lifecycle region witness differs")
    region = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
        r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if region != [tuple(expected_region)]:
        raise ValueError("static native heap reservation differs")
    region_accounting(sections, region, True)
    original = hartstone(directory / f"reset{index}.jsonl", "Zephyr", 4, high_resolution=True)
    if original["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("incomplete observed original PH4 series")
    boot = "HARTSTONE PH SERIES boot target=ESP32 os=Zephyr experiment=4"
    terminal = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
    if not lines.index(begin) < lines.index(first) < lines.index(boot) < terminal < lines.index(final) < len(lines) - 1:
        raise ValueError("RAM window does not enclose original work")
    return {"started_utc": times[0].isoformat(), "completed_utc": times[-1].isoformat(),
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "heap_regions": region,
            "observed_hartstone_series": original, "not_an_uninstrumented_performance_score": True}


def audit(directory=DIRECTORY, verify_upstream=False, build_only=False):
    result = build(directory, verify_upstream)
    if build_only:
        return {"audit": "build-only-pass", "measured": False, **result}
    check_manifest(directory, "capture.sha256")
    if (directory / "run-script.sh").read_bytes() != (ROOT / "tools/run_esp32_hartstone_ram_zephyr.sh").read_bytes() or \
            (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes():
        raise ValueError("changed physical capture recipe")
    resources = audit_cell(directory, "Zephyr", "hartstone_ph4_lifecycle_observation", observation=True, recursive_manifest=True)
    result["machine_control"] = machine(directory)
    runs = [capture(directory, index, resources["ram_sections"], result["native_heap_region"]) for index in (1, 2, 3)]
    if any(a["completed_utc"] >= b["started_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("independent reset windows overlap")
    baseline = [hartstone(REFERENCE / f"reset{index}.jsonl", "Zephyr", 4, high_resolution=True) for index in (1, 2, 3)]
    covered = all(row["observed_hartstone_series"]["first_loss_step"] >= max(item["first_loss_step"] for item in baseline) for row in runs)
    prefix_path = directory / "diagnostic-text-only-prefix/reset1.jsonl"
    prefix = [json.loads(line) for line in prefix_path.read_text().splitlines()]
    if not prefix or any("raw_bytes" in row or row["line"] == "BENCH_RAM lifecycle complete" for row in prefix) or \
            datetime.fromisoformat(prefix[-1]["utc"]) >= datetime.fromisoformat(runs[0]["started_utc"]):
        raise ValueError("excluded text-only interrupted prefix promoted or misclassified")
    if "--raw-output" in (directory / "diagnostic-text-only-prefix/run_esp32_hartstone_ram_zephyr.sh").read_text():
        raise ValueError("text-only diagnostic recipe does not explain the missing raw record")
    return {"audit": "pass", "os": "Zephyr", "resets": 3, **result, "runs": runs, "resources": resources,
        "observed_static_software_reservation_bytes": resources["static_sram_bytes"],
        "dynamic_heap_added_to_static_bytes": 0, "native_static_heap_capacity_bytes": 4096,
        "worker_stack_reservation_bytes": 37 * 4096, "worker_slots_reserved": 37,
        "unused_static_stack_and_heap_arena_bytes_included": True,
        "reference_worker_cohort_executed": covered, "reference_original_series": baseline,
        "allocation_scope": "all allocated physical internal SRAM including pre-reserved stacks and heap arena",
        "stack_live_bytes_high_water_measured": False, "uninstrumented_peak_measured": False,
        "pre_kernel_transient_peak_measured": False, "energy_measured": False, "ranking_eligible": False,
        "clock_witness": "official HAL CPU tick-scale getter; not an independent PLL-register measurement",
        "excluded_capture_attempts": [{"path": "diagnostic-text-only-prefix/reset1.jsonl", "sha256": digest(prefix_path),
            "board_reset_prefixes": 1, "complete_series": False, "raw_bytes_saved": False,
            "reason": "capture option omitted; stopped and preserved, never pooled into the three complete resets"}],
        "archive_recovery_image_unchanged": True,
        "new_metric_created": False, "reason": "static arena ownership is fixed; observer image and its first-loss results remain separate"}


def render_table(result):
    rows = ["| PH4 RAM observation | Zephyr |", "| --- | --- |",
        "| Independent complete resets | 3 |",
        "| Allocated physical software SRAM, observer image | " + str(result["observed_static_software_reservation_bytes"]) + " B |",
        "| Pre-reserved worker stacks, included above | 37 x 4096 B |",
        "| Static native heap arena, included above | 4096 B |",
        "| Observed first-loss steps, not performance scores | " + " / ".join(str(row["observed_hartstone_series"]["first_loss_step"]) for row in result["runs"]) + " |",
        "| Stack live-byte high water / uninstrumented peak | Not measured |"]
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
