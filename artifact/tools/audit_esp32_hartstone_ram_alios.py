#!/usr/bin/env python3
"""Check the unmeasured Rhino PH4 heap-observer build against its measured input."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
import struct
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_image_manifest, audit_flash
from audit_esp32_hartstone_series import audit as hartstone
from audit_esp32_resources import audit_elf_image, static_footprint, image_length
from audit_esp32_ram_census import region_accounting
from audit_esp32_alios_tm import check_native_port
from audit_esp32_alios_tm_irq_ram import check_allocator_source
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_riot_original import digest, check_manifest
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_hartstone_ram_alios_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/ram-hartstone-alios-v1/alios/ph4"
REFERENCE = ROOT / "artifacts/reports/hartstone-alios-native-v4/ph4"
PORT = ROOT / "firmware/bsp/esp32/resource_census/hartstone_lifecycle_alios"
ORIGINAL = ("main.c", "workload.c", "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h")
NATIVE = ("kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_sys.c",
    "kernel/rhino/include/k_task.h", "kernel/rhino/include/k_sem.h", "kernel/rhino/include/k_sys.h",
    "kernel/rhino/include/k_mm.h", "platform/mcu/esp32/aos/soc_impl.c", "platform/mcu/esp32/aos/heap_wrapper.c",
    "platform/mcu/esp32/espos/platform/rhino/espos_task.c", "platform/mcu/esp32/espos/platform/rhino/espos_time.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h", "platform/mcu/esp32/bsp/include/esp32/include/esp_timer.h")


def build(directory=DIRECTORY, verify_upstream=False):
    audit_image_manifest(directory, {"application.elf", "application.bin", "bootloader.bin", "partitions.bin",
        "config", "reference-config", "sdkconfig.h", "k_config.h", "compiler.txt", "build.log", "build-script.sh",
        "census.c", "base-observer.c", "alios-k_mm.c", "original-k_mm.c", "aos.mk", "original-aos.mk",
        "Config.in", "examples-Config.in", "rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S",
        "libesp32.a", "link.opts", "disassembly.txt", "symbols.txt", *ORIGINAL,
        *("native-source/" + name for name in NATIVE)}, allow_nested=True)
    for name in (*ORIGINAL, "sdkconfig.h", "k_config.h", "config", "libesp32.a",
            "rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S"):
        if (directory / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("changed original workload/native configuration/SDK input: " + name)
    for name, maintained in (("census.c", PORT / "alios.c"), ("base-observer.c", PORT.parent / "alios.c"),
        ("alios-k_mm.c", PORT.parent / "alios-k_mm.c"), ("aos.mk", PORT / "aos.mk"),
        ("Config.in", ROOT / "firmware/bsp/esp32/hartstone_alios/Config.in"),
        ("examples-Config.in", ROOT / "firmware/bsp/esp32/hartstone_alios/examples-Config.in"),
        ("original-aos.mk", REFERENCE / "aos.mk"), ("reference-config", REFERENCE / "config"),
        ("build-script.sh", ROOT / "tools/build_esp32_hartstone_ram_alios.sh")):
        if (directory / name).read_bytes() != maintained.read_bytes():
            raise ValueError("changed observer/configuration/build recipe: " + name)
    additions = "$(NAME)_SOURCES += census.c\nGLOBAL_DEFINES += BENCH_RAM=1\nGLOBAL_LDFLAGS += -Wl,--wrap=application_start -Wl,--wrap=krhino_task_suspend\n"
    if (directory / "aos.mk").read_text().replace(additions, "") != (REFERENCE / "aos.mk").read_text():
        raise ValueError("application recipe changes more than the native observer and two wrappers")
    allocator = check_allocator_source(directory)
    if digest(directory / "original-k_mm.c") != allocator["official_sha256"]:
        raise ValueError("original allocator input differs from reconstructed native source")
    source_files = [(name, directory / "native-source" / name) for name in NATIVE]
    source_files.append(("kernel/rhino/k_mm.c", directory / "original-k_mm.c"))
    expected, upstream_bodies = [], []
    for name, path in source_files:
        body = path.read_bytes()
        row = {"path": name, "url": UPSTREAM + name, "sha256": digest(path)}
        if name.endswith("/espos_time.c"):
            if body != (REFERENCE / "espos_time.c").read_bytes() or body.count(b"#if RHINO_CONFIG_SCHED_RR > 0\n") != 1 or body.count(b"#endif\n") != 1:
                raise ValueError("native SDK RR compatibility guard differs from measured reference")
            body = body.replace(b"#if RHINO_CONFIG_SCHED_RR > 0\n", b"").replace(b"#endif\n", b"").rstrip(b"\n")
            row.update(upstream_body_sha256=hashlib.sha256(body).hexdigest(),
                difference="retained FIFO/RR field guard and trailing blank-line normalization")
        expected.append(row)
        upstream_bodies.append(body)
    proof = directory / "official-native-source.json"
    if verify_upstream:
        for (name, path), row, body in zip(source_files, expected, upstream_bodies):
            original = urlopen(row["url"], timeout=60).read()
            if "difference" in row: original = original.rstrip(b"\n")
            if original != body:
                raise ValueError("native source differs from fixed official version: " + name)
        proof.write_text(json.dumps(expected, indent=2) + "\n")
    if not proof.exists() or json.loads(proof.read_text()) != expected:
        raise ValueError("fixed official native source verification missing or changed")
    if "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("original GCC5 compiler changed")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compiled = []
    units = ("app/example/hartstone/main.c", "app/example/hartstone/workload.c", "app/example/hartstone/census.c",
        "kernel/rhino/k_mm.c", *(name for name in NATIVE if name.endswith(".c")),
        "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for name in units:
        selected = [args for args in commands if name in args]
        if len(selected) != 1:
            raise ValueError("missing actual native/observer compile: " + name)
        if name.endswith(".c") and ("-DBENCH_RAM=1" not in selected[0] or
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]):
            raise ValueError("native optimization/observer compilation changed: " + name)
        if "/hartstone/" in name and not {"-DPH_EXPERIMENT=4", "-fno-fast-math", "-ffp-contract=off"} <= set(selected[0]):
            raise ValueError("original workload compiler/math flags changed")
        compiled.append(name)
    links = (directory / "link.opts").read_text()
    if "--wrap=application_start" not in links or "--wrap=krhino_task_suspend" not in links or "--gc-sections" not in links:
        raise ValueError("observer lifecycle wrappers or section collection not linked")
    port = check_native_port(directory, allow_nested=True)
    if port.startswith("historical"):
        raise ValueError("earlier invalid context-switch port selected")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    image_length((directory / "bootloader.bin").read_bytes())
    footprint = static_footprint(directory / "application.elf")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        region = symbols.get_symbol_by_name("g_mm_region")[0]
        section = elf.get_section(region["st_shndx"])
        offset = region["st_value"] - section["sh_addr"]
        if region["st_size"] != 16:
            raise ValueError("native two-region descriptor layout changed")
        values = struct.unpack("<4I", section.data()[offset:offset + 16])
        regions = [values[:2], values[2:]]
        count = symbols.get_symbol_by_name("g_region_num")[0]
        count_section = elf.get_section(count["st_shndx"])
        count_offset = count["st_value"] - count_section["sh_addr"]
        if struct.unpack_from("<I", count_section.data(), count_offset)[0] != 2:
            raise ValueError("compiled native heap region count differs")
        capacity = region_accounting(footprint["ram_sections"], regions, False)
        if symbols.get_symbol_by_name("__wrap_tm_main") or symbols.get_symbol_by_name("__wrap_tm_thread_sleep"):
            raise ValueError("unrelated Thread-Metric wrappers retained in PH4 image")
    failed = directory / "failed-config-selection"
    if "hartstone -> zephyr_condvar" not in (failed / "configure.log").read_text() or list(failed.glob("*.elf")):
        raise ValueError("configuration failure was promoted to a built/measured case")
    return {"audit": "build-only-pass", "os": "AliOS-Rhino", "measured": False,
        "official_native_files_checked": len(expected), "compiled_units_checked": compiled,
        "byte_identical_official_native_files_checked": len(expected) - 1,
        "retained_sdk_rr_compatibility_guard": True,
        "original_files_checked": list(ORIGINAL), "operational_configuration_matches_reference": True,
        "native_port_profile": port, "configured_native_tick_divisors": hardware_tick_divisors(directory, expected_hz=100),
        "static_footprint": footprint, "compiled_native_heap_regions": regions, "native_heap_capacity_bytes": capacity,
        "allocator_hook": allocator, "sdk_clock_library_matches_reference": True,
        "rom_allocator_dispatch_not_rebuilt": True, "terminal_snapshot_before_native_controller_suspend": True,
        "completion_requires_original_first_loss_marker": True, "excluded_configuration_attempts": 1,
        "board_boots": 0, "runtime_peak_reportable": False, "uninstrumented_peak_measured": False,
        "ranking_eligible": False, "energy_measured": False, "new_metric_created": False}


def machine(directory=DIRECTORY):
    check_manifest(directory, "ram-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "ram-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "ram-control-flow.txt", "executed-ram-control.py"} or \
            (directory / "executed-ram-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("unmeasured native control supplement/decoder differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "ram-control-flow.txt").read_text(), "HARTSTONE RHINO RAM CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=("abort",))
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match: continue
                encoding, target = int(match[1], 16), int(match[2], 16)
                delta = encoding >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        symbol["st_value"] == target for symbol in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("native/original/observer call differs from actual encoding")
                calls[name, match[3]] += 1
        for caller, callee, count in (("__wrap_application_start", "application_start", 1),
            ("__wrap_application_start", "report", 1), ("__wrap_application_start", "esp_clk_cpu_freq", 1),
            ("__wrap_krhino_task_suspend", "report", 1), ("__wrap_krhino_task_suspend", "krhino_task_suspend", 1),
            ("application_start", "__wrap_krhino_task_suspend", 1), ("worker", "hartstone_small_whetstone", 1),
            ("report", "bench_ram_observe", 1), ("_malloc_r", "heap_caps_malloc_default", 1),
            ("_free_r", "heap_caps_free", 1), ("_realloc_r", "heap_caps_realloc_default", 1)):
            if calls[caller, callee] != count:
                raise ValueError("original/lifecycle/native allocator call coverage differs: " + caller + " -> " + callee)
        for caller in ("k_mm_alloc", "k_mm_free", "k_mm_realloc"):
            if not calls[caller, "bench_ram_observe"]:
                raise ValueError("native allocator commit observation missing: " + caller)
        app = control["application_start"]
        if calls["application_start", "rtc_clk_cpu_freq_set"] != 1 or \
                app[0x400d5e23] != "400d5e23: 03a0a2 movi\ta10, 3" or \
                not app[0x400d5e26].endswith("<rtc_clk_cpu_freq_set>") or \
                not control["__wrap_application_start"][0x400d5bae].endswith("<esp_clk_cpu_freq>") or \
                not control["__wrap_application_start"][0x400d5be0].endswith("<report>") or \
                not control["__wrap_application_start"][0x400d5be7].endswith("<application_start>"):
            raise ValueError("native entry observation/original 240 MHz setup ordering differs")
        if literal_word(elf, app[0x400d5fdd], 10) != 4096 or literal_word(elf, app[0x400d5fe3], 8) != \
                symbols.get_symbol_by_name("malloc")[0]["st_value"] or \
                literal_word(elf, app[0x400d6042], 9) != symbols.get_symbol_by_name("worker")[0]["st_value"] or \
                not re.search(r"00a492 movi\s+a9, 0x400$", app[0x400d6049]):
            raise ValueError("actual original worker/4096-byte allocation/1024-word native stack operand differs")
        wrapper = control["__wrap_krhino_task_suspend"]
        report_at = next(address for address, row in wrapper.items() if row.endswith("<report>"))
        suspend_at = next(address for address, row in wrapper.items() if row.endswith("<krhino_task_suspend>"))
        if literal_word(elf, wrapper[0x400d5bfc], 3) != symbols.get_symbol_by_name("controller")[0]["st_value"] or \
                literal_word(elf, wrapper[0x400d5c0d], 8) != symbols.get_symbol_by_name("terminal_observed")[0]["st_value"] or \
                report_at >= suspend_at:
            raise ValueError("native controller/one-shot pre-suspend snapshot binding differs")
    return {"reachable_functions_checked": len(control), "encoded_direct_calls_checked": sum(calls.values()),
        "native_allocator_observer_call_counts": {name: calls[name, "bench_ram_observe"] for name in ("k_mm_alloc", "k_mm_free", "k_mm_realloc")},
        "original_worker_stack_bytes": 4096, "native_worker_stack_words": 1024,
        "rom_malloc_code_not_decoded_or_rebuilt": True, "board_boots": 0, "measured": False}


def capture(directory, index, build_info):
    rows = read_raw_capture(directory, index)
    lines = [row["line"] for row in rows]
    prefix = "BENCH_RAM lifecycle begin os=AliOS-Rhino family=native-rhino-region-heap window=application-through-first-loss clock_hz="
    starts = [line for line in lines if line.startswith(prefix)]
    if len(starts) != 1 or starts[0] not in (prefix + "160000000", prefix + "240000000"):
        raise ValueError("native application entry clock/window differs")
    begin = starts[0]
    entry_clock_hz = int(begin[len(prefix):])
    boundary = "BENCH_RAM lifecycle boundary=before-native-controller-suspend"
    complete = "BENCH_RAM lifecycle complete"
    conditions = "HARTSTONE conditions cpu_hz=240000000 cores=1 tick_hz=100 scheduler=priority-fifo"
    if lines.count(begin) != 1 or lines.count(boundary) != 1 or lines.count(complete) != 1 or lines[-1] != complete or \
            lines.count(conditions) != 1 or any(re.search(
                r"Guru Meditation|panic|assert failed|Brownout|watchdog|status=FAIL", line, re.I) for line in lines):
        raise ValueError("incomplete/failed native RAM clock/core/window")
    witnesses = [re.fullmatch(r"HARTSTONE native timer self-check PASS callback_prio=(\d+) worker_prios=30,29,28,27,26", line)
                 for line in lines if line.startswith("HARTSTONE native timer self-check ")]
    if len(witnesses) != 1 or not witnesses[0] or int(witnesses[0][1]) >= 26:
        raise ValueError("native timer priority/self-check witness missing")
    regions = [(position, *map(int, match.groups())) for position, line in enumerate(lines) if (match := re.fullmatch(
        r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if [tuple(row[1:]) for row in regions] != [tuple(row) for row in build_info["compiled_native_heap_regions"]]:
        raise ValueError("printed native regions differ from compiled bounds")
    capacity = region_accounting(build_info["static_footprint"]["ram_sections"], [row[1:] for row in regions], False)
    samples = [(position, match[1], *map(int, match.groups()[1:])) for position, line in enumerate(lines) if (match := re.fullmatch(
        r"BENCH_RAM lifecycle sample phase=(\S+) occupied=(\d+) peak=(\d+) observations=(\d+) invalid=(\d+)", line))]
    if [row[1] for row in samples] != ["application-start", "controller-suspend"]:
        raise ValueError("missing/duplicate native lifecycle sample phases")
    previous_peak = previous_count = 0
    for position, phase, occupied, peak, count, invalid in samples:
        if not 0 < occupied <= peak <= capacity or peak < previous_peak or count <= previous_count or invalid:
            raise ValueError("impossible/regressing native heap sample")
        previous_peak, previous_count = peak, count
    original = hartstone(directory / f"reset{index}.jsonl", "AliOS-Rhino", 4, high_resolution=True)
    if original["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("incomplete original series cannot establish RAM at first loss")
    boot = lines.index("HARTSTONE PH SERIES boot target=ESP32 os=AliOS-Rhino experiment=4")
    terminal = next(position for position, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
    if not lines.index(begin) < regions[0][0] < regions[1][0] < samples[0][0] < boot < lines.index(conditions) < terminal < samples[1][0] < \
            lines.index(boundary) < lines.index(complete):
        raise ValueError("native RAM window does not enclose the unchanged original series")
    workers = 5 + original["first_loss_step"]
    if samples[1][2] < workers * 4096:
        raise ValueError("terminal native heap cannot hold all persistent original worker stacks")
    return {"started_utc": rows[0]["utc"], "completed_utc": rows[-1]["utc"],
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw"),
        "dynamic_heap_peak_bytes": previous_peak, "observations": previous_count,
        "samples": [row[1:] for row in samples], "heap_regions": [row[1:] for row in regions],
        "application_entry_clock_hz": entry_clock_hz, "original_workload_clock_hz": 240000000,
        "entry_before_original_frequency_setup": True,
        "active_original_workers": workers, "observed_hartstone_series": original,
        "not_an_uninstrumented_performance_score": True}


def audit_full(directory=DIRECTORY):
    result = build(directory)
    control = machine(directory)
    check_manifest(directory, "capture.sha256")
    required = {f"reset{index}.{suffix}" for index in (1, 2, 3) for suffix in ("jsonl", "raw")}
    required |= {"image.sha256", "ram-control.sha256", "board-check-full.log", "image-check-full.log",
                 "flash-full.log", "run-script-full.sh", "capture_esp32_uart.py"}
    if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != required:
        raise ValueError("complete three-reset RAM capture manifest coverage differs")
    if (directory / "run-script-full.sh").read_bytes() != (ROOT / "tools/run_esp32_hartstone_ram_alios.sh").read_bytes() or \
            (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes():
        raise ValueError("physical RAM capture recipe changed")
    if (directory / "board-check-full.log").read_text().splitlines().count("MAC: 84:1f:e8:8f:55:dc") != 1:
        raise ValueError("capture preflight does not identify the common physical board")
    audit_flash(directory, "flash-full.log", 3)
    writes = [(int(size), int(offset, 16)) for size, offset in re.findall(
        r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", (directory / "flash-full.log").read_text())]
    if writes != [((directory / name).stat().st_size, offset) for name, offset in (
            ("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("verified RAM image sizes/offsets differ")
    runs = [capture(directory, index, result) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["completed_utc"]) >= datetime.fromisoformat(b["started_utc"])
           for a, b in zip(runs, runs[1:])):
        raise ValueError("independent RAM reset windows overlap")
    reference = [hartstone(REFERENCE / f"reset{index}.jsonl", "AliOS-Rhino", 4, high_resolution=True) for index in (1, 2, 3)]
    if any(row["completion"] != "FIRST_LOSS_REACHED" for row in reference):
        raise ValueError("reference cohort does not contain three complete first-loss runs")
    covered = all(row["observed_hartstone_series"]["first_loss_step"] >= max(item["first_loss_step"] for item in reference)
                  for row in runs)
    peaks = [result["static_footprint"]["static_sram_bytes"] + row["dynamic_heap_peak_bytes"] for row in runs]
    return {"audit": "pass" if covered else "reference-short-diagnostic", "os": "AliOS-Rhino", "build": result,
        "machine_control": control, "independent_resets": 3, "runs": runs, "reference_original_series": reference,
        "observed_software_ram_peak_bytes": peaks, "median_observed_software_ram_peak_bytes": statistics.median(peaks),
        "reference_worker_cohort_covered": covered, "runtime_peak_reportable": covered,
        "window": "application entry through complete first loss; native heap commits; snapshot before original controller suspension",
        "measured": True, "ranking_eligible": False, "uninstrumented_peak_measured": False,
        "stack_live_bytes_high_water_measured": False, "pre_kernel_transient_peak_measured": False,
        "allocator_internal_transient_peak_measured": False, "energy_measured": False, "new_metric_created": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--machine", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.full and (args.verify_upstream or args.machine):
        parser.error("--full already audits the frozen build and machine control")
    result = audit_full(args.directory) if args.full else build(args.directory, args.verify_upstream)
    if args.machine: result["machine_control"] = machine(args.directory)
    content = json.dumps(result, indent=2) + "\n"
    if args.output: args.output.write_text(content)
    else: print(content, end="")
