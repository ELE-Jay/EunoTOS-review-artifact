#!/usr/bin/env python3
"""Audit unchanged NuttX PH4 and its separately instrumented native RAM image."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_image_manifest, audit_flash
from audit_esp32_resources import audit_elf_image, static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_hartstone_series import audit as hartstone
from audit_esp32_riot_original import digest, check_manifest
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_hartstone_ram_nuttx_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/ram-hartstone-nuttx-v3/nuttx/ph4"
REFERENCE = ROOT / "artifacts/reports/hartstone-native-us-v1/nuttx/ph4"
PORT = ROOT / "firmware/bsp/esp32/resource_census/hartstone_lifecycle_nuttx"
UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
ORIGINAL = ("hartstone_series.c", "small_whetstone.c", "small_whetstone.h", "ph_rt_timer.h", "ph_us_schedule.h", "Kconfig")
NATIVE = ("mm/mm_heap/mm.h", "mm/mm_heap/mm_lock.c", "mm/mm_heap/mm_initialize.c",
    "mm/mm_heap/mm_malloc.c", "mm/mm_heap/mm_free.c", "mm/mm_heap/mm_realloc.c",
    "mm/mm_heap/mm_mallinfo.c", "mm/mm_heap/mm_foreach.c", "mm/umm_heap/umm_malloc.c",
    "mm/umm_heap/umm_free.c", "mm/umm_heap/umm_initialize.c", "mm/umm_heap/umm_heap.h", "sched/pthread/pthread_create.c",
    "sched/pthread/pthread_join.c", "sched/pthread/pthread_exit.c",
    "arch/xtensa/src/common/xtensa_createstack.c", "arch/xtensa/src/common/xtensa_releasestack.c", "arch/xtensa/src/esp32/esp32_allocateheap.c",
    "arch/xtensa/src/esp32/esp32_clockconfig.c", "arch/xtensa/src/esp32/esp32_clockconfig.h")
FREELIST_NATIVE = NATIVE + ("mm/mm_heap/mm_addfreechunk.c", "mm/mm_heap/mm_shrinkchunk.c",
    "mm/mm_heap/mm_memalign.c", "mm/mm_heap/mm_size2ndx.c")
FREELIST_DIRECTORY = ROOT / "artifacts/reports/ram-hartstone-nuttx-v4/nuttx/ph4"


def build(directory=DIRECTORY, verify_upstream=False, *, freelist=False):
    native = FREELIST_NATIVE if freelist else NATIVE
    observer = PORT.parent / "hartstone_lifecycle_nuttx_freelist/nuttx.c" if freelist else PORT / "nuttx.c"
    recipe = ROOT / "tools" / ("build_esp32_hartstone_ram_nuttx_freelist.sh" if freelist else "build_esp32_hartstone_ram_nuttx.sh")
    audit_image_manifest(directory, {"application.elf", "application.bin", "bootloader.bin", "partitions.bin",
        "application.map", "config", "reference-config", "compiler.txt", "build.log", "census.c", "base-observer.c",
        "Makefile", "original-Makefile", "pool_check.h", "tm_override.h", "build-script.sh", "symbols.txt",
        "disassembly.txt", *ORIGINAL, *("native-source/" + name for name in native)}, allow_nested=True)
    for name in ORIGINAL:
        if (directory / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("changed original PH4 file: " + name)
    for name, expected in (("census.c", observer), ("base-observer.c", PORT.parent / "nuttx.c"),
            ("Makefile", PORT / "Makefile"), ("original-Makefile", REFERENCE / "Makefile"),
            ("pool_check.h", PORT.parent / "pool_check.h"),
            ("tm_override.h", ROOT / "firmware/bsp/esp32/nuttx_thread_metric/tm_override.h"),
            ("build-script.sh", recipe)):
        if (directory / name).read_bytes() != expected.read_bytes():
            raise ValueError("changed observer or build recipe: " + name)
    original_make = (REFERENCE / "Makefile").read_text()
    observed_make = (directory / "Makefile").read_text().replace(
        "CSRCS    += census.c\nCFLAGS   += -I. -I$(TOPDIR)/mm/mm_heap\n", "")
    if observed_make != original_make:
        raise ValueError("native build changes more than adding the RAM observer/include paths")
    if (directory / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes():
        raise ValueError("native PH4 reference configuration changed")
    operative = lambda path: [line for line in path.read_text().splitlines() if not line.startswith("CONFIG_BASE_DEFCONFIG=")]
    if operative(directory / "config") != operative(REFERENCE / "config"):
        raise ValueError("native PH4 operational configuration differs from measured reference")
    for name in ("application.elf", "application.bin", "build.log"):
        if (directory / "failed-archive-path").exists() and (directory / name).read_bytes() != (directory / "failed-archive-path" / name).read_bytes():
            raise ValueError("archive recovery changed compiled image or actual compile evidence")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in (directory / "application.elf").read_bytes():
        raise ValueError("original compiler not proven")
    config = (directory / "config").read_text().splitlines()
    required = {"CONFIG_BUILD_FLAT=y", "CONFIG_MM_REGIONS=3", "CONFIG_MM_HEAP_MEMPOOL_THRESHOLD=0",
        "CONFIG_MM_BACKTRACE=-1", "CONFIG_EXAMPLES_HARTSTONE_PH_EXPERIMENT=4",
        "CONFIG_EXAMPLES_HARTSTONE_HIGH_RES=y", "CONFIG_ESP32_RT_TIMER=y",
        "CONFIG_ESP32_RT_TIMER_TASK_PRIORITY=223", "CONFIG_ESP32_RT_TIMER_TASK_STACK_SIZE=2048",
        "CONFIG_USEC_PER_TICK=1000", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240",
        "CONFIG_LIBM_TOOLCHAIN=y", "CONFIG_EXAMPLES_HARTSTONE_PRIORITY=50",
        "CONFIG_EXAMPLES_HARTSTONE_STACKSIZE=8192", "CONFIG_IDLETHREAD_STACKSIZE=3072"}
    if not required <= set(config) or {"CONFIG_SMP=y", "CONFIG_MM_KERNEL_HEAP=y"} & set(config):
        raise ValueError("native clock/core/allocator/timer/thread profile changed")
    proof = directory / "official-native-source.json"
    expected = [{"path": name, "url": UPSTREAM + name, "sha256": digest(directory / "native-source" / name)} for name in native]
    if verify_upstream:
        for row in expected:
            if urlopen(row["url"], timeout=60).read() != (directory / "native-source" / row["path"]).read_bytes():
                raise ValueError("native file differs from official fixed source: " + row["path"])
        proof.write_text(json.dumps(expected, indent=2) + "\n")
    if not proof.exists() or json.loads(proof.read_text()) != expected:
        raise ValueError("native official-source verification missing or changed")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if "xtensa-esp32-elf-gcc -c " in line]
    compiled = []
    names = ("census.c", "hartstone_series.c", "small_whetstone.c", *(Path(name).name for name in native if name.endswith(".c")))
    for name in names:
        selected = [args for args in commands if any(Path(arg).name == name for arg in args)]
        if name in ("pthread_create.c", "pthread_exit.c"):
            selected = [args for args in selected if any(arg.endswith("/nuttx/sched") for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("missing actual native/observer compile or optimization: " + name)
        if name in ("census.c", "hartstone_series.c", "small_whetstone.c") and not {
                "-DPH_EXPERIMENT=4", "-fno-fast-math", "-ffp-contract=off"} <= set(selected[0]):
            raise ValueError("changed original workload compiler/math flags")
        compiled.append(name)
    if not any("--wrap=hartstone_main" in line and "--wrap=mm_unlock" in line and "xtensa-esp32-elf-ld" in line
            for line in (directory / "build.log").read_text().splitlines()):
        raise ValueError("native main/allocator wrappers not linked")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        for name in ("hartstone_main", "__wrap_hartstone_main", "__wrap_mm_unlock", "mm_unlock", "worker",
                "pthread_create", "pthread_join", "up_create_stack", "mm_initialize", "mm_addregion", "esp_clk_cpu_freq"):
            if not symbols.get_symbol_by_name(name):
                raise ValueError("original/native/observer linked symbol missing: " + name)
    result = {"audit": "build-only-pass", "measured": False, "os": "NuttX",
        "official_native_files_checked": len(native), "compiled_units_checked": compiled,
        "original_files_checked": list(ORIGINAL), "operational_configuration_matches_reference": True,
        "only_build_taint_label_differs": True,
        "archive_recovery_image_unchanged": True if (directory / "failed-archive-path").exists() else None,
        "static_footprint": static_footprint(directory / "application.elf"),
        "native_heap_control_context_requires_separate_accounting": True,
        "ranking_eligible": False, "uninstrumented_peak_measured": False, "energy_measured": False,
        "new_metric_created": False}
    if freelist:
        failed = directory / "failed-archive-path.sh"
        if failed.exists() and 'cp "$0" "$output/build-script.sh"' not in failed.read_text():
            raise ValueError("archive-path recovery witness differs")
        with (directory / "application.elf").open("rb") as stream:
            symbols = ELFFile(stream).get_section_by_name(".symtab")
            if not symbols.get_symbol_by_name("observe_freelist_locked") or not symbols.get_symbol_by_name("observe_locked") or \
                    symbols.get_symbol_by_name("unused_region_walk_unlock"):
                raise ValueError("free-list and endpoint oracle linkage differs")
        result.update(observer="native-free-chain-at-heap-commit", endpoint_oracle="original-region-walk-under-same-lock",
            board_boots=0, runtime_peak_reportable=False, fewer_observer_cycles_verified_on_board=False,
            reference_worker_cohort_covered=False, archive_path_recovery_without_rebuild=True if failed.exists() else None)
    return result


def freelist_machine(directory=FREELIST_DIRECTORY):
    from collect_esp32_hartstone_ram_nuttx_freelist_control import FUNCTIONS as names, collector_source as decoder
    check_manifest(directory, "ram-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "ram-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "ram-control-flow.txt", "executed-ram-control.py"} or \
            (directory / "executed-ram-control.py").read_text() != decoder((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("free-chain build-only control supplement or decoder differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "ram-control-flow.txt").read_text(), "HARTSTONE NUTTX FREELIST CONTROL",
            elf, symbols, set(names), noreturn=("_exit", "up_exit"))
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match: continue
                encoding, target = int(match[1], 16), int(match[2], 16)
                delta = encoding >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        symbol["st_value"] == target for symbol in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("free-chain/native/original call differs from actual encoding")
                calls[name, match[3]] += 1
        expected = (("__wrap_hartstone_main", "hartstone_main", 1), ("__wrap_hartstone_main", "report", 2),
            ("report", "mallinfo", 1), ("report", "mm_lock", 1), ("report", "observe_freelist_locked", 1),
            ("report", "observe_locked", 1), ("report", "__wrap_mm_unlock", 1),
            ("__wrap_mm_unlock", "observe_freelist_locked", 1), ("__wrap_mm_unlock", "mm_unlock", 1),
            ("mm_malloc", "__wrap_mm_unlock", 1), ("mm_free", "__wrap_mm_unlock", 1),
            ("mm_realloc", "__wrap_mm_unlock", 3), ("mm_addregion", "__wrap_mm_unlock", 1),
            ("mm_foreach", "__wrap_mm_unlock", 1), ("mm_addfreechunk", "mm_size2ndx", 1),
            ("mm_shrinkchunk", "mm_addfreechunk", 1), ("hartstone_main", "pthread_create", 1),
            ("hartstone_main", "pthread_join", 1), ("worker", "hartstone_small_whetstone", 1),
            ("nx_pthread_create", "up_create_stack", 1), ("up_create_stack", "malloc", 1),
            ("up_release_stack", "free", 1), ("umm_initialize", "mm_initialize", 1),
            ("mm_initialize", "mm_addregion", 1))
        if any(calls[caller, callee] != count for caller, callee, count in expected) or \
                calls["__wrap_mm_unlock", "observe_locked"]:
            raise ValueError("free-chain commit/oracle/original call coverage differs")
        report_rows = control["report"]
        ordered = [next(address for address, row in report_rows.items() if re.search(r"call8\s+[0-9a-f]+ <" + name + r">$", row))
                   for name in ("mm_lock", "observe_freelist_locked", "observe_locked", "__wrap_mm_unlock")]
        if ordered != sorted(ordered) or not any(re.search(r"beq\s+a5, a10,", row) for row in report_rows.values()):
            raise ValueError("endpoint oracle lock/order/equality check differs")
        for name, patterns in (("observe_freelist_locked", (r"addi\s+a8, a2, 48$", r"l32i\.n\s+a3, a2, 44$",
                r"l32i\.n\s+a11, a8, 12$", r"l32i\.n\s+a11, a8, 8$", r"movi\.n\s+a8, 19$",
                r"sub\s+a2, a2, a10$")), ("mm_initialize", (r"movi\s+a4, 0x170$",)),
                ("__wrap_hartstone_main", (r"movi\s+a12, 0x170$",)),
                ("hartstone_main", (r"movi\.n\s+a11, 1$", r"slli\s+a11, a11, 12$"))):
            if any(not any(re.search(pattern, row) for row in control[name].values()) for pattern in patterns):
                raise ValueError("free-chain native field layout/capacity/context/original stack operand differs: " + name)
        def has_literal(name, target):
            return any(literal_word(elf, row, int(match[1])) == target for row in control[name].values()
                if (match := re.search(r"l32r\s+a(\d+),", row)))
        for name, symbol in (("hartstone_main", "worker"), ("umm_initialize", "g_mmheap"),
                ("observe_freelist_locked", "observed_heap"), ("observe_locked", "observed_heap")):
            if not has_literal(name, symbols.get_symbol_by_name(symbol)[0]["st_value"]):
                raise ValueError("free-chain original callback or native heap pointer binding differs")
        if symbols.get_symbol_by_name("mm_memalign"):
            raise ValueError("unexecuted allocator helper unexpectedly linked")
    return {"reachable_functions_checked": len(control), "encoded_direct_calls_checked": sum(calls.values()),
        "native_heap_control_bytes": 368, "native_bin_count": 19, "original_worker_stack_bytes": 4096,
        "native_free_node_bytes": 16, "commit_scan_before_native_unlock": True,
        "full_region_oracle_only_at_endpoint_report": True, "endpoint_pair_uses_same_heap_lock": True,
        "compiled_but_not_linked_native_helpers": ["mm_memalign"], "board_boots": 0,
        "runtime_peak_reportable": False, "ranking_eligible": False}


def machine(directory=DIRECTORY):
    check_manifest(directory, "ram-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "ram-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "pilot-capture.sha256", "ram-control-flow.txt", "executed-ram-control.py"}:
        raise ValueError("native RAM control supplement coverage differs")
    if (directory / "executed-ram-control.py").read_text() != collector_source(
            (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("entry-driven native RAM decoder changed")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "ram-control-flow.txt").read_text(), "HARTSTONE RAM CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=("_exit", "up_exit"))
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                encoding, target = int(match[1], 16), int(match[2], 16)
                offset = encoding >> 6
                if offset & (1 << 17): offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != target or not any(
                        symbol["st_value"] == target for symbol in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("native allocator/original call differs from encoded target")
                calls[name, match[3]] += 1
        for caller, callee, count in (("__wrap_hartstone_main", "hartstone_main", 1),
            ("__wrap_hartstone_main", "report", 2), ("__wrap_hartstone_main", "esp_clk_cpu_freq", 1),
            ("report", "mallinfo", 1), ("mallinfo", "mm_mallinfo", 1), ("mm_mallinfo", "mm_foreach", 1),
            ("mm_foreach", "__wrap_mm_unlock", 1), ("mm_malloc", "__wrap_mm_unlock", 1),
            ("mm_free", "__wrap_mm_unlock", 1), ("mm_realloc", "__wrap_mm_unlock", 3),
            ("__wrap_mm_unlock", "mm_unlock", 1), ("hartstone_main", "pthread_create", 1),
            ("hartstone_main", "pthread_join", 1), ("worker", "hartstone_small_whetstone", 1),
            ("pthread_create", "nx_pthread_create", 1), ("nx_pthread_create", "up_create_stack", 1),
            ("up_create_stack", "malloc", 1), ("up_release_stack", "free", 1),
            ("umm_initialize", "mm_initialize", 1), ("mm_initialize", "mm_addregion", 1)):
            if calls[caller, callee] != count:
                raise ValueError("actual original/native/observer call coverage differs: " + caller + " -> " + callee)
        if literal_word(elf, control["hartstone_main"][0x400d68eb], 12) != symbols.get_symbol_by_name("worker")[0]["st_value"] or \
                not re.search(r"1b0c movi\.n\s+a11, 1$", control["hartstone_main"][0x400d68da]) or \
                not re.search(r"11bb40 slli\s+a11, a11, 12$", control["hartstone_main"][0x400d68dc]):
            raise ValueError("actual original worker callback/4096-byte stack operand differs")
        for name, pattern in (("__wrap_hartstone_main", r"70a1c2 movi\s+a12, 0x170$"),
            ("mm_initialize", r"70a142 movi\s+a4, 0x170$"),
            ("__wrap_mm_unlock", r"c08890 sub\s+a8, a8, a9$"),
            ("__wrap_mm_unlock", r"8099f0 add\s+a9, a9, a15$"),
            ("__wrap_mm_unlock", r"c47c movi\.n\s+a4, -4$")):
            if not any(re.search(pattern, row) for row in control[name].values()):
                raise ValueError("actual heap-context size/node-mask/free-byte subtraction differs: " + name)
        if literal_word(elf, control["umm_initialize"][0x400d4913], 8) != symbols.get_symbol_by_name("g_mmheap")[0]["st_value"] or \
                literal_word(elf, control["__wrap_hartstone_main"][0x400d649c], 2) != symbols.get_symbol_by_name("observed_heap")[0]["st_value"]:
            raise ValueError("native heap context pointer binding differs")
    return {"reachable_functions_checked": len(control), "encoded_direct_calls_checked": sum(calls.values()),
        "native_heap_control_bytes": 368, "original_worker_stack_bytes": 4096,
        "observer_scan_is_before_native_unlock": True}


def pilot(directory=DIRECTORY):
    result = build(directory)
    check_manifest(directory, "pilot-capture.sha256")
    audit_flash(directory, "flash-pilot.log", 3)
    flash = (directory / "flash-pilot.log").read_text()
    writes = [(int(size), int(offset, 16)) for size, offset in re.findall(r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", flash)]
    if writes != [((directory / name).stat().st_size, offset) for name, offset in (
            ("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("pilot Flash image sizes/offsets differ")
    native = machine(directory)
    if (directory / "run-script-pilot.sh").read_bytes() != (ROOT / "tools/run_esp32_hartstone_ram_nuttx.sh").read_bytes() or \
            (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes():
        raise ValueError("pilot physical runner/raw capture recipe differs")
    rows = read_raw_capture(directory, 1, prefix="pilot-reset")
    lines = [row["line"] for row in rows]
    if sum(line.startswith("rst:0x") for line in lines) != 1 or lines.count("NuttShell (NSH)") != 1 or any(
            re.search(r"panic|assert failed|Brownout|status=FAIL", line, re.I) for line in lines):
        raise ValueError("pilot failed or lacks one independent native boot")
    begin = "BENCH_RAM lifecycle begin os=NuttX family=native-region-heap window=application-through-first-loss clock_hz=240000000"
    if lines.count(begin) != 1 or "BENCH_RAM lifecycle complete" in lines or any(
            line.startswith("HARTSTONE PH SERIES status=") for line in lines):
        raise ValueError("pilot clock/window differs or pilot unexpectedly completes")
    regions = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
        r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
    if len(regions) != 3:
        raise ValueError("native three-region heap pilot incomplete")
    region_accounting(result["static_footprint"]["ram_sections"], regions, False)
    contexts = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
        r"BENCH_RAM heap-control start=(\d+) bytes=(\d+)", line))]
    with (directory / "application.elf").open("rb") as stream:
        start = ELFFile(stream).get_section_by_name(".symtab").get_symbol_by_name("_sheap")[0]["st_value"]
    if contexts != [(start, native["native_heap_control_bytes"])] or regions[0][0] != start + contexts[0][1]:
        raise ValueError("native heap context is missing, duplicated or not adjacent to the first actual region")
    region_accounting(result["static_footprint"]["ram_sections"], regions + contexts, False)
    sample = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
        r"BENCH_RAM lifecycle sample phase=application-start occupied=(\d+) peak=(\d+) observations=(\d+) invalid=(\d+)", line))]
    if len(sample) != 1 or not 0 < sample[0][0] <= sample[0][1] <= sum(size for _, size in regions) or sample[0][2:] != (3, 0):
        raise ValueError("invalid pilot application-entry heap observation")
    original = hartstone(directory / "pilot-reset1.jsonl", "NuttX", 4, high_resolution=True, allow_incomplete=True)
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(time.utcoffset() is None for time in times) or any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("pilot UART chronology differs")
    failed = ROOT / "artifacts/reports/ram-hartstone-nuttx-v1/nuttx/ph4"
    older = ROOT / "artifacts/reports/ram-hartstone-nuttx-v2/nuttx/ph4"
    if "board/Make.defs" not in (failed / "distclean.log").read_text() or (failed / "application.elf").exists() or \
            list(failed.glob("*reset*.jsonl")):
        raise ValueError("initial stale-link failure was promoted to a built/measured case")
    audit_image_manifest(older, {"application.elf", "application.bin", "census.c", "build-script.sh"}, allow_nested=True)
    for name in ("application.elf", "application.bin", "build.log"):
        if (older / name).read_bytes() != (older / "failed-archive-path" / name).read_bytes():
            raise ValueError("superseded archive recovery changed the old image/compile evidence")
    old_rows = read_raw_capture(older, 1, prefix="pilot-reset")
    if any(row["line"] == "BENCH_RAM lifecycle complete" or row["line"].startswith("HARTSTONE PH SERIES status=")
            for row in old_rows) or datetime.fromisoformat(old_rows[-1]["utc"]) >= times[0]:
        raise ValueError("superseded incomplete pilot chronology or completion differs")
    return {**result, "audit": "incomplete-pilot-pass", "pilot_raw_sha256": digest(directory / "pilot-reset1.raw"),
        "pilot_uart_sha256": digest(directory / "pilot-reset1.jsonl"), "native_heap_regions": regions,
        "machine_control": native, "native_heap_control_context": contexts[0],
        "entry_sample": sample[0], "incomplete_original_series": original,
        "complete_first_loss_measured": False, "runtime_peak_reportable": False,
        "excluded_preflight_attempts": [
            {"cohort": "ram-hartstone-nuttx-v1", "board_boots": 0, "image_built": False,
             "reason": "stale inherited board links", "build_script_sha256": digest(failed / "build-script.sh")},
            {"cohort": "ram-hartstone-nuttx-v2", "board_boots": 1, "complete_series": False,
             "reason": "superseded setup image lacks explicit native heap-control ownership",
             "raw_sha256": digest(older / "pilot-reset1.raw"), "image_sha256": digest(older / "application.elf"),
             "archive_recovery_image_unchanged": True}]}


def interrupted(directory=DIRECTORY):
    """Preserve the failed cohort without promoting its one complete reset."""
    setup = pilot(directory)
    check_manifest(directory, "interrupted-capture.sha256")
    expected = {f"reset{index}.{suffix}" for index in (1, 2) for suffix in ("jsonl", "raw")}
    expected |= {"flash-full.log", "image-check-full.log", "run-script-full.sh",
                 "capture_esp32_uart.py", "kernel-disconnect.log"}
    if {line.split(maxsplit=1)[1] for line in (directory / "interrupted-capture.sha256").read_text().splitlines()} != expected:
        raise ValueError("interrupted cohort manifest coverage differs")
    if (directory / "capture.sha256").exists() or (directory / "reset3.jsonl").exists():
        raise ValueError("interrupted two-reset cohort was promoted to a complete trio")
    audit_flash(directory, "flash-full.log", 3)
    writes = [(int(size), int(offset, 16)) for size, offset in re.findall(
        r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", (directory / "flash-full.log").read_text())]
    if writes != [((directory / name).stat().st_size, offset) for name, offset in (
            ("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))] or \
            (directory / "run-script-full.sh").read_bytes() != (directory / "run-script-pilot.sh").read_bytes():
        raise ValueError("interrupted cohort flash/runner differs from frozen image/recipe")
    reference = [hartstone(REFERENCE / f"reset{index}.jsonl", "NuttX", 4, high_resolution=True)
                 for index in (1, 2, 3)]
    runs = []
    for index in (1, 2):
        rows = read_raw_capture(directory, index)
        lines = [row["line"] for row in rows]
        if lines.count("NuttShell (NSH)") != 1 or any(re.search(
                r"Guru Meditation|panic|assert failed|Brownout|watchdog|status=FAIL", line, re.I) for line in lines):
            raise ValueError("failed or duplicate native boot in interrupted cohort")
        begin = "BENCH_RAM lifecycle begin os=NuttX family=native-region-heap window=application-through-first-loss clock_hz=240000000"
        if lines.count(begin) != 1:
            raise ValueError("interrupted cohort clock/window differs")
        regions = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
            r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
        contexts = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
            r"BENCH_RAM heap-control start=(\d+) bytes=(\d+)", line))]
        if regions != setup["native_heap_regions"] or contexts != [setup["native_heap_control_context"]]:
            raise ValueError("interrupted cohort native heap/context bounds differ")
        samples = [(position, match[1], *map(int, match.groups()[1:])) for position, line in enumerate(lines)
                   if (match := re.fullmatch(r"BENCH_RAM lifecycle sample phase=(\S+) occupied=(\d+) peak=(\d+) observations=(\d+) invalid=(\d+)", line))]
        if [sample[1] for sample in samples] != (["application-start", "series-return"] if index == 1 else ["application-start"]):
            raise ValueError("interrupted cohort lifecycle phases differ")
        capacity = sum(size for _, size in regions)
        previous_peak = previous_count = 0
        for position, phase, occupied, peak, count, invalid in samples:
            if not 0 < occupied <= peak <= capacity or peak < previous_peak or count <= previous_count or invalid:
                raise ValueError("impossible/regressing native heap observation")
            previous_peak, previous_count = peak, count
        if samples[0][2:] != setup["entry_sample"]:
            raise ValueError("interrupted cohort initial native heap state differs")
        original = hartstone(directory / f"reset{index}.jsonl", "NuttX", 4,
                             high_resolution=True, allow_incomplete=index == 2)
        complete = original["completion"] == "FIRST_LOSS_REACHED"
        if complete != (index == 1) or lines.count("BENCH_RAM lifecycle complete") != int(complete) or \
                lines.count("BENCH_RAM lifecycle result=0") != int(complete):
            raise ValueError("interrupted cohort completion markers differ")
        boot = lines.index("HARTSTONE PH SERIES boot target=ESP32 os=NuttX experiment=4")
        if not lines.index(begin) < samples[0][0] < boot:
            raise ValueError("RAM window does not enclose original entry")
        if complete:
            terminal = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
            if not terminal < samples[1][0] < lines.index("BENCH_RAM lifecycle result=0") or \
                    lines[-1] != "BENCH_RAM lifecycle complete":
                raise ValueError("RAM window does not enclose complete original series")
            # NuttX joins each trial's workers; the final occupied value need not retain their stacks.
            if previous_peak - samples[0][2] < (5 + original["first_loss_step"]) * 4096:
                raise ValueError("observed peak cannot contain the actual original worker cohort")
        covered = complete and original["first_loss_step"] >= max(item["first_loss_step"] for item in reference)
        runs.append({"started_utc": rows[0]["utc"], "last_observed_utc": rows[-1]["utc"],
            "raw_sha256": digest(directory / f"reset{index}.raw"), "uart_sha256": digest(directory / f"reset{index}.jsonl"),
            "complete_series": complete, "original_series": original, "samples": [row[1:] for row in samples],
            "reference_worker_cohort_covered": covered,
            "diagnostic_observed_software_ram_bytes": setup["static_footprint"]["static_sram_bytes"] +
                previous_peak + contexts[0][1] if complete else None})
    if runs[0]["last_observed_utc"] >= runs[1]["started_utc"]:
        raise ValueError("independent reset windows overlap")
    kernel = (directory / "kernel-disconnect.log").read_text()
    if not all(term in kernel for term in ("USB disconnect", "ch341-uart ttyUSB0",
            "Cannot enable", "unable to enumerate USB device")):
        raise ValueError("interrupted cohort lacks native USB disconnect evidence")
    last_observed = datetime.fromisoformat(runs[1]["last_observed_utc"])
    # This preserved journal renders leon timestamps in CST (UTC+8).
    disconnects = [datetime.strptime(f"{last_observed.year} {match[1]}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc) for match in re.finditer(
            r"^([A-Z][a-z]{2}\s+\d+ \d\d:\d\d:\d\d) leon kernel: usb 1-11: USB disconnect,", kernel, re.M)]
    matching = [time for time in disconnects if 0 <= (time - last_observed).total_seconds() <= 15]
    if not matching:
        raise ValueError("native USB disconnect is not adjacent to the interrupted UART window")
    return {"audit": "interrupted-cohort-diagnostic-pass", "os": "NuttX", "attempted_resets": 2,
        "complete_resets": 1, "required_resets": 3, "runs": runs,
        "machine_control": setup["machine_control"], "reference_original_series": reference,
        "native_heap_control_bytes": setup["native_heap_control_context"][1],
        "kernel_disconnect_sha256": digest(directory / "kernel-disconnect.log"),
        "matching_kernel_disconnect_utc": min(matching).isoformat(),
        "runtime_peak_reportable": False, "ranking_eligible": False,
        "reference_worker_cohort_covered": all(row["reference_worker_cohort_covered"] for row in runs),
        "uninstrumented_peak_measured": False, "energy_measured": False, "new_metric_created": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--interrupted", action="store_true")
    parser.add_argument("--freelist", action="store_true")
    parser.add_argument("--machine", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sum((args.pilot, args.interrupted, args.verify_upstream)) > 1:
        parser.error("verify the build before the physical pilot")
    if args.freelist and (args.pilot or args.interrupted):
        parser.error("the free-chain image has no measured pilot/full cohort yet")
    directory = FREELIST_DIRECTORY if args.freelist and args.directory == DIRECTORY else args.directory
    result = interrupted(directory) if args.interrupted else pilot(directory) if args.pilot else build(directory, args.verify_upstream, freelist=args.freelist)
    if args.machine:
        result["machine_control"] = freelist_machine(directory) if args.freelist else machine(directory)
    text = json.dumps(result, indent=2) + "\n"
    if args.output: args.output.write_text(text)
    else: print(text, end="")
