#!/usr/bin/env python3
"""Replay native Rhino original tests; retain the GCC5/legacy SDK boundary."""
import argparse
import json
import statistics
import re
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from elftools.elf.elffile import ELFFile

from audit_esp32_report import audit_image_manifest
from audit_esp32_resources import audit_cell
from audit_esp32_tm_basic import CASES, audit
from audit_esp32_tm_reboots import require_cpu2_interrupt, require_self_check

ROOT = Path(__file__).resolve().parents[1]
CONDITIONS = "Thread-Metric conditions cpu_hz=240000000 cores=1 tick_hz=100 scheduler=priority-fifo"


def check_native_port(folder, *, allow_nested=False, gcc13_noop=False):
    pinned = ROOT / "artifacts/reports/alios-native-gcc5-v2/basic_processing"
    revised = ROOT / "firmware/bsp/esp32/alios_board"
    source = (folder / "rhino-port-pinned.c").read_bytes()
    if source == (revised / "rhino-port.c").read_bytes():
        audit_image_manifest(folder, {"rhino-vectors-pinned.S"}, allow_nested=allow_nested)
        if (folder / "rhino-vectors-pinned.S").read_bytes() != (revised / "rhino-vectors.S").read_bytes():
            raise ValueError("unreviewed Rhino coprocessor handler")
        with (folder / "application.elf").open("rb") as image:
            elf = ELFFile(image)
            symbols = elf.get_section_by_name(".symtab").get_symbol_by_name("cpu_intrpt_switch")
            sizes = (8, 11) if gcc13_noop else (8,)
            if not symbols or len(symbols) != 1 or symbols[0]["st_size"] not in sizes:
                raise ValueError("corrected native IRQ switch not witnessed in ELF")
            symbol = symbols[0]
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"] - section["sh_addr"]
            code = section.data()[offset:offset + symbol["st_size"]]
            call = 6 if len(code) == 11 else 3
            if code[:3] != bytes.fromhex("364100") or code[call] & 0x3f != 0x25 or \
                    code[call + 3:] != bytes.fromhex("1df0") or \
                    (call == 6 and code[3:6] != bytes.fromhex("101120")):
                raise ValueError("native IRQ switch still writes the outgoing TCB")
            displacement = int.from_bytes(code[call:call + 3], "little") >> 6
            if displacement & (1 << 17):
                displacement -= 1 << 18
            target = ((symbol["st_value"] + call + 4) & ~3) + displacement * 4
            setup = elf.get_section_by_name(".symtab").get_symbol_by_name("_frxt_setup_switch")
            if not setup or len(setup) != 1 or target != setup[0]["st_value"]:
                raise ValueError("native IRQ switch does not call the reviewed deferred-switch helper")
            handlers = elf.get_section_by_name(".symtab").get_symbol_by_name("_xt_coproc_exc")
            next_handlers = elf.get_section_by_name(".symtab").get_symbol_by_name("_xt_lowint1")
            if not handlers or len(handlers) != 1 or not next_handlers or len(next_handlers) != 1:
                raise ValueError("native coprocessor handler not witnessed in ELF")
            handler = handlers[0]
            section = elf.get_section(handler["st_shndx"])
            offset = handler["st_value"] - section["sh_addr"]
            # This pinned assembly emits zero-size function labels; use the next handler boundary.
            size = next_handlers[0]["st_value"] - handler["st_value"]
            if next_handlers[0]["st_shndx"] != handler["st_shndx"] or not 0 < size <= 512:
                raise ValueError("unreviewed coprocessor handler boundaries")
            code = section.data()[offset:offset + size]
            # CPUID extraction must lead directly to owner-array indexing, not a FreeRTOS TCB write.
            core_id = bytes.fromhex("30eb03303d04")
            if code.count(core_id) != 1 or core_id + bytes.fromhex("0c42302282") not in code:
                raise ValueError("native coprocessor handler retains an unreviewed TCB-offset path")
        profile = "IRQ-current-TCB-deferred; Rhino-safe coprocessor handler"
    elif source == (pinned / "rhino-port-pinned.c").read_bytes():
        profile = "historical legacy early-IRQ-current-TCB"
    else:
        raise ValueError("unreviewed native Rhino context-switch port")
    if (folder / "rhino-portasm-pinned.S").read_bytes() != (pinned / "rhino-portasm-pinned.S").read_bytes():
        raise ValueError("unreviewed native context-switch assembly")
    return profile


def check_conditions(rows):
    if sum(row["line"] == CONDITIONS for row in rows) != 1:
        raise ValueError("missing effective single-core 240 MHz/100 Hz FIFO condition witness")
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
        raise ValueError("expected one early independent ROM reset")
    if any(token in row["line"] for row in rows for token in
           ("ASSERT", "FATAL", "watchdog", "Exception", "reboot!")):
        raise ValueError("native kernel failure in UART")


def check_compilation(folder, case):
    required = {"app/example/thread_metric/main.c", "app/example/thread_metric/port.c",
                "app/example/thread_metric/test.c", "kernel/rhino/k_sched.c",
                "kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_queue.c",
                "kernel/rhino/k_mm.c", "platform/arch/xtensa/lx6/port.c"}
    found = set()
    for line in (folder / "build.log").read_text().replace("\\\n", " ").splitlines():
        if not line.startswith("xtensa-esp32-elf-gcc "):
            continue
        args = shlex.split(line)
        sources = [source for source in required if source in args]
        if not sources:
            continue
        if len(sources) != 1 or sources[0] in found or "-c" not in args or \
                [arg for arg in args if arg.startswith("-DTM_TEST_")] != [f"-DTM_TEST_{case}=1"] or \
                [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("native Rhino/test compile command selection or optimization differs")
        found.add(sources[0])
    if found != required:
        raise ValueError("native Rhino/test compilation not fully witnessed")


def check_irq_adapter_correction(case):
    original = (ROOT / "firmware/bsp/esp32/alios_thread_metric/port.c").read_text()
    corrected = (ROOT / "firmware/bsp/esp32/alios_thread_metric_irq/port.c").read_text()
    if case not in ("interrupt_processing", "interrupt_preemption_processing") or \
            original.count("    krhino_intrpt_enter();\n") != 1 or original.count("    krhino_intrpt_exit();\n") != 1 or \
            corrected != original.replace("    krhino_intrpt_enter();\n", "").replace("    krhino_intrpt_exit();\n", ""):
        raise ValueError("IRQ correction exceeds removal of duplicate native vector nesting")


def audit_case(folder, case, *, irq_vector_corrected=False):
    if irq_vector_corrected:
        check_irq_adapter_correction(case)
    original_name = f"tm_{case}_test.c"
    required = {"main.c", "port.c", "test.c", "tm_override.h", original_name,
                "sdkconfig.h", "k_config.h", "config", "compiler.txt", "build.log",
                "rhino-port-pinned.c", "rhino-portasm-pinned.S", "xtensa_rtos.h",
                "app-aos.mk", "espos_time.c", "examples-Config.in", "boards-Config.in"}
    audit_image_manifest(folder, required)
    port_profile = check_native_port(folder)
    if not port_profile.startswith("historical"):
        check_compilation(folder, case)
    app = ROOT / "firmware/bsp/esp32/alios_thread_metric"
    for name in ("main.c", "port.c", "test.c", "tm_override.h"):
        source = ROOT / "firmware/bsp/esp32/alios_thread_metric_irq/port.c" if irq_vector_corrected and name == "port.c" else app / name
        if (folder / name).read_bytes() != source.read_bytes():
            raise ValueError(f"unreviewed Rhino adapter source: {name}")
    original = ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / original_name
    if (folder / original_name).read_bytes() != original.read_bytes():
        raise ValueError("published timed body changed")
    if "5.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("wrong legacy compiler")
    configuration = (folder / "config").read_text()
    for marker in ('AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="thread_metric"',
                   'AOS_COMP_RHINO=y'):
        if marker not in configuration:
            raise ValueError("wrong native board/application/kernel")
    board = ROOT / "firmware/bsp/esp32/alios_board/esp32bench"
    for name in ("sdkconfig.h", "k_config.h"):
        if (folder / name).read_bytes() != (board / name).read_bytes():
            raise ValueError("unreviewed effective kernel/clock configuration")
    if (folder / "espos_time.c").read_bytes() != (board.parent / "espos_time.c").read_bytes():
        raise ValueError("unreviewed no-round-robin SDK compatibility change")
    symbols = (folder / "symbols.txt").read_text()
    for name in ("krhino_task_create", "krhino_task_suspend", "krhino_task_resume"):
        if not any(line.endswith(" " + name) for line in symbols.splitlines()):
            raise ValueError("native Rhino task code missing from ELF")
    cell = audit_cell(folder, "AliOS-Rhino", case)
    checks = {"message_processing": "queue", "synchronization_processing": "semaphore",
              "memory_allocation": "memory"}
    previous_end = None
    totals, records = [], []
    for reset in (1, 2, 3):
        capture = folder / f"reset{reset}.jsonl"
        rows = [json.loads(line) for line in capture.read_text().splitlines()]
        check_conditions(rows)
        result = audit(capture, "AliOS-Rhino", case)
        if not 25 < result["host_window_seconds"][0] < 40:
            raise ValueError("first original 30 s window not witnessed")
        if case in checks:
            require_self_check(rows, checks[case])
        if case.startswith("interrupt_"):
            require_cpu2_interrupt(rows)
        started = datetime.fromisoformat(rows[0]["utc"]) - timedelta(seconds=rows[0]["elapsed_s"])
        if previous_end is not None and started <= previous_end:
            raise ValueError("independent reset records overlap")
        previous_end = started + timedelta(seconds=rows[-1]["elapsed_s"])
        totals.append(result["original_window_totals"][0])
        records.append(result)
    cell.update({"first_window_values": totals, "first_window_median": statistics.median(totals),
                 "independent_resets": 3, "runs": records, "native_port_profile": port_profile,
                 "ranking_eligible": False})
    return cell


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cases = [args.case] if args.case else list(CASES)
    result = {"status": "PASS", "cells": [audit_case(args.directory.resolve() / case, case)
                                          for case in cases],
              "conditions": {"cpu_hz": 240000000, "cores": 1, "tick_hz": 100,
                             "scheduler": "native Rhino priority FIFO, no RR",
                             "compiler": "Xtensa GCC 5.2.0", "timed_body": "original O0"},
              "comparison_boundary": "legacy GCC5/prebuilt SDK/background services differ",
              "ranking_eligible": False}
    content = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
