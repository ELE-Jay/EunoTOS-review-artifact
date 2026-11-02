#!/usr/bin/env python3
"""Replay Rhino's original one-shot IRQ, with native vector/archive boundaries."""
import argparse
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
from audit_esp32_rhealstone_irq import ROOT, PORT, BASE, OFFICIAL, GUARD, original_formula
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_zephyr_isr import irq_archive_member, rhino_vector_dispatch
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from collect_esp32_rhealstone_irq_control import FUNCTIONS, NORETURN
from collect_esp32_rhealstone_irq_alios_control import EXTRA, collector_source

NATIVE = ("kernel/rhino/k_task.c", "kernel/rhino/k_sched.c", "kernel/rhino/k_sys.c",
    "kernel/rhino/include/k_task.h", "kernel/rhino/include/k_sched.h", "kernel/rhino/include/k_sys.h",
    "kernel/rhino/include/k_default_config.h", "platform/arch/xtensa/lx6/xtensa_init.c",
    "platform/arch/xtensa/lx6/xtensa_intr.c", "platform/arch/xtensa/lx6/include/port.h",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h", "platform/mcu/esp32/espos/platform/rhino/espos_scheduler.c",
    "platform/arch/xtensa/lx6/portasm.S")
ARCHIVE = "platform/mcu/esp32/lib/libesp32.a"
BEGIN = "RHEALSTONE BEGIN RHILATENCY AliOS-Rhino clock=240 cores=1 tick=100 timer=ccount unit=cycles"


def native_path(directory, name):
    return directory / ("rhino-portasm-pinned.S" if name == NATIVE[-1] else "native-source/" + name)


def verify_official(directory):
    rows = []
    for name in (*NATIVE, ARCHIVE):
        with urlopen(UPSTREAM + name, timeout=60) as response:
            data = response.read()
        if data != native_path(directory, name).read_bytes():
            raise ValueError(("Rhino fixed official source/archive differs", name))
        rows.append({"path": name, "url": UPSTREAM + name, "sha256": hashlib.sha256(data).hexdigest()})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    reset = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "RHEALSTONE IRQ SOURCE peripheral=26 requested_level=1 cpu=0 input=13 low_priority=40",
        "RHEALSTONE IRQ COMPLETE actual_irqs=1 released=1 kernel_nest=0 arch_nest=0 original_iterations=1", "RHEALSTONE END")
    if len(reset) != 1 or reset[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RHEALSTONE END" or lines.count("bootload image") != 1 or \
            sum("cpu_start: Pro cpu start user code" in line for line in lines) != 1 or \
            any(re.search(r"FAIL|Guru Meditation|panic|assert failed|watchdog|Brownout|Error ==> ", line, re.I) for line in lines):
        raise ValueError("Rhino original IRQ boot/source/completion differs")
    result = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (-?\d+)", line))]
    trace = [list(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+) value2=(\d+)", line))]
    if len(result) != 1 or len(trace) != 1 or any(not 0 < value < 2**32 for value in trace[0]) or \
            trace[0][2] <= trace[0][1] or original_formula(trace[0], 1, (2, 1, None)) != result[0] or result[0] <= 0:
        raise ValueError("Rhino original single-shot subtraction differs")
    ordered = [lines.index(BEGIN), lines.index(required[1]),
        next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: Interrupt Latency - ")),
        lines.index(required[2]), next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE TIMER_READS ")),
        lines.index("RHEALSTONE END")]
    if ordered != sorted(ordered):
        raise ValueError("Rhino original IRQ phases differ")
    return {"original_single_shot_cycles": result[0], "timer_reads_cycles": trace[0],
        "original_iterations": 1, "actual_irqs": 1, "native_irq_released": True,
        "native_arch_and_kernel_nesting_restored": True,
        "start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory):
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256", "archive-recovery.sha256"):
        check_manifest(directory, name)
    if {line.split(maxsplit=1)[1] for line in (directory / "archive-recovery.sha256").read_text().splitlines()} != \
            {"application.elf", "application.bin", "build.log"}:
        raise ValueError("Rhino completed-build archive-recovery binding differs")
    for name, (_, sha) in OFFICIAL.items():
        if digest(directory / "source" / name) != sha:
            raise ValueError("original Rhealstone source differs")
    original = (directory / "source/ilatency.c").read_text()
    if original.count(GUARD) != 1 or (directory / "ported-ilatency.c").read_text() != \
            original.replace(GUARD, "    !rh_native_priority_scheduler()"):
        raise ValueError("native guard patch changed original measurement body")
    for saved, current in (("port.c", PORT / "alios/port.c"), ("native_rhealstone_port.h", BASE / "alios/port.c"),
            ("aos.mk", PORT / "alios/aos.mk"), ("Config.in", PORT / "alios/Config.in"),
            ("examples-Config.in", PORT / "alios/examples-Config.in"),
            ("scheduler-guard.patch", PORT / "scheduler-guard.patch"),
            ("build_esp32_rhealstone_irq_alios.sh", ROOT / "tools/build_esp32_rhealstone_irq_alios.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_irq_alios.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError(("Rhino original IRQ adapter/build/acquisition differs", saved))
    for source in (BASE / "include", PORT / "include"):
        for path in source.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "include" / path.relative_to(source)).read_bytes():
                raise ValueError("Rhino original IRQ header differs")
    if (directory / "timesys.h").read_bytes() != (directory / "source/timesys.h").read_bytes():
        raise ValueError("compiled original timing formula differs")
    for saved, current in (("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"),
            ("sdkconfig.h", "esp32bench/sdkconfig.h"), ("k_config.h", "esp32bench/k_config.h")):
        if (directory / saved).read_bytes() != (ROOT / "firmware/bsp/esp32/alios_board" / current).read_bytes():
            raise ValueError("Rhino native board/IRQ/configuration port differs")
    if (directory / "collect-irq-control.py").read_text() != collector_source(
            (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()) or \
            {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != \
            {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("Rhino frozen original/native control coverage differs")
    proof = json.loads((directory / "official-native-source.json").read_text())
    if len(proof) != len(NATIVE) + 1 or {row["path"] for row in proof} != set((*NATIVE, ARCHIVE)) or any(
            row["url"] != UPSTREAM + row["path"] or digest(native_path(directory, row["path"])) != row["sha256"] for row in proof):
        raise ValueError("Rhino fixed native source/archive inventory differs")
    if irq_archive_member(native_path(directory, ARCHIVE)) != (directory / "sdk-intr_alloc.o").read_bytes():
        raise ValueError("Rhino native SDK IRQ archive/member differs")
    map_text = (directory / "application.map").read_text()
    if ARCHIVE not in (directory / "link.opts").read_text() or any(not re.search(
            r"\.text\." + name + r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*libesp32\.a\(intr_alloc\.o\)", map_text)
            for name in ("esp_intr_alloc", "esp_intr_free", "esp_intr_get_cpu", "esp_intr_get_intno")):
        raise ValueError("Rhino native SDK IRQ member not bound to linked firmware")
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="rhealstone_irq"', 'AOS_APP_RHEALSTONE_IRQ=y'} <= \
            set((directory / "config").read_text().splitlines()) or "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("Rhino actual native target/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compiled = ("app/example/rhealstone_irq/port.c", "app/example/rhealstone_irq/ilatency.c",
        *(name for name in NATIVE if name.endswith((".c", ".S"))),
        "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for name in compiled:
        selected = [args for args in commands if name in args]
        if len(selected) != 1 or any(arg.startswith("-DRHINO_CONFIG_TICKS_PER_SECOND=") for arg in selected[0]) or \
                (not name.endswith(".S") and ([arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or
                    "-DAOS_NO_WIFI" not in selected[0])) or \
                (name.endswith(".S") and ("-include" not in selected[0] or "out/config/autoconf.h" not in selected[0])):
            raise ValueError(("Rhino original/native actual compilation differs", name))
    divisors = hardware_tick_divisors(directory, expected_hz=100)
    vector = rhino_vector_dispatch(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, set(FUNCTIONS + EXTRA), noreturn=NORETURN)
        for source, target, count in (("Init", "rh_native_priority_scheduler", 1), ("Init", "benchmark_timer_initialize", 2),
                ("Init", "benchmark_timer_read", 2), ("Task_1", "benchmark_timer_initialize", 1),
                ("Task_1", "rh_cause_irq", 1), ("Task_1", "rh_install_irq", 1),
                ("Isr_handler", "benchmark_timer_read", 1), ("Isr_handler", "rh_clear_irq", 1),
                ("rh_install_irq", "esp_intr_alloc", 1), ("rh_install_irq", "esp_intr_get_cpu", 1),
                ("rh_end", "esp_intr_free", 1), ("rtems_task_start", "krhino_task_resume", 1),
                ("rtems_task_exit", "krhino_task_del", 1), ("rh_native_priority_scheduler", "esp_clk_cpu_freq", 1),
                ("rh_native_priority_scheduler", "krhino_cur_task_get", 1),
                ("application_start", "krhino_task_create", 1), ("application_start", "krhino_task_suspend", 1),
                ("create", "krhino_task_create", 1), ("legacy_rtems_task_create", "create", 1),
                ("espos_isr_enter", "krhino_intrpt_enter", 1), ("espos_isr_exit", "krhino_intrpt_exit", 1)):
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$",
                "\n".join(control[source].values()), re.M)
            if len(rows) != count:
                raise ValueError(("Rhino encoded native call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("Rhino encoded native call differs")
        for source in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if not any("rsr.ccount" in row for row in control[source].values()):
                raise ValueError("Rhino native timer CCOUNT instruction differs")
        references = [("rh_cause_irq", 0x3ff000e4), ("rh_clear_irq", 0x3ff000e4),
            ("Task_1", symbols.get_symbol_by_name("Isr_handler")[0]["st_value"]),
            ("rh_native_priority_scheduler", (-240000000) & 0xffffffff), ("rh_native_priority_scheduler", 2400000)]
        references += [("rh_native_priority_scheduler", symbols.get_symbol_by_name(name)[0]["st_value"])
            for name in ("g_sched_lock", "g_intrpt_nested_level", "krhino_sys_nest", "_xt_tick_divisor")]
        references += [(source, symbols.get_symbol_by_name(name)[0]["st_value"])
            for source in ("rh_clear_irq", "rh_end") for name in ("g_intrpt_nested_level", "krhino_sys_nest")]
        for source, expected in references:
            found = False
            for row in control[source].values():
                match = re.match(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+\w+, ([0-9a-f]+) <", row)
                if not match:
                    continue
                address, code, literal = (int(value, 16) for value in match.groups())
                if code & 0xf != 1 or ((address + 3) & ~3) + ((code >> 8) | -65536) * 4 != literal:
                    raise ValueError("Rhino encoded literal address differs")
                sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                    s["sh_addr"] <= literal and literal + 4 <= s["sh_addr"] + s["sh_size"]]
                if len(sections) != 1:
                    raise ValueError("Rhino IRQ literal not mapped to ELF")
                found |= struct.unpack_from("<I", sections[0].data(), literal - sections[0]["sh_addr"])[0] == expected
            if not found:
                raise ValueError("Rhino native trigger/clear/direct ISR/clock/context literal missing")
        guard = "\n".join(control["rh_native_priority_scheduler"].values())
        if not all(re.search(pattern, guard) for pattern in (r"7f0a82 l8ui\s+a8, a10, 127", r"14a032 movi\s+a3, 20",
                r"359837 bne\s+a8, a3,", r"192a32 l32i\s+a3, a10, 100", r"2f1366 bnei\s+a3, 1,")):
            raise ValueError("Rhino actual Init priority/state guard differs")
    footprint = audit_cell(directory, "AliOS-Rhino", "rhealstone-single-irq", observation=True, recursive_manifest=True)
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("Rhino original IRQ independent resets overlap")
    values = [row["original_single_shot_cycles"] for row in captures]
    return {"audit": "pass", "os": "AliOS-Rhino", "resets": 3, "metric_count": 1, "original_iterations": 1,
        "original_single_shot_cycles": values, "median_of_three_single_shots_us": statistics.median(values) / 240,
        "original_measurement_body_preserved": True, "native_scheduler_guard_adapted": True,
        "unmodified_official_source": False, "native_source_files": len(NATIVE), "reachable_functions": len(FUNCTIONS + EXTRA),
        "actual_native_compiled_units_checked": len(compiled), "captures": captures, "footprint": footprint,
        "native_source_identity": proof, "native_source_proof_sha256": digest(directory / "official-native-source.json"),
        "prebuilt_native_irq_archive_sha256": digest(native_path(directory, ARCHIVE)),
        "prebuilt_native_irq_archive_source_rebuilt": False, "native_vector_indirect_nesting_calls": vector,
        "hardware_tick_divisors": divisors, "native_irq_source": 26, "native_irq_input": 13,
        "native_worker_priority": 40, "elf_bin_all_initialized_sections_bound": True,
        "archive_recovery_firmware_rebuilt": False, "archive_recovery_binding_sha256": digest(directory / "archive-recovery.sha256"),
        "ranking_eligible": False, "external_gpio_interrupt_entry_measured": False,
        "boundary": "original one CPU software IRQ per boot, not unused 50000 macro or mean; native Rhino priority FIFO/100Hz/single-core/240MHz/GCC5.2, actual Init20/state/unlocked/non-ISR/clock/hardware-divisor guard, original low priority254 maps to native40; source26/level1/input13 directly registers original handler; native vector enters kernel once before timestamp, adapter has no duplicated entry/exit; clear checks architecture/kernel nesting after original first timestamp, native IRQ free success and both nestings zero after return; original warmup954 vs overhead15 and trigger/vector/cache costs retained; fixed official prebuilt SDK IRQ archive/member is linked, not source rebuilt; no external GPIO, cache normalization, cross-OS ranking, tail latency or general task/heap cleanup claim"}


def render_table(result):
    if result["audit"] != "pass" or result["resets"] != 3 or result["original_iterations"] != 1:
        raise ValueError("incomplete Rhino original one-shot IRQ cohort")
    return "\n".join(("| Original Rhealstone IRQ port / OS | Original single-shot cycles (three boots) | Approximate single-shot us (three boots) |",
        "| --- | --- | --- |", "| Original IRQ port / AliOS-Rhino | " + " / ".join(map(str, result["original_single_shot_cycles"])) +
        " | " + " / ".join(f"{value / 240:.3f}" for value in result["original_single_shot_cycles"]) + " |"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-official", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_official:
        verify_official(args.directory)
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
