#!/usr/bin/env python3
"""Replay the original one-shot IRQ on Zephyr, not a cross-OS latency ranking."""
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
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_rhealstone_irq_control import FUNCTIONS, NORETURN

HAL = "87e7902d7184a8280b4d13bce79801a723f4ddd8"
NATIVE = ("kernel/thread.c", "kernel/sched.c", "kernel/init.c",
    "include/zephyr/drivers/interrupt_controller/intc_esp32.h", "drivers/interrupt_controller/intc_esp32.c",
    "arch/xtensa/core/irq_manage.c", "arch/xtensa/core/vector_handlers.c",
    "arch/xtensa/core/xtensa_intgen.tmpl", "drivers/timer/xtensa_sys_timer.c", "hal/esp_clk.c")
EXTRA = ("sys_clock_cycle_get_32", "legacy_rtems_task_create", "k_is_in_isr", "main")
BEGIN = "RHEALSTONE BEGIN RHILATENCY Zephyr clock=240 cores=1 tick=100 timer=ccount unit=cycles"


def source_urls():
    return {name: ("https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL +
            "/components/esp_hw_support/esp_clk.c" if name.startswith("hal/") else
            "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/" + name) for name in (*NATIVE, "west.yml")}


def verify_official(directory):
    rows = []
    for name, url in source_urls().items():
        path = directory / (name if name == "west.yml" else "native-source/" + name)
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != path.read_bytes():
            raise ValueError(("Zephyr fixed official source differs", name))
        rows.append({"path": name, "url": url, "sha256": hashlib.sha256(data).hexdigest()})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    reset = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "*** Booting Zephyr OS build 3.7.0 ***",
        "RHEALSTONE IRQ SOURCE peripheral=26 requested_level=1 cpu=0 input=3 low_priority=20",
        "RHEALSTONE IRQ COMPLETE actual_irqs=1 released=1 original_iterations=1", "RHEALSTONE END")
    if len(reset) != 1 or reset[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RHEALSTONE END" or sum("Unicore bootloader" in line for line in lines) != 1 or \
            any(re.search(r"FAIL|panic|assert failed|watchdog|Brownout|Error ==> ", line, re.I) for line in lines):
        raise ValueError("Zephyr original IRQ boot/source/completion differs")
    result = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (-?\d+)", line))]
    trace = [list(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+) value2=(\d+)", line))]
    if len(result) != 1 or len(trace) != 1 or any(not 0 < value < 2**32 for value in trace[0]) or \
            trace[0][2] <= trace[0][1] or original_formula(trace[0], 1, (2, 1, None)) != result[0] or result[0] <= 0:
        raise ValueError("Zephyr original single-shot subtraction differs")
    ordered = [lines.index(BEGIN), lines.index(required[2]),
        next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: Interrupt Latency - ")),
        lines.index(required[3]), next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE TIMER_READS ")),
        lines.index("RHEALSTONE END")]
    if ordered != sorted(ordered):
        raise ValueError("Zephyr original IRQ phases differ")
    return {"original_single_shot_cycles": result[0], "timer_reads_cycles": trace[0],
        "original_iterations": 1, "actual_irqs": 1, "native_irq_released": True,
        "start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory):
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    for name, (_, sha) in OFFICIAL.items():
        if digest(directory / "source" / name) != sha:
            raise ValueError("original Rhealstone source differs")
    original = (directory / "source/ilatency.c").read_text()
    if original.count(GUARD) != 1 or (directory / "ported-ilatency.c").read_text() != \
            original.replace(GUARD, "    !rh_native_priority_scheduler()"):
        raise ValueError("native guard patch changed original measurement body")
    for saved, current in (("port.c", PORT / "zephyr/port.c"), ("native_rhealstone_port.c", BASE / "zephyr/port.c"),
            ("prj.conf", BASE / "zephyr/prj.conf"), ("CMakeLists.txt", PORT / "zephyr/CMakeLists.txt"),
            ("scheduler-guard.patch", PORT / "scheduler-guard.patch"),
            ("build_esp32_rhealstone_irq_zephyr.sh", ROOT / "tools/build_esp32_rhealstone_irq_zephyr.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_irq_zephyr.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError(("Zephyr original IRQ adapter/build/acquisition differs", saved))
    for source in (BASE / "include", PORT / "include"):
        for path in source.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "include" / path.relative_to(source)).read_bytes():
                raise ValueError("Zephyr original IRQ header differs")
    collector = (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text().replace(
        'directory = root / "downloads/rhealstone-irq-freertos-v1"', 'directory = root / "downloads/rhealstone-irq-zephyr-v1"')
    collector = collector.replace("for name in FUNCTIONS:",
        'for name in FUNCTIONS + ("sys_clock_cycle_get_32", "legacy_rtems_task_create", "k_is_in_isr", "main"):')
    if (directory / "collect-irq-control.py").read_text() != collector or \
            {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != \
            {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("Zephyr frozen original/native control coverage differs")
    proof = json.loads((directory / "official-native-source.json").read_text())
    if len(proof) != 11 or {row["path"] for row in proof} != set(source_urls()) or \
            (directory / "hal-revision.txt").read_text().strip() != HAL:
        raise ValueError("Zephyr fixed native source inventory differs")
    for row in proof:
        name = row["path"]
        path = directory / (name if name == "west.yml" else "native-source/" + name)
        if row["url"] != source_urls()[name] or digest(path) != row["sha256"]:
            raise ValueError("Zephyr fixed native source differs")
    config = set((directory / "config").read_text().splitlines())
    required = {"CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_XTENSA_CCOUNT_HZ=240000000",
        "CONFIG_SYS_CLOCK_TICKS_PER_SEC=100", "CONFIG_PREEMPT_ENABLED=y", "CONFIG_SCHED_DUMB=y",
        "CONFIG_NUM_PREEMPT_PRIORITIES=32", "CONFIG_MP_MAX_NUM_CPUS=1", "CONFIG_SIZE_OPTIMIZATIONS=y",
        "CONFIG_DYNAMIC_INTERRUPTS=y"}
    if not required <= config or any(flag + "=y" in config for flag in
            ("CONFIG_SMP", "CONFIG_TIMESLICING", "CONFIG_TICKLESS_KERNEL")) or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("Zephyr actual scheduler/clock/core/tick/compiler differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    compiled = ("app-zephyr/port.c", "app-zephyr/ilatency.c", *(name for name in NATIVE if name.endswith(".c") and not name.startswith("hal/")),
        "components/esp_hw_support/esp_clk.c")
    for name in compiled:
        selected = [shlex.split(row["command"]) for row in commands if row["file"].endswith("/" + name)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("Zephyr original/native actual compilation differs", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, set(FUNCTIONS + EXTRA), noreturn=NORETURN)
        for source, target, count in (("Init", "rh_native_priority_scheduler", 1), ("Init", "benchmark_timer_initialize", 2),
                ("Init", "benchmark_timer_read", 2), ("Task_1", "benchmark_timer_initialize", 1),
                ("Task_1", "rh_cause_irq", 1), ("Isr_handler", "benchmark_timer_read", 1), ("Isr_handler", "rh_clear_irq", 1),
                ("rh_install_irq", "esp_intr_alloc", 1), ("rh_clear_irq", "k_is_in_isr", 1), ("rh_end", "esp_intr_free", 1),
                ("rtems_task_start", "z_impl_k_thread_start", 1), ("rtems_task_exit", "z_impl_k_thread_abort", 1),
                ("rh_native_priority_scheduler", "esp_clk_cpu_freq", 1),
                ("rh_native_priority_scheduler", "z_impl_k_thread_priority_get", 1),
                ("benchmark_timer_initialize", "sys_clock_cycle_get_32", 1),
                ("benchmark_timer_read", "sys_clock_cycle_get_32", 1), ("main", "z_impl_k_thread_create", 1)):
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$",
                "\n".join(control[source].values()), re.M)
            if len(rows) != count:
                raise ValueError(("Zephyr original/native encoded call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("Zephyr encoded native call differs")
        if not any("rsr.ccount" in row for row in control["sys_clock_cycle_get_32"].values()) or \
                not any("rsr.misc1" in row for row in control["k_is_in_isr"].values()):
            raise ValueError("Zephyr native timer/ISR context instruction differs")
        for source, expected in (("rh_cause_irq", 0x3ff000e4), ("rh_clear_irq", 0x3ff000e4),
                ("Task_1", symbols.get_symbol_by_name("Isr_handler")[0]["st_value"]),
                ("rh_native_priority_scheduler", 240000000)):
            found = False
            for row in control[source].values():
                match = re.match(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+\w+, ([0-9a-f]+) <", row)
                if not match:
                    continue
                address, code, literal = (int(value, 16) for value in match.groups())
                if code & 0xf != 1 or ((address + 3) & ~3) + ((code >> 8) | -65536) * 4 != literal:
                    raise ValueError("Zephyr encoded literal address differs")
                sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                    s["sh_addr"] <= literal and literal + 4 <= s["sh_addr"] + s["sh_size"]]
                if len(sections) != 1:
                    raise ValueError("Zephyr IRQ literal not mapped to ELF")
                found |= struct.unpack_from("<I", sections[0].data(), literal - sections[0]["sh_addr"])[0] == expected
            if not found:
                raise ValueError("Zephyr native trigger/clear/direct ISR/clock literal missing")
    footprint = audit_cell(directory, "Zephyr", "rhealstone-single-irq", observation=True, recursive_manifest=True)
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("Zephyr original IRQ independent resets overlap")
    values = [row["original_single_shot_cycles"] for row in captures]
    return {"audit": "pass", "os": "Zephyr", "resets": 3, "metric_count": 1, "original_iterations": 1,
        "original_single_shot_cycles": values, "median_of_three_single_shots_us": statistics.median(values) / 240,
        "original_measurement_body_preserved": True, "native_scheduler_guard_adapted": True,
        "unmodified_official_source": False, "native_source_files": len(NATIVE), "reachable_functions": len(FUNCTIONS + EXTRA),
        "actual_native_compiled_units_checked": len(compiled), "captures": captures, "footprint": footprint,
        "native_source_identity": proof, "native_source_proof_sha256": digest(directory / "official-native-source.json"),
        "elf_bin_all_initialized_sections_bound": True, "image_format": "Zephyr elf2image --ram-only-header at 0x1000",
        "native_irq_source": 26, "native_irq_input": 3, "native_worker_priority": 20,
        "ranking_eligible": False, "external_gpio_interrupt_entry_measured": False,
        "boundary": "original one CPU software IRQ per boot, not unused 50000 macro or an average; RTEMS internal table guard replaced with actual Zephyr preemption/FIFO/100Hz/single-core/240MHz/current-priority admission; original low priority254 maps to native20 below Init10; direct original handler at source26/level1/input3, native ISR context check after first timestamp, native IRQ released; original timer read/subtraction retained, warmup970 vs overhead26 cycles and trigger/wrapper/cache costs retained; no external GPIO, cache normalization, cross-OS ranking, tail latency or general task/heap cleanup claim"}


def render_table(result):
    if result["audit"] != "pass" or result["resets"] != 3 or result["original_iterations"] != 1:
        raise ValueError("incomplete Zephyr original one-shot IRQ cohort")
    return "\n".join(("| Original Rhealstone IRQ port / OS | Original single-shot cycles (three boots) | Approximate single-shot us (three boots) |",
        "| --- | --- | --- |", "| Original IRQ port / Zephyr | " + " / ".join(map(str, result["original_single_shot_cycles"])) +
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
