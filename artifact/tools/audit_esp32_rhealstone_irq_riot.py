#!/usr/bin/env python3
"""Replay the original one-shot IRQ with RIOT's explicit tickless boundary."""
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
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_rhealstone_irq_control import FUNCTIONS, NORETURN
from collect_esp32_rhealstone_irq_riot_control import collector_source

SDK = "1329b19fe494500aeb79d19b27cfd99b40c37aec"
NATIVE = ("core/thread.c", "core/sched.c", "core/include/thread.h", "core/include/sched.h",
    "cpu/esp32/irq_arch.c", "cpu/esp32/include/irq_arch.h", "cpu/esp_common/include/irq_arch_common.h",
    "cpu/esp_common/esp-xtensa/thread_arch.c", "cpu/esp_common/vendor/xtensa/xtensa_intr.c",
    "cpu/esp_common/vendor/xtensa/portasm.S", "cpu/esp_common/vendor/xtensa/xtensa_vectors.S", "pkg/esp32_sdk/Makefile",
    "sdk/components/hal/esp32/include/hal/interrupt_controller_ll.h", "sdk/components/esp_hw_support/esp_clk.c")
EXTRA = ("legacy_rtems_task_create", "main", "irq_is_in", "legacy_rh_end")
BEGIN = "RHEALSTONE BEGIN RHILATENCY RIOT clock=240 cores=1 tick=native-tickless timer=ccount unit=cycles"


def source_urls():
    return {name: ("https://raw.githubusercontent.com/espressif/esp-idf/" + SDK + "/" + name[4:]
        if name.startswith("sdk/") else UPSTREAM + name) for name in NATIVE}


def verify_official(directory):
    rows = []
    for name, url in source_urls().items():
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != (directory / "native-source" / name).read_bytes():
            raise ValueError(("RIOT fixed official source differs", name))
        rows.append({"path": name, "url": url, "sha256": hashlib.sha256(data).hexdigest()})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    reset = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "main(): This is RIOT! (Version: 2024.10-devel)", "Single core mode",
        "RHEALSTONE IRQ SOURCE peripheral=26 requested_level=1 cpu=0 input=0 low_priority=11",
        "RHEALSTONE IRQ COMPLETE actual_irqs=1 handler_mask_restored=1 original_iterations=1", "RHEALSTONE END")
    if len(reset) != 1 or reset[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RHEALSTONE END" or any(re.search(
                r"FAIL|panic|assert failed|watchdog|Brownout|Error ==> |RHEALSTONE DIAG", line, re.I) for line in lines):
        raise ValueError("RIOT original IRQ boot/source/completion differs")
    result = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (-?\d+)", line))]
    trace = [list(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+) value2=(\d+)", line))]
    if len(result) != 1 or len(trace) != 1 or any(not 0 < value < 2**32 for value in trace[0]) or \
            trace[0][2] <= trace[0][1] or original_formula(trace[0], 1, (2, 1, None)) != result[0] or result[0] <= 0:
        raise ValueError("RIOT original single-shot subtraction differs")
    ordered = [lines.index(BEGIN), lines.index(required[3]),
        next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: Interrupt Latency - ")),
        lines.index(required[4]), next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE TIMER_READS ")),
        lines.index("RHEALSTONE END")]
    if ordered != sorted(ordered):
        raise ValueError("RIOT original IRQ phases differ")
    return {"original_single_shot_cycles": result[0], "timer_reads_cycles": trace[0],
        "original_iterations": 1, "actual_irqs": 1, "native_handler_mask_restored": True,
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
    for saved, current in (("port.c", PORT / "riot/port.c"), ("native_rhealstone_port.h", BASE / "riot/port.c"),
            ("Makefile", PORT / "riot/Makefile"), ("scheduler-guard.patch", PORT / "scheduler-guard.patch"),
            ("build_esp32_rhealstone_irq_riot.sh", ROOT / "tools/build_esp32_rhealstone_irq_riot.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_irq_riot.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError(("RIOT original IRQ adapter/build/acquisition differs", saved))
    for source in (BASE / "include", PORT / "include"):
        for path in source.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "include" / path.relative_to(source)).read_bytes():
                raise ValueError("RIOT original IRQ header differs")
    if (directory / "timesys.h").read_bytes() != (directory / "source/timesys.h").read_bytes():
        raise ValueError("compiled original timing formula differs")
    if (directory / "collect-irq-control.py").read_text() != collector_source(
            (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()) or \
            {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != \
            {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("RIOT frozen original/native control coverage differs")
    proof = json.loads((directory / "official-native-source.json").read_text())
    if len(proof) != len(NATIVE) or {row["path"] for row in proof} != set(NATIVE):
        raise ValueError("RIOT fixed native source inventory differs")
    for row in proof:
        if row["url"] != source_urls()[row["path"]] or digest(directory / "native-source" / row["path"]) != row["sha256"]:
            raise ValueError("RIOT fixed native source differs")
    if "PKG_VERSION=" + SDK not in (directory / "native-source/pkg/esp32_sdk/Makefile").read_text():
        raise ValueError("RIOT official SDK base revision differs")
    config = (directory / "config").read_text()
    for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
            ("MODULE_CORE_THREAD", 1), ("THREAD_PRIORITY_MAIN", 0)):
        if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
            raise ValueError("RIOT actual native profile differs")
    if any(name in config for name in ("MODULE_SCHED_ROUND_ROBIN", "MODULE_CORE_MBOX", "RHEALSTONE_DIAGNOSTIC")) or \
            "12.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("RIOT scheduler/module/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
        if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    compiled = ("app-riot/port.c", "app-riot/ilatency.c", *(name[4:] if name.startswith("sdk/") else name
        for name in NATIVE if name.endswith((".c", ".S"))))
    for name in compiled:
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DTHREAD_PRIORITY_MAIN=0" not in selected[0] or "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1" not in selected[0]:
            raise ValueError(("RIOT original/native actual compilation differs", name))
    if any(args[-1].endswith("/native_rhealstone_port.c") for args in commands):
        raise ValueError("base adapter compiled separately from wrapper")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, set(FUNCTIONS + EXTRA), noreturn=(*NORETURN, "sched_task_exit"))
        for source, target, count in (("Init", "rh_native_priority_scheduler", 1), ("Init", "benchmark_timer_initialize", 2),
                ("Init", "benchmark_timer_read", 2), ("Task_1", "benchmark_timer_initialize", 1),
                ("Task_1", "rh_cause_irq", 1), ("Task_1", "rh_install_irq", 1),
                ("Isr_handler", "benchmark_timer_read", 1), ("Isr_handler", "rh_clear_irq", 1),
                ("rh_install_irq", "xt_set_interrupt_handler", 1), ("rh_install_irq", "xt_ints_on", 1),
                ("rh_install_irq", "xt_int_has_handler", 1), ("rh_clear_irq", "irq_is_in", 1),
                ("rh_end", "xt_set_interrupt_handler", 1), ("rh_end", "xt_ints_off", 1),
                ("rh_end", "xt_int_has_handler", 1), ("rh_end", "irq_restore", 1),
                ("rtems_task_start", "thread_wakeup", 1), ("rtems_task_exit", "sched_task_exit", 1),
                ("rh_native_priority_scheduler", "esp_clk_cpu_freq", 1), ("rh_native_priority_scheduler", "irq_is_in", 1),
                ("main", "thread_create", 1), ("main", "thread_sleep", 1),
                ("legacy_rtems_task_create", "thread_create", 1)):
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$",
                "\n".join(control[source].values()), re.M)
            if len(rows) != count:
                raise ValueError(("RIOT encoded native call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("RIOT encoded native call differs")
        for source in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if not any("rsr.ccount" in row for row in control[source].values()):
                raise ValueError("RIOT native timer CCOUNT instruction differs")
        for source, expected in (("rh_cause_irq", 0x3ff000e4), ("rh_clear_irq", 0x3ff000e4),
                ("Task_1", symbols.get_symbol_by_name("Isr_handler")[0]["st_value"]),
                ("rh_install_irq", 0x4000681c), ("rh_native_priority_scheduler", (-240000000) & 0xffffffff),
                ("rh_native_priority_scheduler", symbols.get_symbol_by_name("sched_active_thread")[0]["st_value"]),
                ("irq_is_in", symbols.get_symbol_by_name("irq_interrupt_nesting")[0]["st_value"])):
            found = False
            for row in control[source].values():
                match = re.match(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+\w+, ([0-9a-f]+) <", row)
                if not match:
                    continue
                address, code, literal = (int(value, 16) for value in match.groups())
                if code & 0xf != 1 or ((address + 3) & ~3) + ((code >> 8) | -65536) * 4 != literal:
                    raise ValueError("RIOT encoded literal address differs")
                sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                    s["sh_addr"] <= literal and literal + 4 <= s["sh_addr"] + s["sh_size"]]
                if len(sections) != 1:
                    raise ValueError("RIOT IRQ literal not mapped to ELF")
                found |= struct.unpack_from("<I", sections[0].data(), literal - sections[0]["sh_addr"])[0] == expected
            if not found:
                raise ValueError("RIOT native trigger/clear/direct ISR/clock/context literal missing")
        guard = "\n".join(control["rh_native_priority_scheduler"].values())
        if not all(re.search(pattern, guard) for pattern in (r"080822 l8ui\s+a2, a8, 8", r"f21266 bnei\s+a2, 1,",
                r"1888 l32i.n\s+a8, a8, 4", r"0ba032 movi\s+a3, 11", r"ea9837 bne\s+a8, a3,")):
            raise ValueError("RIOT actual Init priority/status guard differs")
        if not any("0008e0 callx8\ta8" in row for row in control["rh_install_irq"].values()) or \
                any(not any("rsr.intenable" in row for row in control[name].values()) for name in ("rh_install_irq", "rh_end")):
            raise ValueError("RIOT matrix ROM dispatch/native interrupt-mask checks differ")
    footprint = audit_cell(directory, "RIOT", "rhealstone-single-irq", observation=True, recursive_manifest=True)
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("RIOT original IRQ independent resets overlap")
    excluded = []
    for version, error in (("v1", "timesys.h: No such file or directory"), ("v2", "multiple definition of")):
        failed = directory.parent / ("rhealstone-irq-riot-" + version)
        if error not in (failed / "build.log").read_text() or (failed / "flash.log").exists() or (failed / "image.sha256").exists():
            raise ValueError("RIOT excluded unflashed failed-build evidence differs")
        excluded.append({"version": version, "build_log_sha256": digest(failed / "build.log"), "flashed": False})
    values = [row["original_single_shot_cycles"] for row in captures]
    return {"audit": "pass", "os": "RIOT", "resets": 3, "metric_count": 1, "original_iterations": 1,
        "original_single_shot_cycles": values, "median_of_three_single_shots_us": statistics.median(values) / 240,
        "original_measurement_body_preserved": True, "native_scheduler_guard_adapted": True,
        "unmodified_official_source": False, "native_source_files": len(NATIVE), "reachable_functions": len(FUNCTIONS + EXTRA),
        "actual_native_compiled_units_checked": len(compiled), "captures": captures, "footprint": footprint,
        "native_source_identity": proof, "native_source_proof_sha256": digest(directory / "official-native-source.json"),
        "elf_bin_all_initialized_sections_bound": True, "native_irq_source": 26, "native_irq_input": 0,
        "native_worker_priority": 11, "tick_hz": None, "matrix_route_restoration_verified": False,
        "excluded_failed_builds": excluded, "ranking_eligible": False, "external_gpio_interrupt_entry_measured": False,
        "boundary": "original one CPU software IRQ per boot, not unused 50000 macro or mean; native RIOT priority FIFO/tickless/single-core/240MHz/GCC12 profile, runtime Init priority1/status/context/clock guard, original low priority254 maps to native11; source26/level1/input0 directly registers original handler; ISR context checked after original first timestamp, handler and mask restored but matrix route not restored; original first-read warmup1930 vs overhead16 cycles, native trigger/vector/cache/adapter costs retained; no external GPIO, cache normalization, cross-OS ranking, tail latency or general task/heap cleanup claim"}


def render_table(result):
    if result["audit"] != "pass" or result["resets"] != 3 or result["original_iterations"] != 1:
        raise ValueError("incomplete RIOT original one-shot IRQ cohort")
    return "\n".join(("| Original Rhealstone IRQ port / OS | Original single-shot cycles (three boots) | Approximate single-shot us (three boots) |",
        "| --- | --- | --- |", "| Original IRQ port / RIOT | " + " / ".join(map(str, result["original_single_shot_cycles"])) +
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
