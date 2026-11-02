#!/usr/bin/env python3
"""Replay the original Rhealstone single-shot IRQ protocol with an explicit native guard."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
import statistics
import struct

from elftools.elf.elffile import ELFFile
from audit_esp32_rhealstone import ROOT, SOURCE, original_formula
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_iperf_original import ANSI
from collect_esp32_rhealstone_irq_control import FUNCTIONS, NORETURN

PORT = ROOT / "firmware/bsp/esp32/rhealstone_irq"
BASE = ROOT / "firmware/bsp/esp32/rhealstone"
OFFICIAL = {
    "ilatency.c": ("testsuites/rhealstone/rhilatency/ilatency.c", "6974aaee075f2ebe7b67b306de3b0b031f268c0505b2a512b6c18040ce88f20f"),
    "timesys.h": ("testsuites/tmtests/include/timesys.h", "0d799927ebf735a64fb88cae83d50a1cad8407098f56b619382b8a7089edde80"),
}
NATIVE = ("components/freertos/FreeRTOS-Kernel/tasks.c", "components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c",
          "components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S", "components/esp_hw_support/intr_alloc.c",
          "components/xtensa/xtensa_intr.c")
GUARD = "    _Scheduler_Table[ 0 ].Operations.initialize !=\n    _Scheduler_priority_Initialize"
BEGIN = "RHEALSTONE BEGIN RHILATENCY FreeRTOS clock=240 cores=1 tick=100 timer=ccount unit=cycles"


def capture(directory, index, elf_sha):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    reset = [row for row in rows if row["line"].startswith("rst:0x")]
    if len(reset) != 1 or reset[0]["elapsed_s"] > 2 or lines.count(BEGIN) != 1 or \
            lines.count("RHEALSTONE END") != 1 or lines[-1] != "RHEALSTONE END" or \
            lines.count("RHEALSTONE IRQ SOURCE peripheral=26 requested_level=1 cpu=0 input=5 low_priority=2") != 1 or \
            lines.count("RHEALSTONE IRQ COMPLETE actual_irqs=1 released=1 original_iterations=1") != 1 or \
            sum("2nd stage bootloader" in line for line in lines) != 1 or \
            sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or \
            sum("Single core mode" in line for line in lines) != 1 or \
            sum("Calling app_main()" in line for line in lines) != 1 or \
            not any("ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines) or \
            any(re.search(r"FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog|Error ==> ", line, re.I) for line in lines):
        raise ValueError("single-IRQ boot, native source, completion or image identity differs")
    result = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (-?\d+)", line))]
    trace = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+) value2=(\d+)", line))]
    if len(result) != 1 or len(trace) != 1 or any(not 0 < value < 2 ** 32 for value in trace[0]) or \
            trace[0][2] <= trace[0][1] or original_formula(trace[0], 1, (2, 1, None)) != result[0] or result[0] <= 0:
        raise ValueError("original single-shot timer/subtraction formula differs")
    ordered = [lines.index(BEGIN), next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE IRQ SOURCE ")),
               next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: Interrupt Latency - ")),
               next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE IRQ COMPLETE ")),
               next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE TIMER_READS ")), lines.index("RHEALSTONE END")]
    if ordered != sorted(ordered):
        raise ValueError("original IRQ phase order differs")
    return {"original_single_shot_cycles": result[0], "timer_reads_cycles": list(trace[0]),
            "original_iterations": 1, "actual_irqs": 1, "native_irq_released": True,
            "start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory):
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    for name, (_, expected) in OFFICIAL.items():
        if digest(directory / "source" / name) != expected or \
                (directory / "source" / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("original Rhealstone source or formula differs")
    original = (directory / "source/ilatency.c").read_text()
    if original.count(GUARD) != 1 or (directory / "ported-ilatency.c").read_text() != \
            original.replace(GUARD, "    !rh_native_priority_scheduler()"):
        raise ValueError("native platform guard patch changed original measurement body")
    for saved, current in (("port.c", PORT / "port.c"), ("native_rhealstone_port.c", BASE / "freertos/port.c"),
            ("scheduler-guard.patch", PORT / "scheduler-guard.patch"),
            ("build_esp32_rhealstone_irq_freertos.sh", ROOT / "tools/build_esp32_rhealstone_irq_freertos.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_irq_freertos.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py"),
            ("collect-irq-control.py", ROOT / "tools/collect_esp32_rhealstone_irq_control.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("single-IRQ adapter/build/acquisition differs")
    for source, saved in ((BASE / "include", "include"), (PORT / "include", "include"), (PORT / "freertos", "build-files")):
        for path in source.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / saved / path.relative_to(source)).read_bytes():
                raise ValueError("single-IRQ API contract or build recipe differs")
    proof = {row["path"]: row for row in json.loads((ROOT / "artifacts/reports/zephyr-isr-freertos-v1/official-native-source.json").read_text())}
    for name in NATIVE:
        if proof[name]["url"] != "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/" + name or \
                digest(directory / "native-source" / name) != proof[name]["sha256"]:
            raise ValueError("single-IRQ native fixed source differs")
    config = set((directory / "config").read_text().splitlines())
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_UNICORE=y", "CONFIG_FREERTOS_HZ=100"} <= config or \
            "CONFIG_ESP_IPC_ISR_ENABLE=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (ROOT / "artifacts/reports/rhealstone-v2/freertos/taskswitch/FreeRTOSConfig.h").read_bytes():
        raise ValueError("single-IRQ native scheduler/clock/core/tick/compiler differs")
    commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    for name in ("app-freertos/port.c", "app-freertos/ilatency.c", *NATIVE):
        suffix = name.removeprefix("components/freertos/")
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + suffix) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("single-IRQ actual original/native compilation differs", name))
    names = {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()}
    if names != {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("single-IRQ control supplement coverage differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)

        def calls(source, target, count):
            text = "\n".join(control[source].values())
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$", text, re.M)
            if len(rows) != count:
                raise ValueError(("single-IRQ original/native call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("single-IRQ encoded native call differs")

        for source, target, count in (("Init", "rh_native_priority_scheduler", 1), ("Init", "benchmark_timer_initialize", 2),
                ("Init", "benchmark_timer_read", 2), ("Task_1", "benchmark_timer_initialize", 1),
                ("Task_1", "rh_cause_irq", 1), ("Isr_handler", "benchmark_timer_read", 1), ("Isr_handler", "rh_clear_irq", 1),
                ("rh_install_irq", "esp_intr_alloc", 1), ("rh_clear_irq", "xPortInIsrContext", 1),
                ("rh_end", "esp_intr_free", 1), ("rtems_task_start", "xTaskCreatePinnedToCore", 1),
                ("rh_native_priority_scheduler", "esp_clk_cpu_freq", 1), ("rh_native_priority_scheduler", "uxTaskPriorityGet", 1),
                ("rtems_task_exit", "vTaskDelete", 1)):
            calls(source, target, count)
        for source in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if not any("rsr.ccount" in text for text in control[source].values()):
                raise ValueError("native timestamp does not read CCOUNT")
        for source, expected in (("rh_cause_irq", 0x3ff000e4), ("rh_clear_irq", 0x3ff000e4),
                                 ("Task_1", symbols.get_symbol_by_name("Isr_handler")[0]["st_value"])):
            matched = False
            for row in control[source].values():
                match = re.match(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+\w+, ([0-9a-f]+) <", row)
                if not match:
                    continue
                address, code, literal = (int(value, 16) for value in match.groups())
                displacement = ((code >> 8) | -65536) * 4
                if code & 0xf != 1 or ((address + 3) & ~3) + displacement != literal:
                    raise ValueError("single-IRQ encoded literal address differs")
                sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                            s["sh_addr"] <= literal and literal + 4 <= s["sh_addr"] + s["sh_size"]]
                if len(sections) != 1:
                    raise ValueError("single-IRQ literal not mapped to image")
                value = struct.unpack_from("<I", sections[0].data(), literal - sections[0]["sh_addr"])[0]
                matched |= value == expected
            if not matched:
                raise ValueError("native trigger/clear or direct original ISR pointer missing")
    footprint = audit_cell(directory, "FreeRTOS", "rhealstone-single-irq", observation=True, recursive_manifest=True)
    captures = [capture(directory, index, footprint["elf_sha256"]) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("single-IRQ independent reset intervals overlap")
    values = [row["original_single_shot_cycles"] for row in captures]
    return {"audit": "pass", "os": "FreeRTOS", "resets": 3, "metric_count": 1, "original_iterations": 1,
            "original_single_shot_cycles": values, "median_of_three_single_shots_us": statistics.median(values) / 240,
            "original_measurement_body_preserved": True, "native_scheduler_guard_adapted": True,
            "unmodified_official_source": False, "native_source_files": len(NATIVE), "captures": captures,
            "original_source_identity": [{"path": name, "url": "https://raw.githubusercontent.com/RTEMS/rtems/acb78c0c8c76f4ae12c60b729948e541c1e3930c/" + path,
                                          "sha256": sha} for name, (path, sha) in OFFICIAL.items()],
            "footprint": footprint, "ranking_eligible": False, "external_gpio_interrupt_entry_measured": False,
            "boundary": "original one software-IRQ trigger per boot, not 50000 loops or an average; RTEMS table guard replaced with actual FreeRTOS priority-profile check; original source low priority 254 maps to native 2; original timestamp/one-shot subtraction retained, first-read warmup 959 and second-read overhead 15 cycles differ; source 26/level1/input5/core0 uses native hardware trigger and directly registered original handler, ISR context checked after timestamp, trigger/wrapper/cache costs retained; only post-timestamp completion wait, IRQ release checked, not general task/heap cleanup; no controlled external GPIO, cache-state calibration, OS ranking, p99 or worst-case claim"}


def render_table(result):
    if result["audit"] != "pass" or result["resets"] != 3 or result["original_iterations"] != 1:
        raise ValueError("incomplete original single-IRQ cohort")
    return "\n".join(("| Original Rhealstone IRQ port / OS | Original single-shot cycles (three boots) | Approximate single-shot us (three boots) |",
                      "| --- | --- | --- |", "| Original IRQ port / FreeRTOS | " +
                      " / ".join(map(str, result["original_single_shot_cycles"])) + " | " +
                      " / ".join(f"{value / 240:.3f}" for value in result["original_single_shot_cycles"]) + " |"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
