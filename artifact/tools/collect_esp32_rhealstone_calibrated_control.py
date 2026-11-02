#!/usr/bin/env python3
"""Freeze original paths plus original tmck and calibrated timer services."""
import os
from pathlib import Path
import runpy
import sys
import tempfile
from collect_esp32_rhealstone_iram_control import collector_source as iram_source, functions

EXTRA = ("legacy_rh_begin", "legacy_rh_end", "rh_timer_check", "check_read_timer")
ZEPHYR_EXTRA = EXTRA + ("main", "entry", "init_entry", "create", "rh_printf")
RIOT_EXTRA = EXTRA + ("main", "entry", "init_entry", "rh_printf")
NUTTX_EXTRA = EXTRA + ("rhealstone_main", "entry", "rh_printf")
ALIOS_EXTRA = EXTRA + ("application_start", "entry", "init_entry", "create", "rh_printf",
    "krhino_cur_task_get", "espos_isr_enter", "espos_isr_exit", "krhino_intrpt_enter", "krhino_intrpt_exit")


def collector_source(source, case, original, system="freertos"):
    if system not in ("freertos", "zephyr", "riot", "nuttx", "alios"):
        raise ValueError("unsupported calibrated native port")
    source = iram_source(source, case, original)
    old = "for name in " + repr(functions(original)) + ":"
    if source.count(old) != 1:
        raise ValueError("original placement collector binding differs")
    extra = {"freertos": EXTRA, "zephyr": ZEPHYR_EXTRA, "riot": RIOT_EXTRA, "nuttx": NUTTX_EXTRA, "alios": ALIOS_EXTRA}[system]
    version = "v2" if system == "riot" else "v1"
    source = source.replace(old, "for name in " + repr(functions(original) + extra) + ":").replace(
        "downloads/rhealstone-freertos-iram-v1/freertos/", "downloads/rhealstone-" + system + "-calibrated-" + version + "/" + system + "/")
    if system != "freertos":
        source = source.replace('"rhealstone.elf"', '"application.elf"')
    if system == "riot":
        source = source.replace('root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"',
                                'root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"')
        source = source.replace('NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
                                'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "sched_task_exit")')
    if system == "nuttx":
        source = source.replace('NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
                                'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "exit")')
    if system == "alios":
        source = source.replace('root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"',
                                'root / "alios-gcc5/xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"')
    return source


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    case = sys.argv[1]
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text(), case,
                             (root / "rhealstone-original" / (case + ".c")).read_text(),
                             sys.argv[2] if len(sys.argv) > 2 else "freertos")
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
