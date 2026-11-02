#!/usr/bin/env python3
"""Freeze full original tmck and actual Zephyr/RIOT task paths."""
import os
from pathlib import Path
import runpy
import sys
import tempfile
from collect_esp32_rhealstone_tmck_control import FUNCTIONS as FREERTOS

COMMON = tuple(name for name in FREERTOS if name not in ("app_main", "xTaskCreatePinnedToCore", "vTaskDelete"))
FUNCTIONS = {"zephyr": COMMON + ("main", "create", "z_impl_k_thread_create", "z_impl_k_thread_start", "z_impl_k_thread_abort"),
    "riot": COMMON + ("main", "thread_create", "thread_wakeup", "sched_task_exit")}


def collector_source(source, system):
    if system not in FUNCTIONS:
        raise ValueError("unsupported full tmck native OS")
    old = 'directory = root / "downloads/rhealstone-irq-freertos-v1"'
    if source.count(old) != 1 or source.count("for name in FUNCTIONS:") != 1:
        raise ValueError("full tmck native collector base changed")
    version = "v2" if system == "zephyr" else "v4"
    result = source.replace(old, 'directory = root / "downloads/rhealstone-tmck-' + system + '-' + version + '/' + system + '/tmck"').replace(
        "for name in FUNCTIONS:", "for name in " + repr(FUNCTIONS[system]) + ":")
    if system == "riot":
        result = result.replace('root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"',
            'root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"').replace(
            'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
            'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "sched_task_exit", "cpu_switch_context_exit")')
    return result


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text(), sys.argv[1])
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
