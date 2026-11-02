#!/usr/bin/env python3
"""Reuse the sealed entry-driven collector for the complete original tmck."""
import os
from pathlib import Path
import runpy
import tempfile

FUNCTIONS = ("Init", "Task_1", "check_read_timer", "benchmark_timer_empty_function",
    "benchmark_timer_initialize", "benchmark_timer_read", "benchmark_timer_disable_subtracting_average_overhead",
    "rtems_task_create", "rtems_task_start", "rtems_task_exit", "rtems_test_exit", "rh_begin", "native_rh_begin",
    "rh_end", "rh_fail", "rh_printf", "app_main", "init_entry", "entry", "xTaskCreatePinnedToCore", "vTaskDelete")


def collector_source(source):
    old = 'directory = root / "downloads/rhealstone-irq-freertos-v1"'
    if source.count(old) != 1 or source.count("for name in FUNCTIONS:") != 1:
        raise ValueError("tmck collector base changed")
    return source.replace(old, 'directory = root / "downloads/rhealstone-tmck-freertos-v1/freertos/tmck"').replace(
        "for name in FUNCTIONS:", "for name in " + repr(FUNCTIONS) + ":").replace(
        'image = str(directory / "application.elf")', 'image = str(directory / "rhealstone.elf")').replace(
        '"application.elf", "image.sha256"', '"rhealstone.elf", "image.sha256"')


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text())
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
