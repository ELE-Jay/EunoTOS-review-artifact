#!/usr/bin/env python3
"""Reuse the frozen entry-driven collector for the RIOT one-shot IRQ image."""
import os
from pathlib import Path
import runpy
import tempfile


def collector_source(source):
    old = 'directory = root / "downloads/rhealstone-irq-freertos-v1"'
    if source.count(old) != 1:
        raise ValueError("frozen collector directory binding differs")
    source = source.replace(old, 'directory = root / "downloads/rhealstone-irq-riot-v3"')
    source = source.replace("for name in FUNCTIONS:",
        'for name in FUNCTIONS + ("legacy_rtems_task_create", "main", "irq_is_in", "legacy_rh_end"):')
    source = source.replace('NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
        'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "sched_task_exit")')
    return source


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text())
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
