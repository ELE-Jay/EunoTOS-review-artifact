#!/usr/bin/env python3
"""Freeze original tmck and native NuttX/Rhino task control from sealed images."""
import os
from pathlib import Path
import runpy
import sys
import tempfile
from collect_esp32_rhealstone_tmck_native_control import COMMON

FUNCTIONS = {"nuttx": tuple(n for n in COMMON if n != "init_entry") +
    ("rhealstone_main", "task_create", "exit", "sched_setscheduler", "esp_clk_cpu_freq"),
    "alios": COMMON + ("application_start", "create", "krhino_task_create", "krhino_task_resume", "krhino_task_del",
        "espos_isr_enter", "espos_isr_exit", "krhino_intrpt_enter", "krhino_intrpt_exit")}


def collector_source(source, system, tick=False):
    if system not in FUNCTIONS:
        raise ValueError("unsupported full tmck remaining native OS")
    old = 'directory = root / "downloads/rhealstone-irq-freertos-v1"'
    if source.count(old) != 1 or source.count("for name in FUNCTIONS:") != 1:
        raise ValueError("full tmck remaining collector base changed")
    names = ("up_timer_initialize", "esp32_timerisr") if tick else FUNCTIONS[system]
    if tick and system != "nuttx":
        raise ValueError("separate tick control is for NuttX only")
    result = source.replace(old, 'directory = root / "downloads/rhealstone-tmck-' + system + '-v1/' + system + '/tmck"').replace(
        "for name in FUNCTIONS:", "for name in " + repr(names) + ":")
    if tick:
        result = result.replace("irq-control-flow.txt", "tmck-tick-control-flow.txt").replace("irq-control.sha256", "tmck-tick-control.sha256").replace(
            "collect-irq-control.py", "collect-tmck-tick-control.py")
    if system == "nuttx":
        result = result.replace('NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
            'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "exit", "_exit")')
    else:
        result = result.replace('root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"',
            'root / "alios-gcc5/xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"')
    return result


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text(), sys.argv[1], tick="--tick" in sys.argv[2:])
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
