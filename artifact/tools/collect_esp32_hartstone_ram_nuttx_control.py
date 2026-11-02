#!/usr/bin/env python3
"""Freeze original/native NuttX paths against the sealed raw setup pilot."""
import os
from pathlib import Path
import re
import subprocess

FUNCTIONS = ("__wrap_hartstone_main", "hartstone_main", "worker", "ph_timer_callback",
    "hartstone_small_whetstone", "__wrap_mm_unlock", "mm_unlock", "report", "mallinfo",
    "mm_mallinfo", "mm_foreach", "mm_initialize", "mm_addregion", "mm_malloc", "mm_free", "mm_realloc",
    "pthread_create", "nx_pthread_create", "pthread_join", "nx_pthread_exit", "up_create_stack",
    "up_release_stack", "esp_clk_cpu_freq", "umm_initialize", "up_allocate_heap")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = ('_exit', 'up_exit')\n",
                    source, count=1, flags=re.S)
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/ram-hartstone-nuttx-v3/nuttx/ph4").replace(
        "capture.sha256", "pilot-capture.sha256").replace("irq-control-flow.txt", "ram-control-flow.txt").replace(
        "irq-control.sha256", "ram-control.sha256").replace("collect-irq-control.py", "executed-ram-control.py").replace(
        "RHEALSTONE IRQ CONTROL", "HARTSTONE RAM CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/ram-hartstone-nuttx-v3/nuttx/ph4"
    if (directory / "pilot-capture.sha256").exists():
        raise SystemExit("NuttX setup-pilot supplement already sealed")
    names = ("pilot-reset1.jsonl", "pilot-reset1.raw", "flash-pilot.log", "image-check-pilot.log",
             "run-script-pilot.sh", "capture_esp32_uart.py")
    with (directory / "pilot-capture.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", *names], cwd=str(directory), stdout=stream)
    script = directory / "collect-ram-control.py"
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    source = script.read_text()
    exec(compile(source, str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
