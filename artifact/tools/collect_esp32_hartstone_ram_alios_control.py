#!/usr/bin/env python3
"""Freeze native/observer call paths for the unmeasured Rhino PH4 image."""
import os
from pathlib import Path
import re

FUNCTIONS = ("__wrap_application_start", "application_start", "worker", "timer_callback",
    "hartstone_small_whetstone", "__wrap_krhino_task_suspend", "krhino_task_suspend", "task_suspend",
    "report", "bench_ram_observe", "k_mm_alloc", "k_mm_free", "k_mm_realloc", "k_mm_init",
    "krhino_init_mm_head", "krhino_task_create", "krhino_task_resume", "krhino_task_pri_change",
    "krhino_sem_create", "krhino_sem_give", "krhino_sem_take", "esp_clk_cpu_freq",
    "_malloc_r", "_free_r", "_realloc_r", "heap_caps_malloc_default", "heap_caps_free",
    "heap_caps_realloc_default", "krhino_mm_alloc", "krhino_mm_free", "krhino_mm_realloc")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = ('abort',)\n", source, count=1, flags=re.S)
    source = source.replace('("image.sha256", "capture.sha256")', '("image.sha256",)')
    source = source.replace('"application.elf", "image.sha256", "capture.sha256",', '"application.elf", "image.sha256",')
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/ram-hartstone-alios-v1/alios/ph4").replace(
        "irq-control-flow.txt", "ram-control-flow.txt").replace("irq-control.sha256", "ram-control.sha256").replace(
        "collect-irq-control.py", "executed-ram-control.py").replace("RHEALSTONE IRQ CONTROL", "HARTSTONE RHINO RAM CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/ram-hartstone-alios-v1/alios/ph4/collect-ram-control.py"
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
