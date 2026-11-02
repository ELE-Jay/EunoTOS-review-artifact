#!/usr/bin/env python3
"""Bind each historical RAM image's native heap initialization to its UART trio."""
import os
from pathlib import Path
import re
import subprocess

PROFILES = ("ram-census-v2/nuttx", *("ram-thread-metric-v1/nuttx/" + case for case in (
    "basic_processing", "cooperative_scheduling-console-v2", "preemptive_scheduling",
    "synchronization_processing", "memory_allocation-selfcheck-v2", "interrupt_processing",
    "interrupt_preemption_processing")))
FUNCTIONS = ("mm_initialize", "mm_addregion", "umm_initialize", "up_allocate_heap", "__wrap_mm_unlock")


def collector_source(source, profile):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = ()\n", source, count=1, flags=re.S)
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/" + profile).replace(
        "capture.sha256", "ram-context-binding.sha256").replace("irq-control-flow.txt", "ram-context-flow.txt").replace(
        "irq-control.sha256", "ram-context-control.sha256").replace("collect-irq-control.py", "executed-ram-context.py").replace(
        "RHEALSTONE IRQ CONTROL", "NUTTX RAM CONTEXT CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    for profile in PROFILES:
        directory = root / "downloads" / profile
        if (directory / "ram-context-binding.sha256").exists():
            raise SystemExit("native context supplement already sealed: " + profile)
        with (directory / "ram-context-binding.sha256").open("w") as stream:
            subprocess.check_call(["sha256sum", "image.sha256", "reset1.jsonl", "reset2.jsonl", "reset3.jsonl"],
                                  cwd=str(directory), stdout=stream)
        script = directory / "collect-ram-context.py"
        script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text(), profile))
        exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
