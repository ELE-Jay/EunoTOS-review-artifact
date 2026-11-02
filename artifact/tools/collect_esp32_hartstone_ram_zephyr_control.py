#!/usr/bin/env python3
"""Reuse the established entry-driven Xtensa decoder for the PH4 census."""
import os
from pathlib import Path
import re

FUNCTIONS = ("__wrap_main", "__wrap_sys_heap_init", "bg_thread_main", "statics_init", "k_heap_init",
    "sys_heap_init", "esp_clk_cpu_freq", "main", "worker", "hartstone_small_whetstone",
    "z_impl_k_thread_create", "z_setup_new_thread", "arch_new_thread")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = ()\n",
                    source, count=1, flags=re.S)
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/ram-hartstone-zephyr-v1/zephyr/ph4").replace(
        "irq-control-flow.txt", "ram-control-flow.txt").replace("irq-control.sha256", "ram-control.sha256").replace(
        "collect-irq-control.py", "collect-ram-control.py").replace("RHEALSTONE IRQ CONTROL", "HARTSTONE RAM CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/ram-hartstone-zephyr-v1/zephyr/ph4"
    if (directory / "ram-control.sha256").exists() or (directory / "ram-control-flow.txt").exists():
        raise SystemExit("PH4 RAM control supplement already exists")
    namespace = {"__name__": "__main__", "__file__": str(root / "collect_esp32_hartstone_ram_zephyr_control.py")}
    # The reused decoder archives its own executed source, not this thin caller.
    script = directory / "collect-ram-control.py"
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    namespace["__file__"] = str(script)
    executed = script.read_text().replace('"collect-ram-control.py"', '"executed-ram-control.py"')
    exec(compile(executed, str(script), "exec"), namespace)
