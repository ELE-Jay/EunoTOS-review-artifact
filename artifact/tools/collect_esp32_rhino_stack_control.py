#!/usr/bin/env python3
"""Reuse the reachable-branch decoder for the native stack observation paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("bench_h_heap_ready", "__wrap_krhino_idle_hook", "__wrap_krhino_task_dyn_del", "espos_task_del")
NORETURN = ("abort",)


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/esp32-rhino-stack-coverage-v1").replace(
        "yield-control", "stack-control").replace("RIOT YIELD CONTROL", "RHINO STACK CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home()/"esp32-pilot")))
    folder = root/"downloads/esp32-rhino-stack-coverage-v1"
    script = folder/"collect-stack-control.py"
    if script.exists():
        raise ValueError("Stack control extraction already exists")
    script.write_text(collector_source(Path(__file__).with_name("collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(),str(script),"exec"),{"__name__":"__main__","__file__":str(script)})
