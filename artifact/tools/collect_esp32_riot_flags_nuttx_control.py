#!/usr/bin/env python3
"""Freeze original RIOT flags and existing NuttX driver-event/one-shot paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_nuttx_control import FUNCTIONS as YIELD_FUNCTIONS, NORETURN
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = tuple(n for n in YIELD_FUNCTIONS if n not in ("riot_yield_main", "sched_yield")) + (
    "riot_flags_main", "peer_entry", "thread_get", "thread_flags_set", "thread_flags_wait_any", "alarm_expired",
    "altmdm_event_init", "altmdm_event_wait", "altmdm_event_set", "altmdm_event_refer", "altmdm_event_destroy",
    "nxsem_init", "nxsem_set_protocol", "nxsem_trywait", "nxsem_wait", "nxsem_wait_uninterruptible",
    "nxsem_post", "nxsem_destroy", "nxsched_get_tcb")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-flags-nuttx-v1").replace(
        "yield-control", "flags-control").replace("RIOT YIELD CONTROL", "RIOT FLAGS CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-flags-nuttx-v1/collect-flags-control.py"
    if script.exists(): raise SystemExit("NuttX flags control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
