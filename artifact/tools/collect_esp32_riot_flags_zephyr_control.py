#!/usr/bin/env python3
"""Freeze unchanged original flag loops and native Zephyr event/counter paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_zephyr_control import FUNCTIONS as YIELD_FUNCTIONS, NORETURN
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = tuple(n for n in YIELD_FUNCTIONS if n != "z_impl_k_yield") + (
    "thread_get", "thread_flags_set", "thread_flags_wait_any", "z_impl_k_event_init", "z_impl_k_event_post",
    "z_impl_k_event_clear", "z_impl_k_event_wait", "k_event_post_internal", "k_event_wait_internal", "event_walk_op",
    "z_sched_waitq_walk", "z_sched_wake_thread", "z_pend_curr", "z_reschedule", "z_reschedule_irqlock", "k_thread_state_str")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-flags-zephyr-v1").replace(
        "yield-control", "flags-control").replace("RIOT YIELD CONTROL", "RIOT FLAGS CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-flags-zephyr-v1/collect-flags-control.py"
    if script.exists(): raise SystemExit("Zephyr flags control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
