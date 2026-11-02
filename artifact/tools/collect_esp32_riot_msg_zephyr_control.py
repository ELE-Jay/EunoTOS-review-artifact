#!/usr/bin/env python3
"""Freeze original message loops and native Zephyr message/counter paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_zephyr_control import FUNCTIONS as YIELD_FUNCTIONS, NORETURN
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = tuple(n for n in YIELD_FUNCTIONS if n != "z_impl_k_yield") + (
    "msg_send", "msg_receive", "k_msgq_init", "k_msgq_cleanup", "z_impl_k_msgq_put", "z_impl_k_msgq_get",
    "z_unpend_first_thread", "z_ready_thread", "z_pend_curr", "z_reschedule", "k_thread_state_str")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-msg-zephyr-v1").replace(
        "yield-control", "msg-control").replace("RIOT YIELD CONTROL", "RIOT MSG CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-msg-zephyr-v1/collect-msg-control.py"
    if script.exists():
        raise SystemExit("Zephyr message control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
