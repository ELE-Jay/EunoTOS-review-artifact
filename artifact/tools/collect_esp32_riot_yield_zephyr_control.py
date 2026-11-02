#!/usr/bin/env python3
"""Freeze original RIOT yield loops and native Zephyr counter/thread paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create", "xtimer_set", "coreclk",
    "main", "peer_entry", "alarm_expired", "fail", "count_thread", "z_impl_k_thread_create", "z_setup_new_thread",
    "arch_new_thread", "z_impl_k_yield", "z_impl_k_thread_abort", "z_thread_abort", "z_impl_k_thread_join",
    "k_thread_foreach", "counter_esp32_init", "counter_esp32_start", "counter_esp32_stop", "counter_esp32_get_value",
    "counter_esp32_set_alarm", "counter_esp32_cancel_alarm", "counter_esp32_isr", "esp_intr_alloc",
    "esp_intr_alloc_intrstatus", "timer_hal_init", "sys_clock_driver_init")
NORETURN = ("fail", "abort", "z_fatal_error", "k_panic")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n",
                    "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n",
                    source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-yield-zephyr-v3")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-yield-zephyr-v3/collect-yield-control.py"
    if script.exists():
        raise SystemExit("Zephyr yield control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
