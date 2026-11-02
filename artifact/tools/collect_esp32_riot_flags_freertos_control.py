#!/usr/bin/env python3
"""Freeze original thread-flag loops and native notification/IRQ dispatch paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create", "thread_get",
    "thread_flags_set", "thread_flags_wait_any", "peer_entry", "xtimer_set", "coreclk", "app_main", "fail",
    "xTaskCreateStaticPinnedToCore", "xTaskGenericNotify", "xTaskGenericNotifyWait", "ulTaskGenericNotifyValueClear",
    "eTaskGetState", "esp_timer_create", "esp_timer_start_once", "timer_process_alarm", "timer_alarm_handler",
    "esp_crosscore_int_send_yield", "esp_crosscore_int_send", "esp_crosscore_isr", "esp_crosscore_int_init",
    "esp_intr_alloc", "esp_intr_alloc_intrstatus")
NORETURN = ("fail", "abort", "__assert_func", "_esp_error_check_failed")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n",
                    "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n",
                    source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-flags-freertos-v1").replace(
        "yield-control-flow.txt", "flags-control-flow.txt").replace("yield-control.sha256", "flags-control.sha256").replace(
        "executed-yield-control.py", "executed-flags-control.py").replace("RIOT YIELD CONTROL", "RIOT FLAGS CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-flags-freertos-v1/collect-flags-control.py"
    if script.exists():
        raise SystemExit("thread flags control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
