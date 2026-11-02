#!/usr/bin/env python3
"""Freeze original one-way message loops and native queue/timer/preemption paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_flags_freertos_control import FUNCTIONS as FLAGS_FUNCTIONS, NORETURN
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = tuple(n for n in FLAGS_FUNCTIONS if n not in ("thread_get", "thread_flags_set", "thread_flags_wait_any",
    "xTaskGenericNotify", "xTaskGenericNotifyWait", "ulTaskGenericNotifyValueClear")) + (
    "msg_send", "msg_receive", "alarm_expired", "xQueueGenericCreateStatic", "xQueueGenericSend", "xQueueReceive",
    "prvCopyDataToQueue", "prvCopyDataFromQueue", "uxQueueMessagesWaiting")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-msg-freertos-v1").replace(
        "yield-control", "msg-control").replace("RIOT YIELD CONTROL", "RIOT MSG CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-msg-freertos-v1/collect-msg-control.py"
    if script.exists(): raise SystemExit("message control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
