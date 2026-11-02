#!/usr/bin/env python3
"""Freeze original yield loops, native task creation and ISR timer dispatch."""
import os
from pathlib import Path
import re

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create",
             "peer_entry", "xtimer_set", "coreclk", "app_main", "fail",
             "xTaskCreateStaticPinnedToCore", "esp_timer_create",
             "esp_timer_start_once", "timer_process_alarm", "timer_alarm_handler")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n",
                    "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = ('fail', 'abort')\n",
                    source, count=1, flags=re.S)
    source = source.replace('(\"image.sha256\", \"capture.sha256\")', '(\"image.sha256\",)')
    source = source.replace('"application.elf", "image.sha256", "capture.sha256",',
                            '"application.elf", "image.sha256",')
    source = source.replace('raise SystemExit("IRQ branch outside original/native body")',
                            'raise SystemExit("yield branch outside body: " + name + " " + hex(entry))')
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/riot-yield-freertos-v1").replace(
        "irq-control-flow.txt", "yield-control-flow.txt").replace("irq-control.sha256", "yield-control.sha256").replace(
        "collect-irq-control.py", "executed-yield-control.py").replace("RHEALSTONE IRQ CONTROL", "RIOT YIELD CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-yield-freertos-v1/collect-yield-control.py"
    if script.exists():
        raise SystemExit("yield control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
