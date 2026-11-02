#!/usr/bin/env python3
"""Freeze unchanged original flag loops and native Rhino/TIMER2 paths."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create", "thread_get",
    "thread_flags_set", "thread_flags_wait_any", "xtimer_set", "coreclk", "application_start", "controller_entry",
    "peer_entry", "alarm_expired", "registry_count", "fail", "krhino_task_create", "task_create$part$0",
    "cpu_task_stack_init", "krhino_cur_task_get", "krhino_event_create", "krhino_event_set", "krhino_event_get",
    "pend_to_blk_obj", "pend_task_wakeup", "pend_state_end_proc", "core_sched", "timer_init",
    "timer_set_counter_value", "timer_set_alarm_value", "timer_isr_register", "timer_enable_intr", "timer_start",
    "timer_pause", "timer_disable_intr", "timer_get_counter_value", "esp_intr_alloc", "esp_intr_alloc_intrstatus",
    "esp_intr_free", "esp_intr_get_cpu", "espos_isr_enter", "espos_isr_exit", "krhino_intrpt_enter", "krhino_intrpt_exit")
NORETURN = ("fail", "abort")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    source = source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-flags-alios-v1").replace(
        "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump",
        "alios-gcc5/xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump").replace('+ name + r', '+ re.escape(name) + r')
    source = source.replace("yield-control", "flags-control").replace("RIOT YIELD CONTROL", "RIOT FLAGS CONTROL")
    anchor = '                branch = re.match('
    if source.count(anchor) != 1: raise ValueError("native entry-driven collector differs")
    return source.replace(anchor, '                if instruction.startswith("jx"):\n'
        '                    raise SystemExit("unreviewed indirect jump: " + name)\n' + anchor)


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-flags-alios-v1/collect-flags-control.py"
    if script.exists(): raise SystemExit("Rhino flags control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
