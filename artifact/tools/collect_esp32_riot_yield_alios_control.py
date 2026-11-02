#!/usr/bin/env python3
"""Freeze original RIOT loops and native Rhino/TIMER2 paths, without captures."""
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source
from collect_esp32_zephyr_syskernel_sema_alios_control import INDIRECT_ADDRESS, INDIRECT_TARGETS

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create", "xtimer_set", "coreclk",
    "application_start", "controller_entry", "peer_entry", "alarm_expired", "registry_count", "fail",
    "krhino_task_create", "task_create$part$0", "cpu_task_stack_init", "krhino_task_yield", "core_sched",
    "ready_list_head_to_tail", "krhino_cur_task_get", "krhino_task_del", "krhino_task_del_hook",
    "timer_init", "timer_set_counter_value", "timer_set_alarm_value", "timer_isr_register", "timer_enable_intr",
    "timer_start", "timer_pause", "timer_disable_intr", "timer_get_counter_value", "esp_intr_alloc",
    "esp_intr_alloc_intrstatus", "esp_intr_free", "esp_intr_get_cpu", "espos_isr_enter", "espos_isr_exit",
    "krhino_intrpt_enter", "krhino_intrpt_exit")
NORETURN = ("fail", "abort")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n",
                    "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n",
                    source, count=1, flags=re.M | re.S)
    source = source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-yield-alios-v2").replace(
        "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump",
        "alios-gcc5/xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump").replace('+ name + r', '+ re.escape(name) + r')
    anchor = '                branch = re.match('
    if source.count(anchor) != 1:
        raise ValueError("entry-driven native branch collector differs")
    return source.replace(anchor, '                if instruction.startswith("jx"):\n'
        '                    if name != "krhino_task_del" or address != ' + str(INDIRECT_ADDRESS) + ' or instruction != "jx\\ta8":\n'
        '                        raise SystemExit("unreviewed indirect jump")\n'
        '                    pending.extend(' + repr(INDIRECT_TARGETS) + ')\n'
        '                    break\n' + anchor)


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-yield-alios-v2/collect-yield-control.py"
    if script.exists():
        raise SystemExit("Rhino yield control recipe already exists")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
