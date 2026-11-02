#!/usr/bin/env python3
"""Freeze original condvar and official Rhino POSIX/native reachable paths."""
import os
from pathlib import Path
import re
import runpy
import tempfile

FUNCTIONS = ("application_start", "condvar_controller", "condvar_blocking_ops", "start_thread_entry", "alt_thread_entry",
    "thread_entry", "k_current_get", "k_thread_priority_get", "k_thread_create", "k_thread_start", "k_thread_join",
    "k_thread_abort", "k_sem_give", "k_sem_take", "k_mutex_lock", "k_condvar_wait", "k_condvar_signal",
    "native_mutex_init", "native_condvar_init", "native_mutex_inspect", "native_condvar_inspect", "registry_count",
    "timing_cycles_to_ns_avg", "native_snprintk", "z_impl_timing_timestamp_get", "pthread_cond_wait",
    "pthread_cond_signal", "pthread_cond_init", "pthread_cond_destroy", "pthread_mutex_init", "pthread_mutex_lock",
    "krhino_mutex_dyn_create", "mutex_create", "krhino_mutex_lock", "krhino_mutex_unlock", "krhino_sem_dyn_create",
    "krhino_sem_dyn_del", "krhino_sem_create", "krhino_sem_del", "krhino_sem_take", "krhino_sem_give", "sem_give",
    "krhino_task_create", "task_create$part$0", "krhino_task_resume", "krhino_task_suspend", "krhino_task_del",
    "task_mutex_free$isra$1", "klist_rm")
NORETURN = ("latency_fail", "abort", "__assert_func")
INDIRECT_ADDRESS = 0x400853af
TABLE_ADDRESS = 0x3f404844
INDIRECT_TARGETS = (0x400853b2, 0x400853d0, 0x400853c7, 0x400853d0, 0x400853c2, 0x400853c2)


def collector_source(source):
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\nNORETURN = .*?\n",
        "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.S)
    if count != 1 or "downloads/rhealstone-irq-freertos-v1" not in source:
        raise ValueError("entry-driven collector source binding changed")
    source = source.replace("rhealstone-irq-freertos-v1", "zephyr-condvar-alios-v1").replace(
        "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/", "alios-gcc5/xtensa-esp32-elf/bin/")
    source = source.replace("RHEALSTONE IRQ CONTROL", "CONDVAR CONTROL").replace("irq-control", "condvar-control")
    source = source.replace('+ name + r', '+ re.escape(name) + r')
    anchor = '                branch = re.match('
    if source.count(anchor) != 1:
        raise ValueError("entry-driven collector branch hook differs")
    return source.replace(anchor, '                if instruction.startswith("jx"):\n'
        '                    if name != "krhino_task_del" or address != ' + str(INDIRECT_ADDRESS) + ' or instruction != "jx\\ta8":\n'
        '                        raise SystemExit("unreviewed indirect jump")\n'
        '                    pending.extend(' + repr(INDIRECT_TARGETS) + ')\n'
        '                    break\n' + anchor)


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "collect-condvar-control.py"
        path.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()), encoding="utf-8")
        runpy.run_path(str(path), run_name="__main__")
