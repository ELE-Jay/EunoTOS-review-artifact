#!/usr/bin/env python3
"""Freeze unchanged RIOT loops and native NuttX pthread/hardware-timer paths."""
import os
from pathlib import Path
import re
import shutil
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "thread_create", "xtimer_set",
    "coreclk", "riot_yield_main", "fail", "count_task", "pthread_create", "nx_pthread_create",
    "pthread_start", "pthread_startup", "pthread_attr_setstack", "pthread_cancel", "nxnotify_cancellation",
    "pthread_join", "pthread_completejoin", "sched_yield", "esp32_oneshot_initialize", "esp32_oneshot_start",
    "esp32_oneshot_cancel", "esp32_oneshot_handler", "esp32_tim_init", "esp32_tim_setisr",
    "up_timer_initialize", "esp32_timerisr", "xtensa_stack_color", "up_use_stack", "nxsched_foreach")
NORETURN = ("fail", "abort", "pthread_exit", "nx_pthread_exit", "up_exit", "_exit")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n",
                    "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n",
                    source, count=1, flags=re.M | re.S)
    source = source.replace('output.name, "executed-yield-control.py"',
        'output.name, "executed-yield-control.py", "native-yield-source/xtensa_checkstack.c"')
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-yield-nuttx-v1")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/riot-yield-nuttx-v1/collect-yield-control.py"
    if script.exists():
        raise SystemExit("NuttX yield control recipe already exists")
    extra = script.parent / "native-yield-source"
    extra.mkdir(exist_ok=True)
    shutil.copy2(root / "riot-yield-nuttx-work-v1/nuttx/arch/xtensa/src/common/xtensa_checkstack.c",
                 extra / "xtensa_checkstack.c")
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
