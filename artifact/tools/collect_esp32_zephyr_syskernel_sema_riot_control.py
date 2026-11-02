#!/usr/bin/env python3
"""Reuse the entry-driven collector for the original/native RIOT semaphore paths."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

FUNCTIONS = ("main", "sema_test", "sema_test_init", "sema_thread1", "sema_thread2", "sema_thread3",
    "thread_entry", "k_sem_init", "k_sem_give", "k_sem_take", "k_sem_take$part$0", "k_thread_create", "k_sleep",
    "k_uptime_delta", "native_sema_mean", "TIME_STAMP_DELTA_GET", "begin_test", "check_result", "verify_retired",
    "sema_create", "sema_destroy", "sema_post", "_sema_wait_ztimer", "thread_create", "thread_yield",
    "thread_stack_init", "task_exit", "sched_switch", "sched_set_status", "mutex_unlock", "mutex_lock_internal", "ztimer_sleep")
NORETURN = ("fail", "core_panic", "_frxt_int_exit")


def collector_source(source):
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\n", source, count=1, flags=re.S)
    if count != 1 or source.count("downloads/zephyr-slab-riot-v3") != 1:
        raise ValueError("entry-driven collector source binding changed")
    for before, after in (("downloads/zephyr-slab-riot-v3", "downloads/zephyr-syskernel-sema-riot-v1"),
        ("SLAB CONTROL", "SEMA CONTROL"), ("slab-control-flow.txt", "sema-control-flow.txt"),
        ("slab-control.sha256", "sema-control.sha256"), ("collect-slab-control.py", "collect-sema-control.py"),
        ('+ name + r', '+ re.escape(name) + r'),
        (r"call8\s+[0-9a-f]+ <fail>", r"call(?:0|8)\s+[0-9a-f]+ <(?:" + "|".join(NORETURN) + ")>")):
        source = source.replace(before, after)
    return source


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-syskernel-sema-riot-v1"
    base = root / "collect_esp32_zephyr_slab_control.py"
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-sema-control.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    for source, target in ((Path(__file__), "collect-sema-riot-wrapper.py"), (base, "collector-base.py")):
        subprocess.check_call(["cp", str(source), str(directory / target)])
    with (directory / "sema-control.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
            "collect-sema-control.py", "collect-sema-riot-wrapper.py", "collector-base.py"], cwd=str(directory), stdout=stream)
