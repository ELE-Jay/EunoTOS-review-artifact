#!/usr/bin/env python3
"""Reuse the original-semaphore entry-driven collector for native NuttX paths."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

from collect_esp32_zephyr_syskernel_sema_control import collector_source as base_source

FUNCTIONS = ("zephyr_sema_main", "run_original", "sema_test", "sema_test_init", "sema_thread1", "sema_thread2",
    "sema_thread3", "thread_entry", "k_sem_init", "k_sem_give", "k_sem_take", "k_thread_create", "k_sleep",
    "k_uptime_delta", "native_sema_mean", "TIME_STAMP_DELTA_GET", "begin_test", "check_result",
    "reap_worker", "task_count", "count_task", "pthread_create", "pthread_startup", "nx_pthread_create",
    "pthread_start", "pthread_exit", "nx_pthread_exit", "pthread_join", "pthread_completejoin",
    "sem_post", "nxsem_post", "sem_wait", "nxsem_wait", "sem_trywait", "nxsem_trywait",
    "sem_setprotocol", "nxsem_set_protocol", "sched_yield", "nxsig_usleep", "esp32_timerisr", "up_timer_initialize")
NORETURN = ("fail", "pthread_exit", "nx_pthread_exit", "up_exit")


def collector_source(source):
    source = base_source(source)
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\n", source, count=1, flags=re.S)
    if count != 1:
        raise ValueError("semaphore base collector binding changed")
    return source.replace("downloads/zephyr-syskernel-sema-freertos-v1", "downloads/zephyr-syskernel-sema-nuttx-v2").replace(
        r"(?:fail|__assert_func)", "(?:" + "|".join(NORETURN) + ")")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-syskernel-sema-nuttx-v2"
    base = root / "collect_esp32_zephyr_slab_control.py"
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-sema-control.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    for source, target in ((Path(__file__), "collect-sema-nuttx-wrapper.py"), (base, "collector-base.py"),
        (root / "collect_esp32_zephyr_syskernel_sema_control.py", "sema-collector-base.py")):
        subprocess.check_call(["cp", str(source), str(directory / target)])
    with (directory / "sema-control.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
            "collect-sema-control.py", "collect-sema-nuttx-wrapper.py", "collector-base.py", "sema-collector-base.py"],
            cwd=str(directory), stdout=stream)
