#!/usr/bin/env python3
"""Reuse entry-driven decoding for original condvar and official pthread paths."""
import os
from pathlib import Path
import re
import runpy
import tempfile

FUNCTIONS = ("app_main", "condvar_blocking_ops", "start_thread_entry", "alt_thread_entry",
    "thread_entry", "k_current_get", "k_thread_priority_get", "k_thread_create", "k_thread_start",
    "k_thread_join", "k_thread_abort", "k_sem_give", "k_sem_take", "k_mutex_lock", "k_condvar_wait",
    "k_condvar_signal", "native_mutex_init", "native_condvar_init", "native_mutex_inspect",
    "native_condvar_inspect", "timing_cycles_to_ns_avg", "native_snprintk", "z_impl_timing_timestamp_get",
    "pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_signal", "pthread_cond_init",
    "pthread_cond_destroy", "pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_trylock",
    "pthread_mutex_lock_internal", "pthread_mutex_unlock", "_lock_acquire_recursive", "_lock_release_recursive",
    "lock_acquire_generic", "lock_release_generic", "xQueueCreateCountingSemaphoreStatic", "xQueueGenericSend",
    "xQueueSemaphoreTake", "xQueueTakeMutexRecursive", "xQueueGiveMutexRecursive", "vQueueDelete",
    "xTaskCreateStaticPinnedToCore", "vTaskDelete", "vTaskDelay", "uxTaskGetNumberOfTasks", "prvIdleTask", "prvDeleteTCB")
NORETURN = ("latency_fail", "abort", "__assert_func")


def collector_source(source):
    result, n = re.subn(r"FUNCTIONS = \(.*?\)\nNORETURN = .*?\n",
        "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.S)
    if n != 1 or 'downloads/rhealstone-irq-freertos-v1' not in result:
        raise ValueError("base entry-driven collector differs")
    return result.replace("rhealstone-irq-freertos-v1", "zephyr-condvar-freertos-v1").replace(
        "RHEALSTONE IRQ CONTROL", "CONDVAR CONTROL").replace("irq-control", "condvar-control")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "collect-condvar-control.py"
        path.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()), encoding="utf-8")
        runpy.run_path(str(path), run_name="__main__")
