#!/usr/bin/env python3
"""Reuse entry-driven control collection for the original semaphore scenarios."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

FUNCTIONS = ("app_main", "run_original", "sema_test", "sema_test_init", "sema_thread1", "sema_thread2",
    "sema_thread3", "thread_entry", "k_sem_init", "k_sem_give", "k_sem_take", "k_thread_create", "k_sleep",
    "k_uptime_delta", "native_sema_mean", "TIME_STAMP_DELTA_GET", "begin_test", "check_result",
    "xQueueGenericCreateStatic", "xQueueGenericSend", "xQueueSemaphoreTake", "vQueueDelete",
    "xTaskCreateStaticPinnedToCore", "vTaskDelete", "vTaskDelay", "xTaskGetTickCount", "uxTaskGetNumberOfTasks",
    "vTaskPrioritySet", "uxTaskPriorityGet", "prvIdleTask", "prvDeleteTCB")


def collector_source(source):
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\n", source, count=1, flags=re.S)
    if count != 1 or source.count("downloads/zephyr-slab-riot-v3") != 1 or source.count("xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump") != 1:
        raise ValueError("entry-driven collector source binding changed")
    for before, after in (
        ("downloads/zephyr-slab-riot-v3", "downloads/zephyr-syskernel-sema-freertos-v1"),
        ('root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"',
         'root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"'),
        ("SLAB CONTROL", "SEMA CONTROL"), ("slab-control-flow.txt", "sema-control-flow.txt"),
        ("slab-control.sha256", "sema-control.sha256"), ("collect-slab-control.py", "collect-sema-control.py")):
        source = source.replace(before, after)
    source = source.replace('raise SystemExit("slab block lacks a terminator")',
        'raise SystemExit(f"sema block lacks a terminator: {name} {entry:x} end={start + size:x}")')
    source = source.replace(r'call8\s+[0-9a-f]+ <fail>', r'call8\s+[0-9a-f]+ <(?:fail|__assert_func)>')
    return source


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-syskernel-sema-freertos-v1"
    base = root / "collect_esp32_zephyr_slab_control.py"
    assertion = directory / "native-control-source/assert.c"
    assertion.parent.mkdir(exist_ok=True)
    subprocess.check_call(["cp", str(root / "esp-idf-v5.2.5/components/newlib/assert.c"), str(assertion)])
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-sema-control.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    subprocess.check_call(["cp", __file__, str(directory / "collect-sema-wrapper.py")])
    subprocess.check_call(["cp", str(base), str(directory / "collector-base.py")])
    with (directory / "sema-control.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
            "collect-sema-control.py", "collect-sema-wrapper.py", "collector-base.py", "native-control-source/assert.c"], cwd=str(directory), stdout=stream)
