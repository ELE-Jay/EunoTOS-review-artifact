#!/usr/bin/env python3
"""Freeze original two-slot stack and reused native lifecycle machine paths."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

from collect_esp32_zephyr_syskernel_sema_control import FUNCTIONS as SEMA_FUNCTIONS, collector_source as sema_collector

FUNCTIONS = ("app_main", "run_stack_original", "stack_test", "stack_test_init",
    "stack_thread1", "stack_thread2", "stack_thread3", "thread_entry", "k_stack_init", "k_stack_push", "k_stack_pop",
    "k_thread_create", "k_sleep", "k_uptime_delta", "native_sema_mean", "TIME_STAMP_DELTA_GET", "begin_test", "check_result",
    "xQueueGenericCreateStatic", "xQueueGenericSend", "xQueueReceive", "uxQueueMessagesWaiting", "vQueueDelete",
    "xTaskCreateStaticPinnedToCore", "vTaskDelete", "vTaskDelay", "xTaskGetTickCount", "uxTaskGetNumberOfTasks",
    "vTaskPrioritySet", "uxTaskPriorityGet", "prvIdleTask", "prvDeleteTCB", "BENCH_START")
NATIVE = tuple("components/freertos/" + name for name in (
    "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
    "FreeRTOS-Kernel/portable/xtensa/portasm.S", "FreeRTOS-Kernel/include/freertos/task.h",
    "FreeRTOS-Kernel/include/freertos/queue.h", "FreeRTOS-Kernel/include/freertos/semphr.h",
    "FreeRTOS-Kernel/include/freertos/FreeRTOS.h", "esp_additions/freertos_tasks_c_additions.h"))


def collector_source(source):
    result = sema_collector(source)
    anchor = "FUNCTIONS = " + repr(SEMA_FUNCTIONS)
    if result.count(anchor) != 1:
        raise ValueError("reused semaphore collector function binding changed")
    return result.replace(anchor, "FUNCTIONS = " + repr(FUNCTIONS)).replace(
        "zephyr-syskernel-sema-freertos-v1", "zephyr-syskernel-stack-freertos-v2").replace(
        "SEMA CONTROL", "SYSSTACK CONTROL").replace("sema-control", "sysstack-control").replace(
        "sysstack-control-flow.txt", "sysstack-control-flow-v2.txt").replace(
        "sysstack-control.sha256", "sysstack-control-v2.sha256").replace(
        "collect-sysstack-control.py", "collect-sysstack-control-v2.py")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-syskernel-stack-freertos-v2"
    base = root / "collect_esp32_zephyr_slab_control.py"
    assertion = directory / "native-control-source/assert.c"
    assertion.parent.mkdir(exist_ok=True)
    assertion_source = root / "esp-idf-v5.2.5/components/newlib/assert.c"
    if assertion.exists():
        if assertion.read_bytes() != assertion_source.read_bytes():
            raise SystemExit("archived assertion source changed")
    else:
        subprocess.check_call(["cp", str(assertion_source), str(assertion)])
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-sysstack-control-v2.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    for source, target in ((Path(__file__), "collect-sysstack-wrapper-v2.py"), (base, "collector-base-v2.py"),
            (root / "collect_esp32_zephyr_syskernel_sema_control.py", "sema-collector-base-v2.py")):
        subprocess.check_call(["cp", str(source), str(directory / target)])
    paths = {"native-source/" + name: "tm-cooperative-no-timeslicing/freertos/" + name.split("components/freertos/")[1]
             for name in NATIVE}
    paths["native-control-source/assert.c"] = "esp-idf-v5.2.5/components/newlib/assert.c"
    rows = []
    for archived, actual in paths.items():
        data = (root / actual).read_bytes()
        if data != (directory / archived).read_bytes():
            raise SystemExit("compiled native bytes differ: " + archived)
        rows.append({"archived_path": archived, "actual_path": actual, "sha256": hashlib.sha256(data).hexdigest()})
    binding = {"elf_sha256": hashlib.sha256((directory / "application.elf").read_bytes()).hexdigest(),
        "compile_commands_sha256": hashlib.sha256((directory / "compile_commands.json").read_bytes()).hexdigest(), "files": rows}
    binding_path = directory / "compiled-native-source-binding.json"
    content = json.dumps(binding, indent=2) + "\n"
    if binding_path.exists():
        if binding_path.read_text() != content:
            raise SystemExit("archived native source binding changed")
    else:
        binding_path.write_text(content)
    with (directory / "sysstack-control-v2.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "sysstack-control-flow-v2.txt",
            "collect-sysstack-control-v2.py", "collect-sysstack-wrapper-v2.py", "collector-base-v2.py", "sema-collector-base-v2.py",
            "native-control-source/assert.c", "compiled-native-source-binding.json"], cwd=str(directory), stdout=stream)
