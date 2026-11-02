#!/usr/bin/env python3
"""Reuse entry-driven collection for the original/native Rhino semaphore paths."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

FUNCTIONS = ("application_start", "controller_entry", "run_original", "sema_test", "sema_test_init",
    "sema_thread1", "sema_thread2", "sema_thread3", "thread_entry", "k_sem_init", "k_sem_give", "k_sem_take",
    "k_thread_create", "k_yield", "k_sleep", "k_uptime_delta", "native_sema_mean", "TIME_STAMP_DELTA_GET",
    "begin_test", "check_result", "verify_retired", "registry_count", "krhino_sem_create", "krhino_sem_del",
    "krhino_sem_give", "sem_give", "krhino_sem_take", "krhino_task_create", "task_create$part$0",
    "krhino_task_yield", "krhino_task_sleep", "krhino_sys_tick_get", "cpu_task_stack_init", "krhino_task_deathbed",
    "krhino_task_del", "krhino_task_del_hook", "klist_rm")
NORETURN = ("fail",)
INDIRECT_ADDRESS = 0x4008532f
INDIRECT_TARGETS = (0x40085332, 0x40085350, 0x40085347, 0x40085350, 0x40085342, 0x40085342)


def collector_source(source):
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\n", source, count=1, flags=re.S)
    if count != 1 or source.count("downloads/zephyr-slab-riot-v3") != 1 or source.count("xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump") != 1:
        raise ValueError("entry-driven collector source binding changed")
    for before, after in (("downloads/zephyr-slab-riot-v3", "downloads/zephyr-syskernel-sema-alios-v1"),
        ('root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"',
         'root / "alios-gcc5/xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"'),
        ("SLAB CONTROL", "SEMA CONTROL"), ("slab-control-flow.txt", "sema-control-flow-v2.txt"),
        ("slab-control.sha256", "sema-control-v2.sha256"), ("collect-slab-control.py", "collect-sema-control-v2.py"),
        ('+ name + r', '+ re.escape(name) + r')):
        source = source.replace(before, after)
    anchor = '                branch = re.match('
    if source.count(anchor) != 1:
        raise ValueError("entry-driven branch collector changed")
    source = source.replace(anchor, '                if instruction.startswith("jx"):\n'
        '                    if name != "krhino_task_del" or address != ' + str(INDIRECT_ADDRESS) + ' or instruction != "jx\\ta8":\n'
        '                        raise SystemExit("unreviewed indirect jump")\n'
        '                    pending.extend(' + repr(INDIRECT_TARGETS) + ')\n'
        '                    break\n' + anchor)
    return source


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-syskernel-sema-alios-v1"
    base = root / "collect_esp32_zephyr_slab_control.py"
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-sema-control-v2.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    for source, target in ((Path(__file__), "collect-sema-alios-wrapper-v2.py"), (base, "collector-base-v2.py")):
        subprocess.check_call(["cp", str(source), str(directory / target)])
    with (directory / "sema-control-v2.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "sema-control-flow-v2.txt",
            "collect-sema-control-v2.py", "collect-sema-alios-wrapper-v2.py", "collector-base-v2.py"], cwd=str(directory), stdout=stream)
