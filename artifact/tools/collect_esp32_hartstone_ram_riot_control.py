#!/usr/bin/env python3
"""Freeze executed RIOT allocator/PH4 paths with the established Xtensa decoder."""
import os
from pathlib import Path
import re
import shutil
import subprocess

FUNCTIONS = ("__wrap_main", "main_trampoline", "main", "worker", "hartstone_small_whetstone",
    "malloc", "_malloc_r", "_free_r", "_realloc_r", "_mallinfo_r", "__malloc_lock", "__malloc_unlock",
    "__wrap__sbrk_r", "_sbrk_r", "__wrap___malloc_unlock", "observe", "report",
    "thread_create", "thread_stack_init", "esp_clk_cpu_freq")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\nNORETURN = ()\n",
                    source, count=1, flags=re.S)
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/ram-hartstone-riot-v1/riot/ph4").replace(
        "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/", "xtensa-esp32-elf/bin/").replace(
        "irq-control-flow.txt", "ram-control-flow.txt").replace("irq-control.sha256", "ram-control.sha256").replace(
        "collect-irq-control.py", "executed-ram-control.py").replace("RHEALSTONE IRQ CONTROL", "HARTSTONE RAM CONTROL").replace(
        'output.name, "executed-ram-control.py"',
        'output.name, "executed-ram-control.py", "flash.log", "application.map", "libg_nano.a", "official-native-library.json", "pilot-reset1.jsonl", "pilot-reset1.raw", "flash-pilot.log", "run-script-pilot.sh"')


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/ram-hartstone-riot-v1/riot/ph4"
    if (directory / "ram-control.sha256").exists() or (directory / "ram-control-flow.txt").exists():
        raise SystemExit("RIOT PH4 RAM control supplement already exists")
    shutil.copyfile(directory / "flash-full.log", directory / "flash.log")
    shutil.copyfile(root / "ram-hartstone-riot-work-v1/app/bin/ram-hartstone-riot-v1/ph4/esp32-wroom-32/hartstone-ph4.map",
                    directory / "application.map")
    library = subprocess.check_output([str(root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-gcc"),
                                       "-print-file-name=libg_nano.a"]).decode().strip()
    shutil.copyfile(library, directory / "libg_nano.a")
    shutil.copyfile(root / "downloads/zephyr-heap-riot-v1/official-native-library.json", directory / "official-native-library.json")
    script = directory / "collect-ram-control.py"
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    namespace = {"__name__": "__main__", "__file__": str(script)}
    source = script.read_text()
    exec(compile(source, str(script), "exec"), namespace)
