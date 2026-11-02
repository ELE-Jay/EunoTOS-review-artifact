#!/usr/bin/env python3
"""Reuse the fixed-block branch collector on native NuttX pool/tick paths."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

FUNCTIONS = ("run_original", "zephyr_slab_main", "check_pool", "mem_slab_test", "begin_test",
             "check_result", "TIME_STAMP_DELTA_GET", "k_mem_slab_alloc", "k_uptime_delta",
             "native_slab_mean", "native_slab_storage", "mempool_init", "mempool_alloc",
             "mempool_free", "mempool_info", "nxsig_usleep", "esp32_timerisr", "up_timer_initialize")


def collector_source(source):
    source, count = re.subn(r"FUNCTIONS = \(.*?\)\n", "FUNCTIONS = " + repr(FUNCTIONS) + "\n", source, count=1, flags=re.S)
    if count != 1 or source.count("downloads/zephyr-slab-riot-v3") != 1 or source.count("xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump") != 1:
        raise ValueError("fixed-block collector source binding changed")
    return source.replace("downloads/zephyr-slab-riot-v3", "downloads/zephyr-slab-nuttx-v1").replace(
        'root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump"',
        'root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump"')


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-slab-nuttx-v1"
    base = root / "collect_esp32_zephyr_slab_control.py"
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "collect-slab-control.py"
        script.write_text(collector_source(base.read_text()))
        runpy.run_path(str(script), run_name="__main__")
    subprocess.check_call(["cp", __file__, str(directory / "collect-slab-nuttx-control.py")])
    subprocess.check_call(["cp", str(base), str(directory / "collector-base.py")])
    with (directory / "slab-control.sha256").open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256", "slab-control-flow.txt",
            "collect-slab-control.py", "collect-slab-nuttx-control.py", "collector-base.py"], cwd=str(directory), stdout=stream)
