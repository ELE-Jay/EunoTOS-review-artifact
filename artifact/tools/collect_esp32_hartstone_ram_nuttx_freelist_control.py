#!/usr/bin/env python3
"""Freeze native-free-chain and original PH4 paths; no physical run is required."""
import os
from pathlib import Path
import re
from collect_esp32_hartstone_ram_nuttx_control import FUNCTIONS as BASE_FUNCTIONS

FUNCTIONS = BASE_FUNCTIONS + ("observe_locked", "observe_freelist_locked", "mm_addfreechunk", "mm_shrinkchunk", "mm_size2ndx")


def collector_source(source):
    source = re.sub(r"FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
        "\nNORETURN = ('_exit', 'up_exit')\n", source, count=1, flags=re.S)
    source = source.replace('("image.sha256", "capture.sha256")', '("image.sha256",)')
    source = source.replace('"application.elf", "image.sha256", "capture.sha256",', '"application.elf", "image.sha256",')
    return source.replace("downloads/rhealstone-irq-freertos-v1", "downloads/ram-hartstone-nuttx-v4/nuttx/ph4").replace(
        "irq-control-flow.txt", "ram-control-flow.txt").replace("irq-control.sha256", "ram-control.sha256").replace(
        "collect-irq-control.py", "executed-ram-control.py").replace("RHEALSTONE IRQ CONTROL", "HARTSTONE NUTTX FREELIST CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    script = root / "downloads/ram-hartstone-nuttx-v4/nuttx/ph4/collect-ram-control.py"
    script.write_text(collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
