#!/usr/bin/env python3
"""Reuse the entry-driven collector for the separate original IRAM controls."""
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile

CASES = ("taskswitch", "taskpreempt", "semshuffle", "mlatency", "deadlockbrk")


def functions(original):
    tasks = sorted(set(re.findall(r"\b(Task0[123]|Init)\s*\(", original)))
    apis = sorted(set(re.findall(r"\b(rtems_(?:task|semaphore|message_queue)_\w+)\s*\(", original)))
    return tuple(tasks + apis + ["benchmark_timer_initialize", "benchmark_timer_read", "rh_begin", "rh_end", "rh_fail", "rtems_test_exit"])


def collector_source(source, case, original):
    if case not in CASES:
        raise ValueError("unknown original IRAM case")
    old = 'directory = root / "downloads/rhealstone-irq-freertos-v1"'
    if source.count(old) != 1 or source.count("for name in FUNCTIONS:") != 1:
        raise ValueError("frozen collector binding differs")
    source = source.replace(old, 'directory = root / "downloads/rhealstone-freertos-iram-v1/freertos/' + case + '"')
    source = source.replace("for name in FUNCTIONS:", "for name in " + repr(functions(original)) + ":")
    return source.replace('image = str(directory / "application.elf")', 'image = str(directory / "rhealstone.elf")').replace(
        '"application.elf", "image.sha256"', '"rhealstone.elf", "image.sha256"')


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    case = sys.argv[1]
    source = collector_source((root / "collect_esp32_rhealstone_irq_control.py").read_text(), case,
                             (root / "rhealstone-original" / (case + ".c")).read_text())
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / "collect-irq-control.py"
        script.write_text(source)
        runpy.run_path(str(script), run_name="__main__")
