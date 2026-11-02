#!/usr/bin/env python3
"""Audit native tickless RIOT repeats as a separate compiler/API cohort."""
import argparse
import json
import statistics
import hashlib
import re
import shlex
from datetime import datetime, timedelta
from pathlib import Path

from audit_esp32_report import audit_image_manifest
from audit_esp32_resources import audit_cell
from audit_esp32_tm_basic import CASES, audit
from audit_esp32_tm_reboots import require_cpu2_interrupt, require_self_check

ROOT = Path(__file__).resolve().parents[1]


def check_compilation(folder, case, workspace="riot_thread_metric_aligned_v1",
                      sources=("main.c", "port.c", "test.c")):
    reproduction = folder / "reproduction"
    required = {"application.bin", "application.elf", "build.log", "clean.log"}
    checked = set()
    for line in (reproduction / "reproduction.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        file = (reproduction / name).resolve()
        if file.parent != reproduction.resolve() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError("invalid RIOT compiler-command reproduction manifest")
        checked.add(file.name)
    if not required <= checked or any((folder / name).read_bytes() != (reproduction / name).read_bytes()
                                     for name in ("application.bin", "application.elf")):
        raise ValueError("RIOT clean build did not reproduce measured ELF/BIN")
    commands = []
    for line in (reproduction / "build.log").read_text().replace("\\\n", " ").splitlines():
        if "xtensa-esp32-elf-gcc" not in line:
            continue
        args = shlex.split(line)
        if "-c" in args and any(Path(arg).parent.name == workspace and
                               Path(arg).name in sources for arg in args):
            commands.append(args)
    expected = {"-DTHREAD_PRIORITY_MAIN=0", "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1"}
    compiled = [Path(arg).name for args in commands for arg in args
                if Path(arg).parent.name == workspace and Path(arg).name in sources]
    if sorted(compiled) != sorted(sources) or any(not expected <= set(args) or
            [arg for arg in args if arg.startswith("-DTM_TEST_")] != [f"-DTM_TEST_{case}=1"] or
            [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]
                                for args in commands):
        raise ValueError("RIOT original-test selection/compiler conditions not witnessed")


def audit_suite(directory):
    cells = []
    checks = {"message_processing": "queue", "synchronization_processing": "semaphore",
              "memory_allocation": "memory"}
    for case in CASES:
        folder = directory / case
        resource = audit_cell(folder, "RIOT", case)
        original_name = f"tm_{case}_test.c"
        reviewed = ROOT / "firmware/bsp/esp32/riot_thread_metric"
        adapter_files = {"main.c", "port.c", "test.c", "tm_override.h", "Makefile"}
        audit_image_manifest(folder, adapter_files | {original_name, "config.h"})
        for name in adapter_files:
            if (folder / name).read_bytes() != (reviewed / name).read_bytes():
                raise ValueError("native adapter/configuration differs from reviewed source")
        original = ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / original_name
        if (folder / original_name).read_bytes() != original.read_bytes():
            raise ValueError("published timed test source differs")
        if "12.2.0" not in (folder / "compiler.txt").read_text():
            raise ValueError("unexpected compiler cohort")
        if "#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240 1" not in (folder / "config.h").read_text():
            raise ValueError("unexpected build clock")
        check_compilation(folder, case)
        values = []
        previous_end = None
        for reset in (1, 2, 3):
            path = folder / f"reset{reset}.jsonl"
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            started = datetime.fromisoformat(rows[0]["utc"]) - timedelta(seconds=rows[0]["elapsed_s"])
            if previous_end is not None and started <= previous_end:
                raise ValueError("independent reset captures overlap")
            previous_end = started + timedelta(seconds=rows[-1]["elapsed_s"])
            result = audit(path, "RIOT", case)
            resets = [row for row in rows if row["line"].startswith("rst:0x")]
            if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
                raise ValueError("missing independent board reset")
            marker = "Thread-Metric conditions cpu_hz=240000000 cores=1 timer=tickless scheduler=priority-fifo"
            if sum(row["line"] == marker for row in rows) != 1:
                raise ValueError("effective conditions not witnessed")
            if case in checks:
                require_self_check(rows, checks[case])
            if case.startswith("interrupt_"):
                require_cpu2_interrupt(rows)
            values.append(result["original_window_totals"][0])
        resource.update({"first_window_values": values, "first_window_median": statistics.median(values),
                         "independent_resets": 3, "ranking_eligible": False})
        cells.append(resource)
    return {"status": "PASS", "cells": cells, "original_cases": 8, "independent_resets": 24,
            "byte_identical_clean_rebuilds": 8,
            "conditions": {"cpu_hz": 240000000, "cores": 1, "kernel_tick": "native tickless",
                           "compiler": "Xtensa GCC 12.2.0", "original_timed_functions": "O0"},
            "comparison_boundary": "compiler, timer and mailbox adapter differ from primary three-OS cohort",
            "hartstone_status": "separate native-us cohort, not audited by this Thread-Metric replay",
            "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = json.dumps(audit_suite(args.directory.resolve()), indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
