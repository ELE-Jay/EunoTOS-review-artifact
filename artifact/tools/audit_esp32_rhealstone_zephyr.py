#!/usr/bin/env python3
"""Replay the unchanged Rhealstone bodies on the qualified native Zephyr port."""
import argparse
import json
from pathlib import Path
import re
import shlex
import statistics
from audit_esp32_rhealstone import ROOT, SOURCE, CASES, audit_capture, digest
from audit_esp32_report import audit_flash


def audit(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "zephyr":
        raise ValueError("unsupported native case/port")
    checked = set()
    for line in (directory / "image.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or digest(path) != expected:
            raise ValueError(("manifest mismatch", name))
        checked.add(str(path.relative_to(directory.resolve())))
    required = {"zephyr.elf", "zephyr.bin", "config", "compiler.txt", "compile_commands.json", case + ".c", "timesys.h",
                "port.c", "CMakeLists.txt", "prj.conf", "disassembly.txt", "include/tmacros.h", "include/rtems/btimer.h", "include/rtems/confdefs.h"}
    if not required <= checked:
        raise ValueError("incomplete source/image binding")
    for name in (case + ".c", "timesys.h"):
        if (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("original workload/calculation changed")
    for name in ("port.c", "CMakeLists.txt", "prj.conf"):
        if (directory / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/zephyr" / name).read_bytes():
            raise ValueError("unreviewed native adapter")
    for name in ("tmacros.h", "rtems/btimer.h", "rtems/confdefs.h"):
        if (directory / "include" / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/include" / name).read_bytes():
            raise ValueError("original adapter contract changed")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_SYS_CLOCK_TICKS_PER_SEC=100",
                    "CONFIG_MP_MAX_NUM_CPUS=1", "# CONFIG_SMP is not set", "# CONFIG_TIMESLICING is not set",
                    "# CONFIG_TICKLESS_KERNEL is not set", "CONFIG_PREEMPT_ENABLED=y", "CONFIG_SIZE_OPTIMIZATIONS=y"):
        if setting not in config:
            raise ValueError(("native profile mismatch", setting))
    if "13.2.0" not in (directory / "compiler.txt").read_text() or b"13.2.0" not in (directory / "zephyr.elf").read_bytes():
        raise ValueError("compiler mismatch")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for name, fragment in ((case + ".c", "/rhealstone-original/"), ("port.c", "/rhealstone/zephyr/")):
        entries = [row for row in commands if Path(row["file"]).name == name and fragment in row["file"]]
        if len(entries) != 1:
            raise ValueError("missing original/native compilation")
        flags = shlex.split(entries[0]["command"])
        if [arg for arg in flags if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("native optimization changed")
    disassembly = (directory / "disassembly.txt").read_text()
    native_calls = {
        "taskswitch": ("k_thread_create", "k_yield"),
        "taskpreempt": ("k_thread_create", "k_thread_suspend", "k_thread_resume"),
        "semshuffle": ("k_thread_create", "k_thread_suspend", "k_yield", "k_mutex_lock", "k_mutex_unlock"),
        "mlatency": ("k_thread_create", "k_msgq_put", "k_msgq_get"),
        "deadlockbrk": ("k_thread_create", "k_thread_suspend", "k_thread_resume", "k_mutex_lock", "k_mutex_unlock"),
    }
    for name in native_calls[case]:
        if not re.search(r"\bcall\w*\s+[^<]*<(?:z_impl_)?" + name + r">", disassembly):
            raise ValueError(("native scheduler hook not called", name))
    audit_flash(directory, "flash.log", 1)
    written = re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())
    if [(int(size), int(address, 16)) for size, address in written] != [((directory / "zephyr.bin").stat().st_size, 0x1000)]:
        raise ValueError("Flash does not bind the archived image")
    runs = [audit_capture(directory / f"reset{i}.jsonl", case, "Zephyr") for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("independent reset windows overlap")
    values = [row["raw_original_cycles"] for row in runs]
    valid = all(row["measurement_eligible"] for row in runs)
    return {"audit": "pass", "os": "Zephyr 3.7.0", "case": case, "resets": 3,
            "original_revision": "RTEMS acb78c0c8c76f4ae12c60b729948e541c1e3930c",
            "raw_original_cycles": values, "measurement_eligible": valid,
            "median_us": statistics.median(values) / 240 if valid else None,
            "range_us": [min(values) / 240, max(values) / 240] if valid else None,
            "captures": runs, "ranking_eligible": False, "binary_sha256": digest(directory / "zephyr.bin"),
            "qualification": ["native k_mutex always inherits priority; original semaphore shuffle did not request inheritance",
                              "threads/stacks statically provisioned, created inactive before start; FreeRTOS adapter creates at start",
                              "single-sample native overhead subtraction can give nonpositive results"],
            "ranking_reason": "port qualifications and original overhead calibration require comparison review"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
