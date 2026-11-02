#!/usr/bin/env python3
"""Replay original Rhealstone on native NuttX tasks, signals, mutexes and MQ."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen
from audit_esp32_report import audit_flash
from audit_esp32_rhealstone import ROOT, SOURCE, CASES, audit_capture, digest
from audit_esp32_riot_original import check_manifest
from audit_esp32_resources import audit_elf_image

UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
NATIVE_SOURCES = ("sched/signal/sig_default.c", "sched/signal/sig_dispatch.c",
                  "sched/sched/sched_suspend.c", "sched/group/group_continue.c", "sched/task/task_restart.c")


def audit(directory, verify_upstream=False):
    case = directory.name
    if case not in CASES or directory.parent.name != "nuttx":
        raise ValueError("unsupported native NuttX original case")
    check_manifest(directory, "image.sha256")
    names = {Path(line.split(maxsplit=1)[1].lstrip("*")).as_posix()
             for line in (directory / "image.sha256").read_text().splitlines()}
    required_files = {"nuttx", "nuttx.bin", "nuttx.map", "bootloader-esp32.bin", "partition-table-esp32.bin",
                      "config", "compiler.txt", "build.log", "disassembly.txt", "original.c", "port.c",
                      "Makefile", "Kconfig", "Make.defs", "include/timesys.h", "include/tmacros.h",
                      "include/rtems/btimer.h", "include/rtems/confdefs.h"}
    required_files.update("native-source/" + name for name in NATIVE_SOURCES)
    if not required_files <= names:
        raise ValueError("incomplete source/image/config/build binding")
    audit_elf_image(directory / "nuttx", directory / "nuttx.bin")
    for name, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h")):
        if (directory / name).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("original body or formula changed")
    for name in ("port.c", "Makefile", "Kconfig", "Make.defs"):
        if (directory / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/nuttx" / name).read_bytes():
            raise ValueError("unreviewed native NuttX adapter")
    for name in ("tmacros.h", "rtems/btimer.h", "rtems/confdefs.h"):
        if (directory / "include" / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/include" / name).read_bytes():
            raise ValueError("original adapter contract changed")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE_SOURCES:
            with urlopen(UPSTREAM + name, timeout=30) as response:
                upstream = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != upstream:
                raise ValueError(("native SDK differs from pinned official source", name))
            records.append({"path": name, "url": UPSTREAM + name, "sha256": upstream})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE_SOURCES) or {row["path"] for row in records} != set(NATIVE_SOURCES) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in records):
        raise ValueError("native suspend/continue/restart source binding differs")
    config = set((directory / "config").read_text().splitlines())
    required = {"CONFIG_BUILD_FLAT=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_USEC_PER_TICK=10000",
                "CONFIG_RR_INTERVAL=0", "CONFIG_PRIORITY_INHERITANCE=y", "CONFIG_SIG_DEFAULT=y",
                "CONFIG_SIG_SIGSTOP_ACTION=y", "CONFIG_EXAMPLES_RHEALSTONE=y", "# CONFIG_EXAMPLES_HARTSTONE is not set"}
    required.update({"# CONFIG_FDCLONE_DISABLE is not set", "# CONFIG_FDCLONE_STDIO is not set"})
    if not required <= config or "CONFIG_SMP=y" in config or "CONFIG_DISABLE_PTHREAD=y" in config or \
            "CONFIG_DISABLE_MQUEUE=y" in config:
        raise ValueError("native signal/PI/MQ/FIFO/clock profile differs")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or b"13.2.0" not in (directory / "nuttx").read_bytes():
        raise ValueError("native compiler differs")
    log = (directory / "build.log").read_text()
    for name in ("original.c", "port.c"):
        commands = []
        for line in log.splitlines():
            if "xtensa-esp32-elf-gcc" not in line or " -c " not in line:
                continue
            args = shlex.split(line)
            if args and Path(args[0]).name == "xtensa-esp32-elf-gcc" and any(Path(arg).name == name for arg in args):
                commands.append(args)
        if len(commands) != 1 or [arg for arg in commands[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                not any("/nuttx-rhealstone-work/" in arg for arg in commands[0]):
            raise ValueError(("original/native compilation missing or changed", name))
    disassembly = (directory / "disassembly.txt").read_text()
    native = {
        "taskswitch": ("task_create", "sched_yield"),
        "taskpreempt": ("task_create", "kill", "nxsched_suspend"),
        "semshuffle": ("task_create", "task_restart", "kill", "sched_yield", "pthread_mutex_lock", "pthread_mutex_unlock"),
        "mlatency": ("task_create", "mq_open", "mq_send", "mq_receive"),
        "deadlockbrk": ("task_create", "task_restart", "kill", "pthread_mutex_lock", "pthread_mutex_unlock"),
    }
    for name in native[case]:
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native API is not called", name))
    for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
        body = re.search(r"^[0-9a-f]+ <" + name + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
        if body is None or not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body[1]):
            raise ValueError(("native cycle counter absent from original timer hook", name))
    audit_flash(directory, "flash.log", 3)
    written = [(int(size), int(address, 16)) for size, address in re.findall(
        r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())]
    expected = [((directory / name).stat().st_size, address) for name, address in
                (("bootloader-esp32.bin", 0x1000), ("partition-table-esp32.bin", 0x8000), ("nuttx.bin", 0x10000))]
    if written != expected:
        raise ValueError("Flash segments do not bind archived native image")
    runs = [audit_capture(directory / f"reset{i}.jsonl", case, "NuttX") for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("native independent reset windows overlap")
    values = [row["raw_original_cycles"] for row in runs]
    valid = all(row["measurement_eligible"] for row in runs)
    return {"audit": "pass", "case": case, "os": "NuttX 12.2.1", "resets": 3,
            "original_revision": "RTEMS acb78c0c8c76f4ae12c60b729948e541c1e3930c",
            "raw_original_cycles": values, "measurement_eligible": valid,
            "median_us": statistics.median(values) / 240 if valid else None,
            "range_us": [min(values) / 240, max(values) / 240] if valid else None,
            "captures": runs, "binary_sha256": digest(directory / "nuttx.bin"), "ranking_eligible": False,
            "qualification": ["native independent task groups are created at original start; priority-ordered FIFO",
                              "native SIGSTOP/SIGCONT job control, not RTEMS direct suspend/resume",
                              "owned native pthread mutex: shuffle explicitly PRIO_NONE, deadlock break explicitly PRIO_INHERIT",
                              "native one-slot MQ copies 16-byte messages; nonblocking send and blocking receive use distinct descriptors",
                              "independent child task groups inherit the native MQ file descriptors",
                              "original single-sample overhead subtraction can produce nonpositive results"],
            "ranking_reason": "native task-group/signal/mutex/calibration paths require semantic review before cross-OS ranking"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
