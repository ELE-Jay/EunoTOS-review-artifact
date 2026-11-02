#!/usr/bin/env python3
"""Replay original Rhealstone on the native, legacy-compiler Rhino cohort."""
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

REVISION = "bacc144bdc5df8fe8e302e3732675a920aa40bc5"
UPSTREAM = f"https://raw.githubusercontent.com/alibaba/AliOS-Things/{REVISION}/"
NATIVE_SOURCES = ("kernel/rhino/k_task.c", "kernel/rhino/k_mutex.c", "kernel/rhino/k_buf_queue.c",
                  "kernel/rhino/include/k_default_config.h", "platform/mcu/esp32/aos/hook_impl.c")


def audit(directory, verify_upstream=False):
    case = directory.name
    if case not in CASES or directory.parent.name != "alios":
        raise ValueError("unsupported native Rhino original case")
    check_manifest(directory, "image.sha256")
    names = {Path(line.split(maxsplit=1)[1].lstrip("*")).as_posix()
             for line in (directory / "image.sha256").read_text().splitlines()}
    required_files = {"application.elf", "application.bin", "rhealstone@esp32bench.map", "link.opts",
                      "bootloader.bin", "partitions.bin", "config", "sdkconfig.h", "k_config.h",
                      "compiler.txt", "build.log", "disassembly.txt", "original.c", "port.c", "aos.mk",
                      "Config.in", "include/timesys.h", "include/tmacros.h", "include/rtems/btimer.h",
                      "include/rtems/confdefs.h", "rhino-port-pinned.c", "rhino-portasm-pinned.S",
                      "rhino-vectors-pinned.S"}
    required_files.update("native-source/" + name for name in NATIVE_SOURCES)
    if not required_files <= names:
        raise ValueError("incomplete source/image/config/build binding")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    for name, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h")):
        if (directory / name).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("original body or formula changed")
    for name in ("port.c", "aos.mk", "Config.in"):
        if (directory / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/alios" / name).read_bytes():
            raise ValueError("unreviewed native Rhino adapter")
    for name in ("tmacros.h", "rtems/btimer.h", "rtems/confdefs.h"):
        if (directory / "include" / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/include" / name).read_bytes():
            raise ValueError("original adapter contract changed")
    for archived, source in (("rhino-port-pinned.c", "rhino-port.c"),
                             ("rhino-vectors-pinned.S", "rhino-vectors.S"),
                             ("k_config.h", "esp32bench/k_config.h"),
                             ("sdkconfig.h", "esp32bench/sdkconfig.h")):
        if (directory / archived).read_bytes() != (ROOT / "firmware/bsp/esp32/alios_board" / source).read_bytes():
            raise ValueError("native board/interrupt/configuration port changed")
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
        raise ValueError("native task/mutex/queue/default-configuration source binding differs")
    config = set((directory / "config").read_text().splitlines())
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="rhealstone"', 'AOS_APP_RHEALSTONE=y'} <= config:
        raise ValueError("native build target differs")
    defaults = (directory / "native-source/kernel/rhino/include/k_default_config.h").read_text()
    if not re.search(r"#define RHINO_CONFIG_MUTEX_INHERIT\s+1\b", defaults):
        raise ValueError("native mutex inheritance disabled")
    if "5.2.0" not in (directory / "compiler.txt").read_text() or b"5.2.0" not in (directory / "application.elf").read_bytes():
        raise ValueError("native legacy compiler differs")
    log = (directory / "build.log").read_text()
    for name in ("original.c", "port.c", "k_task.c", "k_mutex.c", "k_buf_queue.c", "hook_impl.c"):
        matches = []
        for line in log.splitlines():
            if not line.startswith("xtensa-esp32-elf-gcc ") or " -c " not in line:
                continue
            args = shlex.split(line)
            expected = "app/example/rhealstone/" + name if name in ("original.c", "port.c") else \
                "platform/mcu/esp32/aos/hook_impl.c" if name == "hook_impl.c" else "kernel/rhino/" + name
            if expected in args:
                matches.append(args)
        if len(matches) != 1 or [arg for arg in matches[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DAOS_NO_WIFI" not in matches[0]:
            raise ValueError(("original/native compilation missing or changed", name))
    disassembly = (directory / "disassembly.txt").read_text()
    native = {
        "taskswitch": ("krhino_task_create", "krhino_task_resume", "krhino_task_yield"),
        "taskpreempt": ("krhino_task_create", "krhino_task_suspend", "krhino_task_resume"),
        "semshuffle": ("krhino_task_create", "krhino_task_del", "krhino_task_suspend", "krhino_task_yield",
                       "krhino_mutex_lock", "krhino_mutex_unlock"),
        "mlatency": ("krhino_task_create", "krhino_fix_buf_queue_create", "krhino_buf_queue_send", "krhino_buf_queue_recv"),
        "deadlockbrk": ("krhino_task_create", "krhino_task_del", "krhino_task_suspend", "krhino_task_resume",
                        "krhino_mutex_lock", "krhino_mutex_unlock"),
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
                (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]
    if written != expected:
        raise ValueError("Flash segments do not bind archived native image")
    runs = [audit_capture(directory / f"reset{i}.jsonl", case, "AliOS-Rhino") for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("native independent reset windows overlap")
    values = [row["raw_original_cycles"] for row in runs]
    valid = all(row["measurement_eligible"] for row in runs)
    return {"audit": "pass", "case": case, "os": "AliOS/Rhino " + REVISION, "resets": 3,
            "original_revision": "RTEMS acb78c0c8c76f4ae12c60b729948e541c1e3930c",
            "raw_original_cycles": values, "measurement_eligible": valid,
            "median_us": statistics.median(values) / 240 if valid else None,
            "range_us": [min(values) / 240, max(values) / 240] if valid else None,
            "captures": runs, "binary_sha256": digest(directory / "application.bin"), "ranking_eligible": False,
            "qualification": ["GCC5.2 native legacy cohort, not the GCC13 primary profile",
                              "native static tasks created inactive; restart deletes/recreates outside measured loops",
                              "native owned priority-inheritance mutex: inheritance cannot be disabled per object for shuffle",
                              "native one-slot fixed queue copies 16-byte messages; nonblocking send and blocking receive",
                              "original single-sample overhead subtraction and unsigned duration arithmetic retained"],
            "ranking_reason": "legacy toolchain, native mutex and original overhead-calibration qualifications"}


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
