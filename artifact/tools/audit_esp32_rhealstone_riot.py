#!/usr/bin/env python3
"""Replay unchanged Rhealstone bodies with reviewed native RIOT adapters."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen
from audit_esp32_report import audit_flash
from audit_esp32_rhealstone import ROOT, SOURCE, audit_capture, digest
from audit_esp32_riot_original import check_manifest, REVISION, UPSTREAM
from audit_esp32_resources import audit_elf_image

CASES = ("taskswitch", "taskpreempt", "semshuffle", "mlatency", "deadlockbrk")
NATIVE_SOURCES = ("core/thread.c", "core/sched.c", "core/include/thread.h", "core/include/sched.h",
                  "cpu/esp32/irq_arch.c", "cpu/esp_common/esp-xtensa/thread_arch.c")
SYNC_SOURCES = ("core/mutex.c", "core/include/mutex.h", "core/mbox.c", "core/include/mbox.h", "core/include/msg.h")
V4_PORT = {"port.c": "44216500740b47f0918531bc328870ff3bd13e770ec9a49b1b69a94cbc8265ab",
           "Makefile": "58dbc4f9dccd007b4065ef14069f623751405c8e7431f3f4b4382917ddcc0de6"}


def audit(directory, verify_upstream=False):
    case = directory.name
    if case not in CASES or directory.parent.name != "riot":
        raise ValueError("unsupported or unimplemented native RIOT Rhealstone case")
    legacy = directory.parent.parent.name == "rhealstone-riot-v4"
    if legacy and case not in CASES[:2]:
        raise ValueError("unimplemented case in the older native thread-only adapter")
    native_sources = NATIVE_SOURCES if legacy else NATIVE_SOURCES + SYNC_SOURCES
    check_manifest(directory, "image.sha256")
    names = {Path(line.split(maxsplit=1)[1].lstrip("*")).as_posix()
             for line in (directory / "image.sha256").read_text().splitlines()}
    required = {"application.elf", "application.bin", "application.map", "bootloader.bin", "partitions.bin",
                "partitions.csv", "config.h", "compiler.txt", "build.log", "clean.log", "disassembly.txt",
                "original.c", "port.c", "Makefile", "include/timesys.h", "include/tmacros.h",
                "include/rtems/btimer.h", "include/rtems/confdefs.h"}
    required.update("native-source/" + name for name in native_sources)
    if not required <= names:
        raise ValueError("incomplete native source/image/configuration binding")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    for name, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h")):
        if (directory / name).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("original body or formula changed")
    for name in ("port.c", "Makefile"):
        expected = V4_PORT[name] if legacy else digest(ROOT / "firmware/bsp/esp32/rhealstone/riot" / name)
        if digest(directory / name) != expected:
            raise ValueError("unreviewed native RIOT adapter")
    for name in ("tmacros.h", "rtems/btimer.h", "rtems/confdefs.h"):
        if (directory / "include" / name).read_bytes() != (ROOT / "firmware/bsp/esp32/rhealstone/include" / name).read_bytes():
            raise ValueError("original adapter contract changed")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in native_sources:
            with urlopen(UPSTREAM + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != sha:
                raise ValueError(("native SDK differs from pinned official source", name))
            records.append({"path": name, "url": UPSTREAM + name, "sha256": sha})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(native_sources) or {row["path"] for row in records} != set(native_sources) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in records):
        raise ValueError("native scheduler/thread/architecture source binding differs")
    config = (directory / "config.h").read_text()
    for key, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                       ("MODULE_CORE_THREAD", 1), ("THREAD_PRIORITY_MAIN", 0)):
        if not re.search(r"^#define " + key + r" " + str(value) + r"$", config, re.M):
            raise ValueError("native clock/core/thread/Init profile changed")
    if "RHEALSTONE_DIAGNOSTIC" in config or "MODULE_SCHED_ROUND_ROBIN" in config:
        raise ValueError("diagnostic/timesliced profile cannot enter the selected cohort")
    if not legacy:
        inherit = bool(re.search(r"^#define MODULE_CORE_MUTEX_PRIORITY_INHERITANCE 1$", config, re.M))
        if inherit != (case == "deadlockbrk"):
            raise ValueError("original mutex inheritance profile changed")
        if case in ("semshuffle", "deadlockbrk") and not re.search(r"^#define MODULE_CORE_MUTEX 1$", config, re.M):
            raise ValueError("native mutex module absent")
        if case == "mlatency" and not re.search(r"^#define MODULE_CORE_MBOX 1$", config, re.M):
            raise ValueError("native mailbox module absent")
    if "12.2.0" not in (directory / "compiler.txt").read_text() or b"12.2.0" not in (directory / "application.elf").read_bytes():
        raise ValueError("native compiler differs")
    log = (directory / "build.log").read_text().replace("\\\n", " ")
    for name in ("original.c", "port.c"):
        commands = []
        for line in log.splitlines():
            if "xtensa-esp32-elf-gcc" not in line or " -c " not in line:
                continue
            args = shlex.split(line)
            if any(arg.endswith("/rhealstone/riot/" + name) for arg in args):
                commands.append(args)
        if len(commands) != 1 or [arg for arg in commands[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DTHREAD_PRIORITY_MAIN=0" not in commands[0] or \
                "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1" not in commands[0] or \
                any("RHEALSTONE_DIAGNOSTIC" in arg for arg in commands[0]):
            raise ValueError(("original/native compilation missing or changed", name))
    disassembly = (directory / "disassembly.txt").read_text()
    native = ["thread_create", "thread_wakeup"]
    if case in ("taskswitch", "taskpreempt", "mlatency"):
        native.append("sched_task_exit")
    if case in ("taskswitch", "semshuffle"):
        native.append("thread_yield")
    if case in ("taskpreempt", "semshuffle", "deadlockbrk"):
        native.append("thread_sleep")
    if case in ("semshuffle", "deadlockbrk"):
        native += ["sched_set_status", "sched_change_priority", "thread_kill_zombie", "mutex_lock_internal", "mutex_unlock"]
    if case == "mlatency":
        native += ["_mbox_put", "_mbox_get"]
    for name in native:
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native thread API is not called", name))
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
    runs = [audit_capture(directory / f"reset{i}.jsonl", case, "RIOT", "native-tickless") for i in (1, 2, 3)]
    for i in (1, 2, 3):
        lines = [json.loads(line)["line"] for line in (directory / f"reset{i}.jsonl").read_text().splitlines()]
        if lines.count("Single core mode") != 1 or lines.count("main(): This is RIOT! (Version: 2024.10-devel)") != 1 or \
                any("RHEALSTONE DIAG" in line for line in lines):
            raise ValueError("native runtime/version/core or diagnostic profile differs")
        if case == "mlatency" and lines.count(
                "RHEALSTONE queue self-check PASS family=mbox-owned-payload capacity=1 bytes=16") != 1:
            raise ValueError("one-slot copied-payload mailbox contract unverified")
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
        raise ValueError("native independent reset windows overlap")
    values = [row["raw_original_cycles"] for row in runs]
    valid = all(row["measurement_eligible"] for row in runs)
    qualifications = ["native tickless/GCC12 cohort, not the GCC13/100-Hz primary profile",
                      "priority order mapped strictly above idle; original Init has its own thread",
                      "original single-sample overhead subtraction retained; arithmetic validity is not isolated-latency validation"]
    if case == "taskpreempt":
        qualifications.append("positive preempt output nearly cancels calibration; not a validated isolated latency")
    if case in ("semshuffle", "deadlockbrk"):
        qualifications += ["IRQ-protected native runnable-peer suspension and sleeping-thread retirement/recreation outside timed loops",
                           "native inheriting mutex" if case == "deadlockbrk" else
                           "native non-inheriting mutex without RTEMS-style ownership enforcement"]
    if case == "mlatency":
        qualifications += ["owned 16-byte payload plus native mailbox, not an OS-native 16-byte copying queue",
                           "positive message output nearly cancels calibration; not a validated isolated latency"]
    return {"audit": "pass", "case": case, "os": "RIOT " + REVISION, "resets": 3,
            "original_revision": "RTEMS acb78c0c8c76f4ae12c60b729948e541c1e3930c",
            "raw_original_cycles": values, "measurement_eligible": valid,
            "median_us": statistics.median(values) / 240 if valid else None,
            "range_us": [min(values) / 240, max(values) / 240] if valid else None,
            "captures": runs, "binary_sha256": digest(directory / "application.bin"), "ranking_eligible": False,
            "qualification": qualifications, "adapter_cohort": directory.parent.parent.name,
            "isolated_latency_validated": False,
            "ranking_reason": "original calibration and unmatched compiler/native scheduler profiles"}


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
