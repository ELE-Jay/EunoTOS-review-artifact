#!/usr/bin/env python3
"""Audit unchanged original Zephyr synchronization bodies on native NuttX."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
import struct
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_latency_freertos import ROOT, REFERENCE, SOURCES, TAGS, capture, render_table
from audit_esp32_zephyr_original import UPSTREAM as ZEPHYR_UPSTREAM
from audit_esp32_iperf_original import ANSI

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_nuttx"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos/include"
UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
NATIVE_SOURCES = ("sched/pthread/pthread_create.c", "sched/pthread/pthread_mutexinit.c",
    "sched/pthread/pthread_mutextrylock.c", "sched/pthread/pthread_mutexunlock.c",
    "sched/semaphore/sem_post.c", "sched/semaphore/sem_wait.c", "sched/semaphore/sem_trywait.c",
    "sched/semaphore/sem_setprotocol.c", "libs/libc/pthread/pthread_attr_setstack.c",
    "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_releasestack.c",
    "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/common/xtensa_timer.h", "tools/version.sh")


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= covered:
        raise ValueError("native acquisition coverage incomplete")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "image.sha256").read_text().splitlines()}
    if not {"nuttx", "nuttx.bin", "nuttx.map", "config", "compiler.txt", "build.log", "disassembly.txt",
            "bootloader-esp32.bin", "partition-table-esp32.bin", "build-script.sh", "version-metadata", "version-header.h", *(
            "source/" + name for name in SOURCES), *("native-source/" + name for name in NATIVE_SOURCES)} <= covered:
        raise ValueError("native build/source/ELF manifest coverage incomplete")
    original = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in SOURCES:
        proof = original["src/" + name]
        if proof["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original selected source differs")
    for path in PORT.rglob("*"):
        if path.is_file() and (directory / path.relative_to(PORT)).read_bytes() != path.read_bytes():
            raise ValueError("native NuttX adapter differs from inspected implementation")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                (directory / "include" / path.relative_to(SHARED)).read_bytes() != path.read_bytes():
            raise ValueError("shared original timing/format adapter differs")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE_SOURCES:
            with urlopen(UPSTREAM + name, timeout=30) as response:
                upstream = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != upstream:
                raise ValueError(("native NuttX source differs from official version", name))
            records.append({"path": name, "url": UPSTREAM + name, "sha256": upstream})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE_SOURCES) or {row["path"] for row in records} != set(NATIVE_SOURCES) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in records):
        raise ValueError("native pthread/semaphore/stack/tick source provenance differs")
    config = set((directory / "config").read_text().splitlines())
    if not {"CONFIG_BUILD_FLAT=y", "CONFIG_EXAMPLES_ZEPHYR_LATENCY=y", "CONFIG_USEC_PER_TICK=1000000",
            "CONFIG_RR_INTERVAL=0", "CONFIG_PRIORITY_INHERITANCE=y", "CONFIG_PTHREAD_MUTEX_TYPES=y",
            "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240"} <= config or \
            {"CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y", "CONFIG_DISABLE_PTHREAD=y"} & config or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native compiler/clock/FIFO/recursive-mutex profile differs")
    if 'CONFIG_VERSION_STRING="12.2.1"' not in (directory / "version-metadata").read_text().splitlines() or \
            not re.search(r'#define CONFIG_VERSION_STRING\s+"12.2.1"', (directory / "version-header.h").read_text()):
        raise ValueError("native snapshot version metadata/header differs")
    log = (directory / "build.log").read_text()
    commands = [shlex.split(line) for line in log.splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    for name in (*SOURCES[:3], "port.c"):
        selected = [args for args in commands if args and Path(args[0]).name == "xtensa-esp32-elf-gcc" and
                    any(Path(arg).name == name for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                not any("/nuttx-zephyr-latency-work/" in arg for arg in selected[0]):
            raise ValueError(("original/native compilation differs", name))
    for path in NATIVE_SOURCES:
        if not path.endswith(".c"):
            continue
        name = Path(path).name
        selected = [args for args in commands if args and Path(args[0]).name == "xtensa-esp32-elf-gcc" and
                    any(Path(arg).name == name for arg in args) and
                    (not path.startswith("sched/") or "-D__KERNEL__" in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("native operation/stack/tick source compilation differs", path))
    audit_elf_image(directory / "nuttx", directory / "nuttx.bin")
    with (directory / "nuttx").open("rb") as stream:
        symbols = {symbol.name: symbol for symbol in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
        for name in ("sema_test_signal", "sema_context_switch", "mutex_lock_unlock", "z_impl_timing_timestamp_get",
                     "k_sem_give", "k_sem_take", "k_mutex_lock", "k_mutex_unlock", "zephyr_latency_main"):
            if name not in symbols or not symbols[name]["st_size"] or symbols[name]["st_shndx"] == "SHN_UNDEF":
                raise ValueError("original/native operation not linked")
    disassembly = (directory / "disassembly.txt").read_text()
    for name in ("sem_post", "sem_wait", "sem_trywait", "sem_setprotocol", "pthread_mutex_init",
                 "pthread_mutex_trylock", "pthread_mutex_unlock", "pthread_attr_setstack", "pthread_create", "pthread_join"):
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native synchronization/thread API not called", name))
    body = re.search(r"^[0-9a-f]+ <z_impl_timing_timestamp_get>:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
    if body is None or not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body[1]):
        raise ValueError("original timestamp hook does not use native cycle counter")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader-esp32.bin", 0x1000), ("partition-table-esp32.bin", 0x8000), ("nuttx.bin", 0x10000))]:
        raise ValueError("native installed image/board binding differs")
    captures = [capture(directory, i, digest(directory / "nuttx"), "NuttX") for i in (1, 2, 3)]
    data, segments, position = (directory / "nuttx.bin").read_bytes(), [], 24
    for _ in range(data[1]):
        address, size = struct.unpack_from("<II", data, position)
        segments.append((address, size))
        position += size + 8
    for i in (1, 2, 3):
        lines = [ANSI.sub("", json.loads(line)["line"]) for line in (directory / f"reset{i}.jsonl").read_text().splitlines()]
        observed = [(int(n), int(addr, 16), int(size)) for line in lines if (match := re.search(
            r"esp_image: segment (\d+): paddr=[0-9a-f]+ vaddr=([0-9a-f]+) size=[0-9a-f]+h \(\s*(\d+)\)", line))
            for n, addr, size in [match.groups()]]
        if observed != [(index, address, size) for index, (address, size) in enumerate(segments)]:
            raise ValueError("native boot segment trace differs from installed image")
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure semaphore/recursive-mutex subset",
            "os": "NuttX 12.2.1", "resets": 3, "original_iterations": 1000, "metric_count": 6,
            "captures": captures, "metrics": metrics, "source_files": 5, "cores": 1, "clock_mhz": 240,
            "tick_hz": 1, "worker_stack_bytes": 1792, "ranking_eligible": False,
            "unmodified_official_native_suite": False,
            "boundary": "original selected bodies/statistics; native FIFO pthread/static-stack/counting semaphore and recursive owned mutex adapter costs included; semaphore limit is not enforced beyond this original never-overfilled subset; not full native Zephyr suite or cross-OS kernel-only rank"}


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
