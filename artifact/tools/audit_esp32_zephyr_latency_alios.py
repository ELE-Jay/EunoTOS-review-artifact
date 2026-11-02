#!/usr/bin/env python3
"""Replay unchanged original Zephyr synchronization tests on native Rhino."""
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
from audit_esp32_rhealstone_alios import REVISION, UPSTREAM
from audit_esp32_zephyr_latency_freertos import ROOT, REFERENCE, SOURCES, TAGS, capture, render_table
from audit_esp32_zephyr_original import UPSTREAM as ZEPHYR_UPSTREAM

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_alios"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos/include"
NATIVE_SOURCES = ("kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_mutex.c",
    "kernel/rhino/include/k_sys.h", "kernel/rhino/include/k_sem.h", "kernel/rhino/include/k_mutex.h",
    "kernel/rhino/include/k_err.h", "kernel/rhino/include/k_default_config.h",
    "platform/mcu/esp32/aos/hook_impl.c", "platform/arch/xtensa/lx6/xtensa_init.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h")


def hardware_tick_divisors(directory, expected_hz=1):
    if type(expected_hz) is not int or expected_hz not in (1, 100):
        raise ValueError("unsupported audited Rhino tick profile")
    disassembly = (directory / "disassembly.txt").read_text()
    values = {}
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        for name in ("_frxt_timer_int", "_frxt_tick_timer_init"):
            body = re.search(r"^[0-9a-f]+ <" + name + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
            match = re.search(r"\bl32r\s+a[23], ([0-9a-f]+) <[^>]+>", body[1]) if body else None
            if not match:
                raise ValueError("hardware tick comparator increment not found")
            address = int(match[1], 16)
            sections = [section for section in elf.iter_sections() if section["sh_type"] != "SHT_NOBITS" and
                        section["sh_addr"] <= address and address + 4 <= section["sh_addr"] + section["sh_size"]]
            if len(sections) != 1:
                raise ValueError("hardware tick literal is not mapped to ELF")
            section = sections[0]
            values[name] = struct.unpack_from("<I", section.data(), address - section["sh_addr"])[0]
    if set(values.values()) != {240000000 // expected_hz}:
        raise ValueError((f"actual hardware tick divisor differs from {expected_hz}-Hz profile", values))
    return values


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "image.sha256").read_text().splitlines()}
    required = {"application.elf", "application.bin", "zephyr_latency@esp32bench.map", "link.opts", "config",
        "sdkconfig.h", "k_config.h", "compiler.txt", "build.log", "configure.log", "disassembly.txt",
        "bootloader.bin", "partitions.bin", "rhino-port-pinned.c", "rhino-portasm-pinned.S",
        "rhino-vectors-pinned.S", "build-script.sh", *("source/" + name for name in SOURCES),
        *("native-source/" + name for name in NATIVE_SOURCES)}
    if not required <= covered:
        raise ValueError("native original/source/config/image coverage incomplete")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= covered:
        raise ValueError("native acquisition coverage incomplete")
    original = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in SOURCES:
        proof = original["src/" + name]
        if proof["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original selected source differs")
    for path in PORT.rglob("*"):
        if path.is_file() and (directory / path.relative_to(PORT)).read_bytes() != path.read_bytes():
            raise ValueError("native Rhino adapter differs from inspected implementation")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                (directory / "include" / path.relative_to(SHARED)).read_bytes() != path.read_bytes():
            raise ValueError("shared original timing/format adapter differs")
    for archived, source in (("rhino-port-pinned.c", "rhino-port.c"),
                             ("rhino-vectors-pinned.S", "rhino-vectors.S"),
                             ("k_config.h", "esp32bench/k_config.h"), ("sdkconfig.h", "esp32bench/sdkconfig.h")):
        if (directory / archived).read_bytes() != (ROOT / "firmware/bsp/esp32/alios_board" / source).read_bytes():
            raise ValueError("native board/interrupt/configuration port changed")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE_SOURCES:
            with urlopen(UPSTREAM + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != sha:
                raise ValueError(("native Rhino source differs from official revision", name))
            records.append({"path": name, "url": UPSTREAM + name, "sha256": sha})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE_SOURCES) or {row["path"] for row in records} != set(NATIVE_SOURCES) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in records):
        raise ValueError("native semaphore/recursive-mutex/thread/tick provenance differs")
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="zephyr_latency"', 'AOS_APP_ZEPHYR_LATENCY=y'} <= \
            set((directory / "config").read_text().splitlines()):
        raise ValueError("native build target differs")
    if "5.2.0" not in (directory / "compiler.txt").read_text() or b"5.2.0" not in (directory / "application.elf").read_bytes():
        raise ValueError("native legacy compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compilation = ["app/example/zephyr_latency/" + name for name in (*SOURCES[:3], "port.c")]
    compilation += [name for name in NATIVE_SOURCES if name.endswith(".c")]
    for name in compilation:
        selected = [args for args in commands if name in args]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DAOS_NO_WIFI" not in selected[0] or \
                [arg for arg in selected[0] if arg.startswith("-DRHINO_CONFIG_TICKS_PER_SECOND=")] != \
                ["-DRHINO_CONFIG_TICKS_PER_SECOND=1"]:
            raise ValueError(("native/original compilation or real tick override differs", name))
    for name in ("platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S"):
        selected = [args for args in commands if name in args]
        if len(selected) != 1 or \
                [arg for arg in selected[0] if arg.startswith("-DRHINO_CONFIG_TICKS_PER_SECOND=")] != \
                ["-DRHINO_CONFIG_TICKS_PER_SECOND=1"]:
            raise ValueError(("native assembler tick override missing", name))
    divisors = hardware_tick_divisors(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        symbols = {symbol.name: symbol for symbol in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
        for name in ("sema_test_signal", "sema_context_switch", "mutex_lock_unlock", "z_impl_timing_timestamp_get",
                     "k_sem_give", "k_sem_take", "k_mutex_lock", "k_mutex_unlock", "_xt_tick_divisor", "application_start"):
            if name not in symbols or not symbols[name]["st_size"] or symbols[name]["st_shndx"] == "SHN_UNDEF":
                raise ValueError("original/native operation not linked")
    disassembly = (directory / "disassembly.txt").read_text()
    for name in ("krhino_sem_give", "krhino_sem_take", "krhino_mutex_lock", "krhino_mutex_unlock",
                 "krhino_task_create", "krhino_task_resume", "krhino_task_del", "krhino_task_suspend"):
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native synchronization/thread API not called", name))
    body = re.search(r"^[0-9a-f]+ <z_impl_timing_timestamp_get>:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
    if body is None or not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body[1]):
        raise ValueError("original timestamp hook does not read native cycle counter")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native installed image/board binding differs")
    captures = [capture(directory, i, digest(directory / "application.elf"), "AliOS-Rhino") for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure semaphore/recursive-mutex subset",
            "os": "AliOS/Rhino", "revision": REVISION, "resets": 3, "original_iterations": 1000,
            "metric_count": 6, "captures": captures, "metrics": metrics, "source_files": 5, "native_source_files": 11,
            "cores": 1, "clock_mhz": 240, "tick_hz": 1, "native_tick_divisor": 240000000, "compiler": "5.2.0",
            "hardware_tick_divisors": divisors,
            "worker_stack_bytes": 1792, "ranking_eligible": False, "unmodified_official_native_suite": False,
            "boundary": "original selected bodies/statistics; native counting semaphore, owned inheriting recursive mutex and static-task retirement costs included; semaphore limit not enforced beyond original never-overfilled subset; legacy GCC5 profile, not full Zephyr suite or cross-OS rank"}


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
