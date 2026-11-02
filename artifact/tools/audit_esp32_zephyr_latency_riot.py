#!/usr/bin/env python3
"""Replay six unchanged original Zephyr synchronization cases on native RIOT."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, REVISION, UPSTREAM
from audit_esp32_zephyr_latency_freertos import ROOT, REFERENCE, SOURCES, TAGS, capture, render_table
from audit_esp32_zephyr_original import UPSTREAM as ZEPHYR_UPSTREAM

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_riot"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos/include"
NATIVE_SOURCES = ("core/thread.c", "core/sched.c", "core/include/thread.h", "core/include/sched.h",
    "core/mutex.c", "core/include/mutex.h", "core/lib/rmutex.c", "core/lib/include/rmutex.h",
    "sys/sema/sema.c", "sys/include/sema.h", "cpu/esp32/irq_arch.c", "cpu/esp_common/esp-xtensa/thread_arch.c")


def semaphore_branch_evidence(directory, disassembly):
    # Linear Xtensa objdump loses alignment after the literal before this branch.
    path = directory / "semaphore-control-flow.txt"
    text = path.read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbol = elf.get_section_by_name(".symtab").get_symbol_by_name("k_sem_take")[0]
        start, end = symbol["st_value"], symbol["st_value"] + symbol["st_size"]
        section = elf.get_section(symbol["st_shndx"])
        data, base = section.data(), section["sh_addr"]
        rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", text, re.M)
        if not rows or int(rows[0][0], 16) != start + 0x12 or not re.search(
                r"\bbltui\s+[^\n]*" + format(start + 0x12, "x") + r" <k_sem_take\+0x12>", disassembly):
            raise ValueError("supplement is not the actual semaphore branch target")
        for address, encoding, instruction in rows:
            address = int(address, 16)
            encoded = bytes.fromhex(encoding)[::-1]
            if not start <= address < end or address + len(encoded) > end or \
                    data[address - base:address - base + len(encoded)] != encoded:
                raise ValueError("supplemental disassembly bytes differ from frozen ELF")
        calls = [(int(address, 16), int(encoding, 16)) for address, encoding, instruction in rows
                 if re.fullmatch(r"call8\s+[0-9a-f]+ <_sema_wait_ztimer>", instruction)]
        target = elf.get_section_by_name(".symtab").get_symbol_by_name("_sema_wait_ztimer")[0]["st_value"]
        if len(calls) != 1:
            raise ValueError("semaphore branch does not call native wait")
        address, encoding = calls[0]
        offset = encoding >> 6
        if offset & (1 << 17):
            offset -= 1 << 18
        if encoding & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != target:
            raise ValueError("native wait label differs from encoded Xtensa call8 target")
    return {"path": path.name, "sha256": digest(path), "elf_sha256": digest(directory / "application.elf"),
            "instruction_bytes_checked": len(rows), "reason": "linear objdump alignment loss after preceding literal"}


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
             (directory / "image.sha256").read_text().splitlines()}
    if not {"application.elf", "application.bin", "application.map", "config.h", "compiler.txt", "build.log",
            "clean.log", "bootloader.bin", "partitions.bin", "partitions.csv", "disassembly.txt", *(
            "source/" + name for name in SOURCES), *("native-source/" + name for name in NATIVE_SOURCES)} <= names:
        raise ValueError("native original/source/config/image coverage incomplete")
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
             (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= names:
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
            raise ValueError("native RIOT adapter differs from inspected implementation")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                (directory / "include" / path.relative_to(SHARED)).read_bytes() != path.read_bytes():
            raise ValueError("shared original timing/format adapter differs")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE_SOURCES:
            with urlopen(UPSTREAM + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != sha:
                raise ValueError(("native RIOT source differs from official revision", name))
            records.append({"path": name, "url": UPSTREAM + name, "sha256": sha})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE_SOURCES) or {row["path"] for row in records} != set(NATIVE_SOURCES) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in records):
        raise ValueError("native semaphore/recursive-mutex/thread source provenance differs")
    config = (directory / "config.h").read_text()
    for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                        ("THREAD_PRIORITY_MAIN", 10), ("MODULE_CORE_THREAD", 1), ("MODULE_SEMA", 1)):
        if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
            raise ValueError("native core/clock/thread/semaphore profile differs")
    if "MODULE_SCHED_ROUND_ROBIN" in config or "MODULE_CORE_MUTEX_PRIORITY_INHERITANCE" in config or \
            "12.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native tickless/FIFO/non-inheriting/compiler profile differs")
    log = (directory / "build.log").read_text().replace("\\\n", " ")
    commands = [shlex.split(line) for line in log.splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    for name in (*SOURCES[:3], "port.c"):
        selected = [args for args in commands if args and Path(args[0]).name == "xtensa-esp32-elf-gcc" and
                    any(arg.endswith("/zephyr-latency-riot/" + name) for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DTHREAD_PRIORITY_MAIN=10" not in selected[0]:
            raise ValueError(("original/native compilation differs", name))
    for name in ("core/mutex.c", "core/lib/rmutex.c", "sys/sema/sema.c", "core/thread.c", "core/sched.c"):
        selected = [args for args in commands if args and Path(args[0]).name == "xtensa-esp32-elf-gcc" and
                    any(arg.endswith("/RIOT-2024.10-devel/" + name) for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("native kernel operation not compiled", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        symbols = {symbol.name: symbol for symbol in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
        for name in ("sema_test_signal", "sema_context_switch", "mutex_lock_unlock", "z_impl_timing_timestamp_get",
                     "k_sem_give", "k_sem_take", "k_mutex_lock", "k_mutex_unlock", "main"):
            if name not in symbols or not symbols[name]["st_size"] or symbols[name]["st_shndx"] == "SHN_UNDEF":
                raise ValueError("original/native operation not linked")
    disassembly = (directory / "disassembly.txt").read_text()
    branch_evidence = semaphore_branch_evidence(directory, disassembly)
    for name in ("sema_post", "rmutex_trylock", "rmutex_unlock", "mutex_unlock_and_sleep",
                 "thread_create", "thread_wakeup", "mutex_lock_internal", "thread_kill_zombie", "sched_set_status"):
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
    captures = [capture(directory, i, digest(directory / "application.elf"), "RIOT") for i in (1, 2, 3)]
    for i in (1, 2, 3):
        lines = [json.loads(line)["line"] for line in (directory / f"reset{i}.jsonl").read_text().splitlines()]
        joins = [match.groups() for line in lines if (match := re.fullmatch(r"LATENCY NATIVE JOIN before=(\d+) after=(\d+)", line))]
        if len(joins) != 1 or joins[0][0] != joins[0][1] or int(joins[0][0]) < 2:
            raise ValueError("native worker retirement/thread-count check differs")
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure semaphore/recursive-mutex subset",
            "os": "RIOT 2024.10-devel", "revision": REVISION, "resets": 3, "original_iterations": 1000,
            "metric_count": 6, "captures": captures, "metrics": metrics, "source_files": 5, "native_source_files": 12,
            "cores": 1, "clock_mhz": 240, "tick_hz": None, "timer_profile": "native-tickless", "compiler": "12.2.0",
            "worker_stack_bytes": 1792, "ranking_eligible": False, "unmodified_official_native_suite": False,
            "semaphore_branch_evidence": branch_evidence,
            "boundary": "original selected bodies/statistics; native sema/rmutex and inactive-thread/atomic-park/retire adapter costs included; nonsaturating counting semaphore subset and non-inheriting recursive mutex; native TCB occupies stack; tickless/GCC12 profile, not full Zephyr suite or cross-OS rank"}


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
