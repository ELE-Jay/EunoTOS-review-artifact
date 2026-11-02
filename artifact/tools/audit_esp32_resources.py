#!/usr/bin/env python3
"""Replay installed Flash and static SRAM footprint from archived ESP32 images.

Static SRAM is not the whole-system runtime RAM peak. Count physical aliases
once; do not infer Flash use from ELF size or sparse objcopy output.
"""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile

from audit_esp32_report import EVIDENCE, TM, audit_image_manifest
from audit_esp32_tm_irq_match import NUTTX_REUSED_CASES, audit_cohort

FLASH_CAPACITY = 4 * 1024 * 1024
ALIASES = (
    (0x400A0000, 0x400A4000, 0x3FFFC000),
    (0x400A4000, 0x400A8000, 0x3FFF8000),
    (0x400A8000, 0x400B0000, 0x3FFF0000),
    (0x400B0000, 0x400B8000, 0x3FFE8000),
    (0x400B8000, 0x400BC000, 0x3FFE4000),
    (0x400BC000, 0x400C0000, 0x3FFE0000),
    (0x400C0000, 0x400C2000, 0x3FF80000),
)
RAM = ((0x3FF80000, 0x3FF82000), (0x3FFAE000, 0x40000000),
       (0x40070000, 0x400C2000), (0x50000000, 0x50002000))


def union_bytes(intervals):
    end, total = -1, 0
    for start, stop in sorted(intervals):
        if stop <= start:
            raise ValueError("invalid memory interval")
        total += max(0, stop - max(start, end))
        end = max(end, stop)
    return total


def physical_intervals(start, size):
    end = start + size
    cuts = sorted({start, end} | {point for low, high, _ in ALIASES
                                  for point in (low, high) if start < point < end})
    result = []
    for left, right in zip(cuts, cuts[1:]):
        for low, high, target in ALIASES:
            if low <= left < high:
                result.append((target + left - low, target + right - low))
                break
        else:
            result.append((left, right))
    return result


def image_length(data):
    if len(data) < 24 or len(data) > FLASH_CAPACITY or data[0] != 0xE9:
        raise ValueError("not a bounded ESP32 flash image")
    if not 1 <= data[1] <= 16 or data[23] not in (0, 1):
        raise ValueError("invalid ESP32 image header")
    position, checksum = 24, 0xEF
    for _ in range(data[1]):
        if position + 8 > len(data):
            raise ValueError("truncated image segment")
        _, size = struct.unpack_from("<II", data, position)
        position += 8
        if position + size > len(data):
            raise ValueError("truncated image payload")
        for byte in data[position:position + size]:
            checksum ^= byte
        position += size
    end = (position + 16) // 16 * 16
    if end > len(data) or data[end - 1] != checksum:
        raise ValueError("invalid ESP32 payload checksum")
    if data[23]:
        if hashlib.sha256(data[:end]).digest() != data[end:end + 32]:
            raise ValueError("invalid ESP32 image digest")
        end += 32
    return end


def audit_elf_image(elf_path, bin_path, *, ram_only_header=False):
    """Bind every initialized allocated ELF section to its ESP32 image payload."""
    data = bin_path.read_bytes()
    image_length(data)
    position, segments = 24, []
    for _ in range(data[1]):
        address, size = struct.unpack_from("<II", data, position)
        position += 8
        segments.append((address, data[position:position + size]))
        position += size
    if ram_only_header:
        # Zephyr's native elf2image mode leaves mapped Flash segments after
        # the ROM-visible RAM checksum. They are still part of the image.
        if data[23] or image_length(data) != (position + 16) // 16 * 16:
            raise ValueError("unsupported RAM-only-header digest layout")
        position = image_length(data)
        mapped = []
        while position < len(data):
            if position + 8 > len(data):
                raise ValueError("truncated mapped Flash segment header")
            address, size = struct.unpack_from("<II", data, position)
            position += 8
            if not size or size % 4 or position + size > len(data):
                raise ValueError("invalid mapped Flash segment size")
            payload = data[position:position + size]
            if address == 0:
                if any(payload):
                    raise ValueError("nonzero native Flash alignment padding")
            elif any(low <= address and address + size <= high for low, high in
                    ((0x3F400000, 0x3F800000), (0x400D0000, 0x40400000))):
                if (position + 0x1000) % 65536 != address % 65536:
                    raise ValueError("native mapped Flash MMU alignment differs")
                segments.append((address, payload))
                mapped.append(address)
            else:
                raise ValueError("invalid mapped Flash address")
            position += size
        if len(mapped) != 2 or not any(0x3F400000 <= a < 0x3F800000 for a in mapped) or \
                not any(0x400D0000 <= a < 0x40400000 for a in mapped):
            raise ValueError("native IROM/DROM segment coverage differs")
    ordered = sorted((address, address + len(payload)) for address, payload in segments if payload)
    if any(left_end > right_start for (_, left_end), (right_start, _) in zip(ordered, ordered[1:])):
        raise ValueError("ESP32 image contains overlapping load segments")
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf["e_machine"] != "EM_XTENSA" or \
                elf["e_entry"] != struct.unpack_from("<I", data, 4)[0]:
            raise ValueError("native ELF/BIN architecture or entry binding differs")
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_PROGBITS" or not section["sh_flags"] & 2 or not section["sh_size"]:
                continue
            start, size = section["sh_addr"], section["sh_size"]
            cursor, contents = start, section.data()
            # ESP-IDF fills only this descriptor's reserved ELF digest during elf2image.
            if section.name == ".flash.appdesc" and size == 256 and contents[:4] == b"\x32\x54\xcd\xab" and contents[144:176] == bytes(32):
                loaded = next((payload[start - address:start - address + size] for address, payload in segments
                               if address <= start and start + size <= address + len(payload)), None)
                filled = contents[:144] + hashlib.sha256(elf_path.read_bytes()).digest() + contents[176:]
                if loaded == filled:
                    contents = filled
            # Legacy elf2image can split one IRAM section into adjacent segments.
            while cursor < start + size:
                segment = next(((address, payload) for address, payload in segments
                                if address <= cursor < address + len(payload)), None)
                if segment is None:
                    raise ValueError(("compiled native ELF section not present in installed BIN", section.name))
                address, payload = segment
                stop = min(start + size, address + len(payload))
                if payload[cursor - address:stop - address] != contents[cursor - start:stop - start]:
                    raise ValueError(("compiled native ELF section not present in installed BIN", section.name))
                cursor = stop


def static_footprint(path):
    sections, physical = [], []
    initialized = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf["e_machine"] != "EM_XTENSA":
            raise ValueError("wrong ELF architecture")
        for section in elf.iter_sections():
            start, size = section["sh_addr"], section["sh_size"]
            if not section["sh_flags"] & 2 or not size:
                continue
            in_ram = any(low <= start and start + size <= high for low, high in RAM)
            if in_ram:
                physical.extend(physical_intervals(start, size))
                sections.append({"name": section.name, "address": hex(start), "bytes": size,
                                 "type": section["sh_type"]})
            if section["sh_type"] == "SHT_PROGBITS":
                initialized.append((start, start + size))
    return {"static_sram_bytes": union_bytes(physical), "ram_sections": sections,
            "elf_initialized_payload_bytes": union_bytes(initialized),
            "runtime_whole_ram_peak_bytes": None,
            "runtime_peak_status": "not measured by ELF analysis"}


def audit_cell(directory, os, case, observation=False, historical_reuse=True, *, recursive_manifest=False):
    directory = directory.resolve()
    elf_name = {"FreeRTOS": "iotosbench_tm.elf", "Zephyr": "zephyr.elf",
                "NuttX": "nuttx", "RIOT": "application.elf", "AliOS-Rhino": "application.elf"}[os]
    segments = {
        "FreeRTOS": [(0x1000, "bootloader.bin"), (0x8000, "partition-table.bin"),
                     (0x10000, "iotosbench_tm.bin")],
        "Zephyr": [(0x1000, "zephyr.bin")],
        "NuttX": [(0x1000, "bootloader-esp32.bin"), (0x8000, "partition-table-esp32.bin"),
                  (0x10000, "nuttx.bin")],
        "RIOT": [(0x1000, "bootloader.bin"), (0x8000, "partitions.bin"),
                 (0x10000, "application.bin")],
        "AliOS-Rhino": [(0x1000, "bootloader.bin"), (0x8000, "partitions.bin"),
                        (0x10000, "application.bin")],
    }[os]
    if observation:
        elf_name = "application.elf"
        segments = [(0x1000, "application.bin")] if os == "Zephyr" else [
            (0x1000, "bootloader.bin"), (0x8000, "partitions.bin"),
            (0x10000, "application.bin")]
    required = {elf_name, "compiler.txt", *(name for _, name in segments)}
    audit_image_manifest(directory, required, allow_nested=recursive_manifest)
    flash_directory = directory
    boot_content_identity_bound = True
    if not observation and historical_reuse and os == "NuttX" and case in NUTTX_REUSED_CASES:
        audit_cohort(directory, os, case, reuse_identical_image=True)
        image_folder, flash_folder, _ = NUTTX_REUSED_CASES[case]
        original = EVIDENCE / image_folder
        for name in (elf_name, *(name for _, name in segments)):
            if not (original / name).exists() and name in ("bootloader-esp32.bin", "partition-table-esp32.bin"):
                boot_content_identity_bound = False
            elif (directory / name).read_bytes() != (original / name).read_bytes():
                raise ValueError("resource image differs from the measured reused image")
        flash_directory = EVIDENCE / flash_folder
    text = (flash_directory / "flash.log").read_text()
    if text.count("Chip is ESP32-D0WDQ6 (revision v1.1)") != 1 or \
            text.count("MAC: 84:1f:e8:8f:55:dc") != 1 or \
            text.count("Hash of data verified.") != len(segments):
        raise ValueError(f"{directory}: flash verification or board identity missing")
    written = [(int(size), int(offset, 16)) for size, offset in
               re.findall(r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", text)]
    expected, rows = [], []
    for offset, name in segments:
        data = (directory / name).read_bytes()
        end = offset + len(data)
        if end > FLASH_CAPACITY or not data:
            raise ValueError("image exceeds physical flash")
        expected.append((len(data), offset))
        length = image_length(data) if data[0] == 0xE9 else None
        if length is None and not data.startswith(b"\xaa\x50"):
            raise ValueError("invalid partition table signature")
        rows.append({"file": name, "offset": hex(offset), "bytes": len(data),
                     "esp_image_encoded_bytes": length,
                     "sha256": hashlib.sha256(data).hexdigest()})
    if sorted(written) != sorted(expected):
        raise ValueError(f"{directory}: flash log differs from installed image sizes/offsets")
    intervals = [(offset, offset + size) for size, offset in expected]
    if union_bytes(intervals) != sum(size for size, _ in expected):
        raise ValueError("overlapping flash images")
    row = {"os": os, "case": case, "evidence": str(directory.relative_to(EVIDENCE)),
           "elf_sha256": hashlib.sha256((directory / elf_name).read_bytes()).hexdigest(),
           "verified_flash_evidence": str(flash_directory.relative_to(EVIDENCE)),
           "boot_content_identity_bound": boot_content_identity_bound,
           "installed_flash_bytes": sum(size for size, _ in expected),
           "flash_sector_bytes": union_bytes([(a // 4096 * 4096, (b + 4095) // 4096 * 4096)
                                               for a, b in intervals]),
           "physical_flash_capacity_bytes": FLASH_CAPACITY, "segments": rows,
           "unrestricted_product_ranking_eligible": False}
    row.update(static_footprint(directory / elf_name))
    return row


def primary_directory(os, case):
    if os == "FreeRTOS":
        return EVIDENCE / "tm-freertos-native-aligned-v1" / case
    if os == "Zephyr":
        base = "tm-irq-cpu2-v1/zephyr" if case.startswith("interrupt_") else "zephyr-gcc13-align"
        return EVIDENCE / base / case
    if case.startswith("interrupt_"):
        return EVIDENCE / "tm-irq-cpu2-v1/nuttx" / case
    if case == "cooperative_scheduling":
        return EVIDENCE / "tm-cooperative-native-nuttx-v1"
    return EVIDENCE / "tm-nuttx-native-aligned-v1" / case


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--include-riot", action="store_true")
    parser.add_argument("--include-alios", action="store_true")
    parser.add_argument("--fresh-nuttx-message", action="store_true")
    args = parser.parse_args()
    rows = [audit_cell(primary_directory(os, case), os, case)
            for case, _, _ in TM for os in ("FreeRTOS", "Zephyr", "NuttX")]
    if args.fresh_nuttx_message:
        folder = EVIDENCE / "nuttx-message-resource-v2"
        original = primary_directory("NuttX", "message_processing")
        for name in ("nuttx", "nuttx.bin", "config", "compiler.txt", "port.c", "test.c",
                     "iotosbench_main.c", "tm_override.h", "tm_message_processing_test.c"):
            if (folder / name).read_bytes() != (original / name).read_bytes():
                raise ValueError("fresh footprint installation changed the historical application/configuration")
        rows = [row for row in rows if not (row["os"] == "NuttX" and row["case"] == "message_processing")]
        fresh = audit_cell(folder, "NuttX", "message_processing", historical_reuse=False)
        capture = folder / "boot-witness.jsonl"
        raw = [json.loads(line) for line in capture.read_text().splitlines()]
        resets = [row for row in raw if row["line"].startswith("rst:0x")]
        if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or \
                sum("Thread-Metric NuttX ESP32 boot" in row["line"] for row in raw) != 1 or \
                sum("Thread-Metric queue self-check PASS" in row["line"] for row in raw) != 1:
            raise ValueError("fresh installation missing its original-app boot/self-check witness")
        if any(token in row["line"].lower() for row in raw for token in
               ("guru meditation", "error:", "panic", "abort", "assert")):
            raise ValueError("fresh footprint boot witness contains a native failure")
        fresh.update({"boot_witness_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                      "scope": "fresh installed footprint, not a replacement historical performance score",
                      "historical_performance_boot_contents_bound": False})
        rows.append(fresh)
    if args.include_riot:
        rows += [audit_cell(EVIDENCE / "riot-native-gcc12-v3" / case, "RIOT", case)
                 for case, _, _ in TM]
    if args.include_alios:
        rows += [audit_cell(EVIDENCE / "alios-native-gcc5-v3" / case, "AliOS-Rhino", case)
                 for case, _, _ in TM]
    result = {"status": "PASS", "definition": "all verified programmed images, uncompressed bytes; static SRAM physical section union",
              "cells": rows, "whole_runtime_peak_measured": False}
    content = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content)
    else:
        print(content, end="")
