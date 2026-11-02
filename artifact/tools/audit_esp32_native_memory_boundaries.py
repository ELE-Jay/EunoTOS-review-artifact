#!/usr/bin/env python3
"""Bind the native memory layout to every observed FreeRTOS heap region."""
import argparse
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

from audit_esp32_hartstone_ram_riot import symbol_bytes
from audit_esp32_ram_scope import address_coverage
from audit_esp32_resources import audit_elf_image, physical_intervals, static_footprint, union_bytes
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha
from run_esp32_tm_ram_lifetimes import POOL, audit as workload_audit

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
BUILD = REPORTS / "esp32-freertos-startup-handoff-build-v1"
CAPTURE = REPORTS / "esp32-freertos-startup-handoff-b1-v1"
OUTPUT = REPORTS / "esp32-freertos-memory-boundaries-v1"
NATIVE = {
    "heap_memory_layout.h": "85fc0a7c3057e303ec6753c15bb1651de3ccd3d95b15250924d8b2a7781c4bd9",
    "memory_layout_utils.c": "c26bc97aca7ec1f672345a5cbc1e5a99186a56bb75f02b6fbdacc8b87ce9b1c0",
    "heap_caps_init.c": "ce4972193704f61bd9d465cddc851c01fb848602d2990a90e99a238f7c904e8f",
}


def available_heaps(regions, reservations):
    """Native word-expanded exclusions, >16-byte fragments, and typed coalescing."""
    exclusions = sorted((start & ~3, (end + 3) & ~3) for start, end in reservations)
    if any(end < start for start, end in exclusions) or any(
            a >= c or b > c for (a, b), (c, _) in zip(exclusions, exclusions[1:])):
        raise ValueError("Invalid or overlapping native reservations")
    fragments = []
    for region in regions:
        start, size = region["start"], region["bytes"]
        pieces = [(start, start + size)]
        for low, high in exclusions:
            pieces = [span for a, b in pieces for span in
                ((a, min(b, low)), (max(a, high), b)) if span[0] < span[1]]
        for left, right in pieces:
            if right - left <= 16:
                continue
            item = {"start": left, "bytes": right-left, "type": region["type"],
                    "startup_stack": region["startup_stack"]}
            if fragments and fragments[-1]["start"] + fragments[-1]["bytes"] == left and all(
                    fragments[-1][key] == item[key] for key in ("type", "startup_stack")):
                fragments[-1]["bytes"] += item["bytes"]
            else:
                fragments.append(item)
    return fragments


def compiled_layout(elf):
    symbols = elf.get_section_by_name(".symtab")
    fields = {b"start": 0, b"size": 4, b"type": 8, b"iram_address": 12, b"startup_stack": 16}
    types = [die.get_DIE_from_attribute("DW_AT_type")
        for cu in elf.get_dwarf_info().iter_CUs() for die in cu.iter_DIEs()
        if die.tag == "DW_TAG_typedef" and die.attributes.get("DW_AT_name") and
        die.attributes["DW_AT_name"].value == b"soc_memory_region_t"]
    if not types or any(t.attributes["DW_AT_byte_size"].value != 20 or {
            c.attributes["DW_AT_name"].value: c.attributes["DW_AT_data_member_location"].value
            for c in t.iter_children() if c.tag == "DW_TAG_member"} != fields for t in types):
        raise ValueError("Compiled native memory-region ABI differs")
    count = struct.unpack("<I", symbol_bytes(elf, symbols, "soc_memory_region_count", 4))[0]
    data = symbol_bytes(elf, symbols, "soc_memory_regions", count * 20)
    regions = []
    for at in range(0, len(data), 20):
        start, size, kind, alias, startup = struct.unpack_from("<IIIIB3x", data, at)
        if not size or startup not in (0, 1):
            raise ValueError("Invalid native memory-region table")
        if alias and physical_intervals(alias, size) != physical_intervals(start, size):
            raise ValueError("Auditor's physical alias map disagrees with the compiled SoC table")
        regions.append({"start": start, "bytes": size, "type": kind,
                        "iram_alias": alias, "startup_stack": bool(startup)})
    ordered = sorted((r["start"], r["start"] + r["bytes"]) for r in regions)
    if any(b > c for (_, b), (c, _) in zip(ordered, ordered[1:])):
        raise ValueError("Overlapping native memory-region table")
    first, last = [symbols.get_symbol_by_name(n)[0]["st_value"] for n in
        ("soc_reserved_memory_region_start", "soc_reserved_memory_region_end")]
    reservations = sorted((s for s in symbols.iter_symbols() if s.name.startswith("reserved_region_")),
                          key=lambda s: s["st_value"])
    if not reservations or [s["st_value"] for s in reservations] != list(range(first, last, 8)):
        raise ValueError("Native reservation table is not completely symbol-bound")
    reserved = []
    for symbol in reservations:
        start, end = struct.unpack("<II", symbol_bytes(elf, symbols, symbol.name, 8))
        if end < start:
            raise ValueError("Reversed native reservation")
        reserved.append({"symbol": symbol.name, "start": start, "end": end})
    return regions, reserved


def audit():
    native = OUTPUT / "native"
    for name, digest in NATIVE.items():
        if sha(native / name) != digest:
            raise ValueError("Archived native memory-layout implementation changed: " + name)
    measured = workload_audit(CAPTURE, BUILD)
    if json.loads(json.dumps(measured)) != json.loads((CAPTURE / "audit.json").read_text()):
        raise ValueError("Measured startup-handoff image/evidence changed")
    audit_elf_image(BUILD / "application.elf", BUILD / "application.bin")
    with (BUILD / "application.elf").open("rb") as stream:
        regions, reserved = compiled_layout(ELFFile(stream))
    expected = available_heaps(regions, [(r["start"], r["end"]) for r in reserved])
    observed = [[(int(m[1]), int(m[2])) for row in read_raw_capture(CAPTURE / "captures", i)
                 if (m := POOL.fullmatch(row["line"]))] for i in range(1, 6)]
    anticipated = sorted([r["start"], r["bytes"]] for r in expected)
    if len(observed) != 5 or any(sorted([list(p) for p in run]) != anticipated for run in observed):
        raise ValueError("Observed native heap pools do not exhaust the compiled available regions")
    footprint = static_footprint(BUILD / "application.elf")
    exclusions = [(r["start"] & ~3, ((r["end"] + 3) & ~3) - (r["start"] & ~3))
                  for r in reserved if r["start"] < r["end"]]
    coverage = address_coverage(footprint["ram_sections"], observed[0], exclusions=exclusions)
    gaps = [r for r in coverage["segments"] if not r["owners"]]
    for gap in gaps:
        left, right = gap["start"], gap["end"]
        if any(a < right and left < b for r in regions for a, b in physical_intervals(r["start"], r["bytes"])):
            raise ValueError("Unexplained hole inside native memory-region inventory")
        gap["native_class"] = "not offered to the native allocator; occupancy not inferred"
    deferred = [r for r in expected if r["startup_stack"]]
    if len(deferred) != 1 or deferred[0]["start"] != 0x3ffe0440 or deferred[0]["bytes"] != 129984:
        raise ValueError("Deferred startup-stack heap differs")
    return {"audit": "pass", "os": "FreeRTOS", "board_mac": measured["board_mac"],
        "build": BUILD.relative_to(ROOT).as_posix(), "capture": CAPTURE.relative_to(ROOT).as_posix(),
        "elf_sha256": sha(BUILD / "application.elf"), "campaign_sha256": sha(CAPTURE / "campaign.json"),
        "native_sources_sha256": NATIVE, "compiled_soc_regions": regions,
        "compiled_reservations": reserved, "expected_native_heaps": expected,
        "observed_native_heap_pools_per_reset": observed, "native_heap_inventory_complete": True,
        "physical_available_capacity_bytes_not_usage": union_bytes(
            p for r in expected for p in physical_intervals(r["start"], r["bytes"])),
        "address_coverage": coverage, "outside_native_inventory": gaps,
        "reused_workload_resets": 5, "new_board_resets": 0,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "scope": "All compiled native heap candidates and reservations agree with five measured pool inventories; no pool capacity is treated as occupied RAM.",
        "remaining": ["occupancy of ROM/cache and non-allocator RTC ranges before and during the registered lifecycle",
                      "bootloader/ROM-before-application memory and exact simultaneous live-stack peak"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit()
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
