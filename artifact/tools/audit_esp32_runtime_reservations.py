#!/usr/bin/env python3
"""Reconcile compiled ESP32 reservations with measured native heap ownership."""
import argparse
import json
from pathlib import Path
import struct
import sys

from audit_esp32_ram_scope import address_coverage
from audit_esp32_resources import physical_intervals, static_footprint, union_bytes
from run_esp32_followup import read_raw_capture, sha
from run_esp32_tm_ram_lifetimes import POOL


def reconcile(descriptors, reservations, pools):
    regions, physical = [], []
    for row in descriptors:
        start, size, kind, alias, startup = row
        if size <= 0 or kind not in range(5) or startup not in (0, 1):
            raise ValueError("Invalid compiled native memory descriptor")
        spans = physical_intervals(start, size)
        if alias and physical_intervals(alias, size) != spans:
            raise ValueError("Native instruction/data aliases differ physically")
        physical += spans
        regions.append((start, size))
    if union_bytes(physical) != sum(n for _, n in regions):
        raise ValueError("Compiled native capacity aliases itself")
    for start, end in reservations:
        if end < start:
            raise ValueError("Reversed compiled reservation")
    excluded = [(a, b - a) for a, b in reservations if a < b]
    partition = address_coverage([], regions, exclusions=excluded)
    expected = [(s["start"], s["end"]) for s in partition["segments"]
                if "native_heap" in s["owners"] and "native_exclusion" not in s["owners"]]
    actual = [p for start, size in pools for p in physical_intervals(start, size)]
    capacity = union_bytes(expected)
    if union_bytes(actual) != sum(n for _, n in pools) or union_bytes(actual) != capacity or \
            union_bytes(expected + actual) != capacity:
        raise ValueError("Observed heap pools differ from compiled available physical memory")
    return {"compiled_descriptor_capacity_bytes": union_bytes(physical),
        "available_capacity_after_reservations_bytes": capacity,
        "observed_native_capacity_bytes_not_occupancy": sum(n for _, n in pools),
        "native_pool_count": len(pools), "exact_available_address_set_match": True}


def compiled_regions(elf_path):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_hartstone_ram_riot import symbol_bytes
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_XTENSA":
            raise ValueError("Descriptor ABI requires the measured 32-bit little-endian Xtensa image")
        symbols = elf.get_section_by_name(".symtab")
        count = struct.unpack("<I", symbol_bytes(elf, symbols, "soc_memory_region_count", 4))[0]
        if not 1 <= count <= 128:
            raise ValueError("Unbounded compiled native descriptor count")
        data = symbol_bytes(elf, symbols, "soc_memory_regions", count * 20)
        descriptors = [list(struct.unpack_from("<IIIIB3x", data, i * 20)) for i in range(count)]
        reserved = []
        for symbol in symbols.iter_symbols():
            if symbol.name.startswith("reserved_region_"):
                start, end = struct.unpack("<II", symbol_bytes(elf, symbols, symbol.name, 8))
                reserved.append({"symbol": symbol.name, "start": start, "end": end, "bytes": end - start})
        if not reserved:
            raise ValueError("No compiled firmware reservations found")
    return descriptors, reserved


def audit(source, campaign, runtime_audit):
    from audit_esp32_message_steps import audit as continuous_audit
    retained = json.loads(runtime_audit.read_text())
    replayed = continuous_audit(source, campaign)
    if retained != json.loads(json.dumps(replayed)):
        raise ValueError("Retained continuous observation audit changed")
    layout = source / "native-startup/components/heap/port/esp32/memory_layout.c"
    if not layout.is_file():
        raise ValueError("Compiled native memory-layout source is not retained")
    descriptors, reservations = compiled_regions(source / "application.elf")
    reserved_pairs = [(r["start"], r["end"]) for r in reservations]
    footprint = static_footprint(source / "application.elf")
    runs, previous_pools = [], None
    for i in range(1, 6):
        pools = [tuple(map(int, match.groups()))[:2] for row in read_raw_capture(campaign / "captures", i)
                 if (match := POOL.fullmatch(row["line"]))]
        reconciled = reconcile(descriptors, reserved_pairs, pools)
        if previous_pools is not None and pools != previous_pools:
            raise ValueError("Native memory layout differs across the five resets")
        previous_pools = pools
        runs.append(reconciled)
    coverage = address_coverage(footprint["ram_sections"], previous_pools,
        exclusions=[(a, b - a) for a, b in reserved_pairs if a < b])
    unclassified = [s for s in coverage["segments"] if not s["owners"]]
    region_spans = [p for start, size, *_ in descriptors for p in physical_intervals(start, size)]
    config = (source / "config").read_text().splitlines()
    ulp_enabled = any(line.endswith("=y") and "ULP" in line and "COPROC" in line for line in config)
    outside_layout = []
    for segment in unclassified:
        start, end = segment["start"], segment["end"]
        if ulp_enabled or not 0x50000000 <= start < end <= 0x50002000 or \
                union_bytes(region_spans + [(start, end)]) != union_bytes(region_spans) + end - start:
            raise ValueError("An unclassified address range is not explained by this RTC layout")
        outside_layout.append({"start": start, "end": end, "bytes": end - start,
            "classification": "outside compiled allocator layout and declared static/reserved objects; not proven zero contents or an observed usage value"})
    fixed_outside = sum(s["bytes"] for s in coverage["segments"] if "native_exclusion" in s["owners"] and
                        "static" not in s["owners"] and "native_heap" not in s["owners"])
    heap_peaks = [r["native"]["heap_peak_bytes"] for r in retained["runs"] if not r["validation"]]
    return {"audit": "pass", "scope": "runtime address ownership only; capacities and firmware exclusions are not measured live-byte usage or a whole-lifecycle peak",
        "input_identity": {"elf_sha256": sha(source / "application.elf"), "build_manifest_sha256": sha(source / "build.json"),
            "campaign_sha256": sha(campaign / "campaign.json"), "continuous_audit_sha256": sha(runtime_audit),
            "native_layout_source_sha256": sha(layout), "auditor_sha256": sha(Path(__file__))},
        "compiled_descriptors": descriptors, "compiled_reservations": reservations,
        "runs": runs, "coverage": coverage, "outside_compiled_layout": outside_layout,
        "static_sram_bytes": footprint["static_sram_bytes"], "measured_native_heap_peak_bytes": heap_peaks,
        "fixed_reservations_outside_static_and_heap_bytes": fixed_outside,
        "unexplained_runtime_address_bytes": 0, "ulp_coprocessor_enabled": ulp_enabled,
        "reused_original_workload_resets": 5, "new_board_captures": 0,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "remaining": ["pre-application temporal residency and stack coverage", "reserved-region occupancy semantics and observer effects", "other controlled OS profiles"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "campaign", "runtime-audit", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux": parser.error("Audit retained experimental evidence on leon only")
    result = audit(args.source, args.campaign, args.runtime_audit)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("audit", "fixed_reservations_outside_static_and_heap_bytes", "unexplained_runtime_address_bytes", "new_board_captures", "whole_live_ram_peak_bytes")}))
