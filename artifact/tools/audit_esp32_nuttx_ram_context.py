#!/usr/bin/env python3
"""Correct missing native heap-control ownership in eight retained RAM images."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import statistics

from elftools.elf.elffile import ELFFile
from audit_esp32_hartstone_ram_nuttx import DIRECTORY, build
from audit_esp32_ram_census import ROOT, audit_census, region_accounting
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_thread import read_control_rows
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_nuttx_ram_context_control import FUNCTIONS, PROFILES, collector_source


def machine(directory, profile):
    for name, names in (("ram-context-binding.sha256", {"image.sha256", "reset1.jsonl", "reset2.jsonl", "reset3.jsonl"}),
            ("ram-context-control.sha256", {"application.elf", "image.sha256", "ram-context-binding.sha256",
                                           "ram-context-flow.txt", "executed-ram-context.py"})):
        check_manifest(directory, name)
        if {line.split(maxsplit=1)[1] for line in (directory / name).read_text().splitlines()} != names:
            raise ValueError("native context manifest coverage differs")
    if (directory / "executed-ram-context.py").read_text() != collector_source(
            (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(), profile):
        raise ValueError("native context decoder changed")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "ram-context-flow.txt").read_text(),
            "NUTTX RAM CONTEXT CONTROL", elf, symbols, set(FUNCTIONS), noreturn=())
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match: continue
                encoding, target = int(match[1], 16), int(match[2], 16)
                offset = encoding >> 6
                if offset & (1 << 17): offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != target or not any(
                        symbol["st_value"] == target for symbol in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("native context call encoding differs")
                calls[name, match[3]] += 1
        for caller, callee in (("umm_initialize", "mm_initialize"), ("mm_initialize", "mm_addregion"),
                ("mm_addregion", "__wrap_mm_unlock"), ("__wrap_mm_unlock", "mm_unlock")):
            if calls[caller, callee] != 1:
                raise ValueError("native context initialization/observer call differs")
        initializer = control["mm_initialize"]
        for pattern in (r"237b addi\.n\s+a2, a3, 7$", r"102280 and\s+a2, a2, a8$",
                r"70a142 movi\s+a4, 0x170$", r"424a add\.n\s+a4, a2, a4$",
                r"c07720 sub\s+a7, a7, a2$", r"20b440 or\s+a11, a4, a4$"):
            if not any(re.search(pattern, row) for row in initializer.values()):
                raise ValueError("native 368-byte context/managed-region initialization differs")
        for pattern in (r"c47c movi\.n\s+a4, -4$", r"8099f0 add\s+a9, a9, a15$",
                r"c08890 sub\s+a8, a8, a9$"):
            if not any(re.search(pattern, row) for row in control["__wrap_mm_unlock"].values()):
                raise ValueError("native observer free-block subtraction differs")
        starts = [literal_word(elf, row, 9) for row in control["up_allocate_heap"].values()
                  if re.search(r"l32r\s+a9,", row)]
        sheap = symbols.get_symbol_by_name("_sheap")[0]["st_value"]
        if starts != [sheap] or sheap % 8:
            raise ValueError("native allocated heap start/alignment differs")
        pointers = [literal_word(elf, row, 8) for row in control["umm_initialize"].values()
                    if re.search(r"l32r\s+a8,", row)]
        if pointers != [symbols.get_symbol_by_name("g_mmheap")[0]["st_value"]]:
            raise ValueError("native g_mmheap context pointer binding differs")
    return {"reachable_functions_checked": len(control), "encoded_direct_calls_checked": sum(calls.values()),
            "native_heap_control_start": sheap, "native_heap_control_bytes": 368}


def account_context(directory, case, sections, runs):
    build()
    profile = next((profile for profile in PROFILES if (
        "message_processing" if profile == PROFILES[0] else Path(profile).name.split("-")[0]) == case), None)
    if profile is None:
        raise ValueError("unreviewed original-workload native heap context")
    allocator_config = lambda path: [line for line in path.read_text().splitlines() if "CONFIG_MM_" in line]
    if (directory / "mm.h").read_bytes() != (DIRECTORY / "native-source/mm/mm_heap/mm.h").read_bytes() or \
            allocator_config(directory / "config") != allocator_config(DIRECTORY / "config"):
        raise ValueError("historical native allocator header/configuration differs from verified fixed source")
    control = machine(directory, profile)
    context = (control["native_heap_control_start"], control["native_heap_control_bytes"])
    for run in runs:
        if run["regions"][0][0] != context[0] + context[1]:
            raise ValueError("historical UART heap region is not adjacent to the actual initialized context")
        region_accounting(sections, run["regions"] + [context], False)
    return control


def audit():
    native = build()
    cells = []
    for profile in PROFILES:
        directory = ROOT / "artifacts/reports" / profile
        case = "message_processing" if profile == PROFILES[0] else Path(profile).name.split("-")[0]
        original = audit_census(directory, "NuttX", case)
        control = original["native_heap_control"]
        corrected = [original["static_sram_bytes"] + run["dynamic_heap_peak_bytes"] + control["native_heap_control_bytes"]
                     for run in original["runs"]]
        cells.append({"original_case": case, "profile": profile, "independent_resets": 3,
            "historical_static_plus_managed_heap_median_bytes": original["historical_static_plus_managed_heap_median_bytes"],
            "native_heap_control": control, "corrected_observed_software_ram_bytes": corrected,
            "median_corrected_observed_software_ram_bytes": statistics.median(corrected),
            "image_sha256": digest(directory / "application.elf"),
            "binding_manifest_sha256": digest(directory / "ram-context-binding.sha256"),
            "original_records_unchanged": True, "ranking_eligible": False})
    return {"audit": "pass", "os": "NuttX", "original_cases": len(cells), "independent_resets": 24,
        "cells": cells, "fixed_native_header_sha256": digest(DIRECTORY / "native-source/mm/mm_heap/mm.h"),
        "source_verification": "same fixed official mm.h and allocator configuration; initializer decoded separately in each actual ELF",
        "native_source_proof_files": native["official_native_files_checked"],
        "new_board_boots": 0, "historical_records_unchanged": True,
        "definition": "observed static physical SRAM plus simultaneous managed-heap occupation plus separately reserved native heap control",
        "window": "benchmark entry through original 90-second report",
        "pre_kernel_transient_peak_measured": False, "allocator_internal_transient_peak_measured": False,
        "stack_live_bytes_high_water_measured": False, "uninstrumented_peak_measured": False,
        "ranking_eligible": False, "energy_measured": False, "new_metric_created": False}


def report_table(result):
    return "\n".join(["| NuttX original workload RAM accounting | Previous scoped total B | Native heap control B | Corrected scoped total B |",
        "| --- | ---: | ---: | ---: |", *[f"| NuttX RAM correction / {row['original_case']} | {row['historical_static_plus_managed_heap_median_bytes']:g} | {row['native_heap_control']['native_heap_control_bytes']} | {row['median_corrected_observed_software_ram_bytes']:g} |"
            for row in result["cells"]]])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--table", action="store_true")
    args = parser.parse_args()
    result = audit()
    content = report_table(result) + "\n" if args.table else json.dumps(result, indent=2) + "\n"
    if args.output: args.output.write_text(content)
    else: print(content, end="")
