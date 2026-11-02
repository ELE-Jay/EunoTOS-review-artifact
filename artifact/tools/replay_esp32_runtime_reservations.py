#!/usr/bin/env python3
"""Separate ELF-descriptor and raw-byte replay of runtime address ownership."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from elftools.elf.elffile import ELFFile
from replay_esp32_followup import digest, raw_rows, require


def physical_parts(start, size, descriptors):
    aliases = [(r[3], r[3] + r[1], r[0]) for r in descriptors if r[3]]
    if any(r[0] == 0x3ff80000 and r[1] == 8192 for r in descriptors):
        aliases.append((0x400c0000, 0x400c2000, 0x3ff80000))
    cuts = sorted({start, start + size} | {p for lo, hi, _ in aliases for p in (lo, hi) if start < p < start + size})
    output = []
    for lo, hi in zip(cuts, cuts[1:]):
        selected = [(a, b) for a, end, b in aliases if a <= lo < hi <= end]
        require(len(selected) <= 1, "Compiled aliases overlap")
        output.append((selected[0][1] + lo - selected[0][0], selected[0][1] + hi - selected[0][0]) if selected else (lo, hi))
    return output


def fully_covered(parts, domain):
    for start, end in parts:
        cuts = sorted({start, end} | {p for lo, hi in domain for p in (lo, hi) if start < p < end})
        if not all(any(lo <= a < b <= hi for lo, hi in domain) for a, b in zip(cuts, cuts[1:])):
            return False
    return True


def replay(source, folder, primary):
    original = json.loads(primary.read_text())
    require(original["audit"] == "pass" and original["input_identity"]["elf_sha256"] == digest(source / "application.elf") and
            original["input_identity"]["campaign_sha256"] == digest(folder / "campaign.json"), "Different ownership inputs")
    with (source / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        require(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_XTENSA", "Different descriptor ABI")
        symbols = elf.get_section_by_name(".symtab")
        def contents(name):
            rows = symbols.get_symbol_by_name(name)
            require(rows and len(rows) == 1, "Ambiguous native symbol")
            symbol = rows[0]
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"] - section["sh_addr"]
            return section.data()[offset:offset + symbol["st_size"]]
        count = struct.unpack("<I", contents("soc_memory_region_count"))[0]
        data = contents("soc_memory_regions")
        require(1 <= count <= 128 and len(data) == 20 * count, "Native region table size differs")
        descriptors = [list(struct.unpack_from("<IIIIB3x", data, 20 * i)) for i in range(count)]
        reserved = [struct.unpack("<II", contents(s.name)) for s in symbols.iter_symbols() if s.name.startswith("reserved_region_")]
        physical = lambda a, n: physical_parts(a, n, descriptors)
        soc = [p for a, n, *_ in descriptors for p in physical(a, n)]
        domain = soc + [(0x50000000, 0x50002000)]
        excluded = [p for a, end in reserved if a < end for p in physical(a, end - a)]
        static = []
        for section in elf.iter_sections():
            address, size = section["sh_addr"], section["sh_size"]
            if not section["sh_flags"] & 2 or size == 0:
                continue
            parts = physical(address, size)
            if fully_covered(parts, domain):
                static += parts
    pool_runs = []
    for i in range(1, 6):
        lines = [r["line"] for r in raw_rows(folder / "captures" / ("reset%d.jsonl" % i))]
        pool_runs.append([(int(m[1]), int(m[2])) for s in lines if (m := re.fullmatch(
            r"FREERTOS_RAM pool start=(\d+) bytes=(\d+) occupied=\d+ metadata=\d+ native_bias=\d+ checks=\d+", s))])
    require(pool_runs[0] and all(p == pool_runs[0] for p in pool_runs), "Reset address sets differ")
    pools = [p for a, n in pool_runs[0] for p in physical(a, n)]
    groups = {"soc": soc, "domain": domain, "reserved": excluded, "static": static, "heap": pools}
    cuts = sorted({x for spans in groups.values() for pair in spans for x in pair})
    totals = dict(domain=0, soc=0, static=0, heap=0, reserved_outside=0, outside_layout=0)
    for lo, hi in zip(cuts, cuts[1:]):
        present = {name: any(a <= lo < hi <= b for a, b in spans) for name, spans in groups.items()}
        if not present["domain"]:
            continue
        require(present["heap"] == (present["soc"] and not present["reserved"]), "Native heap has a gap or overlaps a reservation")
        for key in ("domain", "soc", "static", "heap"):
            totals[key] += (hi - lo) * present[key]
        totals["reserved_outside"] += (hi - lo) * (present["reserved"] and not present["static"] and not present["heap"])
        totals["outside_layout"] += (hi - lo) * (not any(present[k] for k in ("soc", "static", "reserved")))
    require(totals["domain"] == original["coverage"]["physical_address_universe_bytes"] and
            totals["soc"] == original["runs"][0]["compiled_descriptor_capacity_bytes"] and
            totals["heap"] == original["runs"][0]["observed_native_capacity_bytes_not_occupancy"] and
            totals["static"] == original["static_sram_bytes"] and
            totals["reserved_outside"] == original["fixed_reservations_outside_static_and_heap_bytes"] and
            totals["outside_layout"] == sum(r["bytes"] for r in original["outside_compiled_layout"]), "Primary and separate ownership arithmetic differ")
    return {"replay": "pass", "descriptor_count": count, "totals": totals,
        "alias_source": "compiled descriptor pairs, independently of the primary fixed alias table",
        "primary_sha256": digest(primary), "reused_original_workload_resets": 5, "new_board_captures": 0,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "scope": "address-set conservation, not reserved contents or a whole-lifecycle peak"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "campaign", "primary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux": parser.error("Replay evidence on leon only")
    result = replay(args.source, args.campaign, args.primary)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("replay", "descriptor_count", "totals", "new_board_captures")}))
