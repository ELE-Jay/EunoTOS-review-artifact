#!/usr/bin/env python3
"""Resolve the simple loader already present in the retained Zephyr RAM image."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'artifacts/reports/esp32-zephyr-message-startup-v2'
CAPTURE = 'artifacts/reports/esp32-zephyr-message-startup-b1-v1'


def rom_handoff(lines, segments, entry):
    entries = [(i, m) for i, line in enumerate(lines)
        if (m := re.fullmatch(r'entry 0x([0-9a-f]+)', line))]
    if len(entries) != 1 or int(entries[0][1][1], 16) != entry:
        raise ValueError('ROM did not enter the installed RAM observer')
    stop = entries[0][0]
    loaded = [(int(m[1], 16), int(m[2])) for line in lines[:stop]
        if (m := re.fullmatch(r'load:0x([0-9a-f]+),len:(\d+)', line))]
    if loaded != segments or not any('boot: ESP Simple boot' in s for s in lines[stop + 1:]):
        raise ValueError('ROM segments or simple-loader execution differ')
    return {'rom_loaded_segments': [{'address': a, 'bytes': n} for a, n in loaded],
        'entry': entry, 'separate_second_stage_binary': False}


def audit(root):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import physical_intervals, union_bytes
    from run_esp32_followup import read_raw_capture, sha
    from run_esp32_zephyr_message_lifetimes import audit as message_audit
    source, capture = root / SOURCE, root / CAPTURE
    retained = json.loads((capture / 'audit.json').read_text())
    replay = message_audit(capture, source)
    if json.loads(json.dumps(replay)) != retained:
        raise ValueError('Original Zephyr source/heap/reset evidence changed')
    cfg = (source / 'config').read_text().splitlines()
    if 'CONFIG_ESP_SIMPLE_BOOT=y' not in cfg or 'CONFIG_BOOTLOADER_MCUBOOT=y' in cfg:
        raise ValueError('Not the retained single-image loader configuration')
    image = (source / 'application.bin').read_bytes()
    position, segments = 24, []
    for _ in range(image[1]):
        address, size = struct.unpack_from('<II', image, position)
        segments.append((address, size))
        position += 8 + size
    with (source / 'application.elf').open('rb') as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name('.symtab')
        bounds = [symbols.get_symbol_by_name(n)[0]['st_value'] for n in ('_stack_sentry', '__stack')]
        entry = elf['e_entry']
        loader_sections = [elf.get_section_by_name(n) for n in ('.loader.text', '.loader.data')]
        if any(section is None or not section['sh_flags'] & 2 for section in loader_sections):
            raise ValueError('Simple loader storage absent from allocated ELF sections')
        c_allocators = [n for n in ('malloc', 'calloc', 'realloc', 'sbrk', '_sbrk')
            if symbols.get_symbol_by_name(n)]
        if c_allocators:
            raise ValueError('An additional allocator requires its own ownership proof')
        loader_bytes = sum(section['sh_size'] for section in loader_sections)
    footprint = replay['build']
    static = [p for section in footprint['ram_sections']
        for p in physical_intervals(int(section['address'], 16), section['bytes'])]
    stack = physical_intervals(bounds[0], bounds[1] - bounds[0])
    startup = union_bytes(static + stack)
    if startup != footprint['static_sram_bytes'] + bounds[1] - bounds[0]:
        raise ValueError('Inherited stack and static storage overlap')
    heap = footprint['reservations']['kheap__system_heap']
    if union_bytes(static + physical_intervals(*heap)) != footprint['static_sram_bytes']:
        raise ValueError('Native heap pool is not already static')
    runs = []
    for index, run in enumerate(replay['runs'], 1):
        handoff = rom_handoff([row['line'] for row in read_raw_capture(capture / 'captures', index)], segments, entry)
        if run['native_heap_peak_bytes'] > heap[1] or not run['heap_and_stacks_already_in_static_sram']:
            raise ValueError('Runtime allocations escape the counted static pool')
        runs.append({'reset': index, **handoff, 'software_peak_bytes': startup,
            'runtime_reserved_bytes': footprint['static_sram_bytes'],
            'raw_sha256': sha(capture / 'captures' / ('reset%d.raw' % index))})
    campaign = json.loads((capture / 'campaign.json').read_text())
    return {'audit': 'pass', 'board_mac': campaign['board_mac'], 'reused_resets': len(runs),
        'new_board_resets': 0, 'source': SOURCE, 'capture': CAPTURE,
        'elf_sha256': sha(source / 'application.elf'), 'bin_sha256': sha(source / 'application.bin'),
        'source_audit_sha256': sha(capture / 'audit.json'),
        'simple_loader_already_in_static_bytes': loader_bytes,
        'static_bytes': footprint['static_sram_bytes'],
        'inherited_stack_reservation_bytes': bounds[1] - bounds[0], 'runs': runs,
        'simple_loader_covered_by_existing_native_entry_observer': True,
        'scope': 'ROM handoff to the installed single-image entry, including native simple-loader execution, initialization and the third original message report. Linked static storage and inherited stack capacity are counted once; actual stack use is separate.',
        'whole_lifecycle_peak_allocated_occupancy_bytes': None, 'ranking_eligible': False,
        'remaining': ['Before-entry ROM/cache/RTC ownership and matched cohort observer controls.'],
        'new_model_calls': 0}


def paper_text(zephyr, nuttx):
    values = {r['software_peak_bytes'] for r in nuttx['runs']}
    if zephyr['reused_resets'] != 5 or nuttx['independent_resets'] != 5 or \
            nuttx['separate_validation_resets'] != 1 or len(values) != 1:
        raise ValueError('Loader paragraph needs the complete fixed cohort')
    return ("Zephyr's simple loader belongs to the same ROM-loaded image. All five retained "
        "ROM segment/entry records bind that image to the startup observer; its "
        f"{zephyr['simple_loader_already_in_static_bytes']:,}-B loader text/data already belongs "
        "to static SRAM and is not added again. A separate NuttX loader intervention keeps "
        "the application binary, partition table and OS configuration unchanged, replacing "
        "the prebuilt IDF 5.1-dev loader with the IDF 5.2.5 boot observer used for FreeRTOS. "
        "Five fresh original-message resets and one allocator self-check pass. Native "
        f"allocation ownership and the {values.pop():,}-B software peak match the retained compact "
        f"observer. The diagnostic loader has {nuttx['bootloader_static_bytes']:,}\\,B static "
        f"storage and a {nuttx['inherited_boot_stack_reservation_bytes']:,}-B inherited-stack "
        "reservation. Stage values are not summed into a peak; before-entry ROM and common "
        "hardware ownership remain outside the unified whole-lifecycle result.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Replay experimental evidence on leon')
    value = audit(ROOT)
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: value[k] for k in ('audit', 'reused_resets',
        'simple_loader_already_in_static_bytes', 'simple_loader_covered_by_existing_native_entry_observer')}))
