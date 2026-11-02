#!/usr/bin/env python3
"""Observe generated C frame entries without -finstrument-functions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from guard_esp32_boundary_calls import guarded_assembly as call_guard
from inspect_esp32_stack_entry_coverage import functions

DYNAMIC = {
    'heap_caps_init.c': ('soc_memory_region_t regions[num_regions];', 'heap_t temp_heaps[num_heaps];'),
    'port/memory_layout_utils.c': ('soc_memory_region_t in_regions[soc_memory_region_count];',
                                 'soc_reserved_region_t reserved[num_reserved];'),
}


def dynamic_source(name, text):
    from build_esp32_tm_ram_lifetimes import replace_once
    for declaration in DYNAMIC[name]:
        variable = re.search(r'(\w+)\[', declaration)[1]
        text = replace_once(text, declaration, declaration +
            '\n    bench_boundary_sample((void *)0, ' + variable + ');')
    return 'extern void bench_boundary_sample(void *, void *);\n' + text


def guarded_assembly(text, identity):
    rows = functions(text)
    locations, sites = {}, []
    for index, row in enumerate(rows):
        if len(row['entries']) != 1 or row['opaque'] or row['entries'][0]['frame_bytes'] < 32:
            raise ValueError('Unsupported frame or opaque code: ' + row['name'])
        dynamic = row['other_sp_writes']
        if dynamic and (row['name'] not in ('heap_caps_init', 'soc_get_available_memory_regions') or len(dynamic) != 2):
            raise ValueError('Uncovered dynamic SP write: ' + row['name'])
        if dynamic:
            lines = text.splitlines()
            boundaries = [r['line'] for r in dynamic] + [row['end_line']]
            for start, end in zip(boundaries, boundaries[1:]):
                calls = [l.strip() for l in lines[start:end-1] if re.match(r'\s*call\w*\s+', l)]
                if not calls or calls[0] != 'call8\tbench_boundary_sample':
                    raise ValueError('Dynamic stack allocation lacks its first explicit sample: ' + row['name'])
        stub = '\tcall8 __cyg_profile_func_enter\n'
        guard, generated = call_guard(stub, identity + '_e' + str(index))
        prefix = generated[0]['symbol']
        # Unique labels cannot intercept numeric local-label references in original inline assembly.
        suffixes = {'1': '_sample', '2': '_skip', '3': '_end'}
        guard = re.sub(r'\b([123])f\b', lambda m: prefix + suffixes[m[1]], guard)
        guard = re.sub(r'(?m)^([123]):', lambda m: prefix + suffixes[m[1]] + ':', guard)
        guard = guard.replace(stub, '\tmovi a10, ' + row['name'] + '\n\tmovi a11, 0\n' + stub)
        locations[row['entries'][0]['line']] = guard
        sites.append({**generated[0], 'function': row['name'], 'frame_bytes': row['entries'][0]['frame_bytes'],
                      'dynamic_sp_writes': len(dynamic)})
    output = []
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        output.append(line)
        if number in locations:
            output.append(locations[number])
    return ''.join(output), sites


def launch(evidence, args):
    if '-c' not in args or Path(args[args.index('-c') + 1]).suffix != '.c':
        return subprocess.call(args)
    if any(a.startswith('-finstrument-functions') for a in args) or '-S' in args or '-x' in args:
        raise ValueError('Entry observation requires the original non-profiling C compilation')
    source = Path(args[args.index('-c') + 1]).resolve()
    identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    folder = evidence / identity
    folder.mkdir(parents=True, exist_ok=False)
    before, after = folder / 'original.s', folder / 'guarded.s'
    first = list(args)
    first[first.index('-c')] = '-S'
    first[first.index('-o') + 1] = str(before)
    subprocess.run(first, check=True)
    generated, sites = guarded_assembly(before.read_text(), identity)
    after.write_text(generated)
    second, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg in ('-MF', '-MT', '-MQ'):
            skip = True
        elif arg not in ('-MD', '-MMD'):
            second.append(str(after) if arg == str(source) else arg)
    subprocess.run(second, check=True)
    (folder / 'transform.json').write_text(json.dumps({'transform_kind': 'stack-entry',
        'source': str(source), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'object': str(Path(args[args.index('-o') + 1]).resolve()), 'compiler_command': args,
        'original_sha256': hashlib.sha256(before.read_bytes()).hexdigest(),
        'guarded_sha256': hashlib.sha256(after.read_bytes()).hexdigest(), 'sites': sites}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    a = parser.parse_args()
    sys.exit(launch(a.evidence.resolve(), a.command))
