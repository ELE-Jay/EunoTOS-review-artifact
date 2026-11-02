#!/usr/bin/env python3
"""Single-word ENTRY threshold; native transitions invalidate both pruning paths."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from build_esp32_tm_ram_lifetimes import replace_once
from guard_esp32_stack_entries import guarded_assembly as entry_assembly


def guarded_assembly(text, identity):
    generated, sites = entry_assembly(text, identity)
    for site in sites:
        name = site['symbol']
        start = generated.index('\t.global ' + name + '\n')
        end = generated.index(name + '_end:\n', start) + len(name + '_end:\n')
        generated = replace_once(generated, generated[start:end],
            '\t.global %s\n%s:\n' % (name, name) +
            '\tmovi a8, bench_boundary_threshold\n\tl32i a8, a8, 0\n'
            '\tbgeu a1, a8, ' + name + '_end\n'
            '\tmovi a10, ' + site['function'] + '\n\tmovi a11, 0\n'
            '\tcall8 __cyg_profile_func_enter\n' + name + '_end:\n')
    return generated, sites


def observer_source(text):
    text = replace_once(text, 'static unsigned bench_boundary_control_off;',
        'static unsigned bench_boundary_control_off;\n'
        'extern volatile uint32_t bench_boundary_threshold;\nstatic unsigned bench_threshold_force;')
    text = replace_once(text, 'DRAM_ATTR volatile uint32_t bench_boundary_fast_state[3] = {0, UINT32_MAX, 0};',
        'DRAM_ATTR volatile uint32_t bench_boundary_fast_state[3] = {0, UINT32_MAX, 0};\n'
        'DRAM_ATTR volatile uint32_t bench_boundary_threshold;')
    invalidation = '    bench_boundary_fast_state[1] = boundary_enabled ? 0 : UINT32_MAX;'
    if text.count(invalidation) != 4:
        raise ValueError('Allocation/switch/create/retire invalidators differ')
    text = text.replace(invalidation, invalidation +
        '\n    bench_boundary_threshold = boundary_enabled ? UINT32_MAX : 0;')
    text = replace_once(text, '    bench_boundary_fast_state[0] = fast_sp;',
        '    bench_boundary_threshold = current < 17 && !bench_threshold_force ? fast_sp + 32 : UINT32_MAX;\n'
        '    bench_boundary_fast_state[0] = fast_sp;')
    text = replace_once(text, '    bench_boundary_fast_state[1] = current < 17 ? boundary_slots[current].high : 0;',
        '    bench_boundary_fast_state[1] = current < 17 && !bench_threshold_force ? boundary_slots[current].high : 0;')
    start = text.index('static void bench_boundary_start(void)\n{')
    end = text.index('static void bench_boundary_stop(void)\n{', start)
    text = text[:start] + replace_once(text[start:end], '    portEXIT_CRITICAL(&lock);',
        '    bench_boundary_threshold = UINT32_MAX;\n    portEXIT_CRITICAL(&lock);') + text[end:]
    text = replace_once(text, '    boundary_enabled = 0;',
        '    boundary_enabled = 0;\n    bench_boundary_threshold = 0;')
    text = replace_once(text, 'if (strcmp(command, "validate") == 0)',
        'if (strcmp(command, "validate-full") == 0) { bench_threshold_force = 1; memcpy(command, "validate", 9); }\n'
        '    if (strcmp(command, "validate") == 0)')
    text = replace_once(text, '    puts("BOUNDARY_RAM END");',
        '    printf("BOUNDARY_THRESHOLD force=%u active=%lu value=%lu\\n", bench_threshold_force, '
        '(unsigned long)boundary_enabled, (unsigned long)bench_boundary_threshold);\n'
        '    puts("BOUNDARY_RAM END");')
    return text


def native_source(text):
    text = replace_once(text, '    .literal .Lns_state, bench_native_state',
        '    .literal .Lns_threshold, bench_boundary_threshold\n'
        '    .literal .Lns_active, boundary_enabled\n'
        '    .literal .Lns_fast_state, bench_boundary_fast_state\n'
        '    .literal .Lns_state, bench_native_state')
    return replace_once(text, '.Lns_return:\n    memw', '.Lns_return:\n'
        '    l32r a2, .Lns_active\n    l32i a3, a2, 0\n'
        '    movi a4, 0\n    movi a5, -1\n'
        '    beqz a3, .Lthreshold_commit\n    movi a4, -1\n    movi a5, 0\n'
        '.Lthreshold_commit:\n'
        '    l32r a2, .Lns_threshold\n    s32i a4, a2, 0\n'
        '    l32r a2, .Lns_fast_state\n    s32i a5, a2, 4\n    memw')


def audit_site(site, function, pc, instructions, literal, symbols):
    finish = symbols.get_symbol_by_name(site['symbol'] + '_end')[0]['st_value']
    body = [(op, args) for addr, _, op, args in instructions if pc <= addr < finish
            and op not in ('nop', 'nop.n') and (op, args) != ('or', 'a1, a1, a1')]
    threshold = symbols.get_symbol_by_name('bench_boundary_threshold')[0]
    if threshold['st_size'] != 4 or threshold['st_value'] % 4 or len(body) not in (6, 7):
        raise ValueError('Single-word guard layout differs')
    def load(row, register, target):
        return row[0] == 'l32r' and row[1].startswith(register + ', ') and literal(int(row[1].split(', ')[1], 16)) == target
    if not load(body[0], 'a8', threshold['st_value']) or body[1] not in (
            ('l32i', 'a8, a8, 0'), ('l32i.n', 'a8, a8, 0')) or \
            body[2] != ('bgeu', 'a1, a8, %x' % finish) or \
            not load(body[3], 'a10', function['st_value']) or body[4] not in (
                ('movi', 'a11, 0'), ('movi.n', 'a11, 0')):
        raise ValueError('Single-word guard branch/arguments differ')
    sampler = symbols.get_symbol_by_name('bench_boundary_sample')[0]['st_value']
    call = body[5:]
    if not (call == [('call8', '%x' % sampler)] or len(call) == 2 and call[1][0] == 'callx8' and
            load(call[0], call[1][1], sampler)):
        raise ValueError('Single-word guard sampler differs')


def launch(evidence, args):
    if '-c' not in args or Path(args[args.index('-c') + 1]).suffix != '.c':
        return subprocess.call(args)
    if any(a.startswith('-finstrument-functions') for a in args) or '-S' in args or '-x' in args:
        raise ValueError('Threshold requires original non-profiling compilation')
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
    (folder / 'transform.json').write_text(json.dumps({'transform_kind': 'stack-entry-threshold',
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
