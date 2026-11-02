#!/usr/bin/env python3
"""Inventory actual SP writes with and without compiler profiling, on leon."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def functions(text):
    result, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        declaration = re.fullmatch(r'\s*\.type\s+([\w.$]+),\s*@function\s*', line)
        if declaration:
            if current is not None:
                raise ValueError('Unclosed assembly function')
            current = {'name': declaration[1], 'entries': [], 'other_sp_writes': [], 'profile_calls': 0, 'opaque': []}
        if current is None:
            continue
        if re.fullmatch(r'\s*\.size\s+' + re.escape(current['name']) + r',.*', line):
            current['end_line'] = number
            result.append(current)
            current = None
            continue
        if re.match(r'\s*\.(?:byte|word|short|long|2byte|4byte)\s', line):
            current['opaque'].append(number)
        instruction = re.fullmatch(r'\s+([a-z][a-z0-9.]*)\s+([^#]*?)(?:\s*#.*)?', line)
        if not instruction:
            continue
        op, args = instruction.groups()
        if op == 'call8' and args.strip().startswith('__cyg_profile_func_'):
            current['profile_calls'] += 1
        if args.split(',')[0].strip() not in ('a1', 'sp'):
            continue
        if op == 'entry':
            current['entries'].append({'line': number, 'frame_bytes': int(args.split(',')[1], 0)})
        elif not (op.startswith(('b', 'call', 'wsr', 'wur', 'wer', 'loop')) or
                  op in ('s8i', 's16i', 's32i', 's32e', 's8i.n', 's16i.n', 's32i.n')):
            current['other_sp_writes'].append({'line': number, 'instruction': line.strip()})
    if current is not None:
        raise ValueError('Unclosed final assembly function')
    return result


def inventory(source, output, reuse=None):
    output.mkdir(parents=True, exist_ok=False)
    records = []
    work = json.loads((source / 'compile_commands.json').read_text())[0]['directory']
    for directory in sorted((source / 'inline-assembly').iterdir()):
        record = json.loads((directory / 'transform.json').read_text())
        path = Path(record['source'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['source_sha256']:
            raise ValueError('Compile input changed: ' + str(path))
        args, skip = [], False
        for arg in record['compiler_command']:
            if skip:
                skip = False
            elif arg in ('-MF', '-MT', '-MQ'):
                skip = True
            elif not arg.startswith('-finstrument-functions') and arg not in ('-MD', '-MMD'):
                args.append(arg)
        args[args.index('-c')] = '-S'
        assembly = output / (directory.name + '.s')
        args[args.index('-o') + 1] = str(assembly)
        env = dict(os.environ, PATH=str(Path(args[0]).parent) + ':' + os.environ['PATH'])
        if reuse is None:
            with (output / (directory.name + '.log')).open('x') as log:
                subprocess.run(args, cwd=work, env=env,
                    stdout=log, stderr=subprocess.STDOUT, check=True)
        else:
            old = next(r for r in json.loads((reuse / 'inventory.json').read_text())['records'] if r['source'] == str(path))
            previous = reuse / old['assembly']
            if hashlib.sha256(previous.read_bytes()).hexdigest() != old['assembly_sha256']:
                raise ValueError('Retained compiler assembly changed')
            shutil.copyfile(previous, assembly)
            args = old['compiler_command']
        plain, profiled = functions(assembly.read_text()), functions((directory / 'original.s').read_text())
        records.append({'source': str(path), 'source_sha256': record['source_sha256'],
            'assembly': assembly.name, 'assembly_sha256': hashlib.sha256(assembly.read_bytes()).hexdigest(),
            'compiler_command': args, 'functions': plain, 'profiled_functions': profiled})
    result = {'scope': 'static compiler assembly inventory; not a RAM measurement',
        'translation_units': len(records), 'records': records, 'new_board_runs': 0, 'api_calls': 0,
        'reused_compilation': str(reuse) if reuse is not None else None}
    (output / 'inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reuse', type=Path)
    a = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Run real compiler/evidence work on leon')
    result = inventory(a.source.resolve(), a.output.resolve(), a.reuse.resolve() if a.reuse else None)
    flat = [f for r in result['records'] for f in r['functions']]
    print(json.dumps({'translation_units': len(result['records']), 'functions': len(flat),
        'frame_sizes': sorted({e['frame_bytes'] for f in flat for e in f['entries']}),
        'non_entry_sp_writes': [f for f in flat if f['other_sp_writes']],
        'no_entry': [f['name'] for f in flat if not f['entries']],
        'opaque': [f['name'] for f in flat if f['opaque']]}))
