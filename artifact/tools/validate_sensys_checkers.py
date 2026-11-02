#!/usr/bin/env python3
"""Freeze and replay a small capture-mutation batch using unchanged checkers."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone

from audit_esp32_tm_basic import audit as esp32_check
from tenonos_runtime_oracle import evaluate as tenon_check

ROOT = Path(__file__).resolve().parents[1]
PLAN = 'registry/sensys_checker_validation_v1.json'
FROZEN = (PLAN, 'tools/validate_sensys_checkers.py',
          'tools/audit_esp32_tm_basic.py', 'tools/tenonos_runtime_oracle.py')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def variant(raw, kind, mutation):
    if mutation == 'none':
        return raw
    if kind == 'esp32':
        rows = [json.loads(line) for line in raw.splitlines()]
        if mutation == 'extra-info':
            rows.insert(0, {'elapsed_s': 0, 'line': 'INFO capture validation'})
        else:
            index, = [i for i, r in enumerate(rows) if
                      'Relative Time: 60' in r['line']]
            if mutation == 'missing-window':
                del rows[index]
            elif mutation == 'wrong-heading':
                assert 'Message Processing' in rows[index]['line']
                rows[index]['line'] = rows[index]['line'].replace('Message Processing', 'Synchronization Processing')
            elif mutation == 'backward-time':
                rows[index]['elapsed_s'] = -1
            else:
                raise ValueError('Unknown ESP32 mutation')
        return ''.join(json.dumps(r) + '\n' for r in rows).encode()
    case, key = {'legal-mask': (5, 'irq_masked'), 'missing-worker': (2, 'entered'),
                 'false-irq': (5, 'irq_context'), 'unbalanced-lock': (4, 'locks')}[mutation]
    lines = raw.decode().splitlines(keepends=True)
    index, = [i for i, line in enumerate(lines) if line.startswith('IOTOS_RUNTIME case=%d ' % case)]
    fields = dict(item.split('=') for item in lines[index].split()[1:])
    value = int(fields[key])
    fields[key] = str(1 - value if mutation == 'legal-mask' else
                      value - 1 if mutation == 'missing-worker' else
                      0 if mutation == 'false-irq' else value + 1)
    assert mutation != 'false-irq' or value == 1
    lines[index] = 'IOTOS_RUNTIME ' + ' '.join(k + '=' + v for k, v in fields.items()) + '\n'
    return ''.join(lines).encode()


def register(root, folder):
    plan = json.loads((root / PLAN).read_text())
    folder.mkdir(exist_ok=False)
    registration = {'registered_at': datetime.now(timezone.utc).isoformat(),
                    'files': {p: sha(root / p) for p in (*FROZEN, *plan['inputs'].values())},
                    'protocol': plan}
    (folder / 'registration.json').write_text(json.dumps(registration, indent=2) + '\n')
    return {'registered': True, 'cases': len(plan['cases'])}


def evaluate(root, folder):
    registration = json.loads((folder / 'registration.json').read_text())
    for path, digest in registration['files'].items():
        if sha(root / path) != digest:
            raise ValueError('Frozen input/checker changed: ' + path)
    plan = json.loads((root / PLAN).read_text())
    if plan != registration['protocol']:
        raise ValueError('Protocol changed')
    records = []
    with tempfile.TemporaryDirectory(prefix='iotos-checker-validation-') as temporary:
        for case in plan['cases']:
            raw = (root / plan['inputs'][case['input']]).read_bytes()
            changed = variant(raw, case['input'], case['mutation'])
            if case['mutation'] != 'none' and raw == changed:
                raise ValueError('Mutation made no change')
            reason = None
            try:
                if case['input'] == 'esp32':
                    path = Path(temporary) / 'capture.jsonl'
                    path.write_bytes(changed)
                    accepted = esp32_check(path, 'FreeRTOS', 'message_processing')['audit'] == 'pass'
                else:
                    accepted = tenon_check(changed.decode())['admitted']
            except ValueError as error:
                accepted, reason = False, str(error)
            records.append({**case, 'observed_accept': accepted, 'reason': reason,
                            'matches_expectation': accepted == case['accept'],
                            'variant_sha256': hashlib.sha256(changed).hexdigest()})
    return {'pass': all(r['matches_expectation'] for r in records),
            'scope': plan['scope'], 'records': records,
            'invalid_rejected': sum(not r['accept'] and not r['observed_accept'] for r in records),
            'invalid_total': sum(not r['accept'] for r in records),
            'valid_accepted': sum(r['accept'] and r['observed_accept'] for r in records),
            'valid_total': sum(r['accept'] for r in records),
            'registration_sha256': sha(folder / 'registration.json'),
            'new_hardware_runs': 0, 'new_model_calls': 0}


def replay(root, folder):
    result = evaluate(root, folder)
    if result != json.loads((folder / 'result.json').read_text()):
        raise ValueError('Stored validation result differs from replay')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('register', 'run', 'replay'))
    parser.add_argument('--folder', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform == 'darwin':
        parser.error('Evidence-dependent validation runs only on leon')
    args.folder.resolve().relative_to(ROOT / 'artifacts/reports')
    if args.mode == 'register':
        result = register(ROOT, args.folder)
    elif args.mode == 'run':
        result = evaluate(ROOT, args.folder)
        with (args.folder / 'result.json').open('x') as output:
            json.dump(result, output, indent=2)
    else:
        result = replay(ROOT, args.folder)
    print(json.dumps({k: v for k, v in result.items() if k != 'records'}))
