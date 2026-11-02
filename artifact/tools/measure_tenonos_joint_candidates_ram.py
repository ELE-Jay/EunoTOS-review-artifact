#!/usr/bin/env python3
"""Reuse the fixed-reference RAM method for distinct generated joint candidates."""
import argparse
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import shutil

import measure_tenonos_joint_ram as method
from tenonos_kvm_reproduce import save, sha

ROOT = method.ROOT


@contextmanager
def candidate_study():
    previous = method.NATIVE,method.REGISTRY
    method.NATIVE = 'artifacts/reports/tenonos-joint-candidates-native-rpi4-v1'
    method.REGISTRY = '../artifacts/reports/tenonos-joint-candidate-inventory-v1/memory-protocol.json'
    try:
        yield
    finally:
        method.NATIVE,method.REGISTRY = previous


def audit(base):
    with candidate_study():
        value = method.audit(base)
    value.update(analysis='Complete configuration-matched allocated occupancy of retained generated joint-task candidates',
        scope='Pi4B/KVM guest native entry through termination entry, including observer storage. '
              'Distinct generated configurations passing native task gates; profile aliases do not add samples. '
              'Actual stack use is separate; no uninstrumented RAM, energy or cross-hardware inference.')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','capture','audit'))
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--stage',choices=tuple(method.TEMPLATES))
    parser.add_argument('--socket',default='/tmp/iotos-pi-energy.sock')
    parser.add_argument('--host',default='pi@192.168.31.76')
    args = parser.parse_args()
    method.require(ROOT == method.LEON,'Evidence work remains on leon')
    base = args.folder.resolve();base.relative_to(ROOT/'artifacts/reports')
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with candidate_study():
            if args.action == 'prepare':
                value = method.prepare(base)
                name = Path(__file__).name
                shutil.copyfile(Path(__file__),base/'sources'/name)
                registration = json.loads((base/'registration.json').read_text())
                registration['source_sha256'][name] = sha(base/'sources'/name)
                save(base/'registration.json',registration)
            elif args.action == 'capture' and args.stage:
                value = method.capture(base,args.stage,args.socket,args.host)
            elif args.action == 'audit':
                value = audit(base);save(base/'allocated-occupancy.json',value)
                value = {'audit':value['audit'],'peaks':{p['profile']:p['peak_allocated_occupancy_bytes'] for p in value['profiles']}}
            else:
                parser.error('Capture requires --stage')
        print(json.dumps(value),flush=True)
