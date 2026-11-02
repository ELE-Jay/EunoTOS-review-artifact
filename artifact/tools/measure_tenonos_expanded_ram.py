#!/usr/bin/env python3
"""Apply the existing allocated-occupancy method to retained generated configurations."""
import argparse
import fcntl
import json
from pathlib import Path
import shutil

from audit_tenonos_memory_lifecycle import audit as lifecycle_audit, require
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
NATIVE = 'artifacts/reports/tenonos-expanded-native-threads-rpi4-v1'
REGISTRY = 'tenonos_expanded_ram_rpi4_v1.json'
TEMPLATES = {
    'early': 'tenonos_boot_memory_rpi4_v5.json',
    'metadata': 'tenonos_allocator_metadata_rpi4_v1.json',
    'exit': 'tenonos_exit_memory_rpi4_v2.json',
    'peak': 'tenonos_allocator_peak_rpi4_v2.json',
}


def stage_protocols(root, base):
    reference = json.loads((root/'registry'/REGISTRY).read_text())
    relative = base.relative_to(root).as_posix()
    plans = {}
    for kind, template in TEMPLATES.items():
        plan = json.loads((root/'registry'/template).read_text())
        plan.update(id='tenon-expanded-generated-ram-'+kind+'-v1',
                    reference_campaign=NATIVE, reference_protocol_registry=REGISTRY,
                    bootinfo_repair=relative+'/bootinfo-repair', profiles=reference['profiles'])
        if kind == 'peak':
            plan['peak_reference_campaign'] = relative+'/metadata'
            plan['peak_reference_registry'] = '../'+relative+'/metadata-protocol.json'
        plan['controls'] = ('Same newly built observer image/configuration across the four capture modes; '
            'six original bodies/500 iterations. Pi4B serial 10000000c1b4a936; one KVM vCPU, '
            '128 MiB, performance governor restored; no API calls or new timing/energy results.')
        plan['scope'] = ('Configuration-matched '+kind+' evidence for the allocated-occupancy metric. '
            'Stage census does not measure continuous actual stack use. No uninstrumented RAM, '
            'performance or energy inference; retain all prior evidence and failures.')
        plans[kind] = plan
    return plans


def prepare(base):
    require(ROOT == LEON and not base.exists(), 'Use leon and a new persistent folder')
    base.relative_to(ROOT/'artifacts/reports')
    native = ROOT/NATIVE
    result = lifecycle_audit(ROOT, native, native_threads=True, registry=REGISTRY)
    save(native/'audit.json', result)
    require(shutil.disk_usage(ROOT).free >= 128*1024**2, 'Insufficient persistent space')
    base.mkdir()
    shutil.copyfile(ROOT/'registry'/REGISTRY, base/'protocol.json')
    from tenonos_bootinfo_abi import prepare as bootinfo_prepare
    plan = json.loads((base/'protocol.json').read_text())
    bootinfo_prepare(ROOT, base/'bootinfo-repair', NATIVE, plan['profiles'])
    plans = stage_protocols(ROOT, base)
    for kind, value in plans.items():
        save(base/(kind+'-protocol.json'), value)
    sources = ['measure_tenonos_expanded_ram.py', 'audit_tenonos_allocated_ram.py',
               'audit_tenonos_memory_lifecycle.py', 'tenonos_bootinfo_abi.py',
               'tenonos_boot_memory.py', 'audit_tenonos_boot_memory.py',
               'audit_tenonos_exit_memory.py', 'tenonos_allocator_metadata.py']
    (base/'sources').mkdir()
    for name in sources:
        shutil.copyfile(ROOT/'tools'/name, base/'sources'/name)
    save(base/'registration.json', {'registered_utc':utc(), 'native_audit_sha256':sha(native/'audit.json'),
        'protocol_sha256':sha(base/'protocol.json'),
        'source_sha256':{n:sha(base/'sources'/n) for n in sources},
        'stage_protocol_sha256':{k:sha(base/(k+'-protocol.json')) for k in plans},
        'new_model_calls':0, 'new_builds':0, 'planned_diagnostic_guests':12})
    return {'prepared':True, 'observer_guests':result['fresh_guests'], 'diagnostic_guests_planned':12}


def source_guard(base):
    registration = json.loads((base/'registration.json').read_text())
    require(sha(base/'protocol.json') == registration['protocol_sha256'], 'RAM protocol changed')
    require(sha(ROOT/NATIVE/'audit.json') == registration['native_audit_sha256'], 'Native audit changed')
    for name, digest in registration['source_sha256'].items():
        require(sha(base/'sources'/name) == digest == sha(ROOT/'tools'/name), 'RAM helper changed: '+name)
    for kind, digest in registration['stage_protocol_sha256'].items():
        require(sha(base/(kind+'-protocol.json')) == digest, 'Stage protocol changed')
    return registration


def stage_audit(base, kind):
    from audit_tenonos_boot_memory import audit as early
    from audit_tenonos_exit_memory import audit as tail
    from tenonos_allocator_metadata import audit as metadata
    function = {'early':early, 'exit':tail, 'metadata':metadata, 'peak':metadata}[kind]
    registry = '../'+(base/(kind+'-protocol.json')).relative_to(ROOT).as_posix()
    return function(ROOT, base/kind, registry=registry)


def capture(base, kind, socket, host):
    source_guard(base)
    from tenonos_boot_memory import collect
    collect(base/kind, socket, host, base/(kind+'-protocol.json'))
    value = stage_audit(base, kind)
    save(base/kind/'audit.json', value)
    print(json.dumps({'stage':kind, 'audit':value['audit'], 'new_guests':3}), flush=True)


def audit(base):
    registration = source_guard(base)
    original = lifecycle_audit(ROOT, ROOT/NATIVE, native_threads=True, registry=REGISTRY)
    require(original == json.loads((ROOT/NATIVE/'audit.json').read_text()), 'Native replay differs')
    for kind in TEMPLATES:
        require(stage_audit(base,kind) == json.loads((base/kind/'audit.json').read_text()), 'Stage replay differs')
    from audit_tenonos_allocated_ram import audit as allocated
    sources = {k:((base/k).relative_to(ROOT/'artifacts/reports').as_posix(),sha(base/k/'audit.json'))
               for k in ('early','exit','peak')}
    registries = {k:'../'+(base/(k+'-protocol.json')).relative_to(ROOT).as_posix() for k in sources}
    result = allocated(ROOT, sources=sources, registries=registries)
    result.update(analysis='Newly generated configuration-matched allocated-occupancy observers',
        observer_campaign_sha256=sha(ROOT/NATIVE/'campaign.json'),
        registration_sha256=sha(base/'registration.json'),
        new_guests_in_observer_campaign=9, new_guests_in_supporting_captures=12,
        new_observer_builds=3, new_model_calls=0,
        scope='Pi4B/KVM observer configurations matched to three actual retained generated candidates; '
              'native entry through termination entry, original suite plus separate finite validation. '
              'Includes observer storage. Actual stack use separate and unmeasured in this campaign.',
        method='Replay native reserved ownership, bookkeeping and every native allocation/free; '
               'verify the original-suite peak against native headers/bitmaps. Six early stage maps '
               'bound pre-allocator allocated reservations; actual SP depth is not inferred.')
    plan = json.loads((base/'protocol.json').read_text())
    refs = json.loads((ROOT/plan['reference_registry']).read_text())['variants']
    candidates = {v['id']:v for v in refs}
    for profile in result['profiles']:
        candidate = candidates[profile['profile']]
        require(sha(ROOT/NATIVE/profile['profile']/'input.config') == candidate['config_sha256'],
                'Observer no longer matches retained generated configuration')
        profile['generated_image_sha256'] = candidate['image_sha256']
        profile['generated_config_sha256'] = candidate['config_sha256']
        profile['actual_stack_use_measured'] = False
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare','capture','audit'))
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--stage', choices=tuple(TEMPLATES))
    parser.add_argument('--socket', default='/tmp/iotos-pi-energy.sock')
    parser.add_argument('--host', default='pi@192.168.31.76')
    args = parser.parse_args()
    require(ROOT == LEON, 'Evidence work remains on leon')
    base = args.folder.resolve(); base.relative_to(ROOT/'artifacts/reports')
    if args.action == 'prepare':
        print(json.dumps(prepare(base)))
    elif args.action == 'capture' and args.stage:
        with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            capture(base,args.stage,args.socket,args.host)
    elif args.action == 'audit':
        value = audit(base)
        save(base/'allocated-occupancy.json',value)
        print(json.dumps({'audit':value['audit'], 'peaks':{
            p['profile']:p['peak_allocated_occupancy_bytes'] for p in value['profiles']}}))
    else:
        parser.error('Capture requires --stage')
