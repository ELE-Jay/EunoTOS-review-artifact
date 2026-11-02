#!/usr/bin/env python3
"""Apply the existing allocated-occupancy method to the fixed joint reference."""
import argparse
import fcntl
import json
from pathlib import Path
import shutil

from audit_tenonos_memory_lifecycle import audit as lifecycle_audit, require
from measure_tenonos_expanded_ram import TEMPLATES, stage_audit
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
NATIVE = 'artifacts/reports/tenonos-joint-native-threads-rpi4-v1'
REGISTRY = 'tenonos_joint_ram_rpi4_v1.json'


def stage_protocols(root, base):
    reference = json.loads((root/'registry'/REGISTRY).read_text())
    relative = base.relative_to(root).as_posix()
    plans = {}
    for kind, template in TEMPLATES.items():
        plan = json.loads((root/'registry'/template).read_text())
        plan.update(id='tenon-joint-reference-ram-'+kind+'-v1',
                    reference_campaign=NATIVE, reference_protocol_registry=REGISTRY,
                    bootinfo_repair=relative+'/bootinfo-repair', profiles=reference['profiles'])
        if kind == 'peak':
            plan.update(peak_reference_campaign=relative+'/metadata',
                        peak_reference_registry='../'+relative+'/metadata-protocol.json')
        plan['controls'] = reference['host']+'; same observer image/configuration across capture modes.'
        plan['scope'] = ('Matched '+kind+' evidence for allocated occupancy in one fixed joint reference; '
                         'no model calls, actual stack-use inference, timing or energy score.')
        plans[kind] = plan
    return plans


def prepare(base):
    require(ROOT == LEON and not base.exists(), 'Use leon and a new persistent folder')
    base.relative_to(ROOT/'artifacts/reports')
    result = lifecycle_audit(ROOT, ROOT/NATIVE, native_threads=True, registry=REGISTRY)
    save(ROOT/NATIVE/'audit.json', result)
    require(shutil.disk_usage(ROOT).free >= 128*1024**2, 'Insufficient persistent space')
    base.mkdir()
    shutil.copyfile(ROOT/'registry'/REGISTRY, base/'protocol.json')
    plan = json.loads((base/'protocol.json').read_text())
    from tenonos_bootinfo_abi import prepare as bootinfo_prepare
    bootinfo_prepare(ROOT, base/'bootinfo-repair', NATIVE, plan['profiles'])
    plans = stage_protocols(ROOT, base)
    for kind, value in plans.items():
        save(base/(kind+'-protocol.json'), value)
    from tenonos_memory_observer import HELPERS as native_helpers
    from tenonos_boot_memory import HELPERS as boot_helpers
    sources = sorted(set(native_helpers + boot_helpers + (
        Path(__file__).name, 'measure_tenonos_expanded_ram.py', 'run_tenonos_energy.py',
        'audit_tenonos_allocated_ram.py', 'tenonos_memory_lifecycle.c',
        'audit_tenonos_memory_lifecycle.py', 'tenonos_native_threads.c',
        'audit_tenonos_native_threads.py')))
    (base/'sources').mkdir()
    for name in sources:
        shutil.copyfile(ROOT/'tools'/name, base/'sources'/name)
    save(base/'registration.json', {'registered_utc':utc(), 'native_audit_sha256':sha(ROOT/NATIVE/'audit.json'),
        'protocol_sha256':sha(base/'protocol.json'),
        'source_sha256':{n:sha(base/'sources'/n) for n in sources},
        'stage_protocol_sha256':{k:sha(base/(k+'-protocol.json')) for k in plans},
        'new_model_calls':0, 'planned_supporting_guests':len(plans)*len(plan['profiles'])})
    return {'prepared':True, 'observer_guests':result['fresh_guests'],
            'supporting_guests_planned':len(plans)*len(plan['profiles'])}


def source_guard(base):
    registration = json.loads((base/'registration.json').read_text())
    require(sha(base/'protocol.json') == registration['protocol_sha256'], 'RAM protocol changed')
    require(sha(ROOT/NATIVE/'audit.json') == registration['native_audit_sha256'], 'Native audit changed')
    for name, digest in registration['source_sha256'].items():
        require(sha(base/'sources'/name) == digest == sha(ROOT/'tools'/name), 'RAM helper changed: '+name)
    for kind, digest in registration['stage_protocol_sha256'].items():
        require(sha(base/(kind+'-protocol.json')) == digest, 'Stage protocol changed')
    return registration


def capture(base, kind, socket, host):
    source_guard(base)
    from tenonos_boot_memory import collect
    collect(base/kind, socket, host, base/(kind+'-protocol.json'))
    value = stage_audit(base, kind)
    save(base/kind/'audit.json', value)
    return {'stage':kind, 'audit':value['audit'], 'new_guests':len(json.loads((base/'protocol.json').read_text())['profiles'])}


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
    plan = json.loads((base/'protocol.json').read_text())
    references = {v['id']:v for v in json.loads((ROOT/plan['reference_registry']).read_text())['variants']}
    require({p['profile'] for p in result['profiles']} == set(plan['profiles']), 'Reference selection differs')
    for profile in result['profiles']:
        reference = references[profile['profile']]
        require(sha(ROOT/NATIVE/profile['profile']/'input.config') == reference['config_sha256'],
                'Observer configuration differs from admitted fixed reference')
        profile.update(reference_image_sha256=reference['image_sha256'],
                       reference_config_sha256=reference['config_sha256'],
                       budget_bytes=plan['prospective_budget_bytes'],
                       budget_pass=profile['peak_allocated_occupancy_bytes'] <= plan['prospective_budget_bytes'],
                       actual_stack_use_measured=False)
    result.update(analysis='Configuration-matched allocated occupancy of the fixed joint feasibility reference',
        observer_campaign_sha256=sha(ROOT/NATIVE/'campaign.json'),
        registration_sha256=sha(base/'registration.json'),
        new_guests_in_observer_campaign=original['fresh_guests'],
        new_guests_in_supporting_captures=registration['planned_supporting_guests'],
        new_observer_builds=len(plan['profiles']), new_model_calls=0,
        feasible_ram_reference=all(p['budget_pass'] for p in result['profiles']),
        scope='Pi4B/KVM guest native entry through termination entry, including observer storage. '
              'One hand-specified reference, not model output. Actual stack use remains separate; '
              'no uninstrumented RAM, whole-Pi RAM or cross-hardware ranking inference.')
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
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action == 'prepare':
            value = prepare(base)
        elif args.action == 'capture' and args.stage:
            value = capture(base,args.stage,args.socket,args.host)
        elif args.action == 'audit':
            value = audit(base)
            save(base/'allocated-occupancy.json',value)
            value = {'audit':value['audit'], 'feasible_ram_reference':value['feasible_ram_reference'],
                     'peaks':{p['profile']:p['peak_allocated_occupancy_bytes'] for p in value['profiles']}}
        else:
            parser.error('Capture requires --stage')
        print(json.dumps(value), flush=True)
