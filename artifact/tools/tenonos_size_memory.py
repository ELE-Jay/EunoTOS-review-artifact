#!/usr/bin/env python3
"""Recognize the retained -Os observer boundary without changing guest code."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import struct

import measure_tenonos_joint_ram as method
from measure_tenonos_joint_candidates_ram import candidate_study
from tenonos_kvm_reproduce import save, sha

ROOT = method.ROOT
EARLY = 'artifacts/reports/tenonos-joint-candidates-allocated-rpi4-v1'
ORIGINAL_LAYOUT_SHA = 'c3a3a2b3b63d933ff9a296c7a25def23f160c3800f788f61891331a93116f02d'


def disable_boundary(data, address, local):
    candidates = []
    for offset in range(0,len(data)-11,4):
        words = struct.unpack_from('<3I',data,offset)
        if words[0] != 0x52800020:
            continue
        for load_index,store_index in ((1,2),(2,1)):
            load,store = words[load_index],words[store_index]
            if load & 0xffc0001f != 0xb9400001 or store & 0xffc0001f != 0xb9000000:
                continue
            base,other = (load>>5)&31,(store>>5)&31
            loaded,stored = ((load>>10)&4095)*4,((store>>10)&4095)*4
            if base != 31 and base == other and local['count']['address']-loaded == local['disabled']['address']-stored:
                candidates.append({'pc':address+offset+4*(store_index+1),
                    'store_pc':address+offset+4*store_index, 'sequence_hex':data[offset:offset+12].hex(),
                    'base_register':'x'+str(base),'disabled_offset':stored,'count_offset':loaded})
    method.require(len(candidates) == 1,'Unknown or ambiguous compiled disable boundary')
    return candidates[0]


def layout(path,tlsf):
    import tenonos_exit_memory as original
    raw = Path(original.__file__).read_bytes()
    method.require(hashlib.sha256(raw).hexdigest() == ORIGINAL_LAYOUT_SHA,'Original DWARF decoder changed')
    start = raw.index(b'        # The reviewed native sequence is MOV W0,1; LDR count; STR disabled.\n')
    end = raw.index(b"        return {'variables':",start)
    modified = raw[:start]+b"        transition=disable_boundary(data,main['st_value'],local)\n"+raw[end:]
    namespace = dict(original.__dict__,disable_boundary=disable_boundary)
    exec(compile(modified,str(Path(__file__))+'::layout-only-extension','exec'),namespace)
    return namespace['layout'](path,tlsf)


@contextmanager
def size_study():
    import tenonos_exit_memory as abi
    import tenonos_allocator_metadata as metadata
    import audit_tenonos_exit_memory as exit_audit
    previous = abi.layout,metadata.observer_layout,exit_audit.layout
    with candidate_study():
        abi.layout = metadata.observer_layout = exit_audit.layout = layout
        try:
            yield
        finally:
            abi.layout,metadata.observer_layout,exit_audit.layout = previous


def prepare(base):
    with size_study():
        value = method.prepare(base)
        # The first stage already passed on this identical image; retain its original protocol.
        from audit_tenonos_boot_memory import audit as early_audit
        early = ROOT/EARLY/'early'
        registry = '../'+EARLY+'/early-protocol.json'
        method.require(early_audit(ROOT,early,registry=registry) == json.loads((early/'audit.json').read_text()),
                       'Existing early capture does not replay')
        for name in json.loads((base/'protocol.json').read_text())['profiles']:
            method.require(sha(ROOT/EARLY/'bootinfo-repair'/name/'runtime-image') ==
                           sha(base/'bootinfo-repair'/name/'runtime-image'),'Reused early image differs')
        for name in (Path(__file__).name,'measure_tenonos_joint_candidates_ram.py'):
            shutil.copyfile(ROOT/'tools'/name,base/'sources'/name)
        registration = json.loads((base/'registration.json').read_text())
        registration['source_sha256'].update({n:sha(base/'sources'/n) for n in
            (Path(__file__).name,'measure_tenonos_joint_candidates_ram.py')})
        registration.update(planned_supporting_guests=3, reused_early_campaign=EARLY+'/early',
                            reused_early_audit_sha256=sha(early/'audit.json'),
                            decoder_change='Two equivalent MOV/load/store orders, checked register and native symbol ownership; same DWARF decoder, guest image and original tests.')
        save(base/'registration.json',registration)
        value.update(supporting_guests_planned=3,reused_early_guests=1)
        return value


def audit(base):
    with size_study():
        registration = method.source_guard(base)
        original = method.lifecycle_audit(ROOT,ROOT/method.NATIVE,native_threads=True,registry=method.REGISTRY)
        method.require(original == json.loads((ROOT/method.NATIVE/'audit.json').read_text()),'Native replay differs')
        for kind in ('metadata','exit','peak'):
            method.require(method.stage_audit(base,kind) == json.loads((base/kind/'audit.json').read_text()),'Stage replay differs')
        early = ROOT/registration['reused_early_campaign']
        method.require(sha(early/'audit.json') == registration['reused_early_audit_sha256'],'Reused early audit changed')
        sources = {k:((base/k).relative_to(ROOT/'artifacts/reports').as_posix(),sha(base/k/'audit.json')) for k in ('exit','peak')}
        sources['early'] = (early.relative_to(ROOT/'artifacts/reports').as_posix(),sha(early/'audit.json'))
        registries = {k:'../'+(base/(k+'-protocol.json')).relative_to(ROOT).as_posix() for k in ('exit','peak')}
        registries['early'] = '../'+EARLY+'/early-protocol.json'
        from audit_tenonos_allocated_ram import audit as allocated
        result = allocated(ROOT,sources=sources,registries=registries)
        plan = json.loads((base/'protocol.json').read_text())
        references = {v['id']:v for v in json.loads((ROOT/plan['reference_registry']).read_text())['variants']}
        method.require({p['profile'] for p in result['profiles']} == set(plan['profiles']),'Profile selection differs')
        for p in result['profiles']:
            reference = references[p['profile']]
            method.require(sha(ROOT/method.NATIVE/p['profile']/'input.config') == reference['config_sha256'],'Candidate config differs')
            p.update(reference_image_sha256=reference['image_sha256'],reference_config_sha256=reference['config_sha256'],
                budget_bytes=plan['prospective_budget_bytes'],budget_pass=p['peak_allocated_occupancy_bytes']<=plan['prospective_budget_bytes'],
                actual_stack_use_measured=False)
        result.update(analysis='Complete configuration-matched allocated occupancy of generated joint-task candidates',
            registration_sha256=sha(base/'registration.json'),observer_campaign_sha256=sha(ROOT/method.NATIVE/'campaign.json'),
            new_guests_in_observer_campaign=original['fresh_guests'],new_guests_in_supporting_captures=3,
            reused_early_guests=1,new_observer_builds=len(plan['profiles']),new_model_calls=0,
            feasible_ram_reference=all(p['budget_pass'] for p in result['profiles']),
            scope='Pi4B/KVM observer-inclusive guest allocation capacity from native entry through termination entry. '
                  'Same -Os generated configuration, original six test bodies and retained images; actual stack use separate. '
                  'One early capture reused explicitly; no inferred uninstrumented RAM or new energy result.')
        return result


if __name__ == '__main__':
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','capture','audit'))
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--stage',choices=('metadata','exit','peak'))
    args = parser.parse_args()
    method.require(ROOT == method.LEON,'Evidence remains on leon')
    base = args.folder.resolve();base.relative_to(ROOT/'artifacts/reports')
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action == 'prepare':
            value = prepare(base)
        elif args.action == 'capture' and args.stage:
            with size_study():
                value = method.capture(base,args.stage,'/tmp/iotos-pi-energy.sock','pi@192.168.31.76')
        elif args.action == 'audit':
            value = audit(base);save(base/'allocated-occupancy.json',value)
            value = {'audit':value['audit'],'peaks':{p['profile']:p['peak_allocated_occupancy_bytes'] for p in value['profiles']}}
        else:
            parser.error('Capture requires --stage')
        print(json.dumps(value),flush=True)
