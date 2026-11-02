#!/usr/bin/env python3
"""Measure one retained generated image using the existing board-energy collector."""
import argparse
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import threading
import time

import audit_tenonos_energy as replay
import run_tenonos_energy as collector
from audit_tenonos_tasks import require
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
SPEC = 'registry/tenonos_joint_energy_rpi4_v1.json'


class TrailingSampleStop:
    def __init__(self,event):
        self.event,self.observed = event,False

    def is_set(self):
        if not self.event.is_set():
            return False
        if not self.observed:
            self.observed = True
            return False
        return True


def references(plan,root):
    variants = collector.reference_images(plan,root)
    require(plan['id'] == 'tenon-joint-generated-image-activation-energy-v1' and len(variants) == 1 and
            plan['schedule'] == [list(variants)]*3, 'One image and three registered activations required')
    return variants


@contextmanager
def single_image():
    before = collector.references,collector.SOURCES,replay.references,replay.SOURCES,collector.sample
    collector.references = replay.references = references
    collector.SOURCES = replay.SOURCES = before[1]+(Path(__file__).name,'audit_tenonos_energy.py')
    def covered_sample(meter,folder,origin,stop,ready,errors,interval):
        # An already in-flight query may precede the stop instant; retain one more query.
        return before[4](meter,folder,origin,TrailingSampleStop(stop),ready,errors,interval)
    collector.sample = covered_sample
    try:
        yield
    finally:
        collector.references,collector.SOURCES,replay.references,replay.SOURCES,collector.sample = before


def prepare(output):
    require(ROOT == LEON and not output.exists(),'Prepare a new frozen plan on leon')
    output.relative_to(ROOT/'artifacts/reports')
    spec = json.loads((ROOT/SPEC).read_text())
    from audit_tenonos_joint_tasks import bind, CAMPAIGN
    qualified = bind(ROOT/'artifacts/reports/tenonos-joint-candidate-behavior-rpi4-v1',
                     ROOT/'artifacts/reports/tenonos-joint-candidates-allocated-rpi4-v2')
    require(qualified == json.loads((ROOT/spec['qualified_report']).read_text()),'Joint qualification changed')
    accepted = next(r for r in qualified['rows'] if r['joint_pass'])
    build = ROOT/CAMPAIGN/accepted['trial']/'evaluation/build'
    proof = json.loads((build/'build-result.json').read_text())
    variant = {'id':spec['variant_id'],'build':build.relative_to(ROOT).as_posix(),
               'image_sha256':proof['image_sha256'],'config_sha256':proof['config_sha256']}
    plan = {**spec,'variants':[variant],'schedule':[[variant['id']]]*3,
            'registered_utc':utc(),'specification_sha256':sha(ROOT/SPEC),
            'qualified_report_sha256':sha(ROOT/spec['qualified_report']),
            'candidate_inventory_sha256':sha(ROOT/spec['candidate_inventory']),
            'selected_trial':accepted['trial']}
    references(plan,ROOT)
    save(output,plan)
    return {'selected_trial':accepted['trial'],'images':1,'planned_activations':3,'planned_fresh_guests':9,
            'new_model_calls':0,'new_builds':0,'plan_sha256':sha(output)}


def probe(output):
    require(ROOT == LEON and not output.exists(),'Read instrument into a new leon folder')
    output.relative_to(ROOT/'artifacts/reports');output.mkdir()
    meter = collector.Meter()
    stop,ready,errors = threading.Event(),threading.Event(),[]
    origin = time.monotonic()
    worker = threading.Thread(target=collector.sample,args=(meter,output,origin,stop,ready,errors,.1))
    worker.start()
    try:
        require(ready.wait(3) and not errors,'Instrument did not return an initial sample')
        time.sleep(3)
    finally:
        stop.set();worker.join(3)
        if not worker.is_alive():
            meter.close()
    require(not worker.is_alive() and not errors,'Instrument read failed')
    packets = [json.loads(s) for s in (output/'meter.jsonl').read_text().splitlines()]
    voltages = [int.from_bytes(bytes.fromhex(p['packet_hex'])[8:12],'little')/1e6 for p in packets]
    require(all(4.5 <= voltage <= 5.5 for voltage in voltages),'Unexpected Pi USB supply voltage')
    currents = [int.from_bytes(bytes.fromhex(p['packet_hex'])[12:16],'little',signed=True) for p in packets]
    signs = {1 if i>0 else -1 for i in currents if i}
    require(len(signs) == 1,'Preflight current has zero or mixed direction')
    polarity = signs.pop()
    metadata,powers = collector.trace(output,polarity)
    require(metadata['sample_count'] >= 20,'Too few preflight samples')
    save(output/'probe.json',{'fixed_polarity':polarity,'meter_serial':metadata['meter_serial'],
        'samples':len(powers),'collector_source_sha256':sha(ROOT/'tools/run_tenonos_energy.py'),
        'probe_source_sha256':sha(Path(__file__)),'new_guests':0,'new_model_calls':0,'voltage_commands':False})
    return {'meter_serial':metadata['meter_serial'],'samples':len(powers),'fixed_polarity':polarity}


def audit(folder):
    plan = json.loads((folder/'protocol.json').read_text())
    require(plan['specification_sha256'] == sha(ROOT/SPEC) and
            plan['qualified_report_sha256'] == sha(ROOT/plan['qualified_report']) and
            plan['candidate_inventory_sha256'] == sha(ROOT/plan['candidate_inventory']), 'Selection evidence changed')
    setup = json.loads((folder/'operator-setup.json').read_text())
    require(setup['initial_host']['serial'] == [plan['host_serial']],'Different physical Pi serial')
    with single_image():
        result = replay.audit(folder,ROOT)
    result.update(selected_trial=plan['selected_trial'],scope='One accepted generated image, three whole-Pi activations; no new generation or build.',
                  calibration='Instrument default; external calibration and sensor conversion delay unverified')
    return result


def collect(plan,output,preflight):
    require(ROOT == LEON and not output.exists(),'Collect on leon without overwriting evidence')
    require(sha(ROOT/SPEC) == json.loads(plan.read_text())['specification_sha256'],'Frozen specification changed')
    ssh = ['ssh','-S','/tmp/iotos-pi-energy.sock','-o','BatchMode=yes','-o','ConnectTimeout=10','pi@192.168.31.76']
    require(collector.host_state(ssh)['serial'] == [json.loads(plan.read_text())['host_serial']],'Different physical Pi serial')
    polarity = json.loads((preflight/'probe.json').read_text())['fixed_polarity']
    original_prepare = collector.prepare_runtime_helpers
    temporary_helpers = []
    def retained_helpers(*args):
        value = original_prepare(*args);temporary_helpers.append(value[0]);return value
    collector.prepare_runtime_helpers = retained_helpers
    try:
        with single_image():
            value = collector.run(plan,output,'pi@192.168.31.76','/tmp/iotos-pi-energy.sock',
                                  '/home/pi/tenonos-benchmark-v1',polarity,preflight)
        require(value['status'] == 'complete','Incomplete energy capture; inspect retained evidence')
    finally:
        collector.prepare_runtime_helpers = original_prepare
        if temporary_helpers:
            from tenonos_memory_observer import retain_pi_evidence
            target = output/'runtime-helpers';target.mkdir(exist_ok=False)
            retain_pi_evidence(ssh,'pi@192.168.31.76','/tmp/iotos-pi-energy.sock',temporary_helpers[0],target,0,
                               prefix='iotos-tenon-v4-helpers-')
    return audit(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','probe','collect','audit'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--plan',type=Path)
    parser.add_argument('--preflight',type=Path)
    args = parser.parse_args()
    require(ROOT == LEON,'Experimental evidence stays on leon')
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action == 'prepare':
            result = prepare(args.output.resolve())
        elif args.action == 'probe':
            result = probe(args.output.resolve())
        elif args.action == 'collect':
            require(args.plan is not None and args.preflight is not None,'Collection requires plan and current preflight')
            result = collect(args.plan.resolve(),args.output.resolve(),args.preflight.resolve())
            save(args.output.resolve()/'audit.json',result)
        else:
            result = audit(args.output.resolve())
            require(result == json.loads((args.output.resolve()/'audit.json').read_text()),'Saved energy replay differs')
        print(json.dumps(result),flush=True)
