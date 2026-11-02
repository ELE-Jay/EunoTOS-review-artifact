#!/usr/bin/env python3
"""Independent raw-packet integration and isolated replay of one image's energy."""
import argparse
from bisect import bisect_right
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile

import replay_tenonos_joint as isolated
from audit_tenonos_tasks import require
from measure_tenonos_joint_energy import audit as primary_audit
from package_sensys_paper_evidence import local_file
from tenonos_kvm_reproduce import save, sha

ROOT = Path(__file__).resolve().parents[1]
FOLDER = 'artifacts/reports/tenonos-joint-generated-activation-energy-v1'
REPORT = 'artifacts/reports/tenonos-joint-generated-energy-independent-v1.json'


def integrate(points,start,end):
    times = [p[0] for p in points]
    require(len(points)>1 and all(b>a for a,b in zip(times,times[1:])) and
            times[0] <= start < end <= times[-1], 'Uncovered or unordered integration interval')
    def interpolate(t):
        i = min(bisect_right(times,t)-1,len(points)-2)
        a,p = points[i];b,q = points[i+1]
        return p+(q-p)*(t-a)/(b-a)
    clipped = [(start,interpolate(start))]+[(t,p) for t,p in points if start<t<end]+[(end,interpolate(end))]
    return math.fsum((b-a)*(p+q)/2 for (a,p),(b,q) in zip(clipped,clipped[1:]))


def audit():
    folder = ROOT/FOLDER
    primary = primary_audit(folder)
    require(primary == json.loads((folder/'audit.json').read_text()),'Primary energy replay differs')
    setup = json.loads((folder/'operator-setup.json').read_text())
    polarity = setup['polarity'];rows = []
    for source in primary['rows']:
        p = folder/source['id']
        record = json.loads((p/'activation.json').read_text())
        packets = [json.loads(s) for s in (p/'meter.jsonl').read_text().splitlines()]
        metadata = json.loads((p/'metadata.json').read_text())
        require(metadata['sample_count'] == len(packets) and metadata['meter_serial'] == '086477','Meter sample inventory differs')
        points,voltages,currents = [],[],[]
        for packet in packets:
            raw = bytes.fromhex(packet['packet_hex'])
            voltage = int.from_bytes(raw[8:12],'little')/1000000
            signed = int.from_bytes(raw[12:16],'little',signed=True)/1000000
            start,end = packet['query_start_s'],packet['query_end_s']
            require(48<=len(raw)<=64 and 0<=start<=end<=metadata['duration_actual_s'] and
                    end-start<=.05 and 4.5<=voltage<=5.5 and 0<=signed*polarity<=6,
                    'Invalid raw meter bytes, supply or fixed direction')
            midpoint=(start+end)/2
            require(abs(midpoint-packet['elapsed_s'])<1e-8,'Query midpoint differs')
            points.append((midpoint,voltage*signed*polarity));voltages.append(voltage);currents.append(signed)
        energy = integrate(points,record['start_s'],record['end_s'])
        require(abs(energy-source['energy_j'])<1e-8,'Independent integration differs')
        require(packets[-1]['query_start_s']>record['end_s'],'Missing query started after activation completion')
        gaps = [b[0]-a[0] for a,b in zip(points,points[1:])]
        rows.append({'id':source['id'],'samples':len(points),'energy_j':energy,
            'difference_from_primary_j':energy-source['energy_j'],'query_rate_hz':(len(points)-1)/(points[-1][0]-points[0][0]),
            'median_query_gap_s':statistics.median(gaps),'maximum_query_gap_s':max(gaps),
            'voltage_range_v':[min(voltages),max(voltages)],'signed_current_range_a':[min(currents),max(currents)],
            'leading_coverage_s':record['start_s']-points[0][0],
            'trailing_query_start_margin_s':packets[-1]['query_start_s']-record['end_s'],
            'raw_packet_sha256':sha(p/'meter.jsonl')})
    return {'audit':'pass','registered_trials':3,'activation_trials':3,'fresh_guest_boots':9,
        'new_guests_by_replay':0,'new_model_calls':0,'new_builds':0,'meter_serial':'086477','fixed_polarity':polarity,
        'rows':rows,'primary_audit_sha256':sha(folder/'audit.json'),
        'summary':primary['summary'],'boundary':primary['boundary'],
        'sampling_boundary':'Observed host queries near 10 Hz; sensor conversion cadence and delay are not independently verified.',
        'calibration':primary['calibration'],'ranking_eligible':False,
        'scope':'Independent integer-byte decoding and clipped-knot trapezoids with fsum, compared with the primary segment integration. Same physical captures, not new repetitions or cloud inference energy.'}


def copy_replay(folder):
    require(ROOT == isolated.LEON and not (folder/'receipt.json').exists(),'Use leon and preserve previous receipts')
    index = json.loads((folder/'input-index.json').read_text())
    required = sum(local_file(ROOT,n).stat().st_size for n in index['files'])
    require(shutil.disk_usage('/dev/shm').free>=required+128*1024**2,'Insufficient isolated-copy space')
    with tempfile.TemporaryDirectory(prefix='iotos-joint-energy-replay-',dir='/dev/shm') as temporary:
        root = Path(temporary)
        for name,digest in index['files'].items():
            source = local_file(ROOT,name);require(sha(source)==digest,'Copied input changed')
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        save(root/'JOINT_REPLAY_MANIFEST.json',index)
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1');env.pop('PYTHONPATH',None)
        with (folder/'isolated.stdout').open('x') as out,(folder/'isolated.stderr').open('x') as err:
            step=subprocess.run([sys.executable,str(root/'tools/replay_tenonos_joint_energy.py'),'replay'],
                                cwd=root,env=env,stdout=out,stderr=err,timeout=600)
        require(step.returncode==0,'Isolated energy replay failed; inspect retained logs')
        result=json.loads((folder/'isolated.stdout').read_text())
    result.update(input_index_sha256=sha(folder/'input-index.json'),temporary_copy_removed=True,
                  scope='Same-host isolated input-copy replay of the new one-image energy campaign; not full-paper ZIP or external-person reproduction.')
    save(folder/'receipt.json',result)
    return result


if __name__ == '__main__':
    sys.dont_write_bytecode=True
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','capture','copy-replay','replay'))
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    isolated.RESULT,isolated.evaluate=REPORT,audit
    if args.action=='replay':
        result=isolated.replay()
    else:
        require(ROOT==isolated.LEON and args.output is not None,'Retain experimental evidence on leon')
        output=args.output.resolve();output.relative_to(ROOT/'artifacts/reports')
        if args.action=='audit':
            require(not output.exists(),'Preserve existing audits');result=audit();save(output,result)
        elif args.action=='capture':
            result=isolated.capture(output)
        else:
            result=copy_replay(output)
    print(json.dumps(result),flush=True)
