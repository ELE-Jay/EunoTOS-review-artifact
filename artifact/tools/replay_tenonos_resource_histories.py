#!/usr/bin/env python3
"""Offline replay of prospective RAM-constrained configuration histories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import replay_tenonos_joint as isolated

ROOT=Path(__file__).resolve().parents[1]
PLAN='artifacts/reports/tenonos-resource-history-plan-v1'
CAMPAIGN='artifacts/reports/tenonos-resource-history-campaign-v1'
REPORT='artifacts/reports/tenonos-resource-history-audit-v1.json'


def evaluate():
    from audit_tenonos_resource_histories import audit
    from audit_tenonos_budget_sensitivity import request_limit
    from tenonos_resource_histories import load,require,SPEC
    from tenonos_kvm_reproduce import sha
    result=audit(ROOT/PLAN,ROOT/CAMPAIGN)
    specification=load(ROOT/SPEC)
    origins=load(ROOT/PLAN/'pipeline-origins.json')
    for name,origin in origins.items():
        key='history_pipeline' if name in ('run_tenonos_policy_sequence.py','audit_tenonos_policy_sequence.py') else 'backend_pipeline'
        parent=ROOT/specification[key]
        require(origin['path']==str((parent/name).relative_to(ROOT)) and
            sha(parent/name)==sha(ROOT/PLAN/'pipeline'/name)==origin['sha256']==
            load(parent/'source-variant.json')['variant_sha256'][name],
            'Unchanged generation backend or state-linked runner does not match its frozen ancestor')
    state=load(ROOT/CAMPAIGN/'campaign.json')
    for history in state['histories']:
        for record in history['rounds']:
            folder=ROOT/CAMPAIGN/history['id']/('R'+str(record['round']))/'candidate'
            calls=load(folder/'model-calls.json');used=0
            for call in calls:
                payload=load(folder/(call['stage']+'-request.json'))
                request_limit(history['method'],call['stage'],payload['max_tokens'],used)
                response=folder/(call['stage']+'-response.json')
                if response.exists():
                    used+=load(response)['usage']['completion_tokens']
            require((len(calls),used)==(record['model_calls'],record['completion_tokens']),
                    'Per-round usage or exact stage caps differ')
    # The generic replay engine counts requests; each registered round is one request.
    result['registered_trials']=result['registered_rounds']
    return result


def package(folder,archive):
    from package_esp32_followup import extract_private_archive
    from package_sensys_paper_evidence import local_file
    from tenonos_kvm_reproduce import sha,save
    if ROOT!=isolated.LEON or archive.exists():
        raise ValueError('Create a new private cohort archive on leon')
    archive.resolve().relative_to(ROOT/'reproduction')
    index=json.loads((folder/'input-index.json').read_text());prefix='IoTOSBench-Tenon-Resource-Histories/'
    payloads=dict(index['files'])
    for name,digest in payloads.items():
        if sha(local_file(ROOT,name))!=digest:
            raise ValueError('Indexed cohort input changed')
    required=sum((ROOT/name).stat().st_size for name in payloads)
    if shutil.disk_usage('/dev/shm').free<required+128*1024**2:
        raise ValueError('Insufficient actual-ZIP replay space')
    with tempfile.TemporaryDirectory(prefix='tenon-resource-zip-',dir=archive.parent) as stage, \
            tempfile.TemporaryDirectory(prefix='tenon-resource-unzip-',dir='/dev/shm') as temporary:
        packed=Path(stage)/'cohort.zip'
        with zipfile.ZipFile(packed,'x',zipfile.ZIP_DEFLATED) as output:
            for name,digest in sorted(index['files'].items()):
                raw=(ROOT/name).read_bytes()
                if hashlib.sha256(raw).hexdigest()!=digest or re.search(rb'\bsk-[A-Za-z0-9_-]{24,}',raw):
                    raise ValueError('Changed input or potential credential')
                output.writestr(prefix+name,raw)
            extras={'JOINT_REPLAY_MANIFEST.json':json.dumps(index,indent=2)+'\n',
                'COHORT_README.md':'# Private Tenon resource-modification cohort\n\n'
                'Pi4B ARM64/KVM, independent paper-flow reconstruction, not author engine or RSI. '
                'Replay on leon with the recorded Python runtime: '
                '`/home/reviewer/esp32-pilot/reproduction-audit-runtime/bin/python '
                'tools/replay_tenonos_resource_histories.py replay`. '
                'Native dependency checks were independently performed before packaging; this offline replay '
                'verifies their captured inputs/outcomes, original outputs, memory profiles, clocks and rollback. '
                'No new model calls, hardware sampling, toolchain rebuild or full-paper/external-person claim.\n'}
            for name,text in extras.items():
                output.writestr(prefix+name,text);payloads[name]=hashlib.sha256(text.encode()).hexdigest()
            checksums=''.join(h+'  '+n+'\n' for n,h in sorted(payloads.items()))
            output.writestr(prefix+'SHA256SUMS',checksums)
        with zipfile.ZipFile(packed) as source:
            names=source.namelist()
            if len(names)!=len(set(names)) or set(names)!={prefix+n for n in payloads}|{prefix+'SHA256SUMS'}:
                raise ValueError('Actual ZIP inventory differs')
            if source.read(prefix+'SHA256SUMS').decode()!=checksums:
                raise ValueError('Actual checksum manifest differs')
            for name,digest in payloads.items():
                if hashlib.sha256(source.read(prefix+name)).hexdigest()!=digest:
                    raise ValueError('Actual ZIP bytes differ')
            extract_private_archive(source,Path(temporary))
        env={k:v for k,v in os.environ.items() if k not in
             ('PYTHONPATH','PYTHONHOME','DEEPSEEK_API_KEY','OPENROUTER_API_KEY')}
        env['PYTHONDONTWRITEBYTECODE']='1'
        with (folder/'actual-zip-replay.log').open('x') as log:
            subprocess.run([sys.executable,'-s','tools/replay_tenonos_resource_histories.py','replay'],
                cwd=Path(temporary)/prefix,env=env,check=True,stdout=log,stderr=subprocess.STDOUT,timeout=900)
        digest=sha(packed);os.link(packed,archive)
        if sha(archive)!=digest:
            raise ValueError('Persistent cohort ZIP changed')
    result={'pass':True,'archive':str(archive.relative_to(ROOT)),'archive_sha256':digest,
        'archive_bytes':archive.stat().st_size,'checksummed_files':len(payloads),'evidence_inputs':len(index['files']),
        'actual_zip_isolated_replay':True,'full_paper_package':False,'external_person_reproduction':False}
    save(folder/'zip-receipt.json',result)
    return result


if __name__=='__main__':
    sys.dont_write_bytecode=True
    from tenonos_resource_histories import bootstrap
    from tenonos_kvm_reproduce import save
    bootstrap(ROOT/PLAN)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','capture','copy-replay','replay','zip'))
    parser.add_argument('--folder',type=Path)
    parser.add_argument('--archive',type=Path)
    args=parser.parse_args();isolated.RESULT,isolated.evaluate=REPORT,evaluate
    if args.action=='audit':
        if ROOT!=isolated.LEON or (ROOT/REPORT).exists():
            parser.error('Audit on leon without overwriting a result')
        result=evaluate();save(ROOT/REPORT,result)
    elif args.action=='replay':
        result=isolated.replay()
    elif args.action=='capture':
        result=isolated.capture(args.folder.resolve())
    elif args.action=='zip':
        result=package(args.folder.resolve(),args.archive.resolve())
    else:
        result=isolated.copy_replay(args.folder.resolve(),launcher='tools/replay_tenonos_resource_histories.py',
            scope='Same-host actual offline-copy replay of prescribed resource-constrained histories; '
                  'not full-paper ZIP, external researcher, new guest or author-engine reproduction.')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','histories')},indent=2),flush=True)
