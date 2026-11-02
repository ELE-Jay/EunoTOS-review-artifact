#!/usr/bin/env python3
"""Cross-check RIOT capacity with a second raw parser/physical bitmap, then isolate."""
import argparse
import json
from pathlib import Path

import replay_tenonos_joint as isolated
from replay_esp32_active_rom_capacity import independent_regions,image_regions
from replay_esp32_rom_capacity import fields,memory_cells,sha
from replay_esp32_followup import raw_rows

ROOT=Path(__file__).resolve().parents[1]
PRIMARY='artifacts/reports/esp32-riot-allocated-capacity-v1.json'
RESULT='artifacts/reports/esp32-riot-capacity-crosscheck-v1.json'


def evaluate():
    from audit_esp32_riot_allocated_capacity import audit
    current=json.loads(json.dumps(audit(ROOT)))
    if current!=json.loads((ROOT/PRIMARY).read_text()):
        raise ValueError('Current source/raw capacity certificate differs')
    spans,fixed,stack=independent_regions(ROOT)
    rom=memory_cells(spans);permanent=memory_cells(fixed)
    resident,loaded,sections=image_regions(ROOT/current['source'],'application')
    br,bl,_=image_regions(ROOT/'artifacts/reports/esp32-boot-handoff-build-v1/paired-bootloader','bootloader')
    rows=[]
    for run in current['runs']:
        path=ROOT/current['capture']/'captures'/('reset%d.jsonl'%run['reset'])
        raw_rows(path)
        raw=path.with_suffix('.raw')
        if sha(raw)!=run['raw_sha256']:
            raise ValueError('Original byte capture changed')
        lines=raw.read_bytes().splitlines()
        phases=[fields(s) for s in lines if s.startswith(b'RIOT_MESSAGE_RAM phase ')]
        regions=[fields(s) for s in lines if s.startswith(b'RIOT_MESSAGE_RAM region ')]
        committed=[fields(s) for s in lines if s.startswith(b'RIOT_MESSAGE_RAM phase_region ')]
        bounds={'first_stage':len(rom|bl),'loader':len(rom|br|loaded),'native_entry':len(rom|resident)}
        if len(phases)!=2 or len(regions)!=4 or len(committed)!=8:
            raise ValueError('Incomplete independent phase inventory')
        for phase,key,reservations in zip(phases,('pre_thread','native_threads'),(rom,permanent)):
            p=phase['index'];group=[r for r in committed if r['phase']==p]
            if len(group)!=4 or [r['index'] for r in group]!=list(range(4)):
                raise ValueError('Phase region order differs')
            spans_at_peak=[(region['start'],region['start']+r['committed']) for region,r in zip(regions,group)]
            heap=memory_cells(spans_at_peak);base=resident|reservations
            occupied=len(heap)-phase['free_bytes']+8*phase['free_nodes']
            if heap&base or occupied!=phase['occupied_peak']:
                raise ValueError('Independent physical overlap or native free-metadata accounting differs')
            if p==0 and not stack[0]<phase['sp']<stack[1]:
                raise ValueError('Inherited pre-thread stack witness differs')
            bounds[key]=len(base)+occupied
        if bounds!=run['phase_upper_bounds'] or max(bounds.values())!=run['peak_allocated_occupancy_bytes']:
            raise ValueError('Independent byte-level capacities disagree')
        rows.append({'reset':run['reset'],'raw_sha256':sha(raw),'phase_upper_bounds':bounds,
            'peak_allocated_occupancy_bytes':max(bounds.values())})
    return {'audit':'pass','primary_report_sha256':sha(ROOT/PRIMARY),'retained_independent_resets':len(rows),
        'rows':rows,'complete_declared_lifecycle':True,'new_benchmark_samples':0,'new_model_calls':0,
        'scope':'Second raw-byte parser, physical byte sets, compiled ROM reservation decoding and native free-node arithmetic agree with the source-bound fixed-observer RIOT certificate. Same-host copied replay, not fresh samples, uninstrumented RAM or external-person replication.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','capture','copy-replay','replay'))
    parser.add_argument('--folder',type=Path);args=parser.parse_args()
    isolated.RESULT,isolated.evaluate=RESULT,evaluate
    if args.action=='audit':
        if ROOT!=isolated.LEON or (ROOT/RESULT).exists():parser.error('Preserve existing audits on leon')
        value=evaluate()
        with (ROOT/RESULT).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
    elif args.action=='replay':value=isolated.replay()
    elif args.action=='capture':value=isolated.capture(args.folder.resolve())
    else:value=isolated.copy_replay(args.folder.resolve(),launcher='tools/replay_esp32_riot_capacity.py',
        scope='Actual isolated copied-input replay of RIOT original-message normal cold-boot allocated capacity; no target/API access, native rebuild, uninstrumented claim or external researcher.')
    print(json.dumps({k:v for k,v in value.items() if k!='rows'}))
