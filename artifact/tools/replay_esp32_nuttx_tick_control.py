#!/usr/bin/env python3
"""Independent stdlib replay of a frozen runtime-toggle diagnostic."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from replay_esp32_followup import campaign,digest,raw_rows,require,native_allocation_addresses


def replay(folder,source):
    data=campaign(folder);plan=json.loads((folder/'plan.json').read_text())
    build=json.loads((source/'build.json').read_text())
    require(data['mode']=='nuttx-tick-same-image-control' and data['completed_resets']==4 and
        data['board_mac']=='34:98:7a:a2:85:28' and plan['enabled_order']==[0,1,1,0] and plan['same_binary'] and
        plan['independent_resets']==4 and plan['build_manifest_sha256']==digest(source/'build.json') and
        build.get('native_tick_same_image_control') is True,'Runtime-toggle identity/plan differs')
    for name in ('application.elf','application.bin','bootloader.bin','partitions.bin'):
        require(digest(folder/'build'/name)==digest(source/name),'Runtime arms have different firmware')
    runs=[];previous=None
    for i,enabled in enumerate((0,1,1,0),1):
        run=folder/'runs'/str(i);rows=raw_rows(run/'reset1.jsonl');lines=[r['line'] for r in rows]
        start,end=(datetime.fromisoformat(rows[n]['utc']) for n in (0,-1))
        resets=[r for r in rows if r['line'].startswith('rst:0x')]
        require(len(resets)==1 and resets[0]['elapsed_s']<2 and (previous is None or start>previous),
            'Independent reset chronology differs')
        previous=end
        for name in ('identity.log','flash.log','verify-before.log','verify-after.log'):
            text=(run/name).read_text()
            require(set(re.findall(r'^MAC: ([0-9a-f:]+)$',text,re.M))=={data['board_mac']} and not
                re.search(r'fatal error|digest mismatch|Traceback',text,re.I),'Flash identity/status differs')
            if name.startswith('verify-'):
                actual=[(int(m[0]),int(m[1],16)) for m in re.findall(
                    r'^Verifying 0x[0-9a-f]+ \((\d+)\) bytes @ 0x([0-9a-f]+).*\n-- verify OK \(digest matched\)$',text,re.M)]
                expected=[(((source/n).stat().st_size+3)&~3,a) for n,a in
                    (('bootloader.bin',0x1000),('partitions.bin',0x8000),('application.bin',0x10000))]
                require(actual==expected,'Verified image-segment coverage differs')
        require(lines.count(f'TM_N_TICK_CONTROL enabled={enabled} clock_hz=240000000')==1 and
            lines.count('Thread-Metric queue self-check PASS')==1 and
            lines.count('NUTTX_MESSAGE_RAM END invalid=0 original_reports=3')==1 and not
            re.search(r'panic|abort|Exception|ASSERT|FATAL|ERROR:', '\n'.join(lines),re.I),'Runtime control/correctness differs')
        headings=[(j,int(m[1]),r['elapsed_s']) for j,r in enumerate(rows) if (m:=re.search(
            r'Thread-Metric Message Processing Test .* Relative Time: (\d+)$',r['line']))]
        totals=[(j,int(m[1])) for j,s in enumerate(lines) if (m:=re.fullmatch(r'Time Period Total:\s*(\d+)',s.strip()))]
        require([x[1] for x in headings]==[30,60,90] and len(totals)==3 and
            all(a[0]<b[0]<(headings[j+1][0] if j<2 else len(lines)) and b[1]>0 for j,(a,b) in enumerate(zip(headings,totals))) and
            all(29.5<b[2]-a[2]<30.5 for a,b in zip(headings,headings[1:])),'Original count/window differs')
        values=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
            r'TM_N_TICK_COST calls=(\d+) cycles=(\d+) maximum=(\d+)',s))]
        require(len(values)==1,'Cycle record missing/repeated')
        calls,cycles,maximum=values[0]
        require(8000<=calls<=11000 and 0<maximum<=cycles<=maximum*calls and maximum<2**32,'Cycle arithmetic differs')
        observed=native_allocation_addresses(lines)
        if enabled:
            from replay_esp32_nuttx_tick_stacks import observations
            symbols={m[4]:(int(m[1],16),int(m[2],16)) for s in (source/'symbols.txt').read_text().splitlines()
                if (m:=re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) (\w) (\S+)',s))}
            require(observations(lines,symbols)['samples']==calls,'Sampling/cycle call coverage differs')
        else:
            require(len([s for s in lines if s.startswith('TM_N_LIVE ')])==1 and any(re.fullmatch(
                r'TM_N_LIVE samples=0 records=0 maximum=0 context=216 idle=\d+',s) for s in lines),
                'Disabled arm contains samples')
        runs.append({'enabled':enabled,'original_counts':[v for _,v in totals],'calls':calls,'cycles':cycles,
            'maximum':maximum,'native_heap_peak_bytes':observed['native_heap_peak_bytes']})
    return {'audit':'pass','same_binary':True,'independent_resets':4,'runs':runs,
        'on_off_first_count_ratios':[runs[1]['original_counts'][0]/runs[0]['original_counts'][0],
            runs[2]['original_counts'][0]/runs[3]['original_counts'][0]],
        'original_flash_restored':True,'ranking_eligible':False,'whole_live_ram_peak_bytes':None}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('source',type=Path)
    a=p.parse_args();print(json.dumps(replay(a.folder,a.source),indent=2))
