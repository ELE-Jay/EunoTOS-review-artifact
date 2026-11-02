#!/usr/bin/env python3
"""Separate raw-byte arithmetic and ELF-call decoding for native SP records."""
import argparse
import json
from pathlib import Path
import sys

from replay_esp32_followup import campaign, raw_rows, require


def return_addresses(path):
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        require(elf.elfclass==32 and elf.little_endian and elf['e_machine']=='EM_XTENSA','Different native ABI')
        symbols=elf.get_section_by_name('.symtab')
        target=symbols.get_symbol_by_name('bench_native_sp_note')[0]['st_value']
        locations={str(i):symbols.get_symbol_by_name('bench_native_site_%d'%i)[0]['st_value'] for i in range(1,6)}
        parts=[(s['sh_addr'],s.data()) for s in elf.iter_sections() if s['sh_type']=='SHT_PROGBITS']
    result={}
    for kind,start in locations.items():
        end=min([start+16]+[v for v in locations.values() if v>start])
        found=[]
        for pc in range(start,end-2):
            raw=next((data[pc-a:pc-a+3] for a,data in parts if a<=pc and pc+3<=a+len(data)),b'')
            if len(raw)!=3:continue
            word=int.from_bytes(raw,'little')
            displacement=word>>6
            if displacement >= 1<<17:displacement-=1<<18
            if word&63==5 and (pc&~3)+4+displacement*4==target:found.append(pc+3)
        require(len(found)==1,'Native call0 machine site differs')
        result[kind]=found[0]
    return result


def decode(lines,returns):
    summaries,records,events=[],[],[]
    for line in lines:
        if line.startswith(('NATIVE_SP total=','NATIVE_SP slot ')):
            slot=line.startswith('NATIVE_SP slot ')
            pairs=[p.split('=') for p in line.split()[2 if slot else 1:]]
            require(all(len(p)==2 and p[1].isdigit() for p in pairs) and len({p[0] for p in pairs})==len(pairs),'Malformed native fields')
            (records if slot else summaries).append({k:int(v) for k,v in pairs})
        if line.startswith('TM_RAM event='):
            events.append({k:int(v) for k,v in (p.split('=') for p in line.split()[1:])})
    require(len(summaries)==lines.count('NATIVE_SP END')==1 and
        lines.count('NATIVE_SP ARM domain=reviewed-native-task-irq-transitions observer=stackless')==1,'Incomplete native interval')
    s=summaries[0]
    require(set(s)=={'total','unknown','bad','invalid','joint_peak','peak_pc','peak_site','peak_event','peak_heap','peak_irq','generations','retired','live_mask',*('site%d'%i for i in range(1,6))},'Native schema differs')
    require(all(s[k]==0 for k in ('unknown','bad','invalid')) and all(s['site%d'%i]>0 for i in range(1,6)) and
        sum(s['site%d'%i] for i in range(1,6))==s['total'] and s['site1']==s['site2']==s['site3'] and s['site4']<=s['site3'],
        'Native counts or nesting balance differs')
    require(len({(r['kind'],r['index']) for r in records})==len(records),'Duplicate native context')
    for r in records:
        require(set(r)=={'kind','index','low','high','generation','tcb','samples','minimum','last','min_pc'} and r['kind'] in (0,1,2) and
            0x3ffae000<=r['low']<=r['minimum']<=r['last']<=r['high']<0x40000000,'Invalid native physical interval')
    live,dead,peak=([r for r in records if r['kind']==kind] for kind in range(3))
    require(len(dead)==s['retired'] and sum(r['samples'] for r in live+dead)==s['total'] and
        sorted(r['generation'] for r in live+dead if r['generation'])==list(range(1,s['generations']+1)) and
        sum(1<<r['index'] for r in live if r['index']<16)==s['live_mask'],'Native generation/sample conservation differs')
    require(len([r for r in live if r['index']==16 and r['samples']>0 and r['high']-r['low']==1536])==1,'IRQ context absent')
    for group in (live,peak):
        spans=sorted((r['low'],r['high']) for r in group)
        require(all(a[1]<=b[0] for a,b in zip(spans,spans[1:])),'Simultaneous native contexts overlap')
    require(s['peak_irq'] in (0,1) and any(r['index']==16 for r in peak)==bool(s['peak_irq']) and
        sum(r['high']-r['last'] for r in peak)==s['joint_peak'] and returns.get(str(s['peak_site']))==s['peak_pc'],'Native joint peak or machine return differs')
    if events:
        require([e['event'] for e in events]==list(range(len(events))) and 0<s['peak_event']<=len(events) and
            sum(e['delta'] for e in events[:s['peak_event']] if e['kind']<5)==s['peak_heap'],'Native peak event prefix differs')
    return {'summary':s,'contexts':records,'whole_live_ram_peak_bytes':None,'ranking_eligible':False}


def replay(folder):
    state=campaign(folder)
    require(state['mode']=='tm-message-lifetimes' and state['board_mac']=='34:98:7a:a2:85:28' and state['independent_resets']==5,'Incomplete native campaign')
    returns=return_addresses(folder/'build/application.elf')
    output,previous=[],None
    for name,index in [('validation',1)]+[('captures',i) for i in range(1,6)]:
        rows=raw_rows(folder/name/('reset%d.jsonl'%index))
        boot,start,end=rows[0]['host_boot_id'],rows[0]['capture_started_monotonic_ns'],rows[-1]['clock_read_after_ns']
        require(sum(r['line'].startswith('rst:0x') for r in rows)==1 and start<end and
            (previous is None or previous[0]==boot and previous[1]<start),'Native resets not independently ordered')
        previous=boot,end
        output.append({'validation':name=='validation','native_sp':decode([r['line'] for r in rows],returns)})
    return {'replay':'pass','runs':output,'independent_resets':5,'separate_validation_resets':1,'return_pcs':returns,
        'original_flash_restored':True,'whole_live_ram_peak_bytes':None,'ranking_eligible':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if sys.platform!='linux':p.error('Replay real evidence on leon')
    result=replay(a.directory)
    with a.output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    print('Native raw-byte and machine-return replay passed')
