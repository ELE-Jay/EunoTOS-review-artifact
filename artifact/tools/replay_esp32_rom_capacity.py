#!/usr/bin/env python3
"""Cross-check the capacity certificate with raw bytes, bitmaps and firmware counters."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import replay_tenonos_joint as isolated

ROOT=Path(__file__).resolve().parents[1]
PRIMARY='artifacts/reports/esp32-freertos-allocated-capacity-v1.json'
RESULT='artifacts/reports/esp32-freertos-capacity-crosscheck-v1.json'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(line):
    return {k.decode():int(v) for token in line.split() if b'=' in token for k,v in [token.split(b'=',1)]}


def memory_cells(spans):
    from audit_esp32_resources import ALIASES
    cells=set()
    for low,high in spans:
        for address in range(low,high):
            physical=next((target+address-a for a,b,target in ALIASES if a<=address<b),address)
            cells.add(physical)
    return cells


def native_bitmap(events,pools,deferred,base):
    live={};registered=set();rows=[]
    for cursor in range(len(events)+1):
        if cursor:
            e=events[cursor-1]
            if e['event']!=cursor-1:raise ValueError('Missing original native event')
            p,pointer,delta,kind=e['pool'],e['pointer'],e['delta'],e['kind']
            if kind==0:
                if p in registered or pointer!=pools[p]['start'] or delta!=pools[p]['metadata']:
                    raise ValueError('Changed pool registration')
                registered.add(p)
            elif kind in (1,4):
                if pointer in live or p not in registered:raise ValueError('Invalid new native block')
                live[pointer]=(p,delta)
            elif kind==2:
                if live.pop(pointer,None)!=(p,-delta):raise ValueError('Invalid native release')
            elif kind==3:
                if pointer not in live or live[pointer][0]!=p:raise ValueError('Invalid native resize')
                live[pointer]=(p,live[pointer][1]+delta)
            elif kind in (5,6,7,8):
                # Task ownership/deletion annotations do not allocate native blocks.
                pass
            else:raise ValueError('Unrecognized native event')
        occupied=sum(pools[i]['metadata'] for i in registered)+sum(n for i,n in live.values())
        free_headers=0
        for i in registered:
            pool=pools[i];low=pool['start']+pool['metadata']-4;end=pool['start']+pool['bytes']-4
            bitmap=bytearray((end-low)//4)
            for pointer,(owner,size) in live.items():
                if owner!=i:continue
                start=pointer-4
                if size<=0 or size%4 or (start-low)%4 or not low<=start<start+size<=end:
                    raise ValueError('Block escapes its native pool interior')
                a,b=(start-low)//4,(start+size-low)//4
                if any(bitmap[a:b]):raise ValueError('Native physical blocks overlap')
                bitmap[a:b]=b'\x01'*(b-a)
            holes=re.findall(b'\x00+',bitmap)
            if any(len(hole)<4 for hole in holes):raise ValueError('Impossible subminimum free extent')
            free_headers+=4*len(holes)
        held=0 if deferred in registered else pools[deferred]['bytes']
        rows.append({'cursor':cursor,'native_occupied':occupied,'free_headers':free_headers,
            'startup_held':held,'total':base+occupied+free_headers+held})
    if registered!=set(range(len(pools))) or any(pools[i]['occupied']!=pools[i]['metadata']+
            sum(n for owner,n in live.values() if owner==i) for i in registered):
        raise ValueError('Terminal native counters differ from live block capacities')
    return rows


def crosscheck(root,primary):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import RAM
    def ram(a,b):return a<b and any(lo<=a<b<=hi for lo,hi in RAM)
    def elf_regions(path):
        with path.open('rb') as f:
            e=ELFFile(f);regions=[(p['p_vaddr'],p['p_vaddr']+p['p_memsz']) for p in e.iter_segments()
                if p['p_type']=='PT_LOAD' and ram(p['p_vaddr'],p['p_vaddr']+p['p_memsz'])]
            reserved=[]
            for s in e.get_section_by_name('.symtab').iter_symbols():
                if s.name.startswith('reserved_region_'):
                    section=e.get_section(s['st_shndx']);off=s['st_value']-section['sh_addr']
                    a,b=struct.unpack('<II',section.data()[off:off+8])
                    if ram(a,b):reserved.append((a,b))
        return regions,reserved
    def loaded(path):
        raw=path.read_bytes();offset=24;regions=[]
        if raw[0]!=0xe9:raise ValueError('Wrong native image format')
        for i in range(raw[1]):
            a,n=struct.unpack_from('<II',raw,offset);offset+=8+n
            if ram(a,a+n):regions.append((a,a+n))
        return regions
    source=root/primary['source'];boot=source/'paired-bootloader'
    app_mem,reserved=elf_regions(source/'application.elf');boot_mem,_=elf_regions(boot/'bootloader.elf')
    app_load=loaded(source/'application.bin');boot_load=loaded(boot/'bootloader.bin')
    coarse=memory_cells(primary['coarse_rom_arena_spans'])
    bounds={'rom_first_image_load':len(coarse|memory_cells(boot_load)),
        'loader_and_loaded_application':len(coarse|memory_cells(boot_mem+boot_load+app_load)),
        'application_entry_before_heap':len(coarse|memory_cells(app_mem+app_load))}
    base=len(memory_cells(app_mem+app_load+reserved));rows=[]
    for original in primary['runs']:
        raw=root/primary['capture']/'captures'/('reset%d.raw'%original['reset'])
        if sha(raw)!=original['raw_sha256']:raise ValueError('Original byte capture changed')
        lines=raw.read_bytes().splitlines()
        events=[fields(s) for s in lines if s.startswith(b'TM_RAM event=')]
        pools=[fields(s) for s in lines if s.startswith(b'FREERTOS_RAM pool start=')]
        if not pools or any(p['native_bias']!=4 or p['checks']<=0 for p in pools):
            raise ValueError('Native geometry/successful self-check count differs')
        late=[i for i,p in enumerate(pools) if p['start']==0x3ffe0440 and p['bytes']==0x40000000-0x3ffe0440]
        markers=[fields(s) for s in lines if s.startswith(b'FREERTOS_BOOT_HEAP ')]
        if len(late)!=1 or len(markers)!=1 or markers[0]['count']!=1:
            raise ValueError('Missing unique firmware ownership-transfer snapshot')
        ledger=native_bitmap(events,pools,late[0],base);peak=max(ledger,key=lambda r:r['total'])
        marker=markers[0];at=ledger[marker['before_event']]
        if at['native_occupied']!=marker['before_occupied'] or at['cursor']!=peak['cursor'] or \
                ledger[marker['after_event']]['startup_held'] or not at['startup_held']:
            raise ValueError('Bitmap peak is not the independent firmware-counter handoff witness')
        if dict(bounds,native_ownership_ledger=peak['total'])!=original['phase_upper_bounds'] or \
                peak['total']!=original['coincident_native_witness_bytes'] or \
                peak['total']<max(bounds.values()):
            raise ValueError('Independent byte union/bitmap capacity differs')
        rows.append({'reset':original['reset'],'raw_sha256':sha(raw),'independent_base_bytes':base,
            'direct_firmware_native_counter_bytes':at['native_occupied'],'startup_reserved_bytes':at['startup_held'],
            'mandatory_free_headers_bytes':at['free_headers'],'witness_cursor':at['cursor'],
            'peak_allocated_occupancy_bytes':peak['total'],'early_upper_bounds':bounds})
    return rows


def evaluate():
    from audit_esp32_rom_capacity import audit
    current=json.loads(json.dumps(audit(ROOT)))
    if current!=json.loads((ROOT/PRIMARY).read_text()) or not current['complete_declared_lifecycle']:
        raise ValueError('Current source/raw capacity certificate differs or is incomplete')
    independent=crosscheck(ROOT,current)
    return {'audit':'pass','retained_independent_resets':len(independent),
        'primary_report_sha256':sha(ROOT/PRIMARY),'rows':independent,'complete_declared_lifecycle':True,
        'new_benchmark_samples':0,'new_model_calls':0,
        'scope':'Second raw-byte parser, per-byte physical unions and per-word native bitmaps agree with the primary capacity certificate and the firmware before-release counter. Same retained five resets and source-bound normal-boot ABI; not new samples, external-person replication or native OS ranking.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','capture','copy-replay','replay'))
    parser.add_argument('--folder',type=Path);args=parser.parse_args()
    isolated.RESULT,isolated.evaluate=RESULT,evaluate
    if args.action=='audit':
        if ROOT!=isolated.LEON or (ROOT/RESULT).exists():parser.error('Preserve existing audits on leon')
        result=evaluate()
        with (ROOT/RESULT).open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    elif args.action=='replay':result=isolated.replay()
    elif args.action=='capture':result=isolated.capture(args.folder.resolve())
    else:result=isolated.copy_replay(args.folder.resolve(),launcher='tools/replay_esp32_rom_capacity.py',
        scope='Actual isolated input-copy replay of the retained FreeRTOS cold-boot capacity certificate, not full-paper ZIP, fresh hardware or external-person replication.')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
