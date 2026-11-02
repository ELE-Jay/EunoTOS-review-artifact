#!/usr/bin/env python3
"""Independently union active ROM/image capacities and replay copied evidence."""
import argparse
import json
from pathlib import Path
import struct

import replay_tenonos_joint as isolated
from replay_esp32_rom_capacity import fields,memory_cells,sha

ROOT=Path(__file__).resolve().parents[1]
PRIMARY='artifacts/reports/esp32-active-rom-allocated-capacity-v1.json'
RESULT='artifacts/reports/esp32-active-rom-capacity-crosscheck-v1.json'


def independent_regions(root):
    from elftools.elf.elffile import ELFFile
    app=root/'artifacts/reports/esp32-boot-handoff-build-v1/application.elf'
    with app.open('rb') as f:
        elf=ELFFile(f);sym=elf.get_section_by_name('.symtab');fixed={}
        for name in ('rom_data','rom_pro_data','cpu0_cache'):
            s=sym.get_symbol_by_name('reserved_region_'+name)[0]
            section=elf.get_section(s['st_shndx']);offset=s['st_value']-section['sh_addr']
            fixed[name]=struct.unpack_from('<II',section.data(),offset)
    rom=root/'artifacts/source_snapshots/esp-rom-elfs-20260528/esp32_rev0_rom.elf'
    with rom.open('rb') as f:
        elf=ELFFile(f);sym=elf.get_section_by_name('.symtab')
        stack=[sym.get_symbol_by_name(n)[0]['st_value'] for n in ('_stack_sentry','__stack')]
    spans=[fixed['rom_data'],(fixed['rom_pro_data'][0],stack[1]),fixed['cpu0_cache']]
    return spans,list(fixed.values()),stack


def image_regions(folder,stem):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import RAM
    def ram(a,n):return n>0 and any(lo<=a<a+n<=hi for lo,hi in RAM)
    with (folder/(stem+'.elf')).open('rb') as f:
        elf=ELFFile(f);resident=[(s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in elf.iter_segments()
            if s['p_type']=='PT_LOAD' and ram(s['p_vaddr'],s['p_memsz'])]
        sections=[(s['sh_addr'],s['sh_addr']+s['sh_size']) for s in elf.iter_sections()
            if s['sh_flags']&2 and ram(s['sh_addr'],s['sh_size'])]
    data=(folder/(stem+'.bin')).read_bytes();offset=24;loaded=[]
    if data[0]!=0xe9:raise ValueError('Wrong native image format')
    for _ in range(data[1]):
        address,size=struct.unpack_from('<II',data,offset);offset+=8+size
        if ram(address,size):loaded.append((address,address+size))
    return memory_cells(resident+loaded),memory_cells(loaded),memory_cells(sections)


def crosscheck(root,primary):
    spans,fixed,stack=independent_regions(root);rom=memory_cells(spans);permanent=memory_cells(fixed)
    if len(rom)!=primary['active_rom_capacity_proof']['active_rom_capacity_bytes']:
        raise ValueError('Independent compiled reservation/ROM stack union differs')
    boot=root/'artifacts/reports/esp32-boot-handoff-build-v1/paired-bootloader'
    bresident,bloaded,_=image_regions(boot,'bootloader');rows=[]
    for original in primary['rows']:
        folder=root/original['source'];capture=root/original['capture']
        resident,loaded,sections=image_regions(folder,'application')
        if original['os']=='Zephyr':
            bounds={'first_stage':len(rom|loaded),'native':len(rom|resident)}
        else:
            native=json.loads((capture/'audit.json').read_text())
            padding=len(resident)-len(sections)
            if sections-resident:raise ValueError('An image section escapes its loaded reservation')
        for run in original['runs']:
            raw=capture/'captures'/('reset%d.raw'%run['reset'])
            if sha(raw)!=run['raw_sha256']:raise ValueError('Original byte capture changed')
            lines=raw.read_bytes().splitlines()
            if original['os']=='Zephyr':
                vectors=[fields(s) for s in lines if s.startswith(b'ZEPHYR_BOOT_OWNERSHIP ')]
                boot_stack=[fields(s) for s in lines if s.startswith(b'ZEPHYR_BOOT_STACK ')]
                if len(vectors)!=1 or vectors[0]['entry_vecbase']!=0x40000000 or len(boot_stack)!=1 or \
                        not stack[0]<boot_stack[0]['entry_sp']<=stack[1]:
                    raise ValueError('Missing coincident Zephyr entry/vector/stack witness')
                witness=bounds['native']
            else:
                stages=[fields(s) for s in lines if s.startswith(b'BOOT_RAM phase=')]
                if len(stages)!=2 or [v['phase'] for v in stages]!=[0,1] or any(
                        not 0x3ffe0440<v['entry_sp']<=stack[1] or v['invalid'] for v in stages):
                    raise ValueError('Missing retained NuttX loader-stack witness')
                n=native['runs'][run['reset']-1]
                if n['reset']!=run['reset']:raise ValueError('Native replay reset identity differs')
                bounds={'first_stage':len(rom|bloaded),'loader':len(rom|bresident|loaded),
                    'native_entry':len(rom|resident),
                    'native':n['software_peak_bytes']+padding+len(permanent)}
                witness=max(bounds['loader'],bounds['native'])
            if bounds!=run['phase_upper_bounds'] or witness!=run['peak_allocated_occupancy_bytes'] or \
                    witness!=max(bounds.values()):
                raise ValueError('Independent byte-level phase capacities differ or remain open')
            rows.append({'os':original['os'],'reset':run['reset'],'raw_sha256':sha(raw),
                'phase_upper_bounds':bounds,'peak_allocated_occupancy_bytes':witness})
    return rows


def evaluate():
    from audit_esp32_active_rom_capacity import audit
    primary=json.loads(json.dumps(audit(ROOT)))
    if primary!=json.loads((ROOT/PRIMARY).read_text()):
        raise ValueError('Current source/raw active-ROM capacity certificate differs')
    rows=crosscheck(ROOT,primary)
    return {'audit':'pass','primary_report_sha256':sha(ROOT/PRIMARY),'rows':rows,
        'retained_independent_resets':len(rows),'complete_declared_lifecycle':True,
        'new_benchmark_samples':0,'new_model_calls':0,
        'scope':'Second byte-level physical unions, compiled reservation decoding and raw entry/vector/loader markers agree with the source-bound normal-boot ABI certificate. The existing audited native allocator replay is reused; not a second implementation of that allocator, a new sample, native OS ranking or external-person replication.'}


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
    else:result=isolated.copy_replay(args.folder.resolve(),launcher='tools/replay_esp32_active_rom_capacity.py',
        scope='Actual isolated input-copy replay of retained Zephyr/NuttX normal-boot capacity evidence; not full-paper ZIP, native OS ranking, fresh hardware or external-person replication.')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
