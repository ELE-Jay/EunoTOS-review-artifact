#!/usr/bin/env python3
"""Bound normal IDF boot allocation by its complete ROM ABI arenas and witnesses."""
import argparse
import json
from pathlib import Path
import re
import struct

from audit_esp32_allocated_lifecycle import (rom_model,table_rows,union,image,boot_image,
    native_configuration,cold_boot,reached_peak)
from audit_esp32_rom_boot import instruction_bytes
from audit_esp32_rom_dispatch import instruction_listing
from audit_esp32_rom_callbacks import audit as callback_audit
from read_esp32_rom_capacity import MAC,WINDOWS
from run_esp32_followup import sha,read_raw_capture

ROOT=Path(__file__).resolve().parents[1]
PHYSICAL='artifacts/reports/esp32-rom-physical-capacity-b1-v1'
POOLS={0x3ffae000:0x2000,0x3ffb0000:0x8000,0x3ffb8000:0x8000,
    0x3ffe0000:0x4000,0x3ffe4000:0x4000,0x40070000:0x8000,0x40078000:0x8000}


def load(path):return json.loads(path.read_text())


def inside(spans,start,end):
    return start<=end and (start==end or any(a<=start<end<=b for a,b in spans))


def physical_read(root):
    folder=root/PHYSICAL;state=load(folder/'campaign.json');plan=load(folder/'plan.json')
    if state['status']!='read_complete' or not all(state[k] for k in
            ('firmware_verified_before','firmware_verified_after')) or any(state[k] for k in
            ('flash_written','efuses_written','new_benchmark_samples','new_model_calls')) or \
            plan['mac']!=MAC or plan['flash_or_efuse_write_allowed'] or plan['benchmark_samples']:
        raise ValueError('Incomplete or non-read-only physical ROM acquisition')
    if plan['windows']!={k:list(v) for k,v in WINDOWS.items()} or len(plan['commands'])!=4:
        raise ValueError('Physical ROM range plan changed')
    if set(state['files'])!={str(p.relative_to(folder)) for p in folder.rglob('*')
            if p.is_file() and p.name!='campaign.json'}:
        raise ValueError('Physical ROM evidence inventory is incomplete')
    for name,digest in state['files'].items():
        path=(folder/name).resolve();path.relative_to(folder.resolve())
        if sha(path)!=digest:raise ValueError('Physical ROM bytes/source/log changed')
    for i,command in enumerate(plan['commands']):
        if command[1:5]!=['-m','esptool','--chip','esp32'] or command[5:8]!=[
                '--port','/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0','--baud']:
            raise ValueError('Changed device/decoder prefix')
        if i in (0,3):
            if len(command)!=12 or command[9:11]!=['verify_flash','0'] or Path(command[11]).name!='original-flash.bin':
                raise ValueError('Only original-Flash verification is admitted')
        else:
            name=list(WINDOWS)[i-1];a,n=WINDOWS[name]
            if len(command)!=13 or command[9:12]!=['dump_mem',hex(a),hex(n)] or Path(command[12]).name!=name:
                raise ValueError('Unexpected physical memory operation')
    for name in ('identity-before.log','verify-before.log','verify-after.log'):
        text=(folder/name).read_text()
        if 'esptool.py v4.8.1' not in text or set(re.findall(r'^MAC: ([0-9a-f:]+)$',text,re.M))!={MAC}:
            raise ValueError('Physical device/decoder identity differs')
        if name.startswith('verify-') and ('Verifying 0x400000 (4194304) bytes @ 0x00000000' not in text or
                'verify OK (digest matched)' not in text):
            raise ValueError('Complete original Flash was not verified')
    windows={}
    for name,(a,n) in WINDOWS.items():
        data=(folder/name).read_bytes()
        if len(data)!=n or 'Read %d bytes'%n not in (folder/(name+'.log')).read_text():
            raise ValueError('Partial ROM window')
        windows[a]=data
    rows=read_raw_capture(folder/'captures',1);lines=[r['line'] for r in rows]
    if [s for s in lines if s.startswith('rst:')]!=['rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)'] or \
            sum(bool(re.fullmatch(r'entry 0x[0-9a-f]+',s)) for s in lines)!=1:
        raise ValueError('The unchanged original image did not resume normal flash boot')
    def memory(address,size):
        for start,raw in windows.items():
            if start<=address and address+size<=start+len(raw):return raw[address-start:address-start+size]
        raise ValueError('Requested physical bytes outside captured ROM windows')
    return memory,{'campaign_sha256':sha(folder/'campaign.json'),'plan_sha256':sha(folder/'plan.json'),
        'rom_bytes_read':sum(len(v) for v in windows.values()),'firmware_unchanged_verified':True,
        'windows':{hex(a):sha(folder/name) for name,(a,n) in WINDOWS.items()},
        'new_benchmark_samples':0,'new_model_calls':0}


def envelope(root,protocol,rom):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_runtime_reservations import compiled_regions
    from audit_esp32_resources import RAM
    source=root/protocol['images'][0]['source'];regions,_=compiled_regions(source/'application.elf')
    selected=[(a,a+n) for a,n,*_ in regions if a in POOLS]
    if {a:b-a for a,b in selected}!=POOLS or len(selected)!=len(POOLS):
        raise ValueError('Native compiled ROM/cache/stack arena boundaries differ')
    memory,physical=physical_read(root)
    path=root/protocol['rom']['directory']/protocol['rom']['elf']
    decoded=instruction_listing((path.parent/'disassembly.txt').read_text())
    with path.open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        def value(name):return symbols.get_symbol_by_name(name)[0]['st_value']
        def initial(address,size):
            row=next(r for r in rom['copy_records'] if r[0]<=address and address+size<=r[1])
            return memory(row[2]+address-row[0],size)
        # Non-ALLOC .data sections carry initializer bytes but their ELF LMAs do not
        # encode the full mask-ROM layout. Bind the reset table to real ROM reads.
        for names,width,expected in ((('_data_start','_data_end'),4,rom['copy_records']),
                (('_bss_table_start','_bss_table_end'),3,rom['zero_records'])):
            low,high=map(value,names)
            if table_rows(memory(low,high-low),width)!=[tuple(r) for r in expected]:
                raise ValueError('Physical reset initialization tables differ from the selected ROM ABI')
        copies=[]
        for a,b,src,cpu in rom['copy_records']:
            if a==b:continue
            section=next(s for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS' and
                s['sh_addr']<=a<b<=s['sh_addr']+s['sh_size'])
            if section.data()[a-section['sh_addr']:b-section['sh_addr']]!=memory(src,b-a):
                raise ValueError('Physical initialized data differs from its ROM object ABI')
            copies.append({'section':section.name,'start':a,'end':b,'rom_source':src})
        sections=[{'section':s.name,'start':s['sh_addr'],'end':s['sh_addr']+s['sh_size']} for s in elf.iter_sections()
            if s['sh_flags']&1 and s['sh_size'] and any(a<=s['sh_addr']<s['sh_addr']+s['sh_size']<=b for a,b in RAM)]
        objects=[{'symbol':s.name,'start':s['st_value'],'end':s['st_value']+s['st_size']} for s in symbols.iter_symbols()
            if s['st_info']['type']=='STT_OBJECT' and s['st_size'] and any(
                a<=s['st_value']<s['st_value']+s['st_size']<=b for a,b in RAM)]
        for row in sections+objects:
            if union(selected,[(row['start'],row['end'])])!=union(selected):
                raise ValueError('A declared ROM RAM object escapes the conservative envelope')
        for row in rom['copy_records']+rom['zero_records']:
            if not inside(selected,row[0],row[1]):raise ValueError('ROM reset destination escapes selected arena')
        if not all(inside(selected,value(lo),value(hi)) for lo,hi in
                (('_stack_sentry','__stack'),('_stack_sentry_app','__stack_app'))):
            raise ValueError('A CPU ROM stack escapes the conservative envelope')
        reset_pcs=[pc for pc in decoded if 0x40000450<=pc<0x40000560 or 0x40000704<=pc<=0x4000073d]
        for pc in [0x40000400,*reset_pcs]:instruction_bytes(memory,pc,decoded[pc][0])
        if struct.unpack('<I',memory(0x40000560,4))[0]!=value('__stack') or \
                struct.unpack('<I',initial(0x3ffe0650,4))[0]!=0 or \
                struct.unpack('<I',initial(0x3ffe0654,4))[0]!=0xffffffff:
            raise ValueError('Physical boot stack or initial interrupt state differs')
    callback=json.loads(json.dumps(callback_audit(root)))
    previous=root/'artifacts/reports/esp32-rom-callbacks-v2.json'
    if callback!=load(previous):raise ValueError('Retained normal ROM prefix changed')
    seen=set(callback['reachable_instruction_pcs'])
    if [pc for pc in sorted(seen) if decoded[pc][1]=='wsr.intenable']!=[0x4000bfc4]:
        raise ValueError('An additional interrupt-enable writer requires review')
    expected={0x4000bfb5:('l32i.n','a3, a4, 0'),0x4000bfb7:('l32i.n','a6, a4, 4'),
        0x4000bfb9:('or','a5, a3, a2'),0x4000bfbc:('xor','a5, a5, a2'),
        0x4000bfbf:('s32i.n','a5, a4, 0'),0x4000bfc1:('and','a5, a5, a6'),
        0x4000bfc4:('wsr.intenable','a5')}
    if any(decoded[p][1:]!=(op,args) for p,(op,args) in expected.items()):
        raise ValueError('Native mask-only interrupt transition differs')
    if decoded[0x40000450][1:]!=('movi','a0, 0') or decoded[0x40000453][1:]!=('wsr.intenable','a0'):
        raise ValueError('Reset does not disable peripheral interrupts')
    return selected,{'rom_sha256':sha(path),'native_layout_source_sha256':sha(source/'native-startup/components/heap/port/esp32/memory_layout.c'),
        'physical':physical,'initialized_payloads':copies,'rom_sram_sections':sections,'rom_sram_objects':objects,
        'both_cpu_stacks_and_cache_arenas_counted':True,'physical_initial_enabled':0,
        'only_reached_enable_writer_is_mask_only':True,'prefix_sha256':sha(previous),
        'basis':'Normal successful cold-SPI vendor startup ABI: pre-heap storage is static/on-stack, plus declared image loads. Includes dormant BT and APP arenas conservatively. All declared ROM SRAM objects, reset destinations and CPU stack bounds fit compiled physical pools. This is a capacity upper bound, not a dirty-byte or arbitrary-memory-corruption proof.'}


def audit(root):
    from audit_esp32_allocated_reservations import audit as native_audit,freertos_bookkeeping_history
    from run_esp32_tm_ram_lifetimes import EVENT,POOL
    protocol=load(root/'registry/esp32_allocated_lifecycle_v1.json');rom=rom_model(root,protocol)
    spans,proof=envelope(root,protocol,rom);boot=boot_image(root);spec=protocol['images'][0]
    cfg=native_configuration(root,spec)
    if spec['os']!='FreeRTOS' or 'CONFIG_FREERTOS_UNICORE=y' not in cfg:
        raise ValueError('This certificate is for the bound single-core IDF image')
    current=image(root,spec['source']);native=native_audit(root)
    if current['padding_bytes']+union(rom['fixed'])!=native['fixed_reservations_outside_static_bytes']:
        raise ValueError('Native fixed capacity convention differs')
    source=root/spec['source'];folder=root/spec['capture'];capture=load(folder/'campaign.json')
    if capture['board_mac']!=MAC or capture['independent_resets']!=5:raise ValueError('Wrong retained native cohort')
    bounds={'rom_first_image_load':union(spans,boot['loaded']),
        'loader_and_loaded_application':union(spans,boot['resident'],current['loaded']),
        'application_entry_before_heap':union(spans,current['resident'])}
    runs=[]
    for i in range(1,6):
        lines=[r['line'] for r in read_raw_capture(folder/'captures',i)]
        cold_boot(lines,boot['loaded'],boot['entry'])
        if any(a<0x3ffae018 and 0x3ffae010<b for a,b in boot['loaded']):
            raise ValueError('Loaded image could overwrite ROM console slots')
        events=[tuple(map(int,m.groups())) for s in lines if (m:=EVENT.fullmatch(s))]
        pools=[tuple(map(int,m.groups())) for s in lines if (m:=POOL.fullmatch(s))]
        deferred=native['native_scope']['startup_stack_handoff_region']
        if not inside([(deferred['start'],deferred['start']+deferred['size'])],rom['temporary'][0][0],rom['temporary'][0][1]):
            raise ValueError('Native handoff does not retain the inherited ROM working area')
        history=freertos_bookkeeping_history(events,pools,deferred['start'],current['static_sections_bytes'])
        point=max(history,key=lambda p:p['accounted_bytes'])
        peak=point['accounted_bytes']+current['padding_bytes']+union(rom['fixed'])
        phases=dict(bounds,native_ownership_ledger=peak)
        certificate=reached_peak(phases,{'native_allocation_event':peak})
        runs.append({'reset':i,'phase_upper_bounds':phases,'coincident_native_witness_bytes':peak,
            'witness_event_cursor':point['event_cursor'],'witness_software_and_bookkeeping_bytes':point['accounted_bytes'],
            'certificate':certificate,'raw_sha256':sha(folder/'captures'/('reset%d.raw'%i))})
    qualified=all(r['certificate']['complete'] for r in runs)
    return {'audit':'pass','os':'FreeRTOS','board_mac':MAC,'metric':'peak allocated RAM occupancy','unit':'bytes',
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),'source':spec['source'],'capture':spec['capture'],
        'elf_sha256':current['elf_sha256'],'bin_sha256':current['bin_sha256'],'coarse_rom_arena_spans':spans,
        'coarse_rom_arena_union_bytes':union(spans),'coarse_rom_capacity_proof':proof,
        'native_handoff_source_scope':native['native_scope'],'runs':runs,'retained_independent_resets':5,
        'complete_declared_lifecycle':qualified,'whole_lifecycle_peak_allocated_occupancy_bytes':
            [r['certificate']['peak_bytes'] for r in runs] if qualified else None,
        'ranking_eligible':False,'observer_included':True,'actual_stack_use_measured_by_this_audit':False,
        'new_benchmark_samples':0,'new_model_calls':0,'new_readonly_rom_campaigns':1,
        'scope':'Physical-union allocation capacity from normal POWERON_RESET/SPI boot through third original message report. Coarse ROM capacity dominates arbitrary occupancy inside the admitted ROM ABI arenas; a coincident native witness dominates all early bounds. Includes observer, image padding, native bookkeeping, active startup reservation and fixed ROM/cache capacities. Not an uninstrumented OS score, exact live bytes or instruction-exact stack use.',
        'remaining':['Zephyr/NuttX lifecycle qualification and matched native-ranking admission remain separate.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Replay real evidence on leon without overwriting retained reports')
    result=audit(ROOT)
    with args.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('coarse_rom_capacity_proof','native_handoff_source_scope','runs')},indent=2))
