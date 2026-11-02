#!/usr/bin/env python3
"""Capture/replay matched GCC13 original-message native allocations, before ROM union."""
import argparse
import json
from pathlib import Path
import re
import signal
import struct

from run_esp32_followup import sha
from run_esp32_rhino_message_history import collect,replay,fields
from build_esp32_rhino_gcc13_message_history import sources,REFERENCE,FILES,patched

ROOT=Path(__file__).resolve().parents[1]


def build_proof(source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import audit_elf_image,static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    manifest=json.loads((source/'build.json').read_text());reference=ROOT/REFERENCE
    if manifest['status']!='build_pass_not_measured' or manifest['board_resets'] or \
            manifest['reference_build_sha256']!=sha(reference/'build.json') or manifest['bootstrap_readiness_gate']:
        raise ValueError('Wrong native GCC13 observation build')
    for name,digest in manifest['files'].items():
        path=source/name
        if not path.resolve().is_relative_to(source.resolve()) or sha(path)!=digest:
            raise ValueError('Changed GCC13 message build artifact: '+name)
    paired=manifest.get('paired_vendor_bootloader',False)
    if paired:
        from audit_esp32_allocated_lifecycle import BOOT,boot_image
        from prepare_esp32_riot_capacity import RHINO_BOOT
        parent=ROOT/'artifacts/reports'/manifest['native_application_source']
        if not parent.resolve().is_relative_to((ROOT/'artifacts/reports').resolve()) or \
                sha(parent/'build.json')!=manifest['native_application_manifest_sha256']:
            raise ValueError('Paired loader parent differs')
        boot_source=manifest.get('paired_bootloader_source',BOOT)
        if boot_source not in (BOOT,RHINO_BOOT):raise ValueError('Undeclared native boot profile')
        original=build_proof(parent);boot_image(ROOT,boot_source)
        if original.get('paired_vendor_bootloader') or any(sha(source/n)!=sha(parent/n) for n in
                ('application.elf','application.bin','partitions.bin','config','disassembly.txt')) or \
                sha(source/'bootloader.bin')!=sha(ROOT/boot_source/'bootloader.bin'):
            raise ValueError('Paired loader changed the original observed application or boot image')
    app=source/'application-source';core,message=sources()
    if (app/'census.c').read_text()!=message or (app/'rhino_lifetimes_core.c').read_text()!=core:
        raise ValueError('Native observation implementation changed')
    for name in FILES:
        if (app/name).read_bytes()!=(reference/name).read_bytes():
            raise ValueError('Original GCC13 workload/port changed: '+name)
    for name in ('config','sdkconfig.h','k_config.h','bootloader.bin','partitions.bin'):
        observed=source/('original-native-bootloader.bin' if paired and name=='bootloader.bin' else name)
        if observed.read_bytes()!=(reference/name).read_bytes():
            raise ValueError('Original native configuration changed: '+name)
    if (source/'native-source/kernel/rhino/k_mm.c').read_bytes()!=patched((source/'original-k_mm.c').read_bytes()):
        raise ValueError('Native allocator hook locations differ')
    if '13.2.0' not in (source/'compiler.txt').read_text():
        raise ValueError('Not the matched GCC13 compiler')
    with (source/'application.elf').open('rb') as f:
        elf=ELFFile(f);symbols=elf.get_section_by_name('.symtab')
        symbol=symbols.get_symbol_by_name('bench_h_layout')[0];section=elf.get_section(symbol['st_shndx'])
        pos=symbol['st_value']-section['sh_addr'];layout=list(struct.unpack('<18I',section.data()[pos:pos+72]))
        if symbol['st_size']!=72 or layout[2]!=16 or layout[5:7]!=[32,8192] or layout[-1]!=4:
            raise ValueError('Native allocator accounting ABI differs')
        units=[u.get_top_DIE().attributes for u in elf.get_dwarf_info().iter_CUs()]
        for name in ('main.c','port.c','test.c','census.c'):
            selected=[u for u in units if u.get('DW_AT_name') and
                Path(u['DW_AT_name'].value.decode()).name==name and
                'app/example/thread_metric' in u['DW_AT_name'].value.decode()]
            if len(selected)!=1 or '13.2.0' not in selected[0]['DW_AT_producer'].value.decode():
                raise ValueError('Actual source translation unit differs: '+name)
    audit_elf_image(source/'application.elf',source/'application.bin')
    machine=calls(source,required=[('k_mm_init','bench_h_heap_ready'),('k_mm_alloc','bench_h_observe'),
        ('k_mm_free','bench_h_observe'),('k_mm_realloc','bench_h_observe'),
        ('__wrap_tm_main','tm_main'),('tm_message_processing_thread_report','__wrap_tm_thread_sleep'),
        ('__wrap_krhino_mm_alloc','krhino_mm_alloc'),('message_native_free','krhino_mm_free')],require_iram=False)
    return {'audit':'pass','build_manifest_sha256':sha(source/'build.json'),'native_layout':layout,
        **({'paired_vendor_bootloader':True} if paired else {}),
        'machine_calls':machine,**static_footprint(source/'application.elf'),
        'compiler':'GCC13 / original native Newlib/SDK','whole_lifecycle_ram_pending':True,'ranking_eligible':False}


def observations(lines):
    rows=[fields(s) for s in lines if s.startswith('RHINO_MESSAGE_RAM ')]
    final=[r for r in rows if 'events' in r]
    phases=[r for r in rows if 'occupied_peak' in r]
    layout=[r for r in rows if 'value' in r]
    events=[r for r in rows if 'event' in r];tasks=[r for r in rows if 'name' in r]
    blocks=[r for r in rows if 'block' in r];regions=[r for r in rows if 'start' in r]
    boundaries=[r for r in rows if 'boundary' in r]
    if len(final)!=1 or len(phases)!=2 or len(regions)!=2 or len(layout)!=18:
        raise ValueError('Incomplete native allocation/phase inventory')
    f=final[0]
    if f['invalid'] or f['events']!=len(events) or not 0<len(events)<128 or f['tasks']!=len(tasks) or \
            f['blocks']!=len(blocks) or f['active']!=sum(t['present'] for t in tasks) or \
            [p['index'] for p in phases]!=[0,1] or [e['event'] for e in events]!=list(range(len(events))) or \
            [b['boundary'] for b in boundaries]!=list(range(4)) or f['original_reports']!=3 or \
            f['peak']!=max(e['occupied'] for e in events) or f['peak']!=max(p['occupied_peak'] for p in phases):
        raise ValueError('Invalid/overflowed/incomplete native allocation history')
    values=[r['value'] for r in layout]
    if [r['index'] for r in layout]!=list(range(18)) or values[2]!=16 or values[5:7]!=[32,8192] or values[-1]!=4:
        raise ValueError('Runtime native accounting ABI differs')
    for p in phases:
        if not p['observations'] or p['occupied_peak']!=p['base']+16*p['free_headers']+4*p['free_cells'] or \
                not 0<=p['free_cells']<=256 or p['free_headers']<1 or not 0x3ff80000<=p['sp']<0x40000000 or p['vector']%1024:
            raise ValueError('Free-header/fixed-cell metadata or phase witness differs')
    live={b['pointer']:b['usable'] for b in blocks}
    if len(live)!=len(blocks) or any(not any(r['start']<=p-16<p+n<=r['start']+r['bytes'] for r in regions)
            for p,n in live.items()):
        raise ValueError('Native live block escapes its actual region')
    for t in tasks:
        if t['present'] and any(t[k] for k in ('deleted','stack_freed','tcb_freed')) or \
                t['hwm_measured'] and not 0<=t['spare']<=t['reserved']:
            raise ValueError('Native task lifetime/watermark differs')
        if t['present'] and t['dynamic']==values[15] and (live.get(t['stack'])!=t['stack_usable'] or
                live.get(t['tcb'])!=t['tcb_usable'] or t['stack_usable']<t['reserved']):
            raise ValueError('Heap-backed task lacks its actual retained allocations')
    tm=[t for t in tasks if t['name']=='tm']
    if len(tm)!=2 or any(t['reserved']!=4096 or not t['present'] or t['dynamic']==values[15] for t in tm):
        raise ValueError('Original static message task stacks differ')
    return {'audit':'pass','events':len(events),'heap_peak_bytes':f['peak'],'heap_final_bytes':f['occupied'],
        'legacy_heap_final_bytes':f['legacy'],'phase_peaks':phases,'runtime_layout':values,
        'tasks':tasks,'live_blocks':blocks,'heap_regions':regions,'boundaries':boundaries,
        'whole_lifecycle_peak_allocated_occupancy_bytes':None,'ranking_eligible':False}


def read_run(folder,index):
    from run_esp32_followup import read_raw_capture
    from audit_esp32_alios_tm import check_conditions
    from audit_esp32_tm_basic import audit
    rows=read_raw_capture(folder,index);check_conditions(rows);lines=[r['line'] for r in rows]
    if lines.count('RHINO_MESSAGE_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100 retained_free_metadata=1')!=1 or \
            sum(s.startswith('RHINO_MESSAGE_RAM END ') for s in lines)!=1:
        raise ValueError('Native clock/observation endpoint differs')
    compat=[s for s in lines if s.startswith('BOOT_COMPAT ')]
    if compat and compat!=['BOOT_COMPAT rtc_wdt_enabled=0']:
        raise ValueError('Legacy RTC watchdog handoff failed')
    return {**observations(lines),'original_message':audit(folder/('reset%d.jsonl'%index),'AliOS-Rhino','message_processing')}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('build-audit','collect','audit'))
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path)
    parser.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    parser.add_argument('--port',default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    parser.add_argument('--resets',type=int,choices=(1,5),default=5);args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace'):parser.error('Evidence work remains on leon')
    if args.mode=='collect':
        signal.signal(signal.SIGHUP,signal.SIG_IGN)
        collect(args.root,args.source,args.output,args.port,args.resets,build_check=build_proof,run_check=read_run,runner=__file__)
    else:
        result=build_proof(args.source) if args.mode=='build-audit' else replay(
            args.source,args.output,build_check=build_proof,run_check=read_run)
        if args.mode=='audit':
            with (args.output/'audit.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
        print(json.dumps(result,indent=2))
