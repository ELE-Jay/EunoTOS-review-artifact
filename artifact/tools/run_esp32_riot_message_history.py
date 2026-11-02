#!/usr/bin/env python3
"""Capture/replay original RIOT message heap history; whole-lifecycle RAM remains separate."""
import argparse
from datetime import datetime,timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal
import struct

from run_esp32_followup import Board,sha

ROOT=Path(__file__).resolve().parents[1]
MAC='34:98:7a:a2:85:28'
IMAGES=('application.elf','application.bin','bootloader.bin','partitions.bin')


def fields(line):
    return {k:int(v) if re.fullmatch(r'-?\d+',v) else v for k,v in
        (s.split('=',1) for s in line.split() if '=' in s)}


def build_proof(folder):
    from build_esp32_riot_message_history import source
    from audit_esp32_resources import audit_elf_image,static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    from elftools.elf.elffile import ELFFile
    record=json.loads((folder/'build.json').read_text())
    if record['status']!='build_pass_not_measured' or record['returncode'] or record['board_resets']:
        raise ValueError('Not an unmeasured complete RIOT message observer build')
    for name,digest in record['files'].items():
        path=folder/name
        if not path.resolve().is_relative_to(folder.resolve()) or sha(path)!=digest:
            raise ValueError('RIOT message observer build binding differs: '+name)
    paired=record.get('paired_vendor_bootloader',False)
    if paired:
        from audit_esp32_allocated_lifecycle import BOOT,boot_image
        parent=ROOT/'artifacts/reports'/record['native_application_source']
        if not parent.resolve().is_relative_to((ROOT/'artifacts/reports').resolve()) or \
                sha(parent/'build.json')!=record['native_application_manifest_sha256']:
            raise ValueError('Paired loader application parent differs')
        original=build_proof(parent)
        if original.get('paired_vendor_bootloader') or any(sha(folder/n)!=sha(parent/n) for n in
                ('application.elf','application.bin','partitions.bin','objdump.txt','config')):
            raise ValueError('Paired loader changed the original measured application')
        boot_image(ROOT)
        if sha(folder/'bootloader.bin')!=sha(ROOT/BOOT/'bootloader.bin'):
            raise ValueError('Paired bootloader differs from its source-bound measurement image')
    reference=ROOT/'artifacts/reports/esp32-riot-gcc13-legacy-v1'
    if record['reference_build_sha256']!=sha(reference/'build.json') or \
            (folder/'application-source/census.c').read_text()!=source():
        raise ValueError('Native observation implementation/reference differs')
    for name in ('main.c','port.c','test.c','tm_override.h','riot_tm_baseline.inc'):
        if (folder/'application-source'/name).read_bytes()!=(reference/'source'/name).read_bytes():
            raise ValueError('Original task or native port changed: '+name)
    audit_elf_image(folder/'application.elf',folder/'application.bin')
    machine=calls(folder,required=[('tm_message_processing_thread_report','__wrap_tm_thread_sleep'),
        ('__wrap_tm_thread_sleep','tm_thread_sleep'),('__wrap_main','main'),
        ('kernel_init','__wrap_thread_create'),('__wrap_thread_create','thread_create'),
        ('__wrap___malloc_unlock','__malloc_unlock'),('__wrap___malloc_unlock','observe'),
        ('observe','_mallinfo_r'),('_mallinfo_r','__wrap___malloc_unlock'),
        ('_malloc_r','__wrap___malloc_unlock'),('_free_r','__wrap___malloc_unlock'),
        ('_realloc_r','_malloc_r'),('_realloc_r','_free_r'),('__wrap__sbrk_r','_sbrk_r')],
        require_iram=False,disassembly_name='objdump.txt')
    native_threads=[]
    for path in (reference/'application.elf',folder/'application.elf'):
        with path.open('rb') as f:
            elf=ELFFile(f);layouts=set()
            for unit in elf.get_dwarf_info().iter_CUs():
                for die in unit.iter_DIEs():
                    if die.tag!='DW_TAG_typedef' or not die.attributes.get('DW_AT_name') or \
                            die.attributes['DW_AT_name'].value!=b'thread_t':
                        continue
                    body=die.get_DIE_from_attribute('DW_AT_type')
                    size=body.attributes.get('DW_AT_byte_size')
                    offsets=[d.attributes['DW_AT_data_member_location'].value for d in body.iter_children()
                        if d.tag=='DW_TAG_member' and d.attributes.get('DW_AT_name') and
                        d.attributes['DW_AT_name'].value==b'rq_entry' and 'DW_AT_data_member_location' in d.attributes]
                    if size and len(offsets)==1: layouts.add((size.value,offsets[0]))
            if len(layouts)!=1: raise ValueError('Native thread ABI is absent or inconsistent across compile units')
            native_threads.append(layouts.pop())
    if native_threads[0]!=native_threads[1]:
        raise ValueError('Message observer changed the original native thread ABI')
    with (folder/'application.elf').open('rb') as f:
        elf=ELFFile(f);symbols=elf.get_section_by_name('.symtab')
        layout_symbol=symbols.get_symbol_by_name('bench_r_layout')[0]
        section=elf.get_section(layout_symbol['st_shndx'])
        offset=layout_symbol['st_value']-section['sh_addr']
        layout=list(struct.unpack('<11I',section.data()[offset:offset+44]))
        if layout_symbol['st_size']!=44 or layout!=[native_threads[0][0],2,native_threads[0][1],3,0,8,12,8,96,40,32]:
            raise ValueError('Native task/Newlib accounting layout changed')
        regions=[]
        for suffix in ('','1','2','3'):
            start=symbols.get_symbol_by_name('_sheap'+suffix)[0]['st_value']
            end=symbols.get_symbol_by_name('_eheap'+suffix)[0]['st_value']
            if end<start: raise ValueError('Invalid native heap extent')
            regions.append((start,end))
        if not symbols.get_symbol_by_name('__malloc_free_list'):
            raise ValueError('Native free-list root missing')
    return {'audit':'pass','build_manifest_sha256':sha(folder/'build.json'),'native_regions':regions,
        'thread_bytes':layout[0],'native_layout':layout,'baseline_thread_abi':native_threads[0],
        **({'paired_vendor_bootloader':True} if paired else {}),
        'machine_calls':machine,**static_footprint(folder/'application.elf'),
        'scope':'Native heap history only; whole physical RAM still needs loader/ROM/reservation union',
        'ranking_eligible':False}


def read_run(folder,index,proof):
    from run_esp32_followup import read_raw_capture
    from audit_esp32_tm_basic import audit as original_message
    rows=read_raw_capture(folder,index)
    lines=[r['line'] for r in rows]
    if lines.count('RIOT_MESSAGE_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=0')!=1 or \
            sum(s.startswith('rst:') for s in lines)!=1:
        raise ValueError('Native clock/boot boundary differs')
    values=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM endpoint=')]
    layouts=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM layout ')]
    regions=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM region ')]
    threads=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM thread ')]
    phases=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM phase ')]
    phase_regions=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM phase_region ')]
    ends=[fields(s) for s in lines if s.startswith('RIOT_MESSAGE_RAM END ')]
    if len(values)!=1 or len(ends)!=1 or len(regions)!=4:
        raise ValueError('Incomplete original message allocation endpoint')
    if layouts!=[{'index':i,'value':v} for i,v in enumerate(proof['native_layout'])]:
        raise ValueError('Runtime native task/Newlib layout differs from its ELF')
    v,end=values[0],ends[0]
    if v['endpoint']!='third-original-report' or v['invalid'] or end['invalid'] or \
            end['threads']!=len(threads) or end['native_threads']!=len(threads) or \
            not 0<v['unlocks']<=v['observations'] or not v['sbrks']:
        raise ValueError('Invalid native allocator/task observations')
    for i,(region,bounds) in enumerate(zip(regions,proof['native_regions'])):
        if region['index']!=i or (region['start'],region['end'])!=tuple(bounds) or \
                not region['start']<=region['top']<=region['end'] or \
                not 0<=region['peak_committed']<=region['end']-region['start']:
            raise ValueError('Native committed region differs from actual ELF')
    committed=sum(r['top']-r['start'] for r in regions)
    peak_committed=sum(r['peak_committed'] for r in regions)
    if v['occupied']!=committed-v['free_bytes']+8*v['free_nodes'] or \
            v['peak']!=peak_committed-v['peak_free_bytes']+8*v['peak_free_nodes'] or \
            not 0<v['occupied']<=v['peak'] or v['free_bytes']>committed or v['peak_free_bytes']>peak_committed:
        raise ValueError('Free-block metadata or peak witness accounting differs')
    if len(phases)!=2 or len(phase_regions)!=8 or [p['index'] for p in phases]!=[0,1] or \
            max(p['occupied_peak'] for p in phases)!=v['peak'] or \
            sum(p['observations'] for p in phases)!=v['observations']:
        raise ValueError('Pre-thread/native-thread allocation phases are incomplete')
    for i,p in enumerate(phases):
        group=phase_regions[4*i:4*i+4]
        if [(r['phase'],r['index']) for r in group]!=[(i,j) for j in range(4)] or any(
                not 0<=r['committed']<=b-a for r,(a,b) in zip(group,proof['native_regions'])) or \
                p['occupied_peak']!=sum(r['committed'] for r in group)-p['free_bytes']+8*p['free_nodes'] or \
                p['observations'] and not (0x3ff80000<=p['sp']<0x40000000 and p['vector']%1024==0):
            raise ValueError('Phase peak lacks its coincident region/stack/vector witness')
    if len({t['pid'] for t in threads})!=len(threads) or any(not t['present'] or
            t['tcb']!=(t['stack']+t['capacity']-proof['thread_bytes'])&~3 or
            t['hwm_measured'] and not 0<=t['spare']<=t['capacity']-proof['thread_bytes'] for t in threads):
        raise ValueError('Native embedded task/stack bounds differ')
    result=original_message(folder/('reset%d.jsonl'%index),'RIOT','message_processing')
    return {'audit':'pass','original_message':result,'heap_final_bytes':v['occupied'],
        'heap_peak_bytes':v['peak'],'peak_committed':regions,'threads':threads,
        'phase_peaks':phases,'phase_regions':phase_regions,
        'whole_allocated_ram_peak_bytes':None,'ranking_eligible':False}


def collect(root,source,output,port,resets):
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace'):
        raise ValueError('Capture only on leon')
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    proof=build_proof(source)
    with (root/'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        build=output/'build';build.mkdir()
        for name in IMAGES: shutil.copyfile(source/name,build/name)
        for path,name in ((Path(__file__),'runner.py'),(ROOT/'tools/run_esp32_followup.py','board-helper.py'),
            (ROOT/'tools/capture_esp32_guarded_uart.py','capture_esp32_guarded_uart.py'),
            (root/'capture_esp32_uart.py','capture_esp32_uart.py')):
            shutil.copyfile(path,output/name)
        (output/'build-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
        (output/'plan.json').write_text(json.dumps({'resets':resets,'seconds':110,'board_mac':MAC,
            'build_manifest_sha256':sha(source/'build.json'),'whole_ram_score_pending':True},indent=2)+'\n')
        board=Board(root,output,MAC,port)
        state={'status':'incomplete','kind':'riot-original-message-heap-history','board_mac':MAC,
            'independent_resets':0,'started_utc':datetime.now(timezone.utc).isoformat(),
            'original_flash_restored':False,'old_cohort_modified':False,'energy_measured':False,
            'external_independent_replication':False,'ranking_eligible':False}
        try:
            board.backup()
            try:
                captures=output/'captures';captures.mkdir()
                pairs=board.flash(captures,build)
                for i in range(1,resets+1):
                    board.capture(captures,i,110,stop='RIOT_MESSAGE_RAM END',
                        capture_script=output/'capture_esp32_guarded_uart.py',monotonic_clock=True)
                    board.verify(pairs,captures/('verify-run%d.log'%i))
                    value=read_run(captures,i,proof)
                    state['independent_resets']=i
                    print('RIOT_MESSAGE_RAM',i,value['heap_peak_bytes'],flush=True)
                board.verify(pairs,captures/'verify-after.log')
                state['status']='collection_complete_audit_pending'
            finally:
                board.restore();state['original_flash_restored']=True
        except BaseException as error:
            state['error']=repr(error);raise
        finally:
            state['completed_utc']=datetime.now(timezone.utc).isoformat()
            state['files']={p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}
            (output/'campaign.json').write_text(json.dumps(state,indent=2)+'\n')


def audit(source,output):
    from audit_esp32_followup import envelope,verified,independent_captures
    state=envelope(output);proof=build_proof(source);plan=json.loads((output/'plan.json').read_text())
    if state['kind']!='riot-original-message-heap-history' or state['board_mac']!=MAC or \
            plan['resets']!=state['independent_resets'] or plan['build_manifest_sha256']!=sha(source/'build.json') or \
            json.loads(json.dumps(proof))!=json.loads((output/'build-proof.json').read_text()):
        raise ValueError('Original RIOT message history campaign differs')
    if any(sha(source/n)!=sha(output/'build'/n) for n in IMAGES):
        raise ValueError('Collected original observer image differs')
    verified(output/'captures',output/'build',MAC)
    independent_captures(output/'captures',range(1,plan['resets']+1))
    rows=[read_run(output/'captures',i,proof) for i in range(1,plan['resets']+1)]
    return {'audit':'pass','independent_resets':len(rows),'runs':rows,'original_flash_restored':True,
        'whole_allocated_ram_peak_bytes':None,'ranking_eligible':False,
        'scope':'Native heap/stack evidence, not yet a whole-lifecycle physical RAM result'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('build-audit','collect','audit'))
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    parser.add_argument('--port',default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    parser.add_argument('--resets',type=int,choices=(1,5),default=5)
    args=parser.parse_args()
    if args.mode=='collect':
        collect(args.root,args.source,args.output,args.port,args.resets)
    else:
        result=build_proof(args.source) if args.mode=='build-audit' else audit(args.source,args.output)
        if args.mode=='audit':
            (args.output/'audit.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
