#!/usr/bin/env python3
"""Inspect native allocator structures; metadata reservations are not live RAM."""
import argparse
import json
from pathlib import Path

from audit_tenonos_memory_lifecycle import require,linked_image
from tenonos_exit_memory import layout as observer_layout,members,unqualified,decode,verify_prefix
from tenonos_kvm_reproduce import sha,original_results


def layout(path,tlsf):
    from elftools.elf.elffile import ELFFile
    value=observer_layout(path,tlsf);types={}
    wanted=('tlsf_t','bhdr_t','area_info_t') if tlsf else ('uk_bbpalloc','uk_bbpalloc_memr')
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        for cu in elf.get_dwarf_info().iter_CUs():
            attr=cu.get_top_DIE().attributes.get('DW_AT_name')
            if not attr or Path(attr.value.decode()).name!=('tlsf.c' if tlsf else 'bbuddy.c'):continue
            for die in cu.iter_DIEs():
                name=die.attributes.get('DW_AT_name')
                if name and name.value.decode() in wanted and die.tag in ('DW_TAG_typedef','DW_TAG_structure_type'):
                    kind=unqualified(die)
                    types[name.value.decode()]={'bytes':kind.attributes['DW_AT_byte_size'].value,
                        'fields':{n:{k:v for k,v in f.items() if k!='die'} for n,f in members(kind).items()}}
    require(set(types)==set(wanted),'Native metadata DWARF missing')
    value['metadata']=types
    return value


def field(raw,kind,name):
    f=kind['fields'][name];require(f['bytes'] in (4,8),'Unsupported native scalar field')
    return int.from_bytes(raw[f['offset']:f['offset']+f['bytes']],'little')


def live(rows):
    active={}
    for r in rows:
        if r['op'] in (1,3) and r['p']:
            require(r['p'] not in active,'Live native address reused');active[r['p']]=r['n']
        elif r['op'] in (2,4) and r['p']:
            require(r['p'] in active,'Unmatched native free');del active[r['p']]
    return active


def capacity_trace(rows,tlsf):
    require(rows and rows[0]['op']==5,'Missing native allocator registration')
    previous=baseline=rows[0]['current'];active={};capacity=0;maximum=-1;target=None
    for r in rows[1:]:
        op,p,n=r['op'],r['p'],r['n'];delta=r['current']-previous;previous=r['current']
        if op==6:
            require(r['q']==0 and delta>=0 and (tlsf or delta==0),'Unexplained area-accounting change');baseline+=delta
        elif op in (1,3) and p:
            require(op==(1 if tlsf else 3) and n>0 and p not in active,'Different native allocation interface')
            if tlsf:
                size=delta;require(size>=n+16 and size%16==0,'Invalid TLSF allocated extent');start=p-16
            else:
                require(n%4096==0 and p%4096==0 and delta==n,'Buddy request counter differs')
                size=4096*(1<<((n//4096-1).bit_length()));start=p
            require(all(start+size<=a or a+b<=start for b,_,a in active.values()),'Physical block overlap')
            active[p]=(size,n,start);capacity+=size
        elif op in (2,4) and p:
            require(p in active and op==(2 if tlsf else 4),'Unmatched native capacity release')
            size,requested,_=active.pop(p)
            require(delta==-(size if tlsf else requested) and (tlsf or n==requested),'Native free extent/counter differs')
            capacity-=size
        else:require(delta==0,'Native current changed without a leaf event')
        require(r['current']==baseline+sum(v[0] if tlsf else v[1] for v in active.values()),'Native counter replay differs')
        if r['phase']<=6 and capacity>maximum:maximum=capacity;target=dict(r)
    require(target is not None and target['op'] in (1,3) and target['phase'] in range(1,7),'Peak outside original suite')
    return {'allocated_block_peak_bytes':maximum,'target_event':target,'termination_block_capacity_bytes':capacity,
            'termination_live_allocations':len(active),'scope':'Native allocated-block capacity, original phases 0--6; not whole live RAM'}


def peak_target(elf_path,reference):
    from elftools.elf.elffile import ELFFile
    raw=(reference/'termination.events').read_bytes()
    tlsf='CONFIG_LIBTLSF=y\n' in (reference/'input.config').read_text()
    result=capacity_trace(decode(raw,len(raw)//56),tlsf);found=[];owner=''
    with elf_path.open('rb') as stream:
        for symbol in ELFFile(stream).get_section_by_name('.symtab').iter_symbols():
            if symbol['st_info']['type']=='STT_FILE':owner=symbol.name
            elif owner=='iotos_memory.c' and symbol.name=='record':found.append(symbol['st_value'])
    require(len(found)==1,'Observer record entry missing or ambiguous')
    return {**result,'record_address':found[0],'reference_events_sha256':sha(reference/'termination.events')}


def verify_snapshot(p,s,compiled):
    meta=compiled['metadata'];a=s['allocator'];prefix=s['stage'];tlsf=compiled['allocator']=='tlsf'
    raw=(p/(prefix+'.allocator')).read_bytes();interface=compiled['allocator_bytes'];types=meta['tlsf_t' if tlsf else 'uk_bbpalloc']
    require(len(raw)==interface+types['bytes'],'Incomplete native allocator structure')
    count=s['event_count'];events=(p/(prefix+'.events')).read_bytes()
    require(len(events)==count*56,'Incomplete contemporaneous native events');rows=decode(events,count) if count else []
    active=live(rows);head=field(raw[interface:],types,'area_head' if tlsf else 'memr_head');seen=set();busy={};reserved=0;blocks=0
    for i,item in enumerate(s['regions']):
        require(head==item['address'] and head not in seen,'Broken native region chain');seen.add(head)
        kind=meta['area_info_t' if tlsf else 'uk_bbpalloc_memr'];entry=(p/(prefix+'.region%d'%i)).read_bytes()
        require(len(entry)==kind['bytes'],'Incomplete native region structure');head=field(entry,kind,'next')
        if tlsf:
            header=meta['bhdr_t']['fields']['ptr']['offset'];end=field(entry,kind,'end');cursor=item['address']-header
            for j,b in enumerate(item['blocks']):
                require(b['address']==cursor,'Native TLSF block chain gap')
                data=(p/(prefix+'.region%d.block%d'%(i,j))).read_bytes();require(len(data)==header,'Incomplete TLSF header')
                word=field(data,meta['bhdr_t'],'size');size=word&0xfffffff8;free=bool(word&1)
                if cursor==end:
                    require(size==0 and not free and j==len(item['blocks'])-1,'Invalid native sentinel');cursor+=header
                else:
                    require(cursor<end and size>0,'Invalid native TLSF block')
                    if j==0:require(not free and size>=kind['bytes'],'Missing TLSF area descriptor')
                    elif not free:busy[cursor+header]=size
                    cursor+=header+size
                blocks+=1
            require(cursor==end+header,'TLSF area does not reach sentinel')
        else:
            first=field(entry,kind,'first_page');n=field(entry,kind,'nr_pages');length=field(entry,kind,'mm_alloc_bitmap_size')
            pointer=field(entry,kind,'mm_alloc_bitmap');bitmap=(p/(prefix+'.region%d.bitmap'%i)).read_bytes()
            require(pointer==item['address']+kind['bytes'] and len(bitmap)==length and first==pointer+length and
                    first%4096==0 and n*4096>0 and n<=length*8,'Native bitmap extent differs')
            reserved+=first-item['address']
            for j in range(n):
                if bitmap[j//8]&(1<<(j%8)):busy[first+j*4096]=4096
    require(head==0,'Incomplete native region list')
    if tlsf:
        require(set(busy)==set(active) and all(busy[p]>=n for p,n in active.items()),'TLSF busy blocks differ from live leaf events')
        allocation_bytes=sum(n+meta['bhdr_t']['fields']['ptr']['offset'] for n in busy.values())
        reserved=None
    else:
        require(all(p%4096==0 and n>0 and n%4096==0 for p,n in active.items()),'Invalid native page request')
        # bbuddy maps 2**order pages, but counts the original num_pages request.
        pages={q:4096 for p,n in active.items() for q in range(p,p+4096*(1<<((n//4096-1).bit_length())),4096)}
        require(pages==busy,'Native bitmap and rounded leaf ownership differ')
        allocation_bytes=len(busy)*4096;reserved+=((interface+types['bytes']+4095)//4096)*4096
    counters={n:int.from_bytes(raw[f['offset']:f['offset']+f['bytes']],'little')
              for n,f in compiled.get('native_counters',{}).items()}
    if rows:require(rows[-1]['current']==counters['current'] and rows[-1]['peak']==counters['peak'],
                    'Native event counters differ from contemporaneous allocator bytes')
    return {'stage':prefix,'regions':len(seen),'physical_blocks':blocks if tlsf else None,
            'live_leaf_allocations':len(active),'live_allocated_block_capacity_bytes':allocation_bytes,
            'live_leaf_requested_bytes':sum(active.values()),
            'allocator_interface_struct_bytes':interface,'allocator_private_struct_bytes':types['bytes'],
            'native_counters':counters,'buddy_metadata_reserved_bytes':reserved,'whole_live_ram_peak_bytes':None}


def audit(root,folder,registry=None):
    plan=json.loads((folder/'protocol.json').read_text());state=json.loads((folder/'campaign.json').read_text())
    peak_mode=plan.get('observer_mode')=='allocator-peak'
    registry=registry or ('tenonos_allocator_peak_rpi4_v2.json' if peak_mode else 'tenonos_allocator_metadata_rpi4_v1.json')
    require(plan==json.loads((root/'registry'/registry).read_text()) and
            state['status']=='complete' and state['completed']==plan['profiles'] and state['governor_restored'] and
            state['protocol_sha256']==sha(folder/'protocol.json') and state['new_builds']==state['model_calls']==0,
            'Incomplete metadata campaign')
    reference=root/plan['reference_campaign'];repair=root/plan['bootinfo_repair']
    require(sha(reference/'audit.json')==state['reference_audit_sha256'] and sha(repair/'repair.json')==state['repair_sha256'],
            'Reference evidence changed')
    for n,h in state['source_sha256'].items():require(sha(folder/'helpers'/n)==h,'Frozen recorder changed')
    results=[]
    for name in plan['profiles']:
        p=folder/name;old=reference/name/'build';tlsf='CONFIG_LIBTLSF=y\n' in (p/'input.config').read_text()
        require(sha(p/'linked.elf')==sha(old/'linked-symbols.elf') and sha(p/'input.config')==sha(old/'.config') and
                sha(p/'runtime-image')==sha(repair/name/'runtime-image'),'Image/config differs')
        transfer=json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode']==0 and all(sha(p/n)==h for n,h in transfer['files'].items()),
                'Transferred metadata changed')
        compiled=layout(p/'linked.elf',tlsf);require(compiled==json.loads((p/'exit-layout.json').read_text()),'Metadata layout differs')
        require(compiled==json.loads((p/'gdb-input.json').read_text())['exit_layout'],'GDB metadata layout differs')
        debug=json.loads((p/'debug-result.json').read_text());stages=debug['stages']
        require(debug['pass'] and [s['stage'] for s in stages]==plan['snapshots'] and debug['target_data_writes']==debug['target_code_writes']==debug['inferior_function_calls']==0,
                'Metadata stage/control differs')
        base_stages=[s for s in stages if s['stage']!='allocation-peak']
        expected=[compiled['functions'][key]['address'] for key in ('register','main','ukplat_terminate')]
        require([s['pc'] for s in base_stages]==expected and len({s['allocator'] for s in stages})==1 and
                stages[0]['event_count']==0,'Native stage/allocator identity differs')
        require((p/'termination.events').read_bytes().startswith((p/'main-enter.events').read_bytes()),'Event prefix changed')
        verify_prefix((p/'guest.stdout').read_text(),(p/'termination.events').read_bytes(),{'count':stages[-1]['event_count']})
        from audit_tenonos_native_threads import replay
        require(replay((p/'guest.stdout').read_text())==json.loads((p/'native-lifecycle.json').read_text()),'Native lifecycle differs')
        guest=json.loads((p/'guest.json').read_text())
        require(guest['status']=='complete' and original_results((p/'guest.stdout').read_bytes(),(p/'guest.stderr').read_bytes(),guest['returncode'])['original_output_complete'],
                'Original output incomplete')
        for label in ('before','after'):
            h=json.loads((p/('host-'+label+'.json')).read_text())
            require(h['serial']==['10000000c1b4a936'] and not h['qemu_running'] and h['governor']=='performance' and
                    h['throttled']=='throttled=0x0','Metadata host controls differ')
        snapshots=[verify_snapshot(p,s,compiled) for s in stages]
        result={'profile':name,'snapshots':snapshots,'linked_image':linked_image(p/'linked.elf',p/'runtime-image',tlsf)}
        if peak_mode:
            reference_capture=root/plan['peak_reference_campaign']
            require(state['peak_reference_audit_sha256']==sha(reference_capture/'audit.json'),'Peak reference audit changed')
            target=peak_target(p/'linked.elf',reference_capture/name)
            require(target==json.loads((p/'peak-target.json').read_text())==json.loads((p/'gdb-input.json').read_text())['peak_target'],
                    'Registered peak target differs')
            peak=next(s for s in stages if s['stage']=='allocation-peak');e=target['target_event']
            require(peak['event_count']==e['seq']+1 and debug['peak_entry_event']=={k:e[k] for k in ('seq','op','phase','p','q','n')} and
                    peak['pc']==debug['peak_record_return_pc'] and debug['peak_record_entry_pc']==target['record_address'],
                    'Peak did not follow the registered native event')
            search=[json.loads(line) for line in (p/'peak-search.jsonl').read_text().splitlines()]
            require(len(search)==debug['peak_record_entry_stops'] and search[-1]['entry']==debug['peak_entry_event'] and
                    search[-1]['return_pc']==peak['pc'] and search[-1]['after_count']==peak['event_count'] and
                    all(r['after_count']>r['entry']['seq'] for r in search) and
                    all(a['after_count']==b['entry']['seq'] for a,b in zip(search,search[1:])),
                    'Peak search did not advance across native calls')
            word=native_word(p/'linked.elf',peak['pc']-4);immediate=word&0x3ffffff
            if immediate&(1<<25):immediate-=1<<26
            require(word&0xfc000000==0x94000000 and peak['pc']-4+4*immediate==target['record_address'],
                    'Peak stop is not the native record return')
            peak_raw=(p/'allocation-peak.events').read_bytes()
            require((p/'termination.events').read_bytes().startswith(peak_raw),'Peak prefix differs from complete run')
            terminal=(p/'termination.events').read_bytes();rows=decode(terminal,len(terminal)//56)
            fresh=capacity_trace(rows,tlsf)
            checked=next(s for s in snapshots if s['stage']=='allocation-peak')
            require(rows[e['seq']]==e and fresh=={k:v for k,v in target.items() if k not in ('record_address','reference_events_sha256')} and
                    checked['live_allocated_block_capacity_bytes']==fresh['allocated_block_peak_bytes'],
                    'Peak census and complete fresh lifecycle differ')
            result['allocated_block_capacity_trace']=fresh
            result['peak_record_entry_stops']=debug['peak_record_entry_stops']
        results.append(result)
    require(state['host_initial']['serial']==['10000000c1b4a936'] and not state['host_after_restore']['qemu_running'] and
            state['host_after_restore']['governor']==state['host_initial']['governor'],'Host restore differs')
    return {'audit':'pass','profiles':results,'fresh_diagnostic_guests':3,'new_builds':0,'new_model_calls':0,
            'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'scope':plan['scope']}


def native_word(path,address):
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        for section in ELFFile(stream).iter_sections():
            if section['sh_type']!='SHT_NOBITS' and section['sh_addr']<=address<address+4<=section['sh_addr']+section['sh_size']:
                offset=address-section['sh_addr'];return int.from_bytes(section.data()[offset:offset+4],'little')
    raise ValueError('Native return call is not in linked ELF')


def paper_text(result):
    require(result['audit']=='pass' and result['fresh_diagnostic_guests']==3,'Metadata paper evidence incomplete')
    buddy=next(p for p in result['profiles'] if p['profile']=='accepted-buddy')['snapshots'][-1]
    require(buddy['stage']=='termination' and buddy['live_leaf_requested_bytes']==buddy['native_counters']['current'],
            'Buddy requested-byte scope differs')
    return ('A direct metadata census uses three additional fresh guests, one per configuration, with hardware execution stops '
        'at allocator registration, main entry and termination. Native TLSF block headers and buddy page bitmaps match all '
        'contemporaneous live leaf allocations. At termination the buddy counter reports '
        f"{buddy['native_counters']['current']:,}~B of requests, while the bitmap marks {buddy['live_allocated_block_capacity_bytes']:,}~B "
        'of allocated page capacity: the allocator rounds each request up to a power-of-two page block. Its control-page and '
        f"region-bitmap reservations occupy another {buddy['buddy_metadata_reserved_bytes']:,}~B outside the native counter. "
        'These snapshots resolve accounting differences, not a whole-lifetime live-RAM peak.')


def peak_paper_text(result):
    require(result['audit']=='pass' and result['fresh_diagnostic_guests']==3,'Peak census incomplete')
    profiles=result['profiles']
    require([p['profile'] for p in profiles]==['initial-tlsf','accepted-buddy','accepted-tlsf'],
            'Peak profile order differs')
    peaks=[p['allocated_block_capacity_trace']['allocated_block_peak_bytes'] for p in profiles]
    buddy=next(s for s in profiles[1]['snapshots'] if s['stage']=='allocation-peak')
    require(buddy['live_allocated_block_capacity_bytes']==peaks[1],'Peak narrative differs from census')
    return ('Three further fresh guests locate the first maximum allocated block capacity in the original six-test suite '
        'by replaying complete native allocation histories, then verify its headers or bitmap at the same event. '
        f'The peaks are {peaks[0]:,}, {peaks[1]:,} and {peaks[2]:,}~B for initial TLSF, accepted buddy and accepted TLSF. '
        f"Buddy's native request counter peaks at {buddy['native_counters']['peak']:,}~B, reversing its order relative to "
        'initial TLSF when compared with allocated block capacity. These values include allocated stacks once and '
        'exclude the separate finite-task validation. Allocator bookkeeping and other system reservations remain '
        'separate; this component census does not establish a whole-system allocated-occupancy peak.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();root=Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not args.output.exists(),'Use leon and a new output')
    result=audit(root,args.folder.resolve());args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
