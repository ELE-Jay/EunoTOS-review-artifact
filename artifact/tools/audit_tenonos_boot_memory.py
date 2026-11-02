#!/usr/bin/env python3
"""Replay early SP states and native memory descriptors without target access."""
import argparse
import gzip
import json
from pathlib import Path
import struct
import shutil
import subprocess

from audit_tenonos_memory_lifecycle import require, linked_image
from audit_tenonos_native_threads import replay as native_replay
from tenonos_kvm_reproduce import sha, original_results


def merged(spans):
    result=[]
    for a,b in sorted(spans):
        require(0<=a<b<=1<<64,'Invalid physical interval')
        if result and a<=result[-1][1]:result[-1][1]=max(result[-1][1],b)
        else:result.append([a,b])
    return result


def extent(spans):return sum(b-a for a,b in merged(spans))


def bootinfo(raw,native_stride=None):
    require(len(raw)>=80 and struct.unpack_from('<I',raw)[0]==0xb007b0b0 and raw[4]==1,'Invalid bootinfo header')
    capacity,count=struct.unpack_from('<II',raw,72)
    require(0<count<=capacity and capacity<=4096,'Invalid bootinfo capacity/count')
    if native_stride is None:
        require((len(raw)-80)%capacity==0,'Invalid bootinfo capacity/count')
        stride=(len(raw)-80)//capacity
    else:stride=native_stride
    require(stride in (48,80),'Unknown native descriptor ABI')
    require((len(raw)-80)%stride==0 and count<=(len(raw)-80)//stride,'Native descriptor count exceeds actual storage')
    physical_capacity=(len(raw)-80)//stride
    rows=[]
    for i in range(count):
        a,v,off,n,pages,kind,flags=struct.unpack_from('<5QHH',raw,80+i*stride)
        require(a%4096==0 and off<4096 and 0<pages and off+n<=pages*4096 and
                kind in (0,1,2,4,8,16,32,64),'Invalid native memory descriptor')
        rows.append(dict(address=a,virtual=v,offset=off,bytes=n,pages=pages,kind=kind,flags=flags))
    return {'dtb':struct.unpack_from('<Q',raw,56)[0],'capacity':capacity,'physical_capacity':physical_capacity,
            'advertised_capacity_matches_storage':capacity==physical_capacity,'stride':stride,'regions':rows}


def partition(rows,low=0x40000000,high=0x48000000):
    cuts=sorted({low,high}|{max(low,min(high,x)) for r in rows for x in
                           (r['address'],r['address']+r['pages']*4096)})
    cells=[]
    for a,b in zip(cuts,cuts[1:]):
        owners=[i for i,r in enumerate(rows) if r['address']<=a<b<=r['address']+r['pages']*4096]
        require(len(owners)<=1,'Overlapping native page ownership')
        cells.append({'start':a,'end':b,'bytes':b-a,'descriptor':owners[0] if owners else None,
                      'kind':rows[owners[0]]['kind'] if owners else None})
    return {'guest_ram_bytes':high-low,'descriptor_free_capacity_not_runtime_free_bytes':sum(c['bytes'] for c in cells if c['kind']==1),
        'kernel_reserved_page_bytes':sum(c['bytes'] for c in cells if c['kind']==4),
        'dtb_reserved_page_bytes':sum(c['bytes'] for c in cells if c['kind']==32),
        'commandline_reserved_page_bytes':sum(c['bytes'] for c in cells if c['kind']==16),
        'unclassified_page_bytes':sum(c['bytes'] for c in cells if c['kind'] is None),'segments':cells}


def expected_sp(word,sp,pc,setup):
    if pc==setup['stack_switch_address']:
        require(word==0x9100035f,'Boot SP switch instruction differs')
        return setup['boot_stack_top']
    # ADD/SUB (immediate), with SP as both source and destination, no flags.
    if word&0x1f000000==0x11000000 and word&0x200003ff==0x3ff:
        n=((word>>10)&0xfff)*(4096 if word&(1<<22) else 1)
        return sp-n if word&(1<<30) else sp+n
    if word&0x3a000000==0x28000000 and (word>>5)&31==31 and (word>>23)&3 in (1,3):
        n=(word>>15)&127;n=n-128 if n&64 else n
        opc=word>>30
        scale=(4<<opc) if word&(1<<26) else {0:4,2:8}.get(opc)
        require(scale is not None,'Unsupported writeback pair size')
        return sp+n*scale
    if word&0x3b200000==0x38000000 and (word>>5)&31==31 and (word>>10)&3 in (1,3):
        n=(word>>12)&511
        return sp+(n-512 if n&256 else n)
    return sp


def selected_instruction(word):
    immediate=word&0x1f000000==0x11000000 and word&0x2000001f==31
    extended=word&0x1fe00000==0x0b200000 and word&0x2000001f==31
    pair=word&0x3a000000==0x28000000 and (word>>5)&31==31 and (word>>23)&3 in (1,3)
    single=word&0x3b200000==0x38000000 and (word>>5)&31==31 and (word>>10)&3 in (1,3)
    system=word&0xfff00000==0xd5100000 or word&0xfff8f01f==0xd500401f or word==0xd69f03e0
    return immediate or extended or pair or single or system


def code_boundaries(elf,all_code=False):
    table=elf.get_section_by_name('.symtab');sites={};mapped=0
    for index,section in enumerate(elf.iter_sections()):
        if not section['sh_flags']&4:continue
        begin=section['sh_addr'];end=begin+section['sh_size'];data=section.data()
        markers=sorted(set((s['st_value'],s.name[:2]) for s in table.iter_symbols()
            if s['st_shndx']==index and s.name.startswith(('$x','$d'))))
        require(markers and markers[0][0]==begin,'Executable section lacks complete code/data mappings')
        for (start,kind),finish in zip(markers,[m[0] for m in markers[1:]]+[end]):
            if kind!='$x':continue
            require(start%4==finish%4==0,'Unaligned AArch64 code mapping')
            for pc in range(start,finish,4):
                word=int.from_bytes(data[pc-begin:pc-begin+4],'little');mapped+=1
                if all_code or selected_instruction(word):sites[pc]=word
    return sites,mapped


def boundary_sp(word,before,pc,setup):
    sp=before['sp'];gprs=before['gprs']
    def register(n):return sp if n==31 else gprs[n]
    if word&0x1f000000==0x11000000 and word&0x2000001f==31:
        n=((word>>10)&0xfff)*(4096 if word&(1<<22) else 1)
        base=register((word>>5)&31)
        value=base-n if word&(1<<30) else base+n
        return value & ((1<<(64 if word>>31 else 32))-1)
    if word&0x1fe00000==0x0b200000 and word&0x2000001f==31:
        option=(word>>13)&7;bits=(8,16,32,64)[option&3]
        n=gprs[(word>>16)&31]&((1<<bits)-1)
        if option&4 and n&(1<<(bits-1)):n-=1<<bits
        n<<=(word>>10)&7;base=register((word>>5)&31)
        return (base-n if word&(1<<30) else base+n)&((1<<(64 if word>>31 else 32))-1)
    return expected_sp(word,sp,pc,setup)


def neutral_instruction(pc,word,setup,selected):
    if pc in selected or pc in setup['trace_stages'].values():return False
    return not (direct_targets(pc,word)!={pc+4} or word&0xff000000==0xd4000000 or
                word in (0xd503205f,0xd503207f))


def neutral_region(start,words,selected,stages,max_nodes=4096,max_frontier=4,leaf=None,bounded=None):
    pending=[start];nodes=set();frontier=set()
    while pending:
        pc=pending.pop()
        if pc in nodes or pc in frontier:continue
        word=words.get(pc)
        targets=direct_targets(pc,word) if word is not None else None
        bounded_entry=(bounded and word is not None and word&0xfc000000==0x94000000 and targets=={bounded['entry']})
        if leaf and word is not None and word&0xfc000000==0x94000000 and targets=={leaf['entry']}:
            targets={pc+4}
        if (bounded_entry or word is None or pc in selected or pc in stages or targets is None or
                word&0xff000000==0xd4000000 or word in (0xd503205f,0xd503207f)):
            frontier.add(pc)
        else:nodes.add(pc);pending.extend(targets)
        if len(nodes)>max_nodes or len(frontier)>max_frontier:return None
    if start in frontier or not frontier or len(nodes)<2:return None
    return sorted(nodes),sorted(frontier)


def observed_code(blocks,code):
    observed={}
    for block in blocks:
        raw=bytes.fromhex(block['hex']);begin=block['start']
        require(raw and len(raw)%4==0,'Invalid region code bytes')
        for i in range(0,len(raw),4):
            require(begin+i not in observed and code(begin+i)==raw[i:i+4],'Region code differs or overlaps')
            observed[begin+i]=int.from_bytes(raw[i:i+4],'little')
    return observed


def required_gprs(pc,word,setup):
    needed=set()
    if word&0x1f000000==0x11000000 and word&0x2000001f==31:
        n=(word>>5)&31
        if n!=31:needed.add(n)
    if word&0x1fe00000==0x0b200000 and word&0x2000001f==31:
        needed.update(n for n in ((word>>5)&31,(word>>16)&31) if n!=31)
    if word&0xfffffc1f in (0xd61f0000,0xd63f0000,0xd65f0000):needed.add((word>>5)&31)
    bound=setup.get('reviewed_tag_frame')
    if bound and word&0xfc000000==0x94000000 and direct_targets(pc,word)=={bound['entry']}:
        needed.add(bound['output_pointer_argument'])
    return needed


def hardware_trace(path,setup,code,expected,all_code,prefix_only=False):
    declared={int(k):v for k,v in setup['code_words'].items()}
    code_span=(min(declared),max(declared)+4)
    require({s['pc']:s['word'] for s in setup['boundary_sites']}==expected and
        all(all_code.get(pc)==word for pc,word in declared.items()) and set(expected)<=set(declared),
        'Hardware code/site inventory differs')
    previous=None;count=0;executed=0;blocks=0;regions=0;bounded_calls=0;minimum=setup['boot_stack_top'];known=False;switches=0;unmasked=0
    with gzip.open(path,'rt') as stream:
        for line in stream:
            row=json.loads(line);before,after=row['before'],row['after'];pc=before['pc'];n=row.get('span_instructions',0)
            require(row['i']==count and len(before['gprs'])==31,'Invalid hardware trace record')
            if setup.get('required_registers_only'):
                require(pc in all_code and all(isinstance(before['gprs'][n],int) for n in required_gprs(pc,all_code[pc],setup)),
                        'Required SP/control/pointer register was not observed')
            if previous:require(before['pc']==previous['pc'] and before['sp']==previous['sp'],'Hardware trace has a PC/SP gap')
            else:require(pc==setup['entry_address'],'Wrong hardware trace entry')
            if 'bounded_call' in row:
                from tenonos_boot_memory import bounded_call_guard
                proof=setup.get('reviewed_tag_frame');raw=bytes.fromhex(row['instruction_hex'])
                require(proof is not None and n==0 and len(raw)==4 and code(pc)==raw and
                    int.from_bytes(raw,'little')&0xfc000000==0x94000000 and
                    direct_targets(pc,int.from_bytes(raw,'little'))=={proof['entry']} and
                    row['bounded_call']=={'entry':proof['entry'],'minimum_sp_before':minimum},'Different bounded native call')
                require(bounded_call_guard(before,minimum,known,proof,code_span),
                        'Bounded call can refresh the peak or alias its saved frame/code')
                observed=observed_code(row['bounded_code'],code)
                needed={**{int(p):w for p,w in proof['nodes'].items()},
                        **{int(p):w for p,w in setup['reviewed_leaf']['nodes'].items()}}
                require(observed==needed,'Incomplete bounded function code')
                require(after['pc']==pc+4 and after['sp']==before['sp'] and
                        before['cpsr']&0x3ff==after['cpsr']&0x3ff,'Unexpected bounded-call return')
                bounded_calls+=1
            elif 'region' in row:
                require(setup.get('hardware_neutral_regions') and n==0,'Unexpected control-flow fast-forward')
                region=neutral_region(pc,declared,expected,set(setup['trace_stages'].values()),leaf=setup.get('reviewed_leaf'),bounded=setup.get('reviewed_tag_frame'))
                require(region is not None and row['region']=={'nodes':region[0],'frontier':region[1]},
                        'Fast-forward region is not closed at every SP/system/control boundary')
                observed=observed_code(row['region_code'],code)
                needed=set(region[0]);leaf=setup.get('reviewed_leaf')
                if leaf and any(declared[p]&0xfc000000==0x94000000 and direct_targets(p,declared[p])=={leaf['entry']} for p in region[0]):
                    needed.update(map(int,leaf['nodes']))
                require(set(observed)==needed and all(observed[p]==declared[p] for p in observed),
                        'Incomplete observed region code')
                require(after['pc'] in region[1] and before['sp']==after['sp'] and
                        before['cpsr']&0x1c0==0x1c0 and before['cpsr']&0x3ff==after['cpsr']&0x3ff,
                        'Region stopped outside frontier or changed SP/system state')
                regions+=1
            else:
                raw=bytes.fromhex(row['instruction_hex'])
                require(1<=n<=64 and len(raw)==n*4 and all(code(pc+4*i)==raw[4*i:4*i+4] for i in range(n)),
                        'Hardware capture changed original instruction bytes')
            if 'region' not in row and 'bounded_call' not in row and n>1:
                require(all(neutral_instruction(pc+4*i,int.from_bytes(raw[4*i:4*i+4],'little'),setup,expected)
                            for i in range(n)) and after['pc']==pc+4*n and after['sp']==before['sp'],
                        'Fast-forwarded block changes SP or control/system state')
                blocks+=1
            elif 'region' not in row and 'bounded_call' not in row:
                word=int.from_bytes(raw,'little')
                require(after['sp']==boundary_sp(word,before,pc,setup),'Hardware single-step SP model differs')
                targets=direct_targets(pc,word)
                if targets is None:
                    require(after['pc']==before['gprs'][(word>>5)&31],'Indirect hardware branch target differs')
                else:require(after['pc'] in targets,'Hardware single-step control flow differs')
            if pc==setup['stack_switch_address']:known=True;switches+=1
            if known:
                for sp in ((after['sp'],) if pc==setup['stack_switch_address'] else (before['sp'],after['sp'])):
                    require(setup['boot_stack_top']-setup['boot_stack_bytes']<=sp<=setup['boot_stack_top'],
                            'Hardware trace left known boot-stack reservation')
                    minimum=min(minimum,sp)
            if before['cpsr']&0x1c0!=0x1c0 or after['cpsr']&0x1c0!=0x1c0:unmasked+=1
            previous=after;count+=1;executed+=n
    require(count>0 and switches==1,'No initialized boot stack in hardware trace')
    if not prefix_only:
        terminal=setup['registration_state']
        require(terminal['pc']==previous['pc']==setup['registration_address'] and terminal['sp']==previous['sp'],
                'Incomplete hardware preallocator interval')
    result={'hardware_trace_records':count,'executed_instructions_replayed':executed if not (regions or bounded_calls) else None,'neutral_blocks':blocks,
        'boot_stack_reservation_bytes':setup['boot_stack_bytes'],
        'maximum_observed_boot_sp_span_bytes':setup['boot_stack_top']-minimum,
        'unmasked_boundary_states':unmasked,'all_linked_sp_system_sites':len(expected),
        'mapped_words_not_used_for_disassembler_fast_forward':len(all_code.keys()-declared.keys()),
        'full_code_inventory_and_sp_and_control_transitions_checked':True,'software_breakpoint_instruction_patches':0}
    if regions:result['closed_sp_neutral_control_flow_regions']=regions
    if bounded_calls:result['peak_preserving_bounded_calls']=bounded_calls
    if prefix_only:
        result['coverage']='partial-prefix-only'
        result['last_observed_pc']=previous['pc']
        result['partial_boot_sp_span_lower_bound_bytes']=result.pop('maximum_observed_boot_sp_span_bytes')
    return result


def boundary_trace(path,setup,code,expected):
    declared={s['pc']:s['word'] for s in setup['boundary_sites']}
    require(declared==expected,'Disassembler/ELF-mapping SP/system site inventory differs')
    allowed=set(declared)|set(setup['trace_stages'].values())|{setup['entry_address']}
    previous=None;count=0;known=False;minimum=setup['boot_stack_top'];switches=0;unmasked=0
    prefix=setup.get('prefix_instructions',0)
    with gzip.open(path,'rt') as stream:
        for line in stream:
            row=json.loads(line);before,after=row['before'],row['after'];pc=before['pc']
            require(row['i']==count and (count<prefix or pc in allowed) and len(before['gprs'])==31,
                    'Incomplete/unknown boundary sequence')
            if count==0:require(pc==setup['entry_address'],'Wrong boundary trace entry')
            if previous:
                require(before['sp']==previous['sp'],'SP changed between selected boundaries')
                if count<prefix:require(pc==previous['pc'],'Single-step prefix skipped an instruction')
            if count==prefix and prefix:
                require(previous['pc']==setup['enable_breakpoints_at'],'Wrong end of debug-reset prefix')
            raw=bytes.fromhex(row['instruction_hex']);word=int.from_bytes(raw,'little')
            require(len(raw)==4 and code(pc)==raw,'Boundary instruction differs from ELF')
            require(after['sp']==boundary_sp(word,before,pc,setup),'SP boundary instruction/model differs')
            if count<prefix:
                targets=direct_targets(pc,word)
                if targets is not None:require(after['pc'] in targets,'Invalid prefix control-flow edge')
            if pc==setup['stack_switch_address']:known=True;switches+=1
            if known:
                for sp in ((after['sp'],) if pc==setup['stack_switch_address'] else (before['sp'],after['sp'])):
                    require(setup['boot_stack_top']-setup['boot_stack_bytes']<=sp<=setup['boot_stack_top'],
                            'Boundary trace left boot-stack reservation')
                    minimum=min(minimum,sp)
            if before['cpsr']&0xc0!=0xc0 or after['cpsr']&0xc0!=0xc0:unmasked+=1
            previous=after;count+=1
    terminal=setup['registration_state']
    require(count>0 and switches==1 and terminal['sp']==previous['sp'] and terminal['pc']==setup['registration_address'],
            'Incomplete SP-boundary interval')
    return {'selected_boundary_observations':count,'boot_stack_reservation_bytes':setup['boot_stack_bytes'],
        'maximum_observed_boot_sp_span_bytes':setup['boot_stack_top']-minimum,
        'interrupt_unmasked_boundary_states':unmasked,'all_linked_sp_system_sites':len(declared),
        'single_step_prefix_instructions':prefix,
        'instruction_site_inventory_and_sp_transitions_checked':True}


def direct_targets(pc,word):
    if word&0x7c000000==0x14000000:
        n=word&0x3ffffff
        return {pc+4*(n-(1<<26) if n&(1<<25) else n)}
    if word&0xff000010==0x54000000 or word&0x7e000000==0x34000000:
        n=(word>>5)&0x7ffff
        return {pc+4,pc+4*(n-(1<<19) if n&(1<<18) else n)}
    if word&0x7e000000==0x36000000:
        n=(word>>5)&0x3fff
        return {pc+4,pc+4*(n-(1<<14) if n&(1<<13) else n)}
    if word&0xfffffc1f in (0xd61f0000,0xd63f0000,0xd65f0000):return None
    return {pc+4}


def trace(path,setup,code):
    previous=None;count=0;known=False;minimum=setup['boot_stack_top'];switches=0;indirect=0;unmasked=0
    def edge(a,b):
        nonlocal indirect
        targets=direct_targets(a['pc'],int.from_bytes(bytes.fromhex(a['instruction_hex']),'little'))
        if targets is None:indirect+=1
        else:require(b['pc'] in targets,'Instruction trace skips a direct control-flow edge')
        require(b['sp']==expected_sp(int.from_bytes(bytes.fromhex(a['instruction_hex']),'little'),a['sp'],a['pc'],setup),
                'Unaccounted SP transition in the early instruction trace')
    with gzip.open(path,'rt') as stream:
        for line in stream:
            row=json.loads(line)
            require(set(row)=={'i','pc','sp','pstate','instruction_hex'} and row['i']==count,'Incomplete instruction sequence')
            if count==0:require(row['pc']==setup['entry_address'],'Wrong early trace entry')
            raw=bytes.fromhex(row['instruction_hex'])
            require(len(raw)==4 and code(row['pc'])==raw,'Stepped instruction differs from retained ELF')
            if previous:
                edge(previous,row)
                if previous['pc']==setup['stack_switch_address']:known=True;switches+=1
            if known:
                require(setup['boot_stack_top']-setup['boot_stack_bytes']<=row['sp']<=setup['boot_stack_top'],
                        'Early execution left the known boot-stack reservation')
                minimum=min(minimum,row['sp'])
            if not row['pstate']&0x80:unmasked+=1
            previous=row;count+=1
    terminal=setup['registration_state'];edge(previous,{'pc':terminal['pc'],'sp':terminal['sp']})
    require(count>0 and switches==1 and terminal['pc']==setup['registration_address'],'Incomplete preallocator interval')
    minimum=min(minimum,terminal['sp'])
    return {'instructions':count,'boot_stack_reservation_bytes':setup['boot_stack_bytes'],
        'maximum_observed_boot_sp_span_bytes':setup['boot_stack_top']-minimum,
        'interrupt_unmasked_states':unmasked,'indirect_edges_without_separate_target_register':indirect,
        'code_and_direct_edges_and_sp_transitions_checked':True}


def audit(root,folder,registry=None):
    from elftools.elf.elffile import ELFFile
    plan=json.loads((folder/'protocol.json').read_text());state=json.loads((folder/'campaign.json').read_text())
    hardware=plan.get('trace_mode') in ('hardware-neutral-blocks','hardware-neutral-regions','hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers')
    stage_only=plan.get('trace_mode')=='hardware-stage-census'
    boundary_mode=hardware or plan.get('trace_mode')=='all-sp-and-system-boundaries'
    registry=registry or ('tenonos_boot_memory_rpi4_v11.json' if plan.get('id')=='tenon-rpi4-preallocator-memory-v11' else
              'tenonos_boot_memory_rpi4_v10.json' if plan.get('trace_mode')=='hardware-peak-required-registers' else
              'tenonos_boot_memory_rpi4_v9.json' if plan.get('trace_mode')=='hardware-peak-bounded-calls' else
              'tenonos_boot_memory_rpi4_v8.json' if plan.get('trace_mode')=='hardware-neutral-leaf-regions' else
              'tenonos_boot_memory_rpi4_v7.json' if plan.get('trace_mode')=='hardware-neutral-regions' else
              'tenonos_boot_memory_rpi4_v6.json' if plan.get('bootinfo_repair') else
              'tenonos_boot_memory_rpi4_v5.json' if stage_only else
              'tenonos_boot_memory_rpi4_v4.json' if hardware else
              'tenonos_boot_memory_rpi4_v3.json' if plan.get('debug_reset_prefix') else
              'tenonos_boot_memory_rpi4_v2.json' if boundary_mode else 'tenonos_boot_memory_rpi4_v1.json')
    require(plan==json.loads((root/'registry'/registry).read_text()) and
        state['status']=='complete' and state['completed']==plan['profiles'] and state['governor_restored'] and
        state['protocol_sha256']==sha(folder/'protocol.json') and state['new_builds']==state['model_calls']==0,
        'Incomplete or different preallocator campaign')
    require(state['host_initial']['serial']==['10000000c1b4a936'] and
        state['host_after_restore']['governor']==state['host_initial']['governor'] and
        not state['host_after_restore']['qemu_running'],'Pi identity/restore differs')
    for n,h in state['source_sha256'].items():require(sha(folder/'helpers'/n)==h,'Frozen debug recorder changed')
    reference=root/plan['reference_campaign']
    require(sha(reference/'audit.json')==state['reference_audit_sha256'],'Prior image audit changed')
    result=[]
    repaired=None
    if plan.get('bootinfo_repair'):
        from tenonos_bootinfo_abi import audit as repair_audit
        repaired=repair_audit(root,root/plan['bootinfo_repair'])
        require(sha(root/plan['bootinfo_repair']/'repair.json')==state['repair_sha256'],'Prepared repair changed')
    for name in plan['profiles']:
        p=folder/name;old=reference/name/'build'
        identities=(('linked.elf','linked-symbols.elf'),('input.config','.config'))
        require(all(sha(p/n)==sha(old/m) for n,m in identities),'Existing config/ELF changed')
        image=root/plan['bootinfo_repair']/name/'runtime-image' if repaired else old/'runtime-image'
        require(sha(p/'runtime-image')==sha(image),'Measured image changed')
        transfer=json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode']==0 and
            all(sha(p/n)==h for n,h in transfer['files'].items()),'Returned raw debug evidence changed')
        debug=json.loads((p/'debug-result.json').read_text());setup=json.loads((p/'gdb-input.json').read_text())
        require(debug['pass'] and debug['inferior_function_calls']==0 and
            [s['stage'] for s in debug['stages']]==plan['snapshots'],'Debug stage coverage differs')
        setup['registration_state']=next(s for s in debug['stages'] if s['stage']=='__wrap_uk_alloc_register')
        setup['prefix_instructions']=debug.get('prefix_instructions',0)
        config=(p/'input.config').read_text()
        require('CONFIG_UKPLAT_LCPU_MAXCOUNT=1\n' in config and 'CONFIG_STATIC_PGTABLE=y\n' in config and
                '# CONFIG_PAGING is not set\n' in config,'Different memory mapping configuration')
        with (p/'linked.elf').open('rb') as stream:
            elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
            if plan.get('trace_mode') in ('hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers'):
                from tenonos_boot_memory import reviewed_offset_leaf,reviewed_tag_frame
                symbol=symbols.get_symbol_by_name('fdt_offset_ptr')[0]
                argv=[shutil.which('aarch64-linux-gnu-objdump') or 'objdump','-d']
                if plan['trace_mode']=='hardware-neutral-leaf-regions':
                    argv.extend(['--start-address='+hex(symbol['st_value']),'--stop-address='+hex(symbol['st_value']+symbol['st_size'])])
                raw=subprocess.check_output([*argv,str(p/'linked.elf')]).decode()
                native=reviewed_offset_leaf({'fdt_offset_ptr':(symbol['st_value'],symbol['st_size'])},raw,
                    {s['pc'] for s in setup['boundary_sites']})
                require(native==setup['reviewed_leaf'],'Reviewed leaf differs from independently decoded ELF')
                if plan['trace_mode'] in ('hardware-peak-bounded-calls','hardware-peak-required-registers'):
                    tag=symbols.get_symbol_by_name('fdt_next_tag')[0]
                    bound=reviewed_tag_frame({'fdt_next_tag':(tag['st_value'],tag['st_size'])},raw,
                        {s['pc'] for s in setup['boundary_sites']},native)
                    require(bound==setup['reviewed_tag_frame'],'Fixed-frame proof differs from decoded ELF')
                require(bool(setup.get('required_registers_only'))==(plan['trace_mode']=='hardware-peak-required-registers'),
                        'Register-observation method differs')
            for symbol,key in (('_libkvmplat_entry','entry_address'),('lcpu_bootstack','boot_stack_top'),
                ('bi_bootinfo_sec','bootinfo_address'),('__wrap_uk_alloc_register','registration_address')):
                require(symbols.get_symbol_by_name(symbol)[0]['st_value']==setup[key],'Debug address differs from ELF')
            segments=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_memsz']]
            loaded=[[s['p_paddr'],s['p_paddr']+s['p_memsz']] for s in segments]
            readonly=[[s['p_paddr'],s['p_paddr']+s['p_memsz']] for s in segments if not s['p_flags']&2]
            writable=[[s['p_paddr'],s['p_paddr']+s['p_memsz']] for s in segments if s['p_flags']&2]
            executable=[(s['p_vaddr'],s.data()) for s in segments if s['p_flags']&1]
            def code(pc):
                matches=[data[pc-a:pc-a+4] for a,data in executable if a<=pc<pc+4<=a+len(data)]
                require(len(matches)==1,'Trace PC outside loaded executable code');return matches[0]
            if stage_only:
                require(debug.get('stage_only') and debug['instructions']==0 and setup['stage_only'],'Census acquired continuous trace status')
                stepped={'instructions':0,'stage_snapshots':6,'continuous_sp_established':False,
                         'maximum_observed_boot_sp_span_bytes':None}
            elif boundary_mode:
                expected,mapped=code_boundaries(elf)
                if hardware:
                    all_code,_=code_boundaries(elf,all_code=True)
                    stepped=hardware_trace(p/'early-boundaries.jsonl.gz',setup,code,expected,all_code)
                else:stepped=boundary_trace(p/'early-boundaries.jsonl.gz',setup,code,expected)
                stepped['mapped_code_instructions']=mapped
            else:stepped=trace(p/'early-instructions.jsonl.gz',setup,code)
        require(stepped.get('instructions',stepped.get('selected_boundary_observations',stepped.get('hardware_trace_records')))==debug['instructions'],
                'Raw instruction/boundary count differs')
        stages=[]
        for s in debug['stages']:
            stride=80 if 'CONFIG_UKPLAT_MEMRNAME=y\n' in config else 48
            decoded=bootinfo((p/(s['stage']+'.bootinfo')).read_bytes(),native_stride=stride);regions=decoded['regions']
            if repaired:require(decoded['advertised_capacity_matches_storage'],'Runtime capacity repair not established')
            coverage=partition(regions)
            kernel=merged((r['address'],r['address']+r['pages']*4096) for r in regions if r['kind']==4)
            require(all(any(lo<=a<b<=hi for lo,hi in kernel) for a,b in loaded),'Loaded RAM is not owned by kernel descriptors')
            logical=[(max(0x40000000,r['address']+r['offset']),
                      min(0x48000000,r['address']+r['offset']+r['bytes'])) for r in regions if r['kind']!=1]
            stages.append({'stage':s['stage'],'native_logical_resource_bytes':extent((a,b) for a,b in logical if b>a),
                           'advertised_capacity':decoded['capacity'],'physical_capacity':decoded['physical_capacity'],
                           'advertised_capacity_matches_storage':decoded['advertised_capacity_matches_storage'],
                           'descriptors':regions,'partition':coverage})
        dtb=(p/'devicetree.dtb').read_bytes();magic,n=struct.unpack_from('>II',dtb)
        require(magic==0xd00dfeed and n==len(dtb)==debug['stages'][0]['dtb_bytes'],'Captured FDT size differs')
        guest=json.loads((p/'guest.json').read_text())
        require(guest['status']=='complete' and sha(p/'guest.stdout')==guest['stdout_sha256'] and
            sha(p/'guest.stderr')==guest['stderr_sha256'] and
            original_results((p/'guest.stdout').read_bytes(),(p/'guest.stderr').read_bytes(),guest['returncode'])['original_output_complete'],
            'Original guest incomplete after debug capture')
        lifecycle=native_replay((p/'guest.stdout').read_text())
        require(lifecycle==json.loads((p/'native-lifecycle.json').read_text()),'Fresh native lifecycle differs')
        for label in ('before','after'):
            h=json.loads((p/('host-'+label+'.json')).read_text())
            require(not h['qemu_running'] and h['governor']=='performance' and h['throttled']=='throttled=0x0','Host controls differ')
        result.append({'profile':name,'trace':stepped,'loaded_ram_bytes':extent(loaded),
            'readonly_executable_ram_bytes':extent(readonly),'writable_ram_bytes':extent(writable),
            'dtb_blob_bytes':len(dtb),'stages':stages,'native_thread_generations':lifecycle['native_thread_generations'],
            'linked_image':linked_image(p/'linked.elf',p/'runtime-image','CONFIG_LIBTLSF=y\n' in config)})
    return {'audit':'pass','profiles':result,'fresh_diagnostic_guests':3,'new_builds':0,'model_calls':0,
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'scope':plan['scope'],
        'reference_audit_sha256':state['reference_audit_sha256'],'campaign_sha256':sha(folder/'campaign.json')}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not a.output.exists(),'Use leon and a new output')
    result=audit(root,a.folder.resolve());a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='profiles'}))
