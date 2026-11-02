#!/usr/bin/env python3
"""Close matched Rhino message allocation capacity, including initialization/handoff."""
import argparse
import json
from pathlib import Path
import re

from audit_esp32_allocated_lifecycle import boot_image,cold_boot,image,postload_witness,reached_peak,rom_model,union
from audit_esp32_active_rom_capacity import active_abi
from run_esp32_followup import read_raw_capture,sha
from run_esp32_rhino_gcc13_history import build_proof,read_run
from run_esp32_rhino_message_history import replay

ROOT=Path(__file__).resolve().parents[1]
SOURCE='artifacts/reports/esp32-rhino-common-boot-message-v2'
CAPTURE='artifacts/reports/esp32-rhino-common-boot-message-b1-v2'


def native_ownership(folder,proof,current):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_freertos_ram_lifetimes import calls
    native=folder/'native-source';mm=(folder/'original-k_mm.c').read_text()
    kernel=(native/'kernel/rhino/k_sys.c').read_text()
    port=(native/'platform/arch/xtensa/lx6/portasm.S').read_text()
    if not kernel.index('g_sys_stat = RHINO_RUNNING;')<kernel.index('cpu_first_task_start();') or \
            'l32i    sp,  a3, TOPOFSTACK_OFFS' not in port:
        raise ValueError('Native scheduler handoff no longer retires the inherited stack')
    init=mm[mm.index('kstat_t krhino_init_mm_head('):mm.index('kstat_t krhino_deinit_mm_head(')]
    if 'k_mm_alloc(pmmhead, RHINO_CONFIG_MM_TLF_BLK_SIZE + MM_ALIGN_UP(sizeof(mblk_pool_t)))' not in init or \
            'pmmhead = (k_mm_head *)addr;' not in init or len(re.findall(r'\bk_mm_alloc\(',init))!=1 or \
            re.search(r'\b(?:malloc|calloc|realloc)\s*\(',init):
        raise ValueError('Unobserved initialization has an additional allocation domain')
    head_text=(native/'kernel/rhino/include/k_mm.h').read_text()
    alignment=re.search(r'#define\s+MM_ALIGN_BIT\s+(\d+)',head_text)
    if not alignment or int(alignment[1])>4:
        raise ValueError('Native allocator alignment exceeds the initialization bound')
    for name in ('sdkconfig.h','k_config.h'):
        cfg=(folder/name).read_text()
        if any(re.search(r'#define\s+'+n+r'\s+1\b',cfg) for n in
                ('CONFIG_SPIRAM_SUPPORT','CONFIG_FREERTOS_SMP')):
            raise ValueError('Additional controller/memory/core allocation domain')
    sizes={};irq=None
    with (folder/'application.elf').open('rb') as f:
        elf=ELFFile(f);symbols=elf.get_section_by_name('.symtab')
        if any(symbols.get_symbol_by_name(n) for n in ('esp_bt_controller_init','esp_spiram_init')):
            raise ValueError('Additional initialized controller/memory service needs native ownership evidence')
        for cu in elf.get_dwarf_info().iter_CUs():
            for die in cu.iter_DIEs():
                attrs=die.attributes
                if die.tag!='DW_TAG_typedef' or not attrs.get('DW_AT_name'):continue
                name=attrs['DW_AT_name'].value.decode()
                if name in ('k_mm_head','mblk_pool_t','k_mm_region_info_t'):
                    size=die.get_DIE_from_attribute('DW_AT_type').attributes['DW_AT_byte_size'].value
                    sizes.setdefault(name,set()).add(size)
        if set(sizes)!= {'k_mm_head','mblk_pool_t','k_mm_region_info_t'} or any(len(v)!=1 for v in sizes.values()):
            raise ValueError('Actual initialization structure sizes are inconsistent')
        sizes={k:next(iter(v)) for k,v in sizes.items()}
        irq=[symbols.get_symbol_by_name(n)[0]['st_value'] for n in ('port_IntStack','port_IntStackTop')]
        if irq[1]<=irq[0] or union(current['resident'],[tuple(irq)])!=union(current['resident']):
            raise ValueError('Native interrupt stack is outside the resident image')
        dispatch=symbols.get_symbol_by_name('_frxt_dispatch')[0]
        text=(folder/'disassembly.txt').read_text()
        loads=[(int(pc,16),word) for pc,word in re.findall(
            r'^([0-9a-f]+):\s+([0-9a-f]{4}(?:[0-9a-f]{2})?)\s+l32i(?:\.n)?\s+a1, a3, 0$',text,re.M)
            if dispatch['st_value']<=int(pc,16)<dispatch['st_value']+48]
        if len(loads)!=1:raise ValueError('Native dispatcher has no unique task-stack load')
        pc,word=loads[0];section=elf.get_section(dispatch['st_shndx'])
        if section.data()[pc-section['sh_addr']:pc-section['sh_addr']+len(word)//2]!=bytes.fromhex(word)[::-1]:
            raise ValueError('Native task stack-load bytes differ')
    machine=calls(folder,required=[('krhino_start','cpu_first_task_start')],require_iram=False)
    # Conservative initialized metadata + the one fixed-pool backing allocation.
    # The allocator's temporary "allocated" flags while creating a free extent
    # do not turn that entire allocatable pool into a client allocation.
    init_bound=sizes['k_mm_head']+15+2*(sizes['k_mm_region_info_t']+15+3*16)+sizes['mblk_pool_t']+15+8192+16+30
    return {'initialization_structure_bytes':sizes,'initialization_heap_upper_bytes':init_bound,
        'native_irq_stack':irq,'scheduler_handoff_calls':machine,
        'native_source_sha256':{p.relative_to(native).as_posix():sha(p) for p in native.rglob('*') if p.is_file()},
        'initialized_free_pool_not_charged_as_a_client_allocation':True}


def audit(root):
    source=root/SOURCE;capture=root/CAPTURE
    proof=build_proof(source)
    observed=replay(source,capture,build_check=build_proof,run_check=read_run)
    if not proof.get('paired_vendor_bootloader') or observed['independent_resets']!=5:
        raise ValueError('Need five fresh paired-loader resets, not native-loader substitution')
    protocol=json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())
    rom=rom_model(root,protocol);_,active=active_abi(root,protocol)
    boot_source=json.loads((source/'build.json').read_text())['paired_bootloader_source']
    boot=boot_image(root,boot_source);current=image(root,SOURCE);native=native_ownership(source,proof,current)
    if not boot['proof'].get('legacy_rtc_wdt_handoff'):
        raise ValueError('Need the source-bound legacy watchdog handoff boot profile')
    rows=[]
    for i,run in enumerate(observed['runs'],1):
        lines=[r['line'] for r in read_raw_capture(capture/'captures',i)]
        cold_boot(lines,boot['loaded'],boot['entry']);postload_witness(lines)
        compat=[j for j,s in enumerate(lines) if s=='BOOT_COMPAT rtc_wdt_enabled=0']
        loaded=[j for j,s in enumerate(lines) if 'Loaded app from partition at offset' in s]
        if len(compat)!=1 or not loaded[0]<compat[0]<next(j for j,s in enumerate(lines) if s.startswith('BOOT_RAM phase=0 ')):
            raise ValueError('RTC watchdog disable readback lacks its post-load handoff witness')
        regions=[(r['start'],r['start']+r['bytes']) for r in run['heap_regions']]
        if union(regions)!=sum(b-a for a,b in regions) or union(regions,current['resident'])!=union(regions)+union(current['resident']):
            raise ValueError('Native regions overlap each other or the resident image')
        bounds={'first_stage':union(rom['workspace'],boot['loaded']),
            'loader':union(rom['workspace'],boot['resident'],current['loaded']),
            'native_entry':union(rom['workspace'],current['resident']),
            'allocator_initialization':union(rom['workspace'],current['resident'])+native['initialization_heap_upper_bytes']}
        witnesses={};parts=[]
        for phase,key,spans in zip(run['phase_peaks'],('pre_scheduler','native_tasks'),(rom['workspace'],rom['fixed'])):
            if union(regions,current['resident'],spans)!=union(regions)+union(current['resident'],spans):
                raise ValueError('Native heap capacity overlaps an active hardware/stack owner')
            if phase['index']==0:
                if not rom['temporary'][0][0]<=phase['sp']<rom['temporary'][0][1]:
                    raise ValueError('Pre-scheduler inherited stack witness differs')
            elif not any(t['stack']<=phase['sp']<t['stack']+t['reserved'] for t in run['tasks']):
                raise ValueError('Running native task stack witness is absent')
            if not any(a<=phase['vector']<b for a,b in current['resident']):
                raise ValueError('Runtime interrupt vectors are not in the resident image')
            value=union(current['resident'],spans)+phase['occupied_peak']
            bounds[key]=value;witnesses[key]=value
            parts.append({'phase':phase['index'],'resident_and_active_reservations_bytes':union(current['resident'],spans),
                'heap_occupied_bytes':phase['occupied_peak'],'sp':phase['sp'],'vector_base':phase['vector']})
        certificate=reached_peak(bounds,witnesses)
        if not certificate['complete']:raise ValueError('An earlier capacity upper bound remains undominated')
        rows.append({'reset':i,'phase_upper_bounds':bounds,'coincident_witnesses':witnesses,'phase_components':parts,
            'certificate':certificate,'peak_allocated_occupancy_bytes':certificate['peak_bytes'],
            'actual_task_stack_observations':run['tasks'],'raw_sha256':sha(capture/'captures'/('reset%d.raw'%i))})
    return {'audit':'pass','os':'AliOS-Rhino','board_mac':'34:98:7a:a2:85:28','source':SOURCE,'capture':CAPTURE,
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),'bootloader_source':boot_source,
        'build_manifest_sha256':sha(source/'build.json'),'campaign_sha256':sha(capture/'campaign.json'),
        'elf_sha256':current['elf_sha256'],'bin_sha256':current['bin_sha256'],'metric':'peak allocated RAM occupancy',
        'unit':'bytes','observer_included':True,'static_sections_bytes':current['static_sections_bytes'],
        'image_padding_bytes':current['padding_bytes'],'runs':rows,
        'whole_lifecycle_peak_allocated_occupancy_bytes':[r['peak_allocated_occupancy_bytes'] for r in rows],
        'complete_declared_lifecycle':True,'native_ownership':native,'active_rom_capacity_proof':active,
        'independent_resets':5,'new_board_resets_during_replay':0,'original_flash_restored':True,'ranking_eligible':False,
        'scope':'Fixed GCC13 observer image, normal cold SPI reset through the third original message report. Original native task retirement retained. Includes loader, ROM/cache, initialized allocator metadata, allocated blocks, free-block headers and free-cell pointers; task and IRQ capacities counted once. Actual stack use auxiliary; native-loader controls separate.',
        'remaining':['Independent capacity crosscheck, five-system admission and publication integration remain separate.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Preserve existing evidence on leon')
    value=audit(ROOT)
    with args.output.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
    print(json.dumps({k:value[k] for k in ('audit','os','independent_resets',
        'whole_lifecycle_peak_allocated_occupancy_bytes','complete_declared_lifecycle','original_flash_restored')}))
