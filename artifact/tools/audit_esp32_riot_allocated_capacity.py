#!/usr/bin/env python3
"""Replay RIOT's original-message allocation capacity across cold boot and handoff."""
import argparse
import json
from pathlib import Path
import re

from audit_esp32_allocated_lifecycle import boot_image,cold_boot,image,postload_witness,reached_peak,union
from audit_esp32_active_rom_capacity import active_abi
from run_esp32_followup import read_raw_capture,sha
from run_esp32_riot_message_history import audit as history_audit,build_proof

ROOT=Path(__file__).resolve().parents[1]
SOURCE='artifacts/reports/esp32-riot-common-boot-message-v1'
CAPTURE='artifacts/reports/esp32-riot-common-boot-message-b1-v1'


def phase_capacity(resident,rom_spans,phase,region_rows,regions):
    committed=[(a,a+r['committed']) for r,(a,b) in zip(region_rows,regions)]
    if len(region_rows)!=4 or len(regions)!=4 or any(
            not 0<=r['committed']<=b-a for r,(a,b) in zip(region_rows,regions)):
        raise ValueError('Phase heap extents differ')
    occupied=sum(b-a for a,b in committed)-phase['free_bytes']+8*phase['free_nodes']
    if occupied!=phase['occupied_peak'] or occupied<0 or not phase['observations']:
        raise ValueError('Phase allocation witness differs')
    base=union(resident,rom_spans)
    if union(resident,rom_spans,committed)!=base+sum(b-a for a,b in committed):
        raise ValueError('Heap peak overlaps an active owner; its free-node addresses are required')
    # Only coincident native bytes are added. Separate phase maxima are never summed.
    return {'upper_bytes':base+occupied,'witness_bytes':base+occupied,
        'resident_and_active_reservations_bytes':base,'native_heap_occupied_bytes':occupied,
        'sp':phase['sp'],'vector_base':phase['vector'],'committed_spans_at_witness':committed}


def native_ownership(folder,proof,current,rom):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_freertos_ram_lifetimes import calls
    from audit_esp32_ram_census import region_accounting
    from audit_esp32_riot_ram_lifetimes import LIBRARY_SHA
    from build_esp32_riot_ram_lifetimes import NATIVE,SUPPORT,SDK_FILES,SUPPORT_SDK
    prior=ROOT/'artifacts/reports/esp32-riot-lifetimes-v7'
    official={r['path']:r for r in json.loads((prior/'official-native-source.json').read_text())}
    names=(*NATIVE,*SUPPORT,*('sdk/'+n for n in (*SDK_FILES,*SUPPORT_SDK)))
    native={}
    for name in names:
        path=folder/'native-source'/name
        if sha(path)!=official[name]['sha256']:
            raise ValueError('Native source differs from its retained pinned vendor proof: '+name)
        native[name]=sha(path)
    library=json.loads((prior/'official-native-library.json').read_text())
    if library['audit']!='pass' or sha(prior/'libg_nano.a')!=LIBRARY_SHA or library['library_sha256']!=LIBRARY_SHA:
        raise ValueError('Native Newlib-nano library binding differs')
    mapped=(folder/'application.map').read_text()
    for member in ('mallocr','freer','reallocr','mallinfor','mlock'):
        if not re.search(r'xtensa-esp-elf/lib/esp32/libg_nano\.a\(libc_a-'+member+r'\.o\)',mapped):
            raise ValueError('Actual native allocator archive member differs')
    cfg=(folder/'config').read_text().splitlines()
    if any(re.fullmatch(r'#define MODULE_(?:ESP_WIFI.*|ESP_IDF_HEAP|ESP_SPI_RAM|SCHED_ROUND_ROBIN|PTHREAD.*|ESP_BT.*) 1',s) for s in cfg):
        raise ValueError('Additional allocator/controller/thread domain outside this configuration')
    startup=(folder/'native-source/cpu/esp32/startup.c').read_text()
    arch=(folder/'native-source/cpu/esp_common/esp-xtensa/thread_arch.c').read_text()
    kernel=(folder/'native-source/core/lib/init.c').read_text()
    if not startup.index('    syscalls_init();')<startup.index('    system_init();') or \
            not startup.index('    esp_timer_init();')<startup.index('    kernel_init();') or \
            '    cpu_switch_context_exit();' not in kernel:
        raise ValueError('Native pre-thread/kernel handoff order differs')
    exit_body=arch[arch.index('NORETURN void task_exit(void)\n{'):]
    if not exit_body.index('    sched_run();')<exit_body.index('wsr a2, windowstart')<exit_body.index('call0 _frxt_int_exit') or \
            re.search(r'\b(?:malloc|calloc|realloc|free)\s*\(',exit_body):
        raise ValueError('Native context handoff does not retire the inherited stack without allocation')
    extra=calls(folder,required=[('system_startup_cpu0','syscalls_init'),
        ('syscalls_init','malloc'),('system_startup_cpu0','esp_timer_init'),
        ('esp_timer_init','xTaskCreatePinnedToCore'),('xTaskCreatePinnedToCore','malloc'),
        ('kernel_init','__wrap_thread_create'),('kernel_init','cpu_switch_context_exit'),
        ('cpu_switch_context_exit','task_exit')],
        require_iram=False,disassembly_name='objdump.txt')
    region_accounting(proof['ram_sections'],[(a,b-a) for a,b in proof['native_regions']],False)
    with (folder/'application.elf').open('rb') as f:
        elf=ELFFile(f);symbols=elf.get_section_by_name('.symtab')
        def symbol(name):
            values=symbols.get_symbol_by_name(name) or []
            if len(values)!=1: raise ValueError('Missing or ambiguous native owner: '+name)
            return values[0]
        irq=[symbol(n)['st_value'] for n in ('port_IntStack','port_IntStackTop')]
        vector=symbol('_iram_start')['st_value']
        static={n:[symbol(n)['st_value'],symbol(n)['st_size']] for n in ('main_stack','idle_stack','stacks')}
        if irq[1]-irq[0]!=2048 or union(current['resident'],[tuple(irq)])!=union(current['resident']) or \
                union(current['resident'],[(a,a+b) for a,b in static.values()])!=union(current['resident']):
            raise ValueError('Native fixed IRQ/task stacks escape the resident image')
        if any(symbols.get_symbol_by_name(n) for n in ('heap_caps_malloc','heap_caps_init','tlsf_malloc')):
            raise ValueError('Image includes an unobserved second allocator')
        task=symbol('task_exit');text=(folder/'objdump.txt').read_text()
        matches=[(int(pc,16),int(target,16)) for pc,target in re.findall(
            r'^([0-9a-f]+):\s+[0-9a-f]+\s+call0\s+([0-9a-f]+) <_frxt_int_exit>$',text,re.M)]
        if not any(task['st_value']<=pc<task['st_value']+task['st_size'] and target==symbol('_frxt_int_exit')['st_value']
                for pc,target in matches):
            raise ValueError('Non-returning native context transfer is absent from machine code')
        switch=symbol('cpu_switch_context_exit');dispatch=symbol('_frxt_dispatch')
        if not any(switch['st_value']<=int(pc,16)<switch['st_value']+switch['st_size'] and
                int(target,16)==dispatch['st_value'] for pc,target in re.findall(
                r'^([0-9a-f]+):\s+[0-9a-f]+\s+call0\s+([0-9a-f]+) <_frxt_dispatch>$',text,re.M)):
            raise ValueError('Initial no-save dispatch is absent')
        loads=[(int(pc,16),word) for pc,word in re.findall(
            r'^([0-9a-f]+):\s+([0-9a-f]{6})\s+l32i\s+a1, a3, 0$',text,re.M)
            if dispatch['st_value']<=int(pc,16)<dispatch['st_value']+16]
        if len(loads)!=1:
            raise ValueError('Initial native task stack load is absent')
        pc,word=loads[0];section=elf.get_section(dispatch['st_shndx'])
        if section.data()[pc-section['sh_addr']:pc-section['sh_addr']+3]!=bytes.fromhex(word)[::-1]:
            raise ValueError('Native stack-load disassembly differs from its machine bytes')
    return {'pinned_native_files':native,'newlib_library_sha256':LIBRARY_SHA,
        'retained_native_provenance_sha256':sha(prior/'official-native-source.json'),
        'retained_library_provenance_sha256':sha(prior/'official-native-library.json'),
        'native_handoff_calls':extra,'irq_stack':irq,'static_task_arrays':static,'vector_base':vector,
        'all_task_and_irq_capacities_already_in_resident_or_native_blocks':True,
        'temporary_rom_stack':rom['temporary'][0]}


def audit(root):
    from audit_esp32_allocated_lifecycle import rom_model
    source=root/SOURCE;capture=root/CAPTURE
    history=history_audit(source,capture);proof=build_proof(source)
    if not proof.get('paired_vendor_bootloader') or history['independent_resets']!=5:
        raise ValueError('Need five fresh paired-loader cold boots, not substituted native-loader records')
    protocol=json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())
    rom=rom_model(root,protocol);_,active=active_abi(root,protocol)
    boot=boot_image(root);current=image(root,SOURCE)
    native=native_ownership(source,proof,current,rom)
    runs=[]
    for i,observed in enumerate(history['runs'],1):
        lines=[r['line'] for r in read_raw_capture(capture/'captures',i)]
        cold_boot(lines,boot['loaded'],boot['entry']);postload_witness(lines)
        first=union(rom['workspace'],boot['loaded'])
        loader=union(rom['workspace'],boot['resident'],current['loaded'])
        entry=union(rom['workspace'],current['resident'])
        phases=[]
        for p in observed['phase_peaks']:
            rows=[r for r in observed['phase_regions'] if r['phase']==p['index']]
            if p['vector']!=native['vector_base']:
                raise ValueError('Runtime native vector ownership differs')
            if p['index']==0:
                a,b=rom['temporary'][0]
                if not a<=p['sp']<b:
                    raise ValueError('Pre-thread heap peak lacks its inherited-stack witness')
                spans=rom['workspace']
            else:
                if not any(t['stack']<=p['sp']<t['tcb'] for t in observed['threads']):
                    raise ValueError('Native-thread heap peak lacks its actual task-stack witness')
                spans=rom['fixed']
            phases.append(phase_capacity(current['resident'],spans,p,rows,proof['native_regions']))
        bounds={'first_stage':first,'loader':loader,'native_entry':entry,
            'pre_thread':phases[0]['upper_bytes'],'native_threads':phases[1]['upper_bytes']}
        witnesses={k:v['witness_bytes'] for k,v in zip(('pre_thread','native_threads'),phases)}
        certificate=reached_peak(bounds,witnesses)
        if not certificate['complete']:
            raise ValueError('An earlier ownership bound remains above all coincident witnesses')
        runs.append({'reset':i,'phase_upper_bounds':bounds,'coincident_witnesses':witnesses,
            'phase_components':phases,'certificate':certificate,
            'peak_allocated_occupancy_bytes':certificate['peak_bytes'],
            'actual_stack_observations':observed['threads'],
            'raw_sha256':sha(capture/'captures'/('reset%d.raw'%i))})
    return {'audit':'pass','os':'RIOT','board_mac':'34:98:7a:a2:85:28','source':SOURCE,'capture':CAPTURE,
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),
        'build_manifest_sha256':sha(source/'build.json'),'campaign_sha256':sha(capture/'campaign.json'),
        'elf_sha256':current['elf_sha256'],'bin_sha256':current['bin_sha256'],
        'metric':'peak allocated RAM occupancy','unit':'bytes','observer_included':True,
        'static_sections_bytes':current['static_sections_bytes'],'image_padding_bytes':current['padding_bytes'],
        'runs':runs,'whole_lifecycle_peak_allocated_occupancy_bytes':[r['peak_allocated_occupancy_bytes'] for r in runs],
        'complete_declared_lifecycle':True,'native_ownership':native,'active_rom_capacity_proof':active,
        'independent_resets':5,'new_board_resets_during_replay':0,'original_flash_restored':True,
        'ranking_eligible':False,'scope':'Fixed observer image, normal cold SPI reset through the third original message report. Same source-bound paired vendor boot observer as retained FreeRTOS/NuttX. Includes physical resident padding, ROM/cache, simultaneous native allocation capacity and free-block metadata. Static and heap-backed stack capacities counted once; actual stack use auxiliary. Native-loader five-reset controls remain separate; no uninstrumented RAM is inferred.',
        'remaining':['Five-system matched observer/comparison admission and publication integration remain separate.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Replay only on leon, retaining prior results')
    value=audit(ROOT)
    with args.output.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
    print(json.dumps({k:value[k] for k in ('audit','os','independent_resets',
        'whole_lifecycle_peak_allocated_occupancy_bytes','complete_declared_lifecycle','original_flash_restored')}))
