#!/usr/bin/env python3
"""Bind the active cold-SPI ROM ABI, then qualify retained Z/N capacity peaks."""
import argparse
import json
from pathlib import Path
import re
import struct

from audit_esp32_allocated_lifecycle import audit as model_audit, reached_peak, union
from audit_esp32_rom_capacity import envelope, inside
from audit_esp32_rom_dispatch import instruction_listing
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
RESULT='artifacts/reports/esp32-active-rom-allocated-capacity-v1.json'
INACTIVE_SECTIONS={'.data_btdm','.bss_btdm','.bss_gpio_app','.bss_uart_app',
    '.data_etsc_app','.bss_etsc_app','.data_xtos_app','.bss_xtos_app','.stack_app'}
MASKS={
    0x4000a213:(0x3fffffff,{0x4000a213:('l32r','a8, '),
        0x4000a219:('and','a8, a9, a8'),0x4000a21c:('or','a3, a3, a8'),
        0x4000a222:('s32i.n','a3, a2, 0')}),
    0x40061d48:(0x50000000,{0x40061d45:('l32r','a2, '),0x40061d48:('l32r','a8, '),
        0x40061d4e:('l32i.n','a9, a2, 0'),0x40061d50:('or','a8, a9, a8'),
        0x40061d56:('s32i.n','a8, a2, 0')})}


def classify_sections(sections,spans):
    active=[];inactive=[]
    for row in sections:
        if inside(spans,row['start'],row['end']):active.append(row)
        elif row['section'] in INACTIVE_SECTIONS:inactive.append(row)
        else:raise ValueError('Undeclared ROM SRAM section outside active ABI')
    if {r['section'] for r in inactive}!=INACTIVE_SECTIONS:
        raise ValueError('Inactive controller/APP section inventory changed')
    return active,inactive


def literal_inventory(decoded,seen,memory,spans):
    from audit_esp32_resources import RAM
    data=[];masks=[]
    for pc in sorted(seen):
        _,op,args=decoded[pc]
        if op!='l32r':continue
        literal=int(re.search(r', ([0-9a-f]+) <',args)[1],16)
        value=struct.unpack('<I',memory(literal,4))[0]
        if not any(a<=value<b for a,b in RAM):continue
        row={'pc':pc,'literal':literal,'value':value}
        if any(a<=value<b for a,b in spans):data.append(row);continue
        spec=MASKS.get(pc)
        if not spec or spec[0]!=value or any(
                decoded[p][1]!=opcode or not decoded[p][2].startswith(operands)
                for p,(opcode,operands) in spec[1].items()):
            raise ValueError('Additional SRAM-valued ROM literal needs an ownership classification')
        masks.append(row)
    if {r['pc'] for r in masks}!=set(MASKS):raise ValueError('Native mask inventory changed')
    return data,masks


def active_abi(root,protocol):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_allocated_lifecycle import rom_model,native_configuration
    rom=rom_model(root,protocol);coarse,prior=envelope(root,protocol,rom)
    spans=rom['workspace'];active,inactive=classify_sections(prior['rom_sram_sections'],spans)
    excluded=[(s['start'],s['end']) for s in inactive]
    if any(not inside(spans,r['start'],r['end']) and not inside(excluded,r['start'],r['end'])
            for r in prior['rom_sram_objects']):
        raise ValueError('A ROM SRAM object has no active or disabled-domain owner')
    for row in rom['copy_records']:
        # The ROM copy loop is post-tested, including zero-length records.
        if not inside(spans,row[0],max(row[1],row[0]+4)):
            raise ValueError('A physical reset copy escapes the active ABI')
    for row in rom['zero_records']:
        if not inside(spans,row[0],row[1]):
            raise ValueError('The physical reset tables initialize an additional CPU/controller domain')
    for spec in protocol['images']:
        cfg=native_configuration(root,spec)
        if any(n+'=y' in cfg for n in ('CONFIG_WIFI','CONFIG_ESP_WIFI','CONFIG_ESP32_WIFI',
                'CONFIG_BT_CTLR','CONFIG_BT_HOST','CONFIG_ESP32_MEMMAP_TRACEMEM')):
            raise ValueError('Controller/trace allocation is outside this normal-boot contract')
    folder=root/protocol['rom']['directory'];path=folder/protocol['rom']['elf']
    decoded=instruction_listing((folder/'disassembly.txt').read_text())
    reset_guards={0x40000507:('l32i.n','a2, a4, 12'),0x40000509:('beqi','a2, 1,'),
        0x4000050c:('rsr.prid','a2'),0x40000512:('beq','a2, a3,'),
        0x40000515:('l32i.n','a2, a8, 0'),0x40000517:('s32i.n','a2, a6, 0'),
        0x4000051d:('bltu','a6, a7,'),0x4000071e:('l32i.n','a3, a6, 8'),
        0x40000720:('beqi','a3, 1,'),0x40000723:('rsr.prid','a2'),
        0x40000729:('beq','a2, a3,'),0x40000735:('bltu','a4, a5,')}
    if any(decoded[p][1]!=op or not decoded[p][2].startswith(args)
            for p,(op,args) in reset_guards.items()):
        raise ValueError('Physical reset table selection/copy/zero semantics changed')
    callback=json.loads((root/'artifacts/reports/esp32-rom-callbacks-v2.json').read_text())
    with path.open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        def memory(address,size):
            for section in elf.iter_sections():
                a=section['sh_addr'];b=a+section['sh_size']
                if section['sh_type']!='SHT_NOBITS' and a<=address and address+size<=b:
                    return section.data()[address-a:address-a+size]
            raise ValueError('ROM literal is outside initialized sections')
        seen=set(callback['reachable_instruction_pcs'])
        literals,masks=literal_inventory(decoded,seen,memory,spans)
        functions=[s for s in symbols.iter_symbols() if s['st_info']['type']=='STT_FUNC' and s['st_size']]
        services=[]
        for address in sorted({target for pc,target in callback['calls']}):
            names=[s.name for s in functions if s['st_value']<=address<s['st_value']+s['st_size']]
            if len(names)!=1:raise ValueError('Ambiguous normal ROM service owner')
            services.append({'address':address,'function':names[0]})
    if any(union(spans,[(r['start'],r['end'])])!=union(spans) for r in active) or \
            callback['unresolved_indirect_sites'] or not callback['compiled_function_call_graph_acyclic'] or \
            callback['sum_reachable_entry_frame_bytes']>callback['reserved_pro_stack_bytes']:
        raise ValueError('Active ROM data/control/stack envelope changed')
    # Initialization, native core configuration and the closed normal prefix are
    # allocation-ABI evidence. They are not a general proof of memory safety.
    return spans,{'physical_rom_and_coarse_proof':prior,'coarse_spans':coarse,
        'active_rom_spans':spans,'active_rom_capacity_bytes':union(spans),
        'active_writable_sections':active,'inactive_controller_and_app_sections':inactive,
        'normal_service_entrypoints':services,'sram_literal_references':literals,
        'nonpointer_peripheral_masks':masks,'reset_tables_only_initialize_pro_domains':True,
        'reset_record_tag_semantics':'1 always, 0 skipped on APP PRID 0xabab; both execute on PRO. This flag is not a CPU number.',
        'zero_length_copy_records_write_one_word':True,
        'peripheral_interrupts_disabled_in_rom_prefix':prior['only_reached_enable_writer_is_mask_only'] and
            prior['physical_initial_enabled']==0,
        'rom_stack_capacity_bytes':callback['reserved_pro_stack_bytes'],
        'reachable_frame_capacity_upper_bytes':callback['sum_reachable_entry_frame_bytes'],
        'native_configs':{s['os']:sha(root/s['source']/'config') for s in protocol['images']},
        'general_memory_safety_or_arbitrary_alias_proof':False,
        'basis':'Normal successful cold-SPI vendor allocation ABI: initialized static ROM data, reserved PRO stack, CPU0 cache and caller-owned image buffers. No reachable allocation entrypoint, unknown admitted callback, active Bluetooth/APP CPU/trace or peripheral interrupt context. All other writable ROM SRAM sections belong to disabled BT/APP domains. Retained native transitions separately establish retirement. The bound concerns allocated capacity, not arbitrary writes or dirty bytes.'}


def audit(root):
    protocol=json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())
    model=json.loads(json.dumps(model_audit(root)))
    previous=root/'artifacts/reports/esp32-allocated-lifecycle-v1.json'
    if model!=json.loads(previous.read_text()):raise ValueError('Retained model/source/captures changed')
    spans,proof=active_abi(root,protocol);rows=[]
    for original in model['rows'][1:]:
        runs=[]
        for run in original['runs']:
            certificate=reached_peak(run['phase_upper_bounds'],run['coincident_witnesses'])
            if not certificate['complete']:raise ValueError('An early capacity upper bound remains undominated')
            runs.append({**run,'certificate':certificate,'peak_allocated_occupancy_bytes':certificate['peak_bytes']})
        rows.append({k:original[k] for k in ('os','source','capture','elf_sha256','bin_sha256')} | {
            'runs':runs,'whole_lifecycle_peak_allocated_occupancy_bytes':
                [v['peak_allocated_occupancy_bytes'] for v in runs],
            'complete_declared_lifecycle':True,'observer_included':True,'ranking_eligible':False})
    return {'audit':'pass','metric':'peak allocated RAM occupancy','unit':'bytes','board_mac':model['board_mac'],
        'original_model_sha256':sha(previous),'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),
        'active_rom_capacity_proof':proof,'rows':rows,'retained_independent_resets':10,
        'complete_declared_lifecycle':True,'ranking_eligible':False,'new_benchmark_samples':0,
        'new_board_resets':0,'new_model_calls':0,'actual_stack_use_measured_by_this_audit':False,
        'scope':'Image-specific normal POWERON_RESET/SPI allocation capacity through third original message report, source-bound vendor ROM ABI and measured native ownership transfers. Includes observers, image padding, ROM/cache reservations and native allocator metadata. Not uninstrumented OS ranking, exact live-stack bytes or arbitrary-fault coverage.',
        'remaining':['Matched native/uninstrumented ranking admission and publication integration remain separate.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Audit retained evidence on leon without overwriting reports')
    result=audit(ROOT)
    with args.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('active_rom_capacity_proof','rows')} | {
        'results':{r['os']:r['whole_lifecycle_peak_allocated_occupancy_bytes'] for r in result['rows']}},indent=2))
