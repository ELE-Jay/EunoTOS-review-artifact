#!/usr/bin/env python3
"""Qualify bounded ROM dispatches and one cold-reset callback exclusion."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from audit_esp32_rom_boot import audit as boot_audit, instruction_bytes
from run_esp32_followup import read_raw_capture, sha

ROOT = Path(__file__).resolve().parents[1]
MODEL = 'artifacts/reports/esp32-allocated-lifecycle-v1.json'
MODEL_SHA = '23bdafbf2cef46a7fbdbac11b91a38cfc5f0163fe2b3a5967137bd30db370a05'
DISASSEMBLY_SHA = 'ddf975973a5284171575b8d524cb1494372220ab1fcf662fa41d2af6e7a033f8'
TABLES = (
    ('gpio_pad_select_gpio',40,0x40009f54,0x3ff9bf3c,0x40009ff2,0x4000a0e0,
     {0x40009fdf:'742020',0x40009fe2:'782c',0x40009fe4:'02b827',0x40009fe7:'003d46',
      0x40009fea:'ffda81',0x40009fed:'a02280',0x40009ff0:'0228',0x40009ff2:'0002a0'}),
    ('gpio_pad_set_drv',34,0x4000a0e4,0x3ff9bfdc,0x4000a135,0x4000a224,
     {0x4000a11f:'742020',0x4000a122:'182c',0x4000a124:'743030',0x4000a127:'02b827',
      0x4000a12a:'003d86',0x4000a12d:'ffed81',0x4000a130:'a02280',0x4000a133:'0228',0x4000a135:'0002a0'}),
    ('gpio_pad_pullup',34,0x4000a228,0x3ff9c064,0x4000a242,0x4000a340,
     {0x4000a22f:'742020',0x4000a232:'182c',0x4000a234:'02b827',0x4000a237:'004146',
      0x4000a23a:'fffb81',0x4000a23d:'a02280',0x4000a240:'0228',0x4000a242:'0002a0'}),
    ('gpio_pad_unhold',40,0x4000a460,0x3ff9c174,0x4000a49a,0x4000a72c,
     {0x4000a487:'742020',0x4000a48a:'782c',0x4000a48c:'02b827',0x4000a48f:'00a646',
      0x4000a492:'fff381',0x4000a495:'a08280',0x4000a498:'0888',0x4000a49a:'0008a0'}),
)


def internal_targets(raw,count,start,size,instruction_starts):
    if len(raw) != 4*count or not size:
        raise ValueError('Invalid native jump-table extent')
    targets = struct.unpack('<'+'I'*count,raw)
    if any(not start<=t<start+size or t not in instruction_starts for t in targets):
        raise ValueError('ROM dispatch escapes its compiled function/instruction boundaries')
    return targets


def skips_early_rtc_callback(reset_reason,mask):
    index = reset_reason-1
    return 0<=index<=15 and bool((1<<index)&mask)


def instruction_listing(text):
    return {int(m[1],16):(m[2],m[3],m[4]) for m in re.finditer(
        r'(?m)^([0-9a-f]+):[ \t]+([0-9a-f]{4}|[0-9a-f]{6})[ \t]+([^ \t\n]+)[ \t]*([^\n]*)$',text)}


def cold_spi_route(reset_reason,strap):
    if (reset_reason,strap)!=(1,0x13):
        raise ValueError('This certificate covers only the retained cold SPI boot case')
    return {'strap_bit4_set':bool(strap&16),'reset_minus_11_unsigned':(reset_reason-11)&0xffffffff,
            'skips_reset_11_to_13_reattach':((reset_reason-11)&0xffffffff)>=3}


def audit(root):
    from elftools.elf.elffile import ELFFile
    if sha(root/MODEL) != MODEL_SHA:
        raise ValueError('Retained RAM model changed')
    model = json.loads((root/MODEL).read_text())
    policy_folder = root/'artifacts/reports/esp32-rom-boot-policy-b1-v1'
    policy = boot_audit(policy_folder)
    if policy != json.loads((policy_folder/'audit.json').read_text()) or policy['board_mac'] != model['board_mac']:
        raise ValueError('Physical boot-policy identity differs')
    resets = []
    for cohort in model['rows']:
        capture = root/cohort['capture']
        state = json.loads((capture/'campaign.json').read_text())
        if state['board_mac'] != model['board_mac'] or state['independent_resets'] != 5:
            raise ValueError('Different retained board/cohort')
        for run in cohort['runs']:
            index = run['reset'];raw = capture/'captures'/('reset%d.raw'%index)
            if sha(raw) != run['raw_sha256']:
                raise ValueError('Retained raw reset changed')
            lines = [r['line'] for r in read_raw_capture(capture/'captures',index)]
            printed = [s for s in lines if s.startswith('rst:')]
            if printed != ['rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)']:
                raise ValueError('Callback exclusion needs the recorded normal cold-reset case')
            resets.append({'os':cohort['os'],'reset':index,'raw_sha256':sha(raw)})
    if len(resets) != 15:
        raise ValueError('Expected all fifteen retained resets')
    spec = json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())['rom']
    folder = root/spec['directory'];path = folder/spec['elf'];disassembly = folder/'disassembly.txt'
    if sha(path) != spec['sha256'] or sha(disassembly) != DISASSEMBLY_SHA:
        raise ValueError('Pinned ROM/disassembler output changed')
    decoded = instruction_listing(disassembly.read_text())
    with path.open('rb') as stream:
        elf = ELFFile(stream);symbols = elf.get_section_by_name('.symtab')
        def memory(address,size):
            for section in elf.iter_sections():
                if section['sh_type']!='SHT_NOBITS' and section['sh_addr']<=address and address+size<=section['sh_addr']+section['sh_size']:
                    return section.data()[address-section['sh_addr']:address-section['sh_addr']+size]
            raise ValueError('ROM proof address outside initialized ELF sections')
        tables = []
        for name,count,literal,address,dispatch,default,guards in TABLES:
            found = symbols.get_symbol_by_name(name)
            if found is None or len(found)!=1:
                raise ValueError('Missing or ambiguous native GPIO function')
            symbol = found[0];start,size = symbol['st_value'],symbol['st_size']
            if struct.unpack('<I',memory(literal,4))[0] != address:
                raise ValueError('GPIO table literal changed')
            for pc,word in guards.items():
                instruction_bytes(memory,pc,word)
                if decoded[pc][0] != word:
                    raise ValueError('Disassembled guard is not the pinned instruction')
            instruction_bytes(memory,default,'f01d')
            raw = memory(address,4*count)
            section = next(s for s in elf.iter_sections() if s['sh_addr']<=address and address+len(raw)<=s['sh_addr']+s['sh_size'])
            if section['sh_flags']&1:
                raise ValueError('Dispatch table is not read-only ROM data')
            targets = internal_targets(raw,count,start,size,set(decoded))
            for target in set(targets):
                instruction_bytes(memory,target,decoded[target][0])
            tables.append({'function':name,'function_start':start,'function_bytes':size,'dispatch_pc':dispatch,
                'table_address':address,'entries':count,'unique_targets':len(set(targets)),
                'targets':list(targets),'default_exit_pc':default,'all_targets_are_internal_instructions':True,
                'guards':{hex(p):w for p,w in guards.items()}})
        guards = {0x400076ff:'00ad65',0x4000770d:'0a3d',0x400078ec:'ff6ba1',0x400078f8:'03bd',
            0x400078fa:'230b',0x400078fc:'f40c',0x400078fe:'004565',0x40007901:'02b427',
            0x40007907:'140c',0x40007909:'401200',0x4000790c:'a12400',0x4000790f:'ff6341',
            0x40007912:'238247',0x40007933:'0005e0'}
        for pc,word in guards.items():instruction_bytes(memory,pc,word)
        mask = struct.unpack('<I',memory(0x4000769c,4))[0]
        format_pointer = struct.unpack('<I',memory(0x40007698,4))[0]
        if mask != 0xc3ed or format_pointer != 0x3ff9ea95 or not memory(format_pointer,40).startswith(b'\nrst:0x%x (%s),boot:0x%x (%s)\n\0'):
            raise ValueError('Reset-reason branch/print provenance differs')
        if not skips_early_rtc_callback(1,mask):
            raise ValueError('Observed cold-reset reason does not skip the callback')
        route_guards = {0x4000793c:'fbfa81',0x40007945:'002892',0x40007956:'0898',
            0x4000795b:'021c',0x4000795d:'102920',0x40007962:'62dc',0x4000797c:'00cda5',
            0x400079c1:'5b0aa5',0x400079c9:'003006',0x40007a65:'012825',0x40007a8d:'f5c332',
            0x40007a90:'4933f6',0x40007add:'fb9121',0x40007ae3:'0238',0x40007ae5:'3ce347'}
        for pc,word in route_guards.items():instruction_bytes(memory,pc,word)
        if struct.unpack('<I',memory(0x40006924,4))[0]!=0x3ff44038:
            raise ValueError('SPI route does not consume the printed strap register')
        route = cold_spi_route(1,0x13)
        route.update({'normal_branch_pc':0x40007962,'normal_branch_target':0x4000797c,
            'bypass_jump_pc':0x400079c9,'bypass_jump_target':0x40007a8d,
            'excluded_main_download_region':[0x400079cd,0x40007a8d],
            'excluded_direct_uart_download_callsite':0x40007a65,
            'modern_spi_branch_pc':0x40007ae5,'modern_spi_branch_target':0x40007b25,
            'guards':{hex(p):w for p,w in route_guards.items()},
            'scope':'These specific main-path edges follow the observed strap/reset inputs; not a global no-caller claim about UART or decompressor symbols.'})
    return {'audit':'pass','board_mac':model['board_mac'],'rom_sha256':sha(path),
        'model_sha256':sha(root/MODEL),'physical_boot_policy_sha256':sha(policy_folder/'audit.json'),
        'retained_cold_resets':resets,'bounded_gpio_dispatches':tables,'bounded_table_entries':sum(t['entries'] for t in tables),
        'cold_reset_callback':{'pc':0x40007933,'skipping_branch_pc':0x40007912,'target':0x40007939,
            'recorded_reset_reason':1,'mask':mask,'excluded_for_retained_cold_resets':True,
            'guards':{hex(p):w for p,w in guards.items()},
            'abi':'Native Xtensa call8 window ABI preserves caller-local a3; the same a3 supplies the reset-reason print and branch mask.'},
        'cold_spi_main_route':route,
        'new_board_resets':0,'new_model_calls':0,'whole_lifecycle_peak_allocated_occupancy_bytes':None,
        'rom_owner_exhaustiveness_verified':False,'ranking_eligible':False,
        'scope':'Retrospective control-target facts, not a complete store/allocation proof or new performance sample. Four GPIO computed jumps stay internal; the retained cold-reset/strap inputs skip the early RTC callback and the specified main download region.',
        'remaining':['Complete normal-SPI reachability, target memory ownership and remaining callback state before qualifying a whole-lifecycle capacity bound. No claim that every ROM write or C-library pointer lifetime has been classified.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if sys.platform!='linux' or ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Audit on leon into a new persistent output')
    result=audit(ROOT)
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('bounded_gpio_dispatches','retained_cold_resets','cold_reset_callback')},indent=2))
