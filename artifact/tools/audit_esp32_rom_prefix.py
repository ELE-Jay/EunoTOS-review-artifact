#!/usr/bin/env python3
"""Replay the retained cold-SPI main prefix; do not infer RAM from call reachability."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from audit_esp32_rom_boot import instruction_bytes, rom_facts
from audit_esp32_rom_dispatch import audit as dispatch_audit, instruction_listing
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
EDGES = {0x40007912:0x40007939, 0x40007962:0x4000797c,
    0x40007a90:0x40007add, 0x40007ae5:0x40007b25,
    0x40007b92:0x40007b95, 0x40007bbc:0x40007bd1,
    0x40007626:0x40007646, 0x40007c2e:0x40007c31}


def walk(instructions, start, terminal, forced, dispatches, indirect_calls=None):
    pending=[start];seen=set();calls=[];unknown=[]
    while pending:
        pc=pending.pop()
        if pc in seen:
            continue
        if pc not in instructions:
            raise ValueError('Control edge is not a decoded instruction: '+hex(pc))
        seen.add(pc)
        if pc==terminal:
            continue
        word,op,args=instructions[pc];following=pc+len(word)//2
        if op in ('ret.n','ret','retw.n','retw','rfi','rfe','rfde','ill','ill.n','break','break.n'):
            continue
        if op=='jx':
            targets=dispatches.get(pc)
            if targets is None:
                unknown.append((pc,op,args))
            else:
                pending.extend(targets)
            continue
        if op.startswith('callx'):
            targets=(indirect_calls or {}).get(pc)
            if targets is None:
                unknown.append((pc,op,args))
            else:
                for target in targets:
                    calls.append((pc,target));pending.append(target)
            pending.append(following)
            continue
        if op.startswith('call') or op=='j' or op.startswith(('b','loop')):
            match=re.search(r'(?<![0-9a-f])([0-9a-f]{8}) <',args)
            if match is None:
                raise ValueError('Unparsed direct control instruction: '+hex(pc))
            target=int(match[1],16)
            if op.startswith('call'):
                calls.append((pc,target));pending.extend((following,target))
            elif op=='j':
                pending.append(target)
            elif pc in forced:
                if forced[pc] not in (target,following):
                    raise ValueError('Forced edge is not a native branch successor')
                pending.append(forced[pc])
            else:
                pending.extend((target,following))
        else:
            pending.append(following)
    if terminal not in seen or set(forced)-seen:
        raise ValueError('Declared prefix or route facts were not reached')
    return seen,sorted(calls),sorted(unknown)


def audit(root):
    from elftools.elf.elffile import ELFFile
    dispatch=dispatch_audit(root)
    saved=root/'artifacts/reports/esp32-rom-dispatch-ownership-v3.json'
    if dispatch!=json.loads(saved.read_text()):
        raise ValueError('Retained dispatch/reset evidence changed')
    facts=rom_facts(root,root/'artifacts/reports/esp32-rom-boot-policy-b1-v1')
    if not (facts['console_callsite']['excluded_by_readback'] and
            facts['legacy_loader_callsite']['excluded_by_readback']):
        raise ValueError('The observed physical policy does not exclude fallback')
    folder=root/'artifacts/source_snapshots/esp-rom-elfs-20260528'
    instructions=instruction_listing((folder/'disassembly.txt').read_text())
    tables={t['dispatch_pc']:t['targets'] for t in dispatch['bounded_gpio_dispatches']}
    seen,calls,unknown=walk(instructions,0x400076c4,0x40007c31,EDGES,tables)
    with (folder/'esp32_rev0_rom.elf').open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        def memory(address,size):
            for section in elf.iter_sections():
                base=section['sh_addr']
                if section['sh_type']!='SHT_NOBITS' and base<=address and address+size<=base+section['sh_size']:
                    return section.data()[address-base:address-base+size]
            raise ValueError('Requested proof bytes are outside initialized ROM')
        for pc in seen:
            instruction_bytes(memory,pc,instructions[pc][0])
        # The model's raw traces establish a real nonzero handoff, rather than return from user code.
        from run_esp32_followup import read_raw_capture
        model=json.loads((root/'artifacts/reports/esp32-allocated-lifecycle-v1.json').read_text())
        for row in model['rows']:
            for run in row['runs']:
                lines=[r['line'] for r in read_raw_capture(root/row['capture']/'captures',run['reset'])]
                entries=[int(m[1],16) for line in lines if (m:=re.fullmatch(r'entry 0x([0-9a-f]+)',line))]
                if len(entries)!=1 or not entries[0]:
                    raise ValueError('Retained cold boot has no unique nonzero image handoff')
        for pc in (0x40007c29,0x40007c2c,0x40007c2e,0x40007c31):
            instruction_bytes(memory,pc,instructions[pc][0])
        if struct.unpack('<I',memory(0x40006878,4))[0]!=0x3ffe0400:
            raise ValueError('Native entry-pointer identity differs')
        allocation_names=('malloc','calloc','realloc','sbrk','_malloc_r','_calloc_r','_realloc_r','_sbrk_r')
        allocations={name:symbols.get_symbol_by_name(name)[0]['st_value'] for name in allocation_names}
        reachable={name:address for name,address in allocations.items() if address in seen}
        literals=[]
        for pc in sorted(seen):
            _,op,args=instructions[pc]
            if op=='l32r':
                literal=int(re.search(r', ([0-9a-f]+) <',args)[1],16)
                value=struct.unpack('<I',memory(literal,4))[0]
                if 0x3ffae000<=value<0x40000000:
                    literals.append({'pc':pc,'literal':literal,'value':value})
        setters={name:{'address':symbols.get_symbol_by_name(name)[0]['st_value'],
                      'reached':symbols.get_symbol_by_name(name)[0]['st_value'] in seen}
                 for name in ('ets_install_putc1','ets_install_putc2','ets_install_uart_printf')}
    return {'audit':'pass','rom_sha256':dispatch['rom_sha256'],'model_sha256':dispatch['model_sha256'],
        'dispatch_audit_sha256':sha(saved),'retained_cold_resets':15,'root':0x400076c4,
        'first_handoff_terminal':0x40007c31,'forced_branch_successors':{hex(p):v for p,v in EDGES.items()},
        'reachable_instruction_pcs':sorted(seen),'direct_calls':calls,
        'unresolved_indirect_sites':unknown,'allocation_entrypoints':allocations,
        'directly_reachable_allocation_entrypoints':reachable,'putc_setters':setters,
        'sram_valued_literal_references':literals,
        'control_targets_closed':not unknown,'rom_owner_exhaustiveness_verified':False,
        'whole_lifecycle_peak_allocated_occupancy_bytes':None,'ranking_eligible':False,
        'new_board_resets':0,'new_model_calls':0,
        'scope':'Main normal-SPI synchronous prefix through first native image handoff. Direct calls and bounded GPIO jumps are expanded; callbacks are not guessed from setter names or reset-zero values. Excludes code after user return. Not an exhaustive allocation/store/exception proof.',
        'remaining':['Prove reachable values and all possible writers of both putc slots, then expand admitted callbacks.',
            'Classify pointer-derived ROM stores, image load destinations, reset/exception paths and cache ownership before qualifying lifecycle RAM.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Replay on leon into a new persistent report')
    result=audit(ROOT)
    with args.output.open('x') as stream:
        json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in
        ('reachable_instruction_pcs','direct_calls','sram_valued_literal_references')},indent=2))
