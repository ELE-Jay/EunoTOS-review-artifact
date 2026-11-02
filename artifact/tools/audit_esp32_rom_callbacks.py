#!/usr/bin/env python3
"""Close normal-SPI console callbacks against retained ROM bytes and boot facts."""
import argparse
import json
from pathlib import Path
import re
import struct

from audit_esp32_rom_boot import instruction_bytes
from audit_esp32_rom_dispatch import instruction_listing
from audit_esp32_rom_prefix import EDGES, audit as prefix_audit, walk
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
SPI_EDGES = {0x400076d7:0x400076e9, 0x4000779a:0x400077ac,
    0x400077b6:0x400077bc, 0x400077c4:0x400077cc,
    0x400077d4:0x400077d9, 0x400077e1:0x400077e8,
    0x400077f4:0x400077fd}
SLOT_REFERENCES = {0x40007c5b:0x3ffae014, 0x40007c6c:0x3ffae010,
    0x40007d1b:0x3ffae014, 0x40007d2e:0x3ffae014,
    0x40007d3b:0x3ffae010, 0x40007d59:0x3ffae014,
    0x40007d6b:0x3ffae010}
UNBACKED_LITERALS = {0x4000d589,0x4000d5fc,0x4000d638,0x4000d644,0x4000d668}


def slot_references(instructions, memory):
    found={};unbacked=set()
    for pc,(_,op,args) in instructions.items():
        if op=='l32r':
            literal=int(re.search(r', ([0-9a-f]+) <',args)[1],16)
            try:
                value=struct.unpack('<I',memory(literal,4))[0]
            except ValueError:
                unbacked.add(pc);continue
            if value in (0x3ffae010,0x3ffae014):found[pc]=value
    if found!=SLOT_REFERENCES or unbacked!=UNBACKED_LITERALS:
        raise ValueError('The complete direct putc-slot reference inventory changed')
    return found


def frame_inventory(instructions,seen,calls,functions):
    edges={}
    for pc,target in calls:
        owners=[[a for a,b in functions if a<=point<b] for point in (pc,target)]
        if any(len(o)!=1 for o in owners):
            raise ValueError('A ROM call lacks an unambiguous compiled function owner')
        edges.setdefault(owners[0][0],set()).add(owners[1][0])
    done=set()
    def visit(pc,active):
        if pc in active:raise ValueError('Recursive ROM calls invalidate the finite frame bound')
        if pc in done:return
        for target in edges.get(pc,()):visit(target,active|{pc})
        done.add(pc)
    for pc in edges:visit(pc,set())
    frames=[]
    for pc in sorted(seen):
        _,op,args=instructions[pc]
        if op=='entry':
            match=re.fullmatch(r'a1, (\d+)',args)
            if not match:raise ValueError('Unknown native frame reservation')
            frames.append({'pc':pc,'bytes':int(match[1])})
        elif args.startswith('a1,') and not op.startswith(('s8i','s16i','s32i','s32e','s32c1i','b')) and (op,args)!=('or','a1, a1, a1'):
            raise ValueError('Additional explicit stack-pointer operation requires review')
    return frames


def audit(root):
    from elftools.elf.elffile import ELFFile
    prefix=json.loads(json.dumps(prefix_audit(root)))
    saved=root/'artifacts/reports/esp32-rom-prefix-v1.json'
    if prefix!=json.loads(saved.read_text()):
        raise ValueError('The retained prefix report changed')
    folder=root/'artifacts/source_snapshots/esp-rom-elfs-20260528'
    instructions=instruction_listing((folder/'disassembly.txt').read_text())
    dispatch=json.loads((root/'artifacts/reports/esp32-rom-dispatch-ownership-v3.json').read_text())
    tables={t['dispatch_pc']:t['targets'] for t in dispatch['bounded_gpio_dispatches']}
    # These branches consume PRO PRID and the same latched strap=0x13 printed in all captures.
    forced={**EDGES,**SPI_EDGES}
    with (folder/'esp32_rev0_rom.elf').open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        def memory(address,size):
            for section in elf.iter_sections():
                base=section['sh_addr']
                if section['sh_type']!='SHT_NOBITS' and base<=address and address+size<=base+section['sh_size']:
                    return section.data()[address-base:address-base+size]
            raise ValueError('Requested ROM bytes are outside initialized sections')
        def value(name):return symbols.get_symbol_by_name(name)[0]['st_value']
        references=slot_references(instructions,memory)
        guards={0x400076d1:('l32r','a2'),0x400076d4:('rsr.prid','a3'),
            0x400076d7:('bne','a3, a2'),0x4000778d:('l32r','a2'),
            0x40007790:('movi.n','a4, 14'),0x40007795:('l32i.n','a5, a2, 0'),
            0x40007797:('extui','a5, a5, 0, 5'),0x400077b1:('movi.n','a8, 27'),
            0x400077b3:('and','a10, a10, a8'),0x400077c1:('and','a10, a10, a8'),
            0x400077d1:('and','a10, a10, a8'),0x400077de:('and','a10, a10, a8'),
            0x400077ee:('movi','a2, 13'),0x400077f1:('extui','a4, a4, 0, 5'),
            0x40007c61:('l32i.n','a8, a8, 0'),0x40007c6f:('l32i.n','a8, a8, 0'),
            0x40007d1e:('s32i.n','a2, a8, 0'),0x40007d31:('s32i.n','a9, a8, 0'),
            0x40007d3e:('s32i.n','a2, a8, 0'),0x40007d66:('l32i.n','a3, a3, 0'),
            0x40007d6e:('l32i','a3, a3, 0')}
        for pc,(op,args) in guards.items():
            if instructions[pc][1]!=op or not instructions[pc][2].startswith(args):
                raise ValueError('Changed slot accessor or SPI route operand at '+hex(pc))
        for literal,expected in ((0x40000570,0xabab),(0x40006924,0x3ff44038),
                (0x40007d24,0x40007cf8)):
            if struct.unpack('<I',memory(literal,4))[0]!=expected:
                raise ValueError('Changed PRID/strap/UART callback literal')
        protocol=json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())
        from audit_esp32_allocated_lifecycle import rom_model
        owners=rom_model(root,protocol)
        for slot in set(references.values()):
            if not any(a<=slot and slot+4<=b and cpu==0 for a,b,cpu in owners['zero_records']):
                raise ValueError('Console slot is not reset-zeroed on PRO CPU')
        callbacks={0x40007c69:[value('ets_write_char_uart')],0x40007c75:[]}
        seen,calls,unknown=walk(instructions,0x400076c4,0x40007c31,forced,tables,callbacks)
        for pc in seen|set(guards)|set(references):
            instruction_bytes(memory,pc,instructions[pc][0])
        if unknown or seen&UNBACKED_LITERALS or any(value(n) in seen for n in
                ('ets_install_putc1','ets_install_putc2','sip_init_attach',*prefix['allocation_entrypoints'])):
            raise ValueError('An unmodeled callback, SIP path or allocator remains reachable')
        if value('ets_install_uart_printf') not in seen or value('uart_tx_one_char') not in seen:
            raise ValueError('The fixed console path was not expanded')
        references_in_prefix={pc:v for pc,v in references.items() if pc in seen}
        functions=[(s['st_value'],s['st_value']+s['st_size']) for s in symbols.iter_symbols()
            if s['st_info']['type']=='STT_FUNC' and s['st_size']]
        frames=frame_inventory(instructions,seen,calls,functions)
        frame_sum=sum(f['bytes'] for f in frames)
        if frame_sum>owners['stack_high']-owners['stack_low']:
            raise ValueError('Declared reachable frames escape the reserved PRO stack capacity')
    return {'audit':'pass','rom_sha256':prefix['rom_sha256'],'prefix_sha256':sha(saved),
        'retained_cold_resets':15,'new_board_resets':0,'new_model_calls':0,
        'forced_branch_successors':{hex(p):v for p,v in forced.items()},
        'putc_direct_address_references':{hex(p):v for p,v in references.items()},
        'putc_direct_references_in_prefix':{hex(p):v for p,v in references_in_prefix.items()},
        'admitted_indirect_calls':{hex(p):v for p,v in callbacks.items()},
        'reachable_instruction_pcs':sorted(seen),'calls':calls,
        'unresolved_indirect_sites':unknown,'control_targets_closed_under_declared_slot_values':True,
        'console_alias_exhaustiveness_verified':False,
        'reachable_frame_reservations':frames,'sum_reachable_entry_frame_bytes':frame_sum,
        'reserved_pro_stack_bytes':owners['stack_high']-owners['stack_low'],
        'compiled_function_call_graph_acyclic':True,
        'rom_owner_exhaustiveness_verified':False,'ranking_eligible':False,
        'whole_lifecycle_peak_allocated_occupancy_bytes':None,
        'scope':'Normal synchronous PRO cold-SPI prefix through first image handoff. Slot1 is initially null and the reached setter installs the fixed UART writer; slot2 has no reached direct setter. All direct slot-address references are bound to ROM bytes. Fault paths, pointer-derived aliases and asynchronous callbacks are not inferred absent from this control-flow result.',
        'remaining':['Close pointer-derived writes and normal exception/interrupt ownership against the ROM capacity envelope before promoting lifecycle RAM. Direct slot-reference closure alone is not a general no-alias proof.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Replay on leon into a new persistent report')
    result=audit(ROOT)
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('reachable_instruction_pcs','calls')},indent=2))
