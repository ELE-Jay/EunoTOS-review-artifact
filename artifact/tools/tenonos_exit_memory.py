#!/usr/bin/env python3
"""Describe and decode the existing observer; never rebuild its guest image."""
from pathlib import Path
import struct

from audit_tenonos_memory_lifecycle import require,parse

FIELDS=('op','phase','p','q','n','current','peak')
VARIABLES=('events','count','disabled','phase','overflow','registrations','completed','allocator')


def unqualified(die):
    while die.tag in ('DW_TAG_typedef','DW_TAG_const_type','DW_TAG_volatile_type','DW_TAG_restrict_type'):
        die=die.get_DIE_from_attribute('DW_AT_type')
    return die


def members(die):
    result={}
    for m in unqualified(die).iter_children():
        if m.tag!='DW_TAG_member':continue
        location=m.attributes['DW_AT_data_member_location'].value
        require(isinstance(location,int),'Unsupported native field-location expression')
        kind=unqualified(m.get_DIE_from_attribute('DW_AT_type'))
        width=kind.attributes.get('DW_AT_byte_size')
        result[m.attributes['DW_AT_name'].value.decode()]={'offset':location,'bytes':width.value if width else None,'die':kind}
    return result


def layout(elf_path,tlsf):
    from elftools.elf.elffile import ELFFile
    with elf_path.open('rb') as stream:
        elf=ELFFile(stream);require(elf['e_machine']=='EM_AARCH64' and elf.little_endian,'Different observer architecture')
        table=elf.get_section_by_name('.symtab');local={};filename=''
        for s in table.iter_symbols():
            if s['st_info']['type']=='STT_FILE':filename=s.name
            elif filename=='iotos_memory.c' and s['st_info']['bind']=='STB_LOCAL':
                local[s.name]={'address':s['st_value'],'bytes':s['st_size']}
        require(all(n in local for n in VARIABLES+('allocate','release','addmem')),'Observer local-symbol scope missing')
        require(local['events']['bytes']==4096*56 and all(local[n]['bytes']==4 for n in VARIABLES if n not in ('events','allocator')) and
                local['allocator']['bytes']==8,'Different observer storage ABI')
        dwarfs=elf.get_dwarf_info();owner=None;pool=None
        for cu in dwarfs.iter_CUs():
            name=cu.get_top_DIE().attributes.get('DW_AT_name')
            if not name:continue
            base=Path(name.value.decode()).name
            for die in cu.iter_DIEs():
                attr=die.attributes.get('DW_AT_name')
                if base=='iotos_memory.c' and die.tag=='DW_TAG_variable' and attr and attr.value==b'allocator':
                    owner=unqualified(die.get_DIE_from_attribute('DW_AT_type')).get_DIE_from_attribute('DW_AT_type')
                if base=='tlsf.c' and attr and attr.value==b'tlsf_t' and die.tag=='DW_TAG_typedef':pool=unqualified(die)
        require(owner is not None,'Native allocator DWARF type missing');owner=unqualified(owner)
        fields=members(owner);size=owner.attributes['DW_AT_byte_size'].value
        callback_names=('malloc_backend','free_backend','addmem') if tlsf else ('palloc','pfree','addmem')
        callbacks=[{'field':name,'offset':fields[name]['offset'],'bytes':fields[name]['bytes'],
            'expected':local[function]['address']} for name,function in zip(callback_names,('allocate','release','addmem'))]
        require(all(f['bytes']==8 for f in callbacks),'Different callback pointer width')
        if tlsf:
            require(pool is not None,'TLSF native statistics type missing');stats=members(pool);prefix=size
            current,peak='used_size','max_size'
        else:
            require('_stats' in fields,'Buddy statistics not compiled');stats=members(fields['_stats']['die']);prefix=fields['_stats']['offset']
            current,peak='cur_mem_use','max_mem_use'
        counters={label:{'offset':prefix+stats[name]['offset'],'bytes':stats[name]['bytes']} for label,name in (('current',current),('peak',peak))}
        require(all(f['bytes'] in (4,8) for f in counters.values()),'Unsupported native counter width')
        functions={}
        for name in ('main','printf','ukplat_terminate'):
            found=table.get_symbol_by_name(name);require(found and len(found)==1,'Missing/ambiguous exit control function')
            functions[name]={'address':found[0]['st_value'],'bytes':found[0]['st_size']}
        found=table.get_symbol_by_name('__wrap_uk_alloc_register')
        require(found and len(found)==1,'Missing native registration wrapper')
        functions['register']={'address':found[0]['st_value'],'bytes':found[0]['st_size']}
        main=table.get_symbol_by_name('main')[0];section=elf.get_section(main['st_shndx'])
        data=section.data()[main['st_value']-section['sh_addr']:main['st_value']-section['sh_addr']+main['st_size']]
        # The reviewed native sequence is MOV W0,1; LDR count; STR disabled.
        candidates=[]
        for offset in range(0,len(data)-11,4):
            mov,load,store=struct.unpack_from('<3I',data,offset)
            if mov==0x52800020 and load&0xffc003ff==0xb94002a1 and store&0xffc003ff==0xb90002a0:
                loaded=((load>>10)&4095)*4;stored=((store>>10)&4095)*4
                if local['count']['address']-loaded==local['disabled']['address']-stored:
                    candidates.append((offset,loaded,stored))
        require(len(candidates)==1,'Unknown compiled disable boundary')
        offset,loaded,stored=candidates[0];sequence=data[offset:offset+12]
        transition={'pc':main['st_value']+offset+12,'store_pc':main['st_value']+offset+8,
                    'sequence_hex':sequence.hex(),'base_register':'x21','disabled_offset':stored,'count_offset':loaded}
        return {'variables':{n:local[n] for n in VARIABLES},'leaf_entries':[local[n]['address'] for n in ('allocate','release','addmem')],
            'functions':functions,'allocator_bytes':size,'callbacks':callbacks,'native_counters':counters,
            'event_fields':list(FIELDS),'event_bytes':56,'capacity':4096,'allocator':'tlsf' if tlsf else 'buddy',
            'disable_transition':transition}


def decode(raw,count):
    require(0<count<=4096 and len(raw)==count*56,'Incomplete native event bytes')
    return [dict(seq=i,**dict(zip(FIELDS,row))) for i,row in enumerate(struct.iter_unpack('<7Q',raw))]


def event_text(rows,counters):
    require(counters['count']==len(rows),'Event count differs from memory capture')
    lines=['IOTOS_LIFE '+' '.join('%s=%d'%(k,v) for k,v in row.items()) for row in rows]
    lines.append('IOTOS_LIFE_END events=%d overflow=%d registrations=%d completed=%d'%
        tuple(counters[n] for n in ('count','overflow','registrations','completed')))
    return '\n'.join(lines)+'\n'


def verify_prefix(serial,raw,counters):
    rows=decode(raw,counters['count']);require(rows==parse(serial),'Printed prefix differs from native memory bytes')
    return rows
