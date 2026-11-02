#!/usr/bin/env python3
"""Replay allocated capacities across normal boot, image handoff and original TM."""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = 'registry/esp32_allocated_lifecycle_v1.json'
BOOT = 'artifacts/reports/esp32-boot-handoff-build-v1/paired-bootloader'


def reached_peak(phase_bounds, witnesses):
    if not phase_bounds or not witnesses or any(v < 0 for v in [*phase_bounds.values(),*witnesses.values()]):
        raise ValueError('Missing or invalid allocation phase coverage')
    upper, lower = max(phase_bounds.values()), max(witnesses.values())
    if lower > upper:
        raise ValueError('A witness escapes its lifecycle bound')
    return {'lower_bytes':lower, 'upper_bytes':upper,
        'peak_bytes':lower if lower == upper else None, 'complete':lower == upper}


def table_rows(data, width):
    if width not in (3,4) or not data or len(data) % (4*width):
        raise ValueError('Invalid ROM initialization table width')
    rows = list(struct.iter_unpack('<'+'I'*width,data))
    for row in rows:
        if row[1] < row[0] or row[0] % 4 or row[1] % 4 or row[-1] not in (0,1):
            raise ValueError('Invalid ROM initialization record')
    return rows


class Text(HTMLParser):
    def __init__(self):
        super().__init__();self.parts=[]
    def handle_data(self,data):self.parts.append(data)


def rom_model(root, protocol):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_runtime_reservations import compiled_regions
    from run_esp32_followup import sha
    spec = protocol['rom'];folder=root/spec['directory'];path=folder/spec['elf']
    if sha(path) != spec['sha256'] or sha(root/spec['startup_document']) != spec['startup_document_sha256']:
        raise ValueError('Pinned official ROM/document differs')
    manifest=json.loads((folder/'manifest.json').read_text());archive=folder/'esp-rom-elfs-20260528.tar.gz'
    if sha(archive) != manifest['files'][archive.name]['sha256'] or \
            sha(archive) not in (folder/'esp-rom-elfs-20260528-checksum.sha256').read_text():
        raise ValueError('Official ROM archive differs from its published checksum')
    with tarfile.open(archive,'r:gz') as tar:
        member=manifest['files'][spec['elf']]['archive_member']
        if hashlib.sha256(tar.extractfile(member).read()).hexdigest() != sha(path):
            raise ValueError('ROM ELF is not the published member')
    document=Text();document.feed((root/spec['startup_document']).read_text())
    words=' '.join(' '.join(document.parts).split())
    for phrase in ('APP CPU will be held in reset','before this point all allocations must be static or on the stack',
                   'but it only enables flash MMU for PRO CPU'):
        if phrase not in words:raise ValueError('Required vendor startup contract is absent')
    _,reserved=compiled_regions(root/protocol['images'][0]['source']/'application.elf')
    reserved={r['symbol']:r for r in reserved}
    shared=reserved['reserved_region_rom_data'];pro=reserved['reserved_region_rom_pro_data']
    cache=reserved['reserved_region_cpu0_cache']
    with path.open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        def value(name):return symbols.get_symbol_by_name(name)[0]['st_value']
        def memory(address,size):
            for section in elf.iter_sections():
                if section['sh_type']!='SHT_NOBITS' and section['sh_addr']<=address and \
                        address+size<=section['sh_addr']+section['sh_size']:
                    return section.data()[address-section['sh_addr']:address-section['sh_addr']+size]
            raise ValueError('ROM table is outside initialized ROM sections')
        copy_lo,copy_hi=[value(n) for n in ('_data_start','_data_end')]
        bss_lo,bss_hi=[value(n) for n in ('_bss_table_start','_bss_table_end')]
        copy=table_rows(memory(copy_lo,copy_hi-copy_lo),4)
        zero=table_rows(memory(bss_lo,bss_hi-bss_lo),3)
        if (len(copy),len(zero)) != (13,13) or value('_bss_end_sip') != shared['end'] or \
                value('_bss_end_etsc_pro') != pro['end']:
            raise ValueError('ROM reset tables do not match the compiled native ABI')
        stack_low,stack_high=[value(n) for n in ('_stack_sentry','__stack')]
        workspace=[(shared['start'],shared['end']),(pro['start'],stack_high)]
        for row in copy+zero:
            if row[0]!=row[1] and not any(a<=row[0]<row[1]<=b for a,b in workspace):
                raise ValueError('Normal ROM initialization escapes the declared owner sets')
        if not pro['start'] < pro['end'] < stack_low < stack_high or cache['bytes'] != 32768:
            raise ValueError('Unexpected ROM/cache capacity ABI')
        fixed=[(r['start'],r['end']) for r in (shared,pro,cache)]
        temporary=[(pro['end'],stack_high)]
    return {'fixed':fixed, 'temporary':temporary, 'workspace':workspace+[(cache['start'],cache['end'])],
        'copy_records':copy,'zero_records':zero,'stack_low':stack_low,'stack_high':stack_high,
        'elf_sha256':sha(path),'startup_document_sha256':sha(root/spec['startup_document']),
        'contract':'Normal cold SPI flash boot, CPU1 held reset, no Bluetooth controller or RTC wake stub; source-bound allocated capacities, not byte contents'}


def physical(spans):
    from audit_esp32_resources import physical_intervals
    return [p for a,b in spans for p in physical_intervals(a,b-a) if b>a]


def union(*groups):
    from audit_esp32_resources import union_bytes
    return union_bytes([p for spans in groups for p in physical(spans)])


def image(root, source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import RAM, image_length, static_footprint
    from run_esp32_followup import sha
    folder=root/source;data=(folder/'application.bin').read_bytes();image_length(data)
    position=24;loaded=[]
    for _ in range(data[1]):
        address,size=struct.unpack_from('<II',data,position);position+=8+size
        if size and any(a<=address<address+size<=b for a,b in RAM):loaded.append((address,address+size))
    with (folder/'application.elf').open('rb') as stream:
        elf=ELFFile(stream);entry=elf['e_entry']
        resident=[(s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in elf.iter_segments()
            if s['p_type']=='PT_LOAD' and s['p_memsz'] and any(
                a<=s['p_vaddr']<s['p_vaddr']+s['p_memsz']<=b for a,b in RAM)]
    resident+=loaded
    footprint=static_footprint(folder/'application.elf')
    sections=[(int(s['address'],16),int(s['address'],16)+s['bytes']) for s in footprint['ram_sections']]
    if union(resident,sections) != union(resident):raise ValueError('ELF sections escape image reservations')
    return {'resident':resident,'loaded':loaded,'entry':entry,'static_sections_bytes':footprint['static_sram_bytes'],
        'padding_bytes':union(resident)-union(sections),'elf_sha256':sha(folder/'application.elf'),
        'bin_sha256':sha(folder/'application.bin')}


def cold_boot(lines, loaded, entry):
    resets=[s for s in lines if s.startswith('rst:')]
    if len(resets)!=1 or not re.fullmatch(r'rst:0x1 \(POWERON_RESET\),boot:0x13 \(SPI_FAST_FLASH_BOOT\)',resets[0]):
        raise ValueError('RAM lifecycle requires the declared normal cold flash boot')
    rows=[(i,m) for i,s in enumerate(lines) if (m:=re.fullmatch(r'entry 0x([0-9a-f]+)',s))]
    if len(rows)!=1 or int(rows[0][1][1],16)!=entry:raise ValueError('ROM handoff entry differs')
    actual=[(int(m[1],16),int(m[1],16)+int(m[2])) for s in lines[:rows[0][0]]
        if (m:=re.fullmatch(r'load:0x([0-9a-f]+),len:(\d+)',s))]
    if actual != loaded:raise ValueError('Actual ROM RAM segments differ from installed image')


def boot_image(root,source=BOOT):
    from audit_esp32_bootloader_ram import build as boot_proof
    from audit_esp32_resources import RAM, image_length
    from elftools.elf.elffile import ELFFile
    if not (root/source).resolve().is_relative_to((root/'artifacts/reports').resolve()):
        raise ValueError('Boot observation source escapes persistent reports')
    proof=boot_proof(root/source);data=(root/source/'bootloader.bin').read_bytes();image_length(data)
    loaded=[];position=24
    for _ in range(data[1]):
        address,size=struct.unpack_from('<II',data,position);position+=8+size
        if size and any(a<=address<address+size<=b for a,b in RAM):loaded.append((address,address+size))
    with (root/source/'bootloader.elf').open('rb') as stream:
        elf=ELFFile(stream);entry=elf['e_entry'];symbols=elf.get_section_by_name('.symtab')
        resident=[(s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_memsz']]
        if any(symbols.get_symbol_by_name(n) for n in ('malloc','calloc','realloc','_sbrk_r','sbrk')):
            raise ValueError('Bootloader has an additional allocator service')
    cfg=(root/source/'config').read_text().splitlines()
    if 'CONFIG_FREERTOS_UNICORE=y' not in cfg or any(n+'=y' in cfg for n in
            ('CONFIG_SECURE_BOOT','CONFIG_SECURE_BOOT_V2_ENABLED','CONFIG_SECURE_FLASH_ENC_ENABLED','CONFIG_ULP_COPROC_ENABLED')):
        raise ValueError('Bootloader exceeds the declared single-core plain-image contract')
    support=root/source/'source/sdk/components/bootloader_support/src'
    utility=(support/'bootloader_utility.c').read_text()
    image_format=(support/'esp_image_format.c').read_text()
    tail=utility[utility.index('static void set_cache_and_start_app(\n'):]
    if not tail.index('Cache_Read_Enable(0);') < tail.index('bootloader_atexit();') < tail.index('(*entry)();') or \
            'void (*entry_t)(void) __attribute__((noreturn))' not in tail or \
            'esp_image_load_mode_t mode = ESP_IMAGE_LOAD;' not in image_format or \
            'bootloader_console_deinit();' not in utility[utility.index('void bootloader_atexit(void)'):]:
        raise ValueError('Post-load console observation is not on the native non-returning handoff path')
    return {'resident':resident+loaded,'loaded':loaded,'entry':entry,'proof':proof}


def native_configuration(root, spec):
    config=(root/spec['source']/'config').read_text().splitlines()
    excluded=('CONFIG_BT','CONFIG_BT_ENABLED','CONFIG_ESP_BT','CONFIG_SPIRAM',
        'CONFIG_ESP32_SPIRAM','CONFIG_ULP_COPROC_ENABLED','CONFIG_ESP32_ULP_COPROC',
        'CONFIG_SMP','CONFIG_SECURE_BOOT','CONFIG_SECURE_FLASH_ENC_ENABLED')
    if any(name+'=y' in config for name in excluded):
        raise ValueError('Native image has an unmodeled controller, CPU or memory domain')
    return config


def postload_witness(lines):
    phases=[(i,s) for i,s in enumerate(lines) if s.startswith('BOOT_RAM phase=')]
    loaded=[i for i,s in enumerate(lines) if 'Loaded app from partition at offset' in s]
    # Both stored observations are printed at console deinit, after image loading.
    if len(phases)!=2 or len(loaded)!=1 or not loaded[0] < phases[0][0] < phases[1][0] or \
            not phases[0][1].startswith('BOOT_RAM phase=0 ') or \
            not phases[1][1].startswith('BOOT_RAM phase=1 '):
        raise ValueError('Missing post-load/pre-transfer ownership witness')


def audit(root):
    from audit_esp32_allocated_reservations import audit as freertos_audit, freertos_bookkeeping_history
    from run_esp32_tm_ram_lifetimes import EVENT,POOL
    from run_esp32_followup import read_raw_capture,sha
    from run_esp32_zephyr_message_lifetimes import audit as zephyr_audit
    from measure_esp32_nuttx_bootloader import audit as nuttx_audit
    protocol=json.loads((root/PROTOCOL).read_text());model=rom_model(root,protocol);boot=boot_image(root)
    rom_before=union(model['workspace']);fixed=union(model['fixed']);temporary=union(model['temporary'])
    f=freertos_audit(root);zspec=protocol['images'][1];nspec=protocol['images'][2]
    z=zephyr_audit(root/zspec['capture'],root/zspec['source']);n=nuttx_audit(root,root/nspec['capture'])
    for value,path in ((z,root/zspec['capture']/'audit.json'),(n,root/nspec['capture']/'audit.json')):
        if json.loads(json.dumps(value))!=json.loads(path.read_text()):raise ValueError('Retained source/raw audit differs')
    rows=[]
    for spec in protocol['images']:
        system=spec['os'];current=image(root,spec['source']);runs=[]
        cfg=native_configuration(root,spec)
        folder=root/spec['capture'];capture=json.loads((folder/'campaign.json').read_text())
        if capture['board_mac']!=protocol['board_mac'] or capture['independent_resets']!=5:
            raise ValueError('Different board or incomplete lifecycle cohort')
        for index in range(1,6):
            lines=[r['line'] for r in read_raw_capture(folder/'captures',index)]
            first= current if system=='Zephyr' else boot
            cold_boot(lines,first['loaded'],first['entry'])
            first_bound=union(model['workspace'],first['loaded'])
            if system=='FreeRTOS':
                events=[tuple(map(int,m.groups())) for s in lines if (m:=EVENT.fullmatch(s))]
                pools=[tuple(map(int,m.groups())) for s in lines if (m:=POOL.fullmatch(s))]
                native=f['native_scope'];deferred=native['startup_stack_handoff_region']
                if not deferred['start']<=model['temporary'][0][0]<model['temporary'][0][1]<=deferred['start']+deferred['size']:
                    raise ValueError('Inherited workspace is not charged before native handoff')
                history=freertos_bookkeeping_history(events,pools,deferred['start'],current['static_sections_bytes'])
                point=max(history,key=lambda r:r['accounted_bytes'])
                native_peak=point['accounted_bytes']+current['padding_bytes']+fixed
                loader_bound=union(model['workspace'],boot['resident'],current['loaded'])
                if current['padding_bytes']+fixed != f['fixed_reservations_outside_static_bytes']:
                    raise ValueError('Image padding/hardware union disagrees with native exclusions')
                bounds={'first_stage':first_bound,'loader':loader_bound,'native':native_peak}
                witnesses={'native':native_peak};origin='native-heap-event-%d'%point['event_cursor']
                components={'software_sections_and_native_peak_bytes':point['accounted_bytes'],
                    'image_padding_bytes':current['padding_bytes'],'fixed_rom_cache_bytes':fixed}
            elif system=='Zephyr':
                observed=z['runs'][index-1];state=observed['application_startup_stack']
                if state.get('entry_vector_base')!=0x40000000 or not observed['heap_and_stacks_already_in_static_sram']:
                    raise ValueError('Zephyr lacks a coincident ROM-vector ownership witness')
                native_peak=union(current['resident'],model['workspace'])
                bounds={'first_stage':first_bound,'native':native_peak};witnesses={'native_entry':native_peak}
                origin='recorded-ROM-vector-native-entry'
                components={'resident_image_bytes':union(current['resident']),
                    'fixed_rom_cache_bytes':fixed,'inherited_rom_workspace_bytes':temporary}
            else:
                observed=n['runs'][index-1]
                startup=(root/spec['source']/'native-source/arch/xtensa/src/esp32/esp32_start.c').read_text()
                if 'CONFIG_BUILD_FLAT=y' not in cfg or not startup.index('sp = (uint32_t)g_idlestack') < \
                        startup.index('"wsr %0, vecbase') < startup.index('  nx_start();'):
                    raise ValueError('NuttX does not retire inherited stack/vectors before native initialization')
                loader_peak=union(boot['resident'],current['loaded'],model['workspace'])
                # App RAM covers all bootstrap IRAM; surviving loader text/data are disjoint.
                bootstrap=[p for p in boot['resident'] if 0x40080000<=p[0]<0x400a0000]
                if union(current['loaded'],bootstrap)!=union(current['loaded']):
                    raise ValueError('Unproven bootstrap lifetime outside loaded app RAM')
                native_peak=observed['software_peak_bytes']+current['padding_bytes']+fixed
                entry_peak=union(current['resident'],model['workspace'])
                bounds={'first_stage':first_bound,'loader':loader_peak,'native_entry':entry_peak,'native':native_peak}
                witnesses={'after_loaded_segments':loader_peak,'native':native_peak}
                origin='loader-final-loaded-segment-observation'
                components={'loader_and_loaded_application_bytes':union(boot['resident'],current['loaded']),
                    'fixed_rom_cache_bytes':fixed,'inherited_rom_workspace_bytes':temporary}
                if len(observed['boot_stages'])!=2:raise ValueError('Missing retained loader observations')
                postload_witness(lines)
            certificate=reached_peak(bounds,witnesses)
            runs.append({'reset':index,'phase_upper_bounds':bounds,'coincident_witnesses':witnesses,
                'peak_origin':origin,'components_at_witness':components,'certificate':certificate,
                'raw_sha256':sha(folder/'captures'/('reset%d.raw'%index))})
        rows.append({'os':system,**spec,'elf_sha256':current['elf_sha256'],'bin_sha256':current['bin_sha256'],
            'static_sections_bytes':current['static_sections_bytes'],'image_padding_bytes':current['padding_bytes'],
            'runs':runs,'complete_declared_model':all(r['certificate']['complete'] for r in runs),
            'model_peak_allocated_occupancy_bytes':[r['certificate']['peak_bytes'] for r in runs],
            'whole_lifecycle_peak_allocated_occupancy_bytes':None})
    return json.loads(json.dumps({'audit':'pass','protocol_sha256':sha(root/PROTOCOL),'board_mac':protocol['board_mac'],
        'metric':'peak allocated RAM occupancy','unit':'bytes','rom':model,'bootloader':BOOT,
        'rows':rows,'retained_independent_resets':15,
        'campaign_cohort':{'prior_resets_reused':10,'new_zephyr_resets':5,'separate_zephyr_validation_resets':1},
        'additional_resets_during_replay':0,'new_model_calls':0,
        'complete_declared_model':all(r['complete_declared_model'] for r in rows),
        'rom_owner_exhaustiveness_verified':False,'complete_declared_lifecycle':False,'ranking_eligible':False,
        'scope':'Normal cold flash boot through third original message report, including observer, fixed ROM/cache capacities, native stack/vector ownership transitions, loaded-image padding and native allocations. Addressable internal SRAM/RTC allocation, not dirty byte contents or exact live stack use.',
        'remaining':['The ROM reset copy/zero tables establish initialized owners, not an exhaustive proof of all transient ROM allocations on the observed SPI path; model results remain provisional.',
            'Matched perturbation controls and native/uninstrumented ranking remain separate; preserve native-loader performance/energy groups.']}))


def summary(value):
    return {k:value[k] for k in ('audit','scope','board_mac','complete_declared_model','complete_declared_lifecycle','ranking_eligible',
        'retained_independent_resets','campaign_cohort','additional_resets_during_replay','new_model_calls','remaining')} | {'rows':[
        {k:r[k] for k in ('os','source','capture','elf_sha256','bin_sha256','static_sections_bytes',
            'image_padding_bytes','complete_declared_model','model_peak_allocated_occupancy_bytes',
            'whole_lifecycle_peak_allocated_occupancy_bytes')} | {
                'peak_origin':r['runs'][0]['peak_origin'],'phase_upper_bounds':r['runs'][0]['phase_upper_bounds']}
        for r in value['rows']]}


def paper_text(value):
    rows=value['rows']
    if value['audit']!='pass' or not value['complete_declared_model'] or \
            value['complete_declared_lifecycle'] or value['ranking_eligible']:
        raise ValueError('This paragraph reports provisional model accounting, not qualified whole-RAM scores')
    peaks=[]
    for row in rows:
        if len(set(row['model_peak_allocated_occupancy_bytes']))!=1:
            raise ValueError('Report per-reset variation instead of a single repeated value')
        peaks.append(row['model_peak_allocated_occupancy_bytes'][0])
    return ('A common allocation-capacity replay combines physical image segments, native block '
        'transitions and fixed ROM/cache reservations. Five new Zephyr message resets and a separate '
        'allocator check preserve the original workload; entry readback records the ROM vector base '
        'in every reset, and the original Flash image is restored. Together with ten retained '
        'FreeRTOS/NuttX resets, the declared owner model gives provisional peaks of '
        f'{peaks[0]:,}, {peaks[1]:,} and {peaks[2]:,}\\,B for FreeRTOS, Zephyr and NuttX, respectively. '
        'The model includes loader overlap, alignment gaps, allocated stack capacity and mandatory '
        'free-block metadata without summing separate phase maxima. ROM reset copy/zero tables do '
        'not establish exhaustiveness of transient ROM ownership; these model values therefore '
        'remain separate from qualified whole-lifecycle RAM and ranking. Actual stack use is auxiliary.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if sys.platform!='linux':parser.error('Evidence remains on leon')
    result=audit(ROOT)
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(summary(result),indent=2))
