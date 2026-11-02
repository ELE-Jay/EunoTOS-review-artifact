"""Audit native periodic IRQ-return reservation snapshots, without inferring a peak."""
import re
import struct
import json
from pathlib import Path


def build(source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_freertos_ram_lifetimes import calls
    from build_esp32_zephyr_message_lifetimes import TICK_NATIVE
    from run_esp32_followup import sha
    provenance = Path(__file__).resolve().parents[1]/'artifacts/reports/zephyr-tick-source-v1.json'
    official = json.loads(provenance.read_text())
    if len(official) != len(TICK_NATIVE) or {r['path'] for r in official} != set(TICK_NATIVE) or any(
            r['url'] != 'https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/'+r['path'] or
            sha(source/'native-source'/r['path']) != r['sha256'] for r in official):
        raise ValueError("Pinned official native IRQ/timer source identity differs")
    text = {p:(source/"native-source"/p).read_text() for p in TICK_NATIVE}
    if 'z_get_next_switch_handle(interrupted) : interrupted;' not in text[TICK_NATIVE[0]] or \
            'sys_clock_announce(IS_ENABLED(CONFIG_TICKLESS_KERNEL) ? dticks : 1);' not in text[TICK_NATIVE[-1]] or \
            'ret = &frame->ptr_to_bsa;' not in (source/"native-source/arch/xtensa/core/thread.c").read_text():
        raise ValueError("Native context/periodic-clock anchors differ")
    with (source/"application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name('.symtab')
        s = symbols.get_symbol_by_name('tm_z_live_layout')[0]
        section = elf.get_section(s['st_shndx'])
        offset = s['st_value'] - section['sh_addr']
        layout = struct.unpack('<II', section.data()[offset:offset+8])
        records = symbols.get_symbol_by_name('tm_z_live_records')[0]
        if layout[0] != 68 or layout[1] >= 96 or records['st_size'] != 128*76:
            raise ValueError("Compiled native BSA/TCB/record layout differs")
    machine = calls(source, [('ccompare_isr','__wrap_sys_clock_announce'),
        ('__wrap_sys_clock_announce','sys_clock_announce'),
        ('xtensa_excint1_c','return_to'), ('return_to','__wrap_z_get_next_switch_handle'),
        ('__wrap_z_get_next_switch_handle','z_get_next_switch_handle')], require_iram=False)
    return {'native_tick_stack_snapshots':True, 'native_tick_source_manifest_sha256':sha(provenance), 'tick_stack_layout':{
        'bsa_bytes':layout[0], 'switch_handle_offset':layout[1],
        'record_capacity':128, 'record_bytes':76}, 'native_tick_calls':machine}


def observations(lines, proof, events):
    header = re.compile(r'TM_Z_LIVE samples=(\d+) ticks=(\d+) records=(\d+) maximum=(\d+) pending=0 bsa_bytes=68')
    record = re.compile(r'TM_Z_LIVE record=(\d+) sample=(\d+) tick=(\d+) current=(\d+) irq_sp=(\d+) heap=(\d+) events=(\d+) total=(\d+)')
    task = re.compile(r'TM_Z_LIVE record=(\d+) task=(\d+) tcb=(\d+) handle=(\d+) bsa=(\d+)')
    heads = [m for s in lines if (m:=header.fullmatch(s))]
    rows = [tuple(map(int,m.groups())) for s in lines if (m:=record.fullmatch(s))]
    tasks = [tuple(map(int,m.groups())) for s in lines if (m:=task.fullmatch(s))]
    if len(heads) != 1 or sum(s.startswith('TM_Z_LIVE ') for s in lines) != 1+len(rows)+len(tasks):
        raise ValueError("Incomplete/invalid native tick records")
    samples,ticks,count,maximum = map(int,heads[0].groups())
    if not 8000 <= samples <= 11000 or ticks != samples or not 0 < count <= 128 or len(rows) != count:
        raise ValueError("Native periodic observation window differs")
    r = proof['reservations']
    bounds = {r['z_main_thread'][0]:r['z_main_stack'],r['z_idle_threads'][0]:r['z_idle_stacks'],
        r['threads'][0]:[r['stacks'][0],4096],r['threads'][0]+480:[r['stacks'][0]+20480,4096]}
    irq,capacity = r['z_interrupt_stacks']
    last = 0
    output = []
    for i,(index,sample,tick,current,sp,heap,epoch,total) in enumerate(rows):
        if index != i or not last < sample <= samples or tick != sample or current not in bounds or \
                not irq <= sp < irq+capacity or sp%16 or not 0 < epoch <= len(events) or \
                events[epoch-1]['allocated'] != heap:
            raise ValueError("Tick sample, IRQ pointer or native heap epoch differs")
        group = [t for t in tasks if t[0] == i]
        if len(group) != 4 or [t[1] for t in group] != list(range(4)) or {t[2] for t in group} != set(bounds):
            raise ValueError("Simultaneous native task inventory differs")
        detail = []
        depth = irq+capacity-sp
        for _,_,tcb,handle,bsa in group:
            low,size = bounds[tcb]
            if not low <= handle < handle+4 <= bsa or bsa+68 > low+size or handle%4 or bsa%4:
                raise ValueError("Native context handle/BSA outside declared stack")
            depth += low+size-handle
            detail.append({'tcb':tcb,'stack_low':low,'stack_top':low+size,'handle':handle,
                'bsa':bsa,'restored_sp':bsa+68,'reserved_span_bytes':low+size-handle})
        if total != depth or output and depth <= output[-1]['simultaneous_stack_reserved_span_bytes']:
            raise ValueError("Native record-high sum differs")
        output.append({'sample':sample,'tick':tick,'current_tcb':current,'irq_sp':sp,
            'irq_reserved_span_bytes':irq+capacity-sp,'heap_occupied_bytes':heap,'heap_event_count':epoch,
            'tasks':detail,'simultaneous_stack_reserved_span_bytes':depth})
        last = sample
    if output[-1]['simultaneous_stack_reserved_span_bytes'] != maximum or any(t[0] >= count for t in tasks):
        raise ValueError("Native maximum/record binding differs")
    return {'samples':samples,'record_high_snapshots':output,'maximum_sampled_stack_reserved_span_bytes':maximum,
        'new_ram_bytes_to_add':0,'exact_peak_established':False,'whole_live_ram_peak_bytes':None,
        'scope':'100-Hz native IRQ-return context reservations, observer included; not exact live or whole-RAM peak'}
