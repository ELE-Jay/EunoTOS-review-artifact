"""Bind native timer-context observations to stack ownership and allocator epochs."""
import json
from pathlib import Path
import re
import struct


def probe_cost(lines,samples):
    if [s for s in lines if s.startswith('TM_N_TICK_CONTROL ')]!=[
            'TM_N_TICK_CONTROL enabled=1 clock_hz=240000000']:
        raise ValueError('Default tick control/clock differs')
    rows=[s for s in lines if s.startswith('TM_N_TICK_COST ')]
    match=re.fullmatch(r'TM_N_TICK_COST calls=(\d+) cycles=(\d+) maximum=(\d+)',rows[0]) if len(rows)==1 else None
    if match is None:raise ValueError('Tick cycle witness missing/repeated')
    calls,cycles,maximum=map(int,match.groups())
    if calls!=samples or not 0<maximum<=cycles<=calls*maximum or maximum>=2**32:
        raise ValueError('Tick cycle arithmetic/sample coverage differs')
    return dict(calls=calls,cycles=cycles,maximum=maximum)


def build(source):
    from elftools.elf.elffile import ELFFile
    from nuttx_message_observer import TICK_NATIVE
    from run_esp32_followup import sha
    from audit_esp32_freertos_ram_lifetimes import calls
    manifest=Path(__file__).resolve().parents[1]/'artifacts/reports/nuttx-tick-source-v1.json'
    official=json.loads(manifest.read_text())
    if len(official)!=len(TICK_NATIVE) or {r['path'] for r in official}!=set(TICK_NATIVE) or any(
            r['url']!='https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/'+r['path'] or
            sha(source/'native-source'/r['path'])!=r['sha256'] for r in official):
        raise ValueError('Native timer/context sources differ from pinned NuttX 12.2.1')
    with (source/'application.elf').open('rb') as stream:
        elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
        sym=symbols.get_symbol_by_name('bench_n_live_layout')[0]
        section=elf.get_section(sym['st_shndx']);offset=sym['st_value']-section['sh_addr']
        layout=struct.unpack('<7I',section.data()[offset:offset+28])
        rows=symbols.get_symbol_by_name('bench_n_live_records')[0]
        idle=symbols.get_symbol_by_name('g_idletcb')[0]
        if sym['st_size']!=28 or layout!=(216,3,164,60,64,56,128) or \
                layout[2]!=idle['st_size'] or any(n+4>layout[2] for n in layout[3:]) or rows['st_size']!=128*124:
            raise ValueError('Compiled native context/TCB/observer record layout differs')
    return {'native_tick_stack_snapshots':True,'native_tick_source_manifest_sha256':sha(manifest),
        'tick_stack_layout':dict(zip(('context_bytes','sp_index','tcb_bytes','allocation_offset','base_offset',
            'span_offset','regs_offset'),layout)), 'tick_idle_tcb':idle['st_value'],
        'native_tick_calls':calls(source,[('esp32_timerisr','__wrap_nxsched_process_timer'),
            ('__wrap_nxsched_process_timer','nxsched_process_timer'),('xtensa_int_decode','xtensa_irq_dispatch'),
            ('xtensa_irq_dispatch','irq_dispatch')],require_iram=False)}


def observations(lines,proof,events,live):
    summary=re.compile(r'TM_N_LIVE samples=(\d+) records=(\d+) maximum=(\d+) context=(\d+) idle=(\d+)')
    record=re.compile(r'TM_N_LIVE record=(\d+) sample=(\d+) current=(\d+) irq_sp=(\d+) heap=(\d+) events=(\d+) total=(\d+)')
    task=re.compile(r'TM_N_LIVE record=(\d+) task=(\d+) tcb=(\d+) low=(\d+) top=(\d+) regs=(\d+) saved_sp=(\d+)')
    heads=[m for s in lines if (m:=summary.fullmatch(s))]
    records=[tuple(map(int,m.groups())) for s in lines if (m:=record.fullmatch(s))]
    tasks=[tuple(map(int,m.groups())) for s in lines if (m:=task.fullmatch(s))]
    if len(heads)!=1 or sum(s.startswith('TM_N_LIVE ') for s in lines)!=1+len(records)+len(tasks):
        raise ValueError('Native context observations missing/repeated/invalid')
    samples,count,maximum,context,idle=map(int,heads[0].groups())
    if not 8000<=samples<=11000 or not 0<count<=128 or len(records)!=count or \
            context!=proof['tick_stack_layout']['context_bytes'] or idle!=proof['tick_idle_tcb']:
        raise ValueError('Native tick sampling window/layout differs')
    bounds={s['tcb']:(s['allocation'],s['allocation']+s['usable']) for s in live}
    low,n=proof['reservations']['g_idlestack'];bounds[idle]=(low,low+n)
    if len(live)!=4 or len(bounds)!=5:raise ValueError('Original retained task inventory differs')
    output=[];last_sample=0
    for i,(index,sample,current,sp,heap,epoch,total) in enumerate(records):
        if index!=i or not last_sample<sample<=samples or current not in bounds or sp%16 or \
                not 0<epoch<=len(events) or events[epoch-1]['occupied']!=heap:
            raise ValueError('Native sample order/current/heap epoch differs')
        group=[t for t in tasks if t[0]==i]
        if len(group)!=5 or [t[1] for t in group]!=list(range(5)) or {t[2] for t in group}!=set(bounds):
            raise ValueError('Simultaneous task-context set differs')
        detail=[];calculated=0
        for _,_,tcb,low,top,regs,saved in group:
            outer_low,outer_top=bounds[tcb]
            if not outer_low<=low<top==outer_top or not low<=regs<=top-context or regs%4 or \
                    not low<=saved<=top or saved%16:
                raise ValueError('Native context/SP escapes its live stack allocation')
            if tcb==current and not low<=sp<top:raise ValueError('IRQ not on interrupted task stack')
            used=min(regs,saved,sp) if tcb==current else min(regs,saved)
            depth=top-used;calculated+=depth
            detail.append({'tcb':tcb,'stack_low':low,'stack_top':top,'context_address':regs,
                'restored_sp':saved,'reserved_span_bytes':depth})
        if calculated!=total or output and total<=output[-1]['simultaneous_stack_reserved_span_bytes']:
            raise ValueError('Native simultaneous record-high sum differs')
        output.append({'sample':sample,'current_tcb':current,'irq_sp':sp,'heap_occupied_bytes':heap,
            'heap_event_count':epoch,'tasks':detail,'simultaneous_stack_reserved_span_bytes':total})
        last_sample=sample
    if output[-1]['simultaneous_stack_reserved_span_bytes']!=maximum or any(t[0]>=count for t in tasks):
        raise ValueError('Native maximum/record binding differs')
    return {'samples':samples,'record_high_snapshots':output,'maximum_sampled_stack_reserved_span_bytes':maximum,
        'new_ram_bytes_to_add':0,'exact_peak_established':False,'whole_live_ram_peak_bytes':None,
        'scope':'100-Hz native timer-entry task/context reservations including same-stack IRQ and observer; not exact live or whole-RAM peak'}
