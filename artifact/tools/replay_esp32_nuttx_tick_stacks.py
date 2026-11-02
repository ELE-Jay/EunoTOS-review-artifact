"""Independent stdlib replay of native same-stack IRQ reservations; no board calls."""
import re


def probe_cost(lines,samples):
    controls=[s for s in lines if s.startswith('TM_N_TICK_CONTROL ')]
    values=[s for s in lines if s.startswith('TM_N_TICK_COST ')]
    if controls!=['TM_N_TICK_CONTROL enabled=1 clock_hz=240000000'] or len(values)!=1:
        raise ValueError('Cycle control/witness inventory differs')
    parts=values[0].split()[1:]
    if len(parts)!=3 or any(not re.fullmatch(r'\w+=\d+',p) for p in parts):
        raise ValueError('Malformed cycle field')
    row={k:int(v) for k,v in (p.split('=') for p in parts)}
    if set(row)!={'calls','cycles','maximum'} or row['calls']!=samples or not \
            0<row['maximum']<=row['cycles']<=row['maximum']*samples or row['maximum']>=2**32:
        raise ValueError('Cycle witness arithmetic differs')
    return row


def observations(lines,symbols):
    def rows(prefix,selected=None):
        result=[]
        for line in lines if selected is None else selected:
            if not line.startswith(prefix):continue
            parts=[p.split('=',1) for p in line[len(prefix):].split()]
            if any(len(p)!=2 or re.fullmatch(r'-?\d+',p[1]) is None for p in parts) or len({p[0] for p in parts})!=len(parts):
                raise ValueError('Malformed/repeated native observation field')
            result.append({k:int(v) for k,v in parts})
        return result
    headers=rows('TM_N_LIVE ')
    # The three record shapes share a prefix, but have disjoint required fields.
    summary=[r for r in headers if 'samples' in r]
    records=[r for r in headers if 'sample' in r]
    tasks=[r for r in headers if 'task' in r]
    if len(summary)!=1 or len(headers)!=1+len(records)+len(tasks):raise ValueError('Native snapshot inventory differs')
    h=summary[0];idle=symbols['g_idletcb'][0]
    if set(h)!={'samples','records','maximum','context','idle'} or h['context']!=216 or h['idle']!=idle or \
            not 8000<=h['samples']<=11000 or not 0<len(records)==h['records']<=128:
        raise ValueError('Native context ABI/sample window differs')
    live=rows('TM_N_STACK live ')
    bounds={r['tcb']:(r['allocation'],r['allocation']+r['usable']) for r in live}
    low,size=symbols['g_idlestack'];bounds[idle]=(low,low+size)
    if len(live)!=4 or len(bounds)!=5:raise ValueError('Retained native task list differs')
    events=rows('TM_N_RAM ',[s for s in lines if s.startswith('TM_N_RAM event=')])
    output=[]
    for i,r in enumerate(records):
        if set(r)!={'record','sample','current','irq_sp','heap','events','total'} or r['record']!=i or \
                not 0<r['sample']<=h['samples'] or output and r['sample']<=output[-1]['sample'] or \
                r['current'] not in bounds or r['irq_sp']%16 or not 0<r['events']<=len(events) or \
                events[r['events']-1]['occupied']!=r['heap']:
            raise ValueError('Sample/current/allocator epoch differs')
        group=[t for t in tasks if t['record']==i]
        if len(group)!=5 or [t['task'] for t in group]!=list(range(5)) or {t['tcb'] for t in group}!=set(bounds):
            raise ValueError('Simultaneous task inventory differs')
        detail=[];total=0
        for t in group:
            a,b=bounds[t['tcb']];lo,hi,ctx,saved=[t[k] for k in ('low','top','regs','saved_sp')]
            if set(t)!={'record','task','tcb','low','top','regs','saved_sp'} or not a<=lo<hi==b or \
                    not lo<=ctx<=hi-216 or ctx%4 or not lo<=saved<=hi or saved%16:
                raise ValueError('Context/SP not inside its allocated native stack')
            depth=hi-min(ctx,saved)
            if t['tcb']==r['current']:
                if not lo<=r['irq_sp']<hi:raise ValueError('IRQ not inside current task stack')
                depth=max(depth,hi-r['irq_sp'])
            total+=depth
            detail.append({'tcb':t['tcb'],'stack_low':lo,'stack_top':hi,'context_address':ctx,
                'restored_sp':saved,'reserved_span_bytes':depth})
        if total!=r['total'] or output and total<=output[-1]['simultaneous_stack_reserved_span_bytes']:
            raise ValueError('Native record-high arithmetic differs')
        output.append({'sample':r['sample'],'current_tcb':r['current'],'irq_sp':r['irq_sp'],
            'heap_occupied_bytes':r['heap'],'heap_event_count':r['events'],'tasks':detail,
            'simultaneous_stack_reserved_span_bytes':total})
    if output[-1]['simultaneous_stack_reserved_span_bytes']!=h['maximum'] or any(t['record']>=h['records'] for t in tasks):
        raise ValueError('Maximum/record binding differs')
    return {'samples':h['samples'],'record_high_snapshots':output,'maximum_sampled_stack_reserved_span_bytes':h['maximum'],
        'new_ram_bytes_to_add':0,'exact_peak_established':False,'whole_live_ram_peak_bytes':None,
        'scope':'100-Hz native timer-entry task/context reservations including same-stack IRQ and observer; not exact live or whole-RAM peak'}
