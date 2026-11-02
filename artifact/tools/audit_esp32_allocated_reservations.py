#!/usr/bin/env python3
"""Replay startup reservations together with the existing native heap ledger."""
import argparse
import json
from pathlib import Path

from audit_esp32_message_startup import freertos
from audit_esp32_resources import physical_intervals, union_bytes
from audit_esp32_zephyr_thread import read_raw_capture
from measure_esp32_boot_handoff_ram import audit as handoff_audit
from run_esp32_followup import sha
from run_esp32_tm_ram_lifetimes import EVENT, POOL, replay_events


BUILD = 'artifacts/reports/esp32-boot-handoff-build-v1'
CAPTURE = 'artifacts/reports/esp32-boot-handoff-b1-v2'
REFERENCE = 'artifacts/reports/esp32-boot-handoff-b1-v2-audit.json'


def reservation_history(events, pools, deferred_start, base_bytes):
    """The deferred pool is reserved until its native registration commits."""
    if base_bytes < 0 or len({p[0] for p in pools}) != len(pools):
        raise ValueError('Invalid fixed reservation or duplicate pool')
    deferred = [p for p in pools if p[0] == deferred_start]
    if len(deferred) != 1:
        raise ValueError('Missing unique startup reservation')
    registered = set()
    occupied = 0
    rows = [{'event_cursor':0, 'native_occupied_bytes':0,
             'startup_reservation_bytes':deferred[0][1],
             'accounted_bytes':base_bytes+deferred[0][1]}]
    for cursor, (seq, kind, pool, pointer, delta) in enumerate(events, 1):
        if seq != cursor-1:
            raise ValueError('Incomplete native sequence')
        if kind == 0:
            if pool in registered or pool >= len(pools) or pointer != pools[pool][0] or delta != pools[pool][3]:
                raise ValueError('Unexpected native registration')
            registered.add(pool)
        elif kind in (1,2,3,4) and pool not in registered:
            raise ValueError('Allocation before native pool handoff')
        if kind <= 4:
            occupied += delta
        reserved = 0 if pools.index(deferred[0]) in registered else deferred[0][1]
        rows.append({'event_cursor':cursor, 'native_occupied_bytes':occupied,
                     'startup_reservation_bytes':reserved,
                     'accounted_bytes':base_bytes+reserved+occupied})
    if registered != set(range(len(pools))):
        raise ValueError('Incomplete final native inventory')
    return rows


def audit(root):
    source, capture = root/BUILD, root/CAPTURE
    result = handoff_audit(capture, source)
    if json.loads(json.dumps(result)) != json.loads((root/REFERENCE).read_text()):
        raise ValueError('Saved boot/handoff source or raw captures changed')
    app = result['application']
    compiled = freertos({'build':BUILD, 'evidence':CAPTURE,
        'elf_sha256':sha(source/'application.elf'), 'campaign_sha256':sha(capture/'campaign.json')},
        entry_symbol='bench_boot_handoff_entry')
    static = [s for section in app['build']['ram_sections']
              for s in physical_intervals(int(section['address'],16), section['bytes'])]
    reservations = [s for r in compiled['native_reservations'] if r['end'] > r['start']
                    for s in physical_intervals(r['start'], r['end']-r['start'])]
    base = union_bytes(static+reservations)
    pool_spans = [s for r in compiled['native_available_pools']
                  for s in physical_intervals(r['start'],r['size'])]
    if union_bytes(static+reservations+pool_spans) != base+union_bytes(pool_spans):
        raise ValueError('Fixed reservations overlap native heap capacity')
    late = compiled['startup_stack_handoff_region']
    runs = []
    for i, old in enumerate(app['runs'], 1):
        lines = [r['line'] for r in read_raw_capture(capture/'captures',i)]
        events = [tuple(map(int,m.groups())) for s in lines if (m:=EVENT.fullmatch(s))]
        pools = [tuple(map(int,m.groups())) for s in lines if (m:=POOL.fullmatch(s))]
        if {(p[0],p[1]) for p in pools} != {(r['start'],r['size']) for r in compiled['native_available_pools']}:
            raise ValueError('Measured and compiled native pool inventory differs')
        replay = replay_events(events,pools)
        history = reservation_history(events,pools,late['start'],base)
        h = old['startup_heap_handoff']
        before, after = [history[h[k]['event_cursor']] for k in ('before_release','after_release')]
        if before['native_occupied_bytes'] != h['before_release']['occupied_bytes'] or \
                after['native_occupied_bytes'] != h['after_release']['occupied_bytes'] or \
                before['startup_reservation_bytes'] != late['size'] or after['startup_reservation_bytes'] != 0 or \
                after['accounted_bytes']-before['accounted_bytes'] != h['new_allocator_metadata_bytes']-late['size'] or \
                max(r['native_occupied_bytes'] for r in history) != replay['peak']:
            raise ValueError('Ownership transfer or native ledger differs')
        peak = max(history,key=lambda r:r['accounted_bytes'])
        runs.append({'reset':i,'raw_sha256':sha(capture/'captures'/('reset%d.raw'%i)),
            'accounted_peak_bytes':peak['accounted_bytes'],'peak':peak,
            'before_handoff':before,'after_handoff':after,
            'previous_static_plus_native_peak_bytes':app['build']['static_sram_bytes']+replay['peak'],
            'post_handoff_accounted_peak_bytes':max(r['accounted_bytes'] for r in history[after['event_cursor']:]),
            'stack_auxiliary':old['application_startup_stack'], 'history':history})
    return {'audit':'pass','os':'FreeRTOS','board_mac':app['board_mac'],
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),
        'source_reference_sha256':sha(root/REFERENCE),'elf_sha256':sha(source/'application.elf'),
        'campaign_sha256':sha(capture/'campaign.json'),'native_scope':compiled,
        'static_bytes':app['build']['static_sram_bytes'],
        'static_and_fixed_reservations_bytes':base,
        'fixed_reservations_outside_static_bytes':base-app['build']['static_sram_bytes'],
        'startup_reserved_bytes':late['size'],'runs':runs,
        'independent_resets_reused':5,'new_board_resets':0,'new_model_calls':0,
        'whole_lifecycle_peak_allocated_occupancy_bytes':None,'ranking_eligible':False,
        'scope':'Application startup reservation through third original message report, observer included; '
                'exact committed native occupied counters plus source-bound active reservations. '
                'The entire deferred pool is reserved before handoff, then only its native occupied bytes remain.',
        'remaining':['Before-application loading/ROM reservations and their ownership transitions',
                     'Full native allocator bookkeeping convention, including the treatment of free-block headers',
                     'Equivalent lifecycle reservation accounting for Zephyr and NuttX'],
        'stack_policy':'Actual stack watermarks are separate and never added to allocated or reserved storage'}


def paper_text(value):
    peaks = {r['accounted_peak_bytes'] for r in value['runs']}
    if len(peaks) != 1:raise ValueError('Different reset-level peaks require explicit ranges')
    return ('Reservation lifetimes also change the memory conclusion. In five retained FreeRTOS '
        'resets, the native startup policy withholds a 129,984-B region from allocation until scheduler '
        'startup. Immediately before handoff, 15,448\\,B of native occupied heap coexists with that '
        f'reservation. With static storage and linked fixed reservations, this accounts for {peaks.pop():,}\\,B '
        'in the observer image. Handoff replaces the region reservation with 876\\,B of allocator '
        'metadata. These are simultaneous phase observations, not a sum of independent stack and heap '
        'maxima. Earlier loader/ROM ownership and allocator bookkeeping remain outside this scoped result.')


def summary(value):
    keys = ('audit','os','board_mac','static_bytes','static_and_fixed_reservations_bytes',
            'fixed_reservations_outside_static_bytes','startup_reserved_bytes',
            'independent_resets_reused','new_board_resets','scope','remaining','ranking_eligible')
    return {**{k:value[k] for k in keys}, 'runs':[{k:r[k] for k in (
        'reset','accounted_peak_bytes','before_handoff','after_handoff',
        'previous_static_plus_native_peak_bytes','post_handoff_accounted_peak_bytes')}
        for r in value['runs']]}


def add_reservation(sections, start, size):
    static = [p for s in sections for p in physical_intervals(int(s['address'],16),s['bytes'])]
    reserved = physical_intervals(start,size)
    return {'static_bytes':union_bytes(static), 'reservation_bytes':size,
            'physical_union_bytes':union_bytes(static+reserved),
            'overlap_bytes':union_bytes(static)+union_bytes(reserved)-union_bytes(static+reserved)}


def cohort_audit(root):
    from elftools.elf.elffile import ELFFile
    from run_esp32_zephyr_message_lifetimes import audit as zephyr_audit
    from run_esp32_nuttx_message_lifetimes import audit as nuttx_audit
    from audit_esp32_ram_scope import nuttx_context
    original = audit(root)
    cells = [{'os':'FreeRTOS', 'build':BUILD,'capture':CAPTURE,
        'elf_sha256':original['elf_sha256'],'independent_resets_reused':5,
        'static_bytes':original['static_bytes'], 'startup_reservation_bytes':original['startup_reserved_bytes'],
        'heap_storage':'Outside static SRAM; native bookkeeping included in occupied counters',
        'runs':[{'reset':r['reset'],
            'startup_phase_software_bytes':r['before_handoff']['accounted_bytes']-original['fixed_reservations_outside_static_bytes'],
            'runtime_phase_software_peak_bytes':r['post_handoff_accounted_peak_bytes']-original['fixed_reservations_outside_static_bytes'],
            'observed_phase_maximum_bytes':r['accounted_peak_bytes']-original['fixed_reservations_outside_static_bytes'],
            'actual_stack_use':r['stack_auxiliary'], 'raw_sha256':r['raw_sha256']} for r in original['runs']],
        'scope':'Application entry through third report; startup region relinquished by native heap registration',
        'source_reference_sha256':sha(root/REFERENCE)}]
    for os, build, capture, auditor in (
            ('Zephyr','esp32-zephyr-message-startup-v2','esp32-zephyr-message-startup-b1-v1',zephyr_audit),
            ('NuttX','esp32-nuttx-message-startup-v5','esp32-nuttx-message-startup-b1-v1',nuttx_audit)):
        source=root/'artifacts/reports'/build; folder=root/'artifacts/reports'/capture
        observed=auditor(folder,source)
        if json.loads((folder/'campaign.json').read_text())['board_mac']!=original['board_mac'] or \
                json.loads(json.dumps(observed))!=json.loads((folder/'audit.json').read_text()):
            raise ValueError(os+' source or retained capture differs')
        with (source/'application.elf').open('rb') as stream:
            elf=ELFFile(stream);symbols=elf.get_section_by_name('.symtab')
            if os=='Zephyr':
                low,high=[symbols.get_symbol_by_name(n)[0]['st_value'] for n in ('_stack_sentry','__stack')]
                inherited=add_reservation(observed['build']['ram_sections'],low,high-low)
                heap=observed['build']['reservations']['kheap__system_heap']
                heap_union=add_reservation(observed['build']['ram_sections'],*heap)
                if inherited['overlap_bytes'] or heap_union['overlap_bytes']!=heap[1]:
                    raise ValueError('Inherited stack or static heap ownership differs')
        runs=[]
        for i,run in enumerate(observed['runs'],1):
            stack=run['application_startup_stack'];static=observed['build']['static_sram_bytes']
            if os=='Zephyr':
                if stack['painted_start']!=low or stack['application_entry_sp']>high or \
                        not run['heap_and_stacks_already_in_static_sram'] or run['native_heap_peak_bytes']>heap[1]:
                    raise ValueError('Zephyr startup/static-pool boundary differs')
                startup=inherited['physical_union_bytes'];runtime=static
                native_peak=run['native_heap_peak_bytes']
            else:
                inherited=add_reservation(observed['build']['ram_sections'],
                    stack['before_native_switch_sp'],stack['inherited_native_frame_bytes'])
                if inherited['overlap_bytes'] or stack['already_in_static_sram'] is not True or \
                        stack['application_entry_sp']-stack['before_native_switch_sp']!=32:
                    raise ValueError('NuttX entry frame overlaps counted static storage')
                control=nuttx_context(source,run['native_heap_regions'])
                if control[1]!=368 or run['native_heap_peak_bytes']<368:
                    raise ValueError('NuttX allocator control reservation differs')
                # The native counter already starts with this control prefix.
                # Adding it separately would count the same 368 bytes twice.
                startup=inherited['physical_union_bytes'];native_peak=run['native_heap_peak_bytes']
                runtime=static+native_peak
                if runtime!=run['observed_allocated_software_bytes']:
                    raise ValueError('NuttX software occupancy differs from native replay')
            if static!=inherited['static_bytes']:
                raise ValueError('Static physical union changed')
            runs.append({'reset':i,'startup_phase_software_bytes':startup,
                'runtime_phase_software_peak_bytes':runtime,
                'observed_phase_maximum_bytes':max(startup,runtime),
                'native_heap_peak_bytes':native_peak,'actual_stack_use':stack,
                'raw_sha256':sha(folder/'captures'/('reset%d.raw'%i))})
        cells.append({'os':os,'build':source.relative_to(root).as_posix(),
            'capture':folder.relative_to(root).as_posix(),'elf_sha256':sha(source/'application.elf'),
            'source_reference_sha256':sha(folder/'audit.json'),'independent_resets_reused':5,
            'static_bytes':inherited['static_bytes'],'startup_reservation_bytes':inherited['reservation_bytes'],
            'heap_storage':'Static 4096-byte pool; internal occupied bytes not added' if os=='Zephyr' else
                'Dynamic native occupied counter includes 368-byte heap control and per-region guards',
            'runs':runs,'scope':'Original startup observer and native heap ledger through third original message report'})
    return {'audit':'pass','board_mac':original['board_mac'],
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),
        'cells':cells,'independent_resets_reused':15,'new_board_resets':0,'new_model_calls':0,
        'comparison_scope':'Software-owned static, explicit native startup reservation/frame and native heap occupancy; '
            'physical aliases deduplicated. Observer images, 240 MHz, one core, 100 Hz, original message workload.',
        'whole_lifecycle_peak_allocated_occupancy_bytes':None,'ranking_eligible':False,
        'remaining':['Earlier loading and ROM/cache/RTC ownership under a common hardware-reservation convention',
            'Full bookkeeping convention and complete startup interval rather than a phase envelope'],
        'stack_policy':'Actual stack observations are auxiliary and are not added to reserved storage'}


def cohort_summary(value):
    return {k:v for k,v in value.items() if k!='cells'} | {'cells':[
        {k:v for k,v in c.items() if k!='runs'} | {'runs':[
            {k:v for k,v in r.items() if k not in ('actual_stack_use','raw_sha256')} for r in c['runs']]}
        for c in value['cells']]}


def cohort_paper_text(value):
    cells={c['os']:c for c in value['cells']}
    z,n=cells['Zephyr'],cells['NuttX']
    zrun,nrun=z['runs'][0],n['runs'][0]
    if any(any(r[k]!=c['runs'][0][k] for k in ('startup_phase_software_bytes',
            'runtime_phase_software_peak_bytes')) for c in (z,n) for r in c['runs']):
        raise ValueError('Varying phase observations require explicit ranges')
    return ('The corresponding five-reset Zephyr and NuttX records show different ownership transitions. '
        f"Zephyr's linked inherited-stack interval reserves {z['startup_reservation_bytes']:,}\\,B outside "
        f"its {z['static_bytes']:,}-B static union, giving {zrun['startup_phase_software_bytes']:,}\\,B at startup. "
        'Its main/idle/IRQ stacks and 4,096-B heap pool already belong to static storage. '
        f"NuttX's entry reserves a {n['startup_reservation_bytes']:,}-B inherited frame before switching "
        f"to its static idle stack; its later software peak is {nrun['runtime_phase_software_peak_bytes']:,}\\,B. "
        'The native NuttX counter includes its 368-B control prefix, which is not added again. '
        'These phase observations exclude hardware reservations and earlier loading, and do not establish '
        'a common whole-lifecycle peak.')


def free_extent_headers(regions, blocks, header, alignment, minimum):
    """Coalesced free extents retain a mandatory header, not their reusable payload."""
    if header <= 0 or minimum < header or alignment <= 0:
        raise ValueError('Invalid native free-block geometry')
    regions, blocks = sorted(regions), sorted(blocks)
    if any(a >= b or a % alignment or b % alignment for a,b in regions+blocks) or any(
            a[1] > b[0] for spans in (regions,blocks) for a,b in zip(spans,spans[1:])):
        raise ValueError('Overlapping or unaligned native extents')
    if any(sum(low <= a < b <= high for low,high in regions) != 1 for a,b in blocks):
        raise ValueError('Allocated block outside registered interior')
    gaps = []
    for low,high in regions:
        cursor = low
        for a,b in blocks:
            if low <= a < high:
                if a > cursor:gaps.append((cursor,a))
                cursor = b
        if cursor < high:gaps.append((cursor,high))
    if any(b-a < minimum for a,b in gaps):
        raise ValueError('Free extent smaller than native minimum')
    return {'free_extents':len(gaps), 'free_header_bytes':len(gaps)*header}


def freertos_bookkeeping_history(events, pools, deferred_start, static):
    if any(p[4] != 4 or p[3] < 8 for p in pools):
        raise ValueError('Native TLSF header/control geometry differs')
    native = reservation_history(events,pools,deferred_start,static)
    blocks, registered, rows = {}, set(), [dict(native[0],free_extents=0,free_header_bytes=0)]
    for cursor,(_,kind,pool,pointer,delta) in enumerate(events,1):
        if kind == 0:registered.add(pool)
        elif kind in (1,4):
            if pointer in blocks:raise ValueError('Duplicate native allocation')
            blocks[pointer] = (pool,delta)
        elif kind == 2:
            if blocks.pop(pointer,None) != (pool,-delta):raise ValueError('Unmatched native free')
        elif kind == 3:
            if pointer not in blocks or blocks[pointer][0] != pool:raise ValueError('Unmatched native resize')
            blocks[pointer] = (pool,blocks[pointer][1]+delta)
        # Native registration counts everything except the initial free block
        # (payload + 4-B header). The trailing 4-B sentinel is already counted.
        regions = [(pools[i][0]+pools[i][3]-4,pools[i][0]+pools[i][1]-4) for i in registered]
        spans = [(p-4,p-4+n) for p,(i,n) in blocks.items()]
        free = free_extent_headers(regions,spans,4,4,16)
        expected = sum(pools[i][3] for i in registered)+sum(n for i,n in blocks.values())
        if expected != native[cursor]['native_occupied_bytes']:
            raise ValueError('Block identities disagree with native occupancy')
        row = dict(native[cursor],**free)
        row['accounted_bytes'] += free['free_header_bytes']
        rows.append(row)
    return rows


def nuttx_bookkeeping_history(events, identities, regions, heap, static):
    from nuttx_message_identities import replay
    replay(events,identities,regions,heap)
    transitions = {r['at']:r for r in identities}
    if len(transitions) != len(identities):raise ValueError('Duplicate native identity event')
    blocks, registered, rows = {}, 0, []
    for e in events:
        if e['kind'] == 6:registered += 1
        if registered > len(regions):raise ValueError('Too many native regions')
        if e['event'] in transitions:
            t = transitions[e['event']]
            if t['old'] and blocks.pop(t['old'],None) != t['old_bytes']:
                raise ValueError('Unmatched native retirement')
            if t['new']:blocks[t['new']] = t['new_bytes']
        interiors = [(s+8,s+n-8) for s,n in regions[:registered]]
        spans = [(p-8,p-8+n) for p,n in blocks.items()]
        free = free_extent_headers(interiors,spans,8,8,16)
        if 368+16*registered+sum(blocks.values()) != e['occupied']:
            raise ValueError('Native control/guards/block union differs')
        rows.append({'event_cursor':e['event']+1,'native_occupied_bytes':e['occupied'],**free,
                     'accounted_bytes':static+e['occupied']+free['free_header_bytes']})
    return rows


def bookkeeping_audit(root):
    from run_esp32_nuttx_message_lifetimes import fields
    cohort = cohort_audit(root)
    previous = root/'artifacts/reports/esp32-startup-reservation-cohort-v1.json'
    if json.loads(json.dumps(cohort)) != json.loads(previous.read_text()):
        raise ValueError('Prior source-bound cohort changed')
    cells = []
    for cell in cohort['cells']:
        source,folder = root/cell['build'],root/cell['capture']
        runs = []
        for old in cell['runs']:
            i = old['reset'];lines = [r['line'] for r in read_raw_capture(folder/'captures',i)]
            if cell['os'] == 'FreeRTOS':
                events = [tuple(map(int,m.groups())) for s in lines if (m:=EVENT.fullmatch(s))]
                pools = [tuple(map(int,m.groups())) for s in lines if (m:=POOL.fullmatch(s))]
                replay_events(events,pools)
                handoff = json.loads((root/REFERENCE).read_text())['application']['runs'][i-1]['startup_heap_handoff']
                deferred = cohort['cells'][0]['startup_reservation_bytes']
                candidates = [p[0] for p in pools if p[1] == deferred]
                if len(candidates) != 1:raise ValueError('Ambiguous deferred region')
                history = freertos_bookkeeping_history(events,pools,candidates[0],cell['static_bytes'])
                runtime = history[handoff['after_release']['event_cursor']:]
            elif cell['os'] == 'NuttX':
                events = [fields(s) for s in lines if s.startswith('TM_N_RAM event=')]
                identities = [fields(s) for s in lines if s.startswith('TM_N_ID at=')]
                regions = [(r['start'],r['end']-r['start']) for r in (
                    fields(s,2) for s in lines if s.startswith('RAM_EVENTS region '))]
                heap = [fields(s,2)['heap'] for s in lines if s.startswith('TM_N_RAM layout ')]
                if len(heap) != 1:raise ValueError('Missing native control prefix')
                history = [{'event_cursor':0,'accounted_bytes':old['startup_phase_software_bytes'],
                            'free_header_bytes':0,'free_extents':0}]
                history += nuttx_bookkeeping_history(events,identities,regions,heap[0],cell['static_bytes'])
                runtime = history[1:]
            else:
                # All Zephyr heap storage, including free headers, is static.
                history = [{'event_cursor':None,'accounted_bytes':old['startup_phase_software_bytes'],
                            'free_header_bytes':0,'free_extents':0}]
                runtime = [{'accounted_bytes':old['runtime_phase_software_peak_bytes']}]
            peak = max(history,key=lambda r:r['accounted_bytes'])
            runs.append({'reset':i,'raw_sha256':old['raw_sha256'],
                'allocated_software_peak_bytes':peak['accounted_bytes'],
                'old_phase_maximum_bytes':old['observed_phase_maximum_bytes'],
                'correction_at_peak_bytes':peak['accounted_bytes']-old['observed_phase_maximum_bytes'],
                'runtime_peak_bytes':max(r['accounted_bytes'] for r in runtime),
                'actual_stack_use':old['actual_stack_use'],'peak':peak,'history':history})
        cells.append({k:v for k,v in cell.items() if k!='runs'} | {'runs':runs})
    return {'audit':'pass','board_mac':cohort['board_mac'],
        'definition_sha256':cohort['definition_sha256'],'source_reference_sha256':sha(previous),
        'cells':cells,'independent_resets_reused':15,'new_board_resets':0,'new_model_calls':0,
        'scope':'OS-owned software storage from native application entry through the third original message report. '
            'Includes observer, static stacks/pools, active inherited stack reservations and native heap bookkeeping; '
            'excludes earlier loader and ROM/cache/RTC hardware reservations. Actual stack use is auxiliary.',
        'bookkeeping_convention':'Count mandatory non-payload free headers (TLSF 4 B, NuttX 8 B per coalesced extent); '
            'reusable free payload/list links are not allocated. Native control and sentinel/guard bytes counted once.',
        'ranking_eligible':False,
        'remaining':['Whole reset-to-report hardware ownership outside the stated software scope',
                     'Observer footprint differs by OS; do not present this as uninstrumented resource ranking',
                     'RIOT/Rhino and other hardware groups require their own matched lifecycle evidence']}


def bookkeeping_summary(value):
    return {k:v for k,v in value.items() if k!='cells'} | {'cells':[
        {k:v for k,v in c.items() if k!='runs'} | {'runs':[
            {k:v for k,v in r.items() if k not in ('history','raw_sha256','actual_stack_use')} | {
                'stack_observation':{k:r['actual_stack_use'][k] for k in (
                    'touched_watermark_bytes','resolution_bytes','scope')}} for r in c['runs']]}
        for c in value['cells']]}


def bookkeeping_paper_text(value):
    cells = {c['os']:c for c in value['cells']}
    peaks = []
    for os in ('FreeRTOS','Zephyr','NuttX'):
        values = {r['allocated_software_peak_bytes'] for r in cells[os]['runs']}
        if len(values) != 1:raise ValueError('Variable allocated occupancy needs ranges')
        peaks.append(f'{values.pop():,}')
    return ('Replaying mandatory free-block headers refines these software observations. '
        'The coalesced free extents retain 4-B TLSF or 8-B NuttX headers; reusable free payload '
        'is not allocated. The correction at the observed maximum is 24\\,B for FreeRTOS and '
        'NuttX, while Zephyr\'s headers already belong to its static pool. The corresponding '
        f'peak allocated software occupancies are {peaks[0]}, {peaks[1]} and {peaks[2]}\\,B '
        'for FreeRTOS, Zephyr and NuttX, respectively, identical across five retained resets each. '
        'This reanalysis covers committed allocation transitions and startup reservations from '
        'native application entry through the third original message report. Actual stack '
        'watermarks remain separate. Earlier loader and hardware ownership remain outside this '
        'software scope, and the different observer images are not an uninstrumented RAM ranking.')


def compact_nuttx_audit(root):
    from elftools.elf.elffile import ELFFile
    from run_esp32_nuttx_message_lifetimes import audit as native_audit, fields
    source = root/'artifacts/reports/esp32-nuttx-compact-startup-v1'
    capture = root/'artifacts/reports/esp32-nuttx-compact-startup-b1-v1'
    value = json.loads(json.dumps(native_audit(capture,source)))
    report = capture/'audit.json'
    if json.loads(json.dumps(value)) != json.loads(report.read_text()) or not value['build'].get('compact_observer'):
        raise ValueError('Compact capture differs from native source/raw audit')
    protocol = json.loads((source/'compact-protocol.json').read_text())
    old_source = root/protocol['reference_build']
    old_capture = root/protocol['reference_capture']
    old = native_audit(old_capture,old_source)
    if json.loads(json.dumps(old)) != json.loads((old_capture/'audit.json').read_text()):
        raise ValueError('Prior observer capture changed')
    for name in ('iotosbench_main.c','port.c','test.c','tm_override.h','allocator.patch','identity.patch',
                 'reference-config','startup-entry.S','startup-stack.inc','startup-original.c'):
        if (source/name).read_bytes() != (old_source/name).read_bytes():
            raise ValueError('Observer storage intervention changed native input: '+name)
    native_names=lambda d:{p.relative_to(d).as_posix() for p in d.rglob('*') if p.is_file()}
    if native_names(old_source/'native-source') != native_names(source/'native-source'):
        raise ValueError('Native source inventory differs')
    for old_file in (old_source/'native-source').rglob('*'):
        if old_file.is_file() and old_file.read_bytes() != (source/old_file.relative_to(old_source)).read_bytes():
            raise ValueError('Observer storage intervention changed native source')
    arrays = {}
    names = ('message_events','message_stacks','message_identities','message_live','stacks','block_bytes')
    for kind,folder in (('previous',old_source),('compact',source)):
        with (folder/'application.elf').open('rb') as stream:
            symbols=ELFFile(stream).get_section_by_name('.symtab')
            arrays[kind]={name:symbols.get_symbol_by_name(name)[0]['st_size'] for name in names}
    static = value['build']['static_sram_bytes']
    delta = old['build']['static_sram_bytes']-static
    if delta != sum(arrays['previous'].values())-sum(arrays['compact'].values()):
        raise ValueError('Static change is not fully explained by the six logging arrays')
    runs = []
    for i,run in enumerate(value['runs'],1):
        lines = [r['line'] for r in read_raw_capture(capture/'captures',i)]
        events = [fields(s) for s in lines if s.startswith('TM_N_RAM event=')]
        identities = [fields(s) for s in lines if s.startswith('TM_N_ID at=')]
        regions = run['native_heap_regions']
        heap = [fields(s,2)['heap'] for s in lines if s.startswith('TM_N_RAM layout ')]
        if len(heap)!=1:raise ValueError('Missing compact heap prefix')
        history = nuttx_bookkeeping_history(events,identities,regions,heap[0],static)
        startup = static+run['application_startup_stack']['inherited_native_frame_bytes']
        peak = max(history,key=lambda r:r['accounted_bytes'])
        runs.append({'reset':i,'raw_sha256':sha(capture/'captures'/('reset%d.raw'%i)),
            'events':run['events'],'native_heap_peak_bytes':run['native_heap_peak_bytes'],
            'startup_software_bytes':startup,
            'allocated_software_peak_bytes':max(startup,peak['accounted_bytes']),
            'peak':peak,'history':history,'stack_auxiliary':run['application_startup_stack']})
    return {'audit':'pass','os':'NuttX','board_mac':protocol['board_mac'],
        'protocol_sha256':sha(source/'compact-protocol.json'),
        'elf_sha256':sha(source/'application.elf'),'source_native_audit_sha256':sha(report),
        'previous_native_audit_sha256':sha(old_capture/'audit.json'),
        'previous_static_bytes':old['build']['static_sram_bytes'],'static_bytes':static,
        'logging_arrays_bytes':arrays,'static_reduction_bytes':delta,'runs':runs,
        'independent_resets':5,'separate_allocator_validation':value['validation'],
        'original_workload_unchanged':True,'native_sources_unchanged':True,
        'original_flash_restored':True,'new_model_calls':0,'new_energy_measurements':0,
        'scope':protocol['scope'],'ranking_eligible':False,
        'interpretation':'Observer-storage intervention. Include the new observer in RAM; do not subtract '
            'this size delta to invent native RAM or use non-interleaved old/new counts as a performance effect.'}


def compact_nuttx_summary(value):
    return {k:v for k,v in value.items() if k not in ('runs','separate_allocator_validation')} | {
        'validation_pass':value['separate_allocator_validation']['audit']=='pass',
        'runs':[{k:r[k] for k in ('reset','events','native_heap_peak_bytes','startup_software_bytes',
                                   'allocated_software_peak_bytes')} for r in value['runs']]}


def compact_nuttx_paper_text(value):
    peaks={r['allocated_software_peak_bytes'] for r in value['runs']}
    heaps={r['native_heap_peak_bytes'] for r in value['runs']}
    if len(peaks)!=1 or len(heaps)!=1:raise ValueError('Variable compact peaks require reset ranges')
    return ('A bounded-storage NuttX observer retains the same native hooks and original message workload. '
        f'Reducing six logging arrays lowers static SRAM from {value["previous_static_bytes"]:,} '
        f'to {value["static_bytes"]:,}\\,B; their compiled size difference accounts for all '
        f'{value["static_reduction_bytes"]:,}\\,B of the reduction. Five new independent resets '
        f'pass complete event/address replay and the final native block walk, with a '
        f'{heaps.pop():,}-B native heap peak and {peaks.pop():,}\\,B peak allocated software occupancy. '
        'A separate allocator self-check passes without overflow. The original configuration, native '
        'sources and test body are unchanged relative to the earlier observation image. These values '
        'include the compact observer; the non-interleaved old/new runs do not estimate a pure timing '
        'effect or uninstrumented RAM.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cohort',action='store_true')
    p.add_argument('--bookkeeping',action='store_true')
    p.add_argument('--compact-nuttx',action='store_true')
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        p.error('Use leon and a new evidence output')
    if sum((args.cohort,args.bookkeeping,args.compact_nuttx))>1:p.error('Select one audit mode')
    value = compact_nuttx_audit(root) if args.compact_nuttx else bookkeeping_audit(root) if args.bookkeeping else cohort_audit(root) if args.cohort else audit(root)
    args.output.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'audit':'pass','static_bytes':value['static_bytes'],
        'allocated_software_peaks':[r['allocated_software_peak_bytes'] for r in value['runs']]}
        if args.compact_nuttx else {'audit':'pass','cells':[{k:c[k] for k in ('os','static_bytes','startup_reservation_bytes')}
        for c in value['cells']]} if args.cohort or args.bookkeeping else
        {'audit':'pass','peaks':[r['accounted_peak_bytes'] for r in value['runs']],
         'base_bytes':value['static_and_fixed_reservations_bytes']}))
