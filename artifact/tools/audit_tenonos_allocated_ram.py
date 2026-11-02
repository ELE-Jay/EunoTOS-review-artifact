#!/usr/bin/env python3
"""Reconstruct guest allocated occupancy from matched native memory captures."""
import argparse
import json
from pathlib import Path

from audit_tenonos_memory_lifecycle import require
from audit_tenonos_boot_memory import extent, merged, audit as boot_audit
from audit_tenonos_exit_memory import audit as exit_audit
from tenonos_allocator_metadata import audit as peak_audit, capacity_trace, decode, field
from tenonos_kvm_reproduce import sha


SOURCES = {
    'early': ('tenonos-boot-memory-required-rpi4-v1',
              'b9bb0a204d35f472441ad9467f52e157cc3c4c30f38f2a00b20f7d40be3f50df'),
    'exit': ('tenonos-exit-memory-rpi4-v2',
             'e36d027eeb0c21c65a2f25712d8cfb1ca43f3b0ca0b696d15a850028ffe5e1ea'),
    'peak': ('tenonos-allocator-peak-rpi4-v2',
             '6aec3a15423594dc40411fe5c2036a11506114eb53c65db60d39892b4aef0c51'),
}


def occupancy(resident, control, regions, active, tlsf):
    """Free TLSF block headers are unavailable capacity; their payload is reusable."""
    metadata = list(control)
    free_headers = []
    blocks = sorted(active.values())
    require(extent(blocks) == sum(b-a for a, b in blocks), 'Allocated extents overlap')
    require(all(sum(lo <= a < b <= hi for lo, hi, _ in regions) == 1
                for a, b in blocks), 'Allocation outside registered managed areas')
    for lo, hi, fixed in regions:
        metadata.extend(fixed)
        if not tlsf:
            continue
        cursor = lo
        for a, b in blocks:
            if lo <= a < hi:
                if cursor < a:
                    require(a-cursor >= 32, 'TLSF free gap cannot contain a native block')
                    free_headers.append((cursor, cursor+16))
                cursor = b
        if cursor < hi:
            require(hi-cursor >= 32, 'TLSF free tail cannot contain a native block')
            free_headers.append((cursor, cursor+16))
    metadata.extend(free_headers)
    require(extent(metadata) == sum(b-a for a, b in metadata), 'Metadata overlaps itself')
    spans = merged([*resident, *metadata, *blocks])
    require(extent(spans) == extent(resident)+extent(metadata)+extent(blocks),
            'Resident, metadata and native blocks overlap')
    return {'allocated_occupancy_bytes': extent(spans),
            'resident_reserved_bytes': extent(resident),
            'allocator_metadata_reserved_bytes': extent(metadata),
            'allocated_block_bytes': extent(blocks),
            'physical_union': spans, 'free_headers': [list(r) for r in free_headers]}


def geometry(folder, compiled, snapshot, pools):
    tlsf = compiled['allocator'] == 'tlsf'
    kinds = compiled['metadata']
    size = compiled['allocator_bytes'] + kinds['tlsf_t' if tlsf else 'uk_bbpalloc']['bytes']
    alignment = 16 if tlsf else 4096
    a = snapshot['allocator']
    control = [(a, a+(size+alignment-1)//alignment*alignment)]
    regions = {}
    for i, item in enumerate(snapshot['regions']):
        raw = (folder/(snapshot['stage']+'.region%d' % i)).read_bytes()
        kind = kinds['area_info_t' if tlsf else 'uk_bbpalloc_memr']
        if tlsf:
            header = kinds['bhdr_t']['fields']['ptr']['offset']
            require(header == 16, 'Different TLSF header convention')
            start = item['address']-header
            word = field((folder/(snapshot['stage']+'.region%d.block0' % i)).read_bytes(),
                         kinds['bhdr_t'], 'size')
            lo, hi = start+header+(word & 0xfffffff8), field(raw, kind, 'end')
            fixed = [(start, lo), (hi, hi+header)]
        else:
            lo = field(raw, kind, 'first_page')
            hi = lo+4096*field(raw, kind, 'nr_pages')
            fixed = [(item['address'], lo)]
        matches = [(x, y) for x, y in pools if x <= lo < hi <= y]
        require(len(matches) == 1, 'Native area has no unique boot pool')
        x, y = matches[0]
        require(x not in regions, 'Native area unexpectedly split or merged')
        cover = fixed + [(lo, hi)] + (control if x <= a < y else [])
        require(merged(cover) == [[x, y]], 'Native area has unclassified padding or lost capacity')
        regions[x] = (lo, hi, fixed)
    return control, regions


def snapshot_free_headers(folder, snapshot, compiled):
    result = []
    for i, area in enumerate(snapshot['regions']):
        for j, block in enumerate(area['blocks']):
            raw = (folder/(snapshot['stage']+'.region%d.block%d' % (i, j))).read_bytes()
            if field(raw, compiled['metadata']['bhdr_t'], 'size') & 1:
                result.append([block['address'], block['address']+16])
    return sorted(result)


def replay(rows, resident, control, regions, initial_pool, tlsf):
    capacity_trace(rows, tlsf)
    selected = {initial_pool}
    active = {}
    previous = rows[0]['current']
    history = []
    # Buddy registers before directly adding its initial area. No allocation
    # occurs in that gap; count its post-init reservation as a checked bound.
    for row in rows:
        op, p, n = row['op'], row['p'], row['n']
        delta = row['current']-previous
        previous = row['current']
        if op == 6:
            require(p in regions and p not in selected and row['q'] == 0,
                    'Unknown/repeated native area addition')
            selected.add(p)
        elif op in (1, 3) and p:
            size = delta if tlsf else 4096*(1 << ((n//4096-1).bit_length()))
            start = p-16 if tlsf else p
            active[p] = (start, start+size)
        elif op in (2, 4) and p:
            del active[p]
        value = occupancy(resident, control, [regions[x] for x in sorted(selected)], active, tlsf)
        history.append({'seq': row['seq'], 'phase': row['phase'], **value})
    require(selected == set(regions), 'Unobserved native region')
    return history


def audit(root, sources=None, registries=None):
    sources = sources or SOURCES
    registries = registries or {}
    reports = root/'artifacts/reports'
    supporting = {}
    for name, function in (('early', boot_audit), ('exit', exit_audit), ('peak', peak_audit)):
        directory, expected = sources[name]
        folder = reports/directory
        require(sha(folder/'audit.json') == expected, 'Prior %s evidence identity changed' % name)
        value = function(root, folder, registry=registries.get(name))
        require(value == json.loads((folder/'audit.json').read_text()), 'Prior %s replay changed' % name)
        supporting[name] = value
    results = []
    for original in supporting['early']['profiles']:
        name = original['profile']
        folder = reports/sources['peak'][0]/name
        early = reports/sources['early'][0]/name
        tail = reports/sources['exit'][0]/name
        for filename in ('linked.elf', 'runtime-image', 'input.config'):
            require(sha(folder/filename) == sha(early/filename) == sha(tail/filename),
                    'Different image or config across lifecycle windows')
        stages = original['stages']
        stable = stages[1]['partition']['segments']
        require(all(s['partition']['segments'] == stable for s in stages[1:]),
                'Resident reservations changed after native platform entry')
        resident = [(s['start'], s['end']) for s in stable if s['kind'] != 1]
        pools = [(s['start'], s['end']) for s in stable if s['kind'] == 1]
        require(all(s['kind'] in (1, 4, 32) for s in stable), 'Unclassified guest RAM')
        initial_reserved = extent((s['start'], s['end']) for s in stages[0]['partition']['segments']
                                  if s['kind'] != 1)
        require(initial_reserved <= extent(resident), 'Early reservation exceeds later resident union')
        compiled = json.loads((folder/'exit-layout.json').read_text())
        debug = json.loads((folder/'debug-result.json').read_text())
        peak_snapshot = next(s for s in debug['stages'] if s['stage'] == 'allocation-peak')
        tlsf = compiled['allocator'] == 'tlsf'
        control, regions = geometry(folder, compiled, peak_snapshot, pools)
        require(set(regions) == {x for x, _ in pools} and control[0][0] == pools[0][0],
                'Not all native boot pools classified')
        raw = (folder/'termination.events').read_bytes()
        tail_raw = (tail/'termination.events').read_bytes()
        require(tail_raw.startswith(raw) and len(tail_raw) == len(raw)+56,
                'Exit window differs from peak-run event trajectory')
        rows = decode(tail_raw, len(tail_raw)//56)
        require(rows[-1]['op'] == 33 and rows[-1]['current'] == rows[-2]['current'],
                'Unaccounted final reclamation')
        history = replay(rows, resident, control, regions, pools[0][0], tlsf)
        peak = max((r for r in history if r['phase'] <= 6), key=lambda r:r['allocated_occupancy_bytes'])
        require(peak['seq']+1 == peak_snapshot['event_count'], 'Whole occupancy peak differs from direct census')
        require(max(r['allocated_occupancy_bytes'] for r in history) == peak['allocated_occupancy_bytes'],
                'Later validation or exit exceeds original-workload peak')
        registration = debug['stages'][0]
        if tlsf:
            old_control, old_regions = geometry(folder, compiled, registration, pools)
            require(old_control == control and old_regions == {pools[0][0]:regions[pools[0][0]]},
                    'TLSF initial region differs from final geometry')
        else:
            require(not registration['regions'], 'Buddy registered with unexpected regions')
        for snapshot in debug['stages'][1:]:
            c, g = geometry(folder, compiled, snapshot, pools)
            require(c == control and g == regions, 'Allocator fixed reservations changed')
            if tlsf:
                require(snapshot_free_headers(folder, snapshot, compiled) ==
                        sorted(history[snapshot['event_count']-1]['free_headers']),
                        'Replayed free headers differ from native census')
        bound = occupancy(resident, control, list(regions.values()), {}, tlsf)['allocated_occupancy_bytes']
        require(bound < peak['allocated_occupancy_bytes'], 'Initialization reservation bound exceeds peak')
        results.append({'profile':name, 'peak_allocated_occupancy_bytes':peak['allocated_occupancy_bytes'],
            'peak':peak, 'terminal':history[-1], 'initialization_reserved_upper_bound_bytes':bound,
            'lifecycle_events':len(rows), 'image_sha256':sha(folder/'runtime-image'),
            'config_sha256':sha(folder/'input.config'), 'observer_event_buffer_bytes':4096*56,
            'stack_auxiliary':{'boot_reserved_bytes':json.loads((early/'gdb-input.json').read_text())['boot_stack_bytes'],
                'boot_observed_sp_span_bytes':original['trace']['maximum_observed_boot_sp_span_bytes'],
                'scope':'Native entry to allocator registration; included storage, not added to peak',
                'whole_lifecycle_actual_stack_use_bytes':None},
            'history':history})
    return {'audit':'pass', 'metric':'peak allocated guest RAM occupancy', 'unit':'bytes',
        'definition_sha256':sha(root/'registry/ram_allocated_occupancy_v1.json'),
        'scope':'Matched one-vCPU 128-MiB Pi4B/KVM observer images, native entry through termination entry; '
                'six unchanged original workloads. Separate phase-7 validation does not raise the peak.',
        'method':'Replay reserved physical intervals and every native allocation/free; verify metadata, '
                 'free headers and peak blocks against original snapshots. Matched early/exit captures '
                 'close boundaries; these are reused runs, not new repetitions.',
        'free_metadata_convention':'Count unavailable TLSF block headers, area descriptors, sentinels, '
                 'aligned control and buddy bitmap/control reservations. Reusable free-block payload '
                 '(including overlaid free-list links) is not allocated occupancy.',
        'source_audit_sha256':{k:v[1] for k,v in sources.items()},
        'fresh_guests':0, 'new_builds':0, 'new_model_calls':0,
        'whole_live_ram_peak_bytes':None, 'cross_platform_ranking_eligible':False,
        'profiles':results}


def paper_text(result):
    p = {r['profile']:r for r in result['profiles']}
    order = ('initial-tlsf', 'accepted-buddy', 'accepted-tlsf')
    values = [p[n]['peak_allocated_occupancy_bytes'] for n in order]
    return ('For the three Pi4B/KVM observer configurations, replaying resident page reservations, '
        'allocator bookkeeping and simultaneous native blocks closes allocated occupancy from native '
        'entry through termination entry. The initial TLSF, accepted buddy and accepted TLSF peaks are '
        f'{values[0]:,}, {values[1]:,} and {values[2]:,}\\,B, respectively. '
        'All occur at the directly captured original-suite peak; the subsequent finite validation does '
        'not increase them. These guest-only values include the 1-MiB device tree, kernel page padding '
        'and observer storage, but exclude the Linux host and free pool capacity. Matched earlier boot '
        'and exit captures close the boundaries without adding new repetitions. Actual stack use is '
        'separate: the observed early boot SP span is 800\\,B within an already reserved 4,096-B stack; '
        'whole-lifecycle actual stack use remains unmeasured.')


def summary(result):
    keys = ('profile', 'peak_allocated_occupancy_bytes', 'image_sha256', 'stack_auxiliary')
    return {k:v for k,v in result.items() if k != 'profiles'} | {'profiles':[
        {**{k:p[k] for k in keys}, 'components':{k:p['peak'][k] for k in (
            'resident_reserved_bytes', 'allocator_metadata_reserved_bytes', 'allocated_block_bytes')}}
        for p in result['profiles']]}


def trajectory_profiles(histories, aliases, measured):
    """Join existing reference profiles to accepted states, never relabel them as new captures."""
    lookup = {(a['history'],a['round'],a['role']):a for a in aliases}
    require(len(lookup) == len(aliases) == 4*len(histories), 'Duplicate or missing state aliases')
    require(len({h['id'] for h in histories}) == len(histories), 'Duplicate history')
    rows = []
    for h in histories:
        require((h['accepted_rounds'],h['rejected_rounds']) == (2,0) and
                len(h['round_wall_s']) == 2 and
                all(n > 0 for n in h['round_wall_s']) and
                sum(h['round_wall_s']) <= h['total_round_wall_s'],
                'This reanalysis requires two accepted rounds with complete costs')
        chain = [lookup.get((h['id'],1,'parent_build')),
                 lookup.get((h['id'],1,'retained_build')),
                 lookup.get((h['id'],2,'retained_build'))]
        parent = lookup.get((h['id'],2,'parent_build'))
        require(all(chain) and parent is not None and all(parent[k] == chain[1][k]
                for k in ('identity','image_sha256','config_sha256')), 'History parent continuity differs')
        states = []
        for stage,a in enumerate(chain):
            require(a['identity'] in measured, 'History state has no measured configuration')
            p = measured[a['identity']]
            require(p['profile'] == a['lifecycle'] and p['peak_allocated_occupancy_bytes'] > 0,
                    'Reference profile mapping differs')
            states.append({'stage':stage,'profile':p['profile'],'identity':a['identity'],
                'candidate_image_sha256':a['image_sha256'],'candidate_config_sha256':a['config_sha256'],
                'observer_image_sha256':p['image_sha256'],
                'reference_peak_allocated_occupancy_bytes':p['peak_allocated_occupancy_bytes']})
        first,middle,last = [s['reference_peak_allocated_occupancy_bytes'] for s in states]
        rows.append({'history':h['id'],'method':h['method'],'states':states,
            'endpoint_change_from_initial_percent':100*(last/first-1),
            'middle_change_from_initial_percent':100*(middle/first-1),
            'largest_profiled_state_bytes':max(first,middle,last),
            'round_wall_s':h['round_wall_s'],'total_round_wall_s':h['total_round_wall_s']})
    return rows


def trajectory_audit(root):
    from audit_tenonos_memory_impact import bind_histories
    from audit_tenonos_tasks import configuration
    from bind_tenonos_runtime_candidates import identity
    reports = root/'artifacts/reports'
    value = audit(root)
    report = reports/'tenonos-allocated-occupancy-rpi4-v1.json'
    require(value == json.loads(report.read_text()), 'Allocated reference profiles changed')
    binding = bind_histories(root)
    recorded = reports/'tenonos-repaired-profile-binding-v1.json'
    require(binding == json.loads(recorded.read_text()), 'Accepted-state source bindings changed')
    parent = reports/'tenonos-author-engine-20261027-v1'
    history_path = parent/'policy-choice-audit-v1.json'
    histories = json.loads(history_path.read_text())
    require(histories['audit'] == 'pass' and histories['registered_histories'] == 6 and
            histories['registered_rounds'] == 12, 'Incomplete accepted histories')
    measured = {}
    for p in value['profiles']:
        native = reports/'tenonos-native-threads-rpi4-v2'/p['profile']
        capture = reports/SOURCES['peak'][0]/p['profile']
        proof = json.loads((native/'source-proof.json').read_text())
        require(proof['test_bodies_changed'] is False and
                sha(capture/'input.config') == sha(native/'build/.config') and
                sha(capture/'linked.elf') == sha(native/'build/linked-symbols.elf'),
                'Allocated capture differs from source-qualified observer build')
        key = identity(configuration(native/'input.config'),proof['identity'],sha(native/'build/compiler.stdout'))
        require(key not in measured, 'Ambiguous observer reference identity')
        measured[key] = p
    rows = trajectory_profiles(histories['histories'],binding['aliases'],measured)
    require(len(rows) == 6 and len(measured) == 3 and all(
        [s['profile'] for s in row['states']] == ['initial-tlsf','accepted-buddy','accepted-tlsf']
        for row in rows), 'Unexpected task sequence; do not silently generalize this case')
    return {'audit':'pass','analysis':'Retrospective configuration-matched resource profiles along accepted histories',
        'scope':value['scope'],'histories':rows,'distinct_measured_profiles':3,'state_aliases':18,
        'new_model_calls':0,'new_guest_boots':0,'new_builds':0,
        'source_sha256':{'allocated_profiles':sha(report),'state_binding':sha(recorded),
                         'accepted_histories':sha(history_path)},
        'exact_generated_image_ram_measured':False,'synchronized_candidate_energy_assigned':False,
        'posthoc_ram_threshold_applied':False,'online_redeployment_overlap_peak_measured':False,
        'boundary':'Three separately measured observer reference profiles matched by complete input configuration, '
            'source/adapter and GCC-version output identity. Six histories reuse these profiles, not 18 new RAM '
            'measurements. No uninstrumented candidate RAM, online transition peak, RAM-budget failure or RSI claim.'}


def trajectory_summary(value):
    return {k:v for k,v in value.items() if k!='histories'} | {'histories':[
        {k:v for k,v in h.items() if k!='states'} | {'states':[
            {k:s[k] for k in ('stage','profile','reference_peak_allocated_occupancy_bytes')} for s in h['states']]}
        for h in value['histories']]}


def trajectory_paper_text(value):
    sequences = {tuple(s['reference_peak_allocated_occupancy_bytes'] for s in h['states']) for h in value['histories']}
    require(len(sequences) == 1, 'Distinct histories need separate resource sequences')
    a,b,c = sequences.pop();h = value['histories'][0]
    return ('Configuration-matched resource profiling exposes a difference between endpoint and history views. '
        f'All six repaired histories pass through observer reference states with allocated peaks of {a:,}, '
        f'{b:,} and {c:,}\\,B. The endpoint is {abs(h["endpoint_change_from_initial_percent"]):.2f}\\% '
        f'below the initial reference, whereas the intermediate buddy state is '
        f'{h["middle_change_from_initial_percent"]:.2f}\\% above it. Complete input configuration, source, '
        'adapter and compiler-version identities bind each state to one of three measured reference profiles. '
        'Reusing them across six histories does not create eighteen RAM samples or measure candidate-image '
        'RAM during redeployment. No RAM threshold was imposed after observing the results. The sequence '
        'illustrates a resource requirement omitted by endpoint-only reporting under this fixed workload.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--histories', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    require(root == Path('/home/reviewer/esp32-pilot/audit-workspace') and not args.output.exists(),
            'Run on leon with a new evidence output')
    result = trajectory_audit(root) if args.histories else audit(root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'audit':result['audit'], 'histories':len(result['histories']),
        'sequence':[s['reference_peak_allocated_occupancy_bytes'] for s in result['histories'][0]['states']]}
        if args.histories else {'audit':result['audit'], 'peaks':{
            p['profile']:p['peak_allocated_occupancy_bytes'] for p in result['profiles']}}))
