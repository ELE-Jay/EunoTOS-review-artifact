#!/usr/bin/env python3
"""Replay the current manuscript's B1 runtime tables from source-bound captures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from statistics import median

from audit_esp32_b1_controlled_energy import audit as energy_audit
from audit_esp32_message_ram_cohort import audit as ram_audit
from run_esp32_b1_message import audit as kernel_audit
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
SYSTEMS = ("FreeRTOS", "Zephyr", "NuttX")
CASES = (
    ("Preemptive scheduling", "preemptive_scheduling", 1),
    ("Message processing", "message_processing", 1),
    ("Synchronization", "synchronization_processing", 1),
    ("Interrupt processing", "interrupt_processing", 1),
    ("Interrupt preemption", "interrupt_preemption_processing", 3),
)
HARTSTONE_PH3_SOURCES = (
    ("FreeRTOS", "hartstone-native-us-fifo-v1/freertos/ph3", True),
    ("Zephyr", "hartstone-native-us-v1/zephyr/ph3", False),
    ("NuttX", "hartstone-native-us-v1/nuttx/ph3", False),
)


def require_rows(source, label, expected):
    tables = [body for body in re.findall(r"\\begin\{table\*?\}.*?\\end\{table\*?\}", source, re.S)
              if "\\label{" + label + "}" in body]
    if len(tables) != 1:
        raise ValueError("Missing/duplicate table: " + label)
    for row in expected:
        matches = [line.strip() for line in tables[0].splitlines()
                   if line.strip().startswith(row.split(" & ", 1)[0] + " & ")]
        if matches != [row + r" \\"]:
            raise ValueError("Published row differs from source replay: " + row)
    body = tables[0].split(r"\midrule", 1)[-1]
    numeric_rows = [line.strip() for line in body.splitlines()
                    if " & " in line and re.search(r"\d", line.split(" & ", 1)[1])]
    if sorted(numeric_rows) != sorted(row + r" \\" for row in expected):
        raise ValueError("Published numeric row coverage differs from source replay")


def checked_manuscript_sha(path, original_bytes):
    digest = hashlib.sha256(original_bytes).hexdigest()
    if sha(path) != digest:
        raise ValueError('Manuscript changed during the evidence audit; rerun after synchronization')
    return digest


def allocator_order_rows(result):
    rows = []
    for profile, label in (('initial-tlsf', 'Initial TLSF'), ('accepted-buddy', 'Accepted buddy')):
        cell, = [p for p in result['profiles'] if p['profile'] == profile]
        peak, = [p for p in cell['snapshots'] if p['stage'] == 'allocation-peak']
        blocks = cell['allocated_block_capacity_trace']['allocated_block_peak_bytes']
        if peak['live_allocated_block_capacity_bytes'] != blocks:
            raise ValueError('Counter and block-capacity comparison must bind the same peak event')
        rows.append(f"{label} & {peak['native_counters']['peak']:,} & {blocks:,}")
    return rows


def ram_image_rows(capacity):
    from run_esp32_message_observer_pairs import audit as pair_audit
    rows, bindings = [], {}
    names = ('esp32-boot-handoff-observer-pairs-b1-v2',
             'esp32-zephyr-ownership-observer-pairs-b1-v2',
             'esp32-nuttx-compact-loader-observer-pairs-b1-v1')
    for tag, cell, name in zip(('F1', 'Z1', 'N1'), capacity['rows'], names, strict=True):
        folder = REPORTS / name
        checked = json.loads(json.dumps(pair_audit(folder)))
        if checked != json.loads((folder / 'audit.json').read_text()) or \
                checked['independent_resets'] != 10 or not checked['original_flash_restored']:
            raise ValueError('Final RAM image control differs')
        group, = checked['cells']
        if len(group['pairs']) != 5:
            raise ValueError('Five matched final-image pairs required')
        os_name = cell['os']
        observer = folder / 'builds' / os_name / 'observer/application.bin'
        baseline = folder / 'builds' / os_name / 'baseline/application.bin'
        if sha(observer) != sha(ROOT / cell['source'] / 'application.bin'):
            raise ValueError('RAM capacity and perturbation control use different images')
        change = (group['median_ratio'] - 1) * 100
        rows.append(tag + ' / ' + os_name + r' & \texttt{' + sha(observer)[:12] +
                    r'} & \texttt{' + sha(baseline)[:12] + '} & $' + f'{change:.6f}' + r'\%$')
        bindings[name] = sha(folder / 'audit.json')
    return rows, bindings


def unified_mainboard_rows(result):
    from esp32_mainboard_figure import publication_summary
    view=publication_summary(result)
    ranges=view['weight_sensitivity']['rank_ranges']
    return [('AliOS/Rhino' if r['os']=='AliOS-Rhino' else r['os'])+' & '+
        f"{r['kernel_index']:.2f} & {r['network_mbit_s']:.3f} & "+
        f"{r['energy_uj_per_original_count']:.5f} & {r['peak_allocated_ram_bytes']:,.0f} & "+
        f"{r['overall_score']:.2f} & {ranges[r['os']][0]}--{ranges[r['os']][1]}" for r in view['rows']]


def tenon_energy_rows(result):
    if not result["pass"] or (result["activation_trials"], result["fresh_guest_boots"],
            result["model_calls"], result["rebuilds"]) != (9, 27, 0, 0) or result["ranking_eligible"]:
        raise ValueError("Different Pi activation-energy scope")
    labels = {"initial-tlsf": "Initial TLSF", "accepted-buddy": "Accepted buddy", "accepted-tlsf": "Accepted TLSF"}
    rows = []
    if [r["variant"] for r in result["summary"]] != list(labels):
        raise ValueError("Missing or reordered Pi image")
    for row in result["summary"]:
        if row["n"] != 3:
            raise ValueError("Three activations per retained image required")
        energy = row["energy_j"]
        rows.append(f"{labels[row['variant']]} & {energy['median']:.2f} [{energy['min']:.2f}, {energy['max']:.2f}] & "
                    f"{row['duration_s']['median']:.2f}")
    return rows


def tenon_scale_rows(result):
    if not result["pass"] or (result["distinct_configurations"], result["retained_state_aliases"],
            result["fresh_guest_boots"], result["model_calls"]) != (3, 24, 9, 0) or result["prospective_before_generation"]:
        raise ValueError("Different post-trajectory scale-validation scope")
    labels = {"initial-tlsf": "Initial TLSF", "accepted-buddy": "Accepted buddy", "accepted-tlsf": "Accepted TLSF"}
    return [f"{labels[row['profile']]} & {row['aliases']} & 3/3" for row in result["profiles"]]


def tenon_build_energy_rows(result):
    if not result["pass"] or (result["trials"], result["native_builds"], result["fresh_guest_boots"], result["model_calls"]) != (9, 9, 27, 0):
        raise ValueError("Different native-build energy scope")
    labels = {"initial-tlsf": "Initial TLSF", "accepted-buddy": "Accepted buddy", "accepted-tlsf": "Accepted TLSF"}
    if [r["variant"] for r in result["summary"]] != list(labels) or any(r["n"] != 3 for r in result["summary"]):
        raise ValueError("Native-build energy profile coverage differs")
    return [f"{labels[r['variant']]} & {r['energy_j']['median']:.2f} [{r['energy_j']['min']:.2f}, "
            f"{r['energy_j']['max']:.2f}] & {r['duration_s']['median']:.2f}" for r in result["summary"]]


def tenon_memory_rows(result):
    if not result["pass"] or result["fresh_guests"] != 9 or result["model_calls"] != 0 or \
            result["ranking_eligible"] or result["whole_live_ram_peak_bytes"] is not None:
        raise ValueError("Different native allocator observation scope")
    labels = {"initial-tlsf": "Initial TLSF", "accepted-buddy": "Accepted buddy", "accepted-tlsf": "Accepted TLSF"}
    if [p["profile"] for p in result["profiles"]] != list(labels) or any(p["fresh_guests"] != 3 for p in result["profiles"]):
        raise ValueError("Native memory profile coverage differs")
    return [f"{labels[p['profile']]} & {p['median_native_allocator_peak_bytes']:,} & {p['writable_static_load']['bytes']:,}"
            for p in result["profiles"]]


def require_tenon_runtime_claims(source, result):
    if result['audit'] != 'pass' or result['fresh_guests'] != 9 or len(result['profiles']) != 3 or \
            not all(p['admitted'] for p in result['profiles']):
        raise ValueError('Different Tenon behavioral scope')
    guests = [g for p in result['profiles'] for g in p['guests']]
    records = sum(len(g['cases']) for g in guests)
    values = []
    for index in range(6):
        rows = [g['cases'][index]['facts'] for g in guests]
        if any(not c['admitted'] for g in guests for c in g['cases']):
            raise ValueError('Behavioral case failed')
        values.append({k: {r[k] for r in rows} for k in rows[0]})
    def one(index, field):
        if len(values[index][field]) != 1: raise ValueError('Reported behavioral value varies')
        return next(iter(values[index][field]))
    if one(3,'locks') != one(3,'unlocks') or one(4,'irq_context') != 1:
        raise ValueError('Different semaphore or IRQ behavior')
    text = source.split('\\label{app:tenonruntime}',1)[1].split('\\subsection',1)[0]
    required = [f'All nine guests pass the declared behavioral checks, producing {records} case records',
        f'expected preempted two-thread endpoint of {one(0,"a")}/{one(0,"b")}',
        f'all {sum(one(i,"created") for i in range(6))} created workers entering once',
        f'{one(2,"preempt_checks"):,} returning higher-priority resume calls',
        f'{one(3,"locks"):,} semaphore acquisitions and releases',
        'one software-requested SGI callback in native IRQ dispatch',
        f'{one(5,"sleeps")} ten-tick sleeps',
        'without retroactively upgrading historical model-task success rates']
    if len(guests) != 9 or any(text.count(s) != 1 for s in required):
        raise ValueError('Published Tenon runtime claims differ from facts')
    return {'fresh_guests':len(guests),'case_records':records,'historical_task_scores_unchanged':True}


def require_tenon_candidate_claims(source, result):
    rows = result['aliases']
    counts = (result['registered_generated_candidates'],result['distinct_configurations'],
              result['behavior_admitted_aliases'],result['reused_guest_boots'],result['new_guest_boots'])
    reused = sum(r['reused'] for r in rows)
    if result['audit'] != 'pass' or counts != (18,3,18,6,3) or len(rows) != 18 or reused != 15 or \
            len({r['identity'] for r in rows}) != 3 or not all(r['behavior_admitted'] for r in rows) or \
            not result['historical_success_rates_and_wall_times_unchanged'] or result['new_model_calls'] != 0:
        raise ValueError('Different generated-configuration behavioral scope')
    text = source.split('\\label{app:tenoncandidates}',1)[1].split('\\subsection',1)[0]
    required = [f'bind all {counts[0]} generated candidates from the larger-budget batch to three distinct configurations',
        'Fifteen candidate aliases reuse two qualified profiles (six guest boots)',
        'remaining size-optimized TLSF configuration receives three new guest boots',
        f'All {counts[2]} aliases pass the configuration-level behavioral checks',
        'Historical compiler executable hashes were not captured',
        'aliases are not independent samples',
        'historical task-success denominators, completion budgets, timing and energy remain unchanged']
    if any(text.count(s) != 1 for s in required):
        raise ValueError('Published candidate-binding claims differ from evidence')
    return dict(zip(('generated_aliases','configurations','admitted_aliases','reused_guests','new_guests'),counts))


def require_tenon_lifecycle_claims(source,result):
    guests = [g for p in result['profiles'] for g in p['guests']]
    fields = ('events','native_allocations','native_frees','original_task_generations','reclaimed_original_tasks',
              'finite_tasks','finite_reclaimed','finite_task_address_reuses','original_tasks_without_adapter_delete')
    expected = (691,245,232,62,62,4,4,3,1)
    if result['audit']!='pass' or result['fresh_guests']!=9 or len(guests)!=9 or len(result['profiles'])!=3 or \
            any(tuple(g[k] for k in fields)!=expected for g in guests) or \
            any(p['static_writable']['bytes']!=528384 for p in result['profiles']):
        raise ValueError('Different native-memory lifecycle scope')
    text = source.split('\\label{app:tenonlifecycle}',1)[1].split('\\section',1)[0]
    claims = ['Each of nine fresh guests records 691 events, including 245 allocations and 232 frees',
        'storage of all 62 original tasks and four validation tasks to actual reclamation',
        'four sequential validation tasks reuse one task address',
        'Writable static storage is 528,384~B',
        'do not close early/unmanaged storage or continuous live-stack coverage']
    if any(text.count(s)!=1 for s in claims):
        raise ValueError('Published memory-lifecycle claims differ from evidence')
    return {'guests':9,'events_per_guest':691,'original_task_lifetimes':558,'separate_validation_lifetimes':36}


def native_sp_pairs_text(result):
    if result["audit"] != "pass" or result["independent_resets"] != 10 or not result["original_flash_restored"] or \
            result["whole_live_ram_peak_bytes"] is not None:
        raise ValueError("Different native-transition observer control scope")
    cell = result["cells"][0]
    lo, hi = [(v-1)*100 for v in cell["ratio_range"]]
    return ("Five matched baseline/native-transition-observer pairs change the first original count by a median of "
            f"{(cell['median_ratio']-1)*100:+.4f}\\% (range {lo:+.4f}\\% to {hi:+.4f}\\%). "
            f"The whole-image static increase is {cell['observer_static_delta_bytes']:,}\\,B.")


def ablation_and_hartstone_tables():
    from audit_esp32_followup import envelope, interrupts
    from audit_esp32_report import audit_hartstone_native_cohort

    name = "esp32-irq-ablation-capture-b1-v1"
    folder = REPORTS / name
    intervention = interrupts(folder, envelope(folder), REPORTS / "esp32-irq-ablation-v2")
    if intervention["independent_resets"] != 18 or not intervention["single_adapter_intervention"]:
        raise ValueError("Incomplete matched adapter intervention")
    titles = {"interrupt_processing": "Processing", "interrupt_preemption_processing": "Preemption processing"}
    tables = {"tab:ablation": [" & ".join((titles[cell["case"]],
        f"{cell['medians']['legacy']:,}", f"{cell['medians']['corrected']:,}",
        f"+{cell['relative_change_percent']:.2f}\\%")) for cell in intervention["cells"]]}
    evidence = {name: sha(folder / "campaign.json"), "esp32-irq-ablation-v2": sha(REPORTS / "esp32-irq-ablation-v2/build.json")}
    values = {"rhino_adapter_intervention": intervention, "hartstone_ph3": []}
    rows = []
    for system, relative, fifo in HARTSTONE_PH3_SOURCES:
        directory = REPORTS / relative
        image, runs = audit_hartstone_native_cohort(directory, system, 3, fifo=fifo)
        steps = [r["best_step"] for r in runs]
        speeds = [r["raw_speed_kwips"] for r in runs]
        utilization = [100 * (20000 + 254 * step) / speed for step, speed in zip(steps, speeds)]
        rows.append(f"{system} & {median(steps)} & {median(speeds)} & {median(utilization):.2f}\\%")
        captures = []
        for path in sorted(directory.glob("reset*.jsonl")):
            key = path.relative_to(ROOT).as_posix()
            evidence[key] = sha(path)
            captures.append({"path": key, "sha256": evidence[key]})
        values["hartstone_ph3"].append({"os": system, "image_sha256": image,
            "best_steps": steps, "raw_kwips": speeds, "requested_utilization_pct": utilization,
            "captures": captures, "board_cohort": "B0", "independent_resets": len(runs)})
    tables["tab:hartstone"] = rows
    return tables, evidence, values


def startup_handoff_text(build, run):
    h = run["startup_heap_handoff"]
    before, after = h["before_release"], h["after_release"]
    return (f"Five further resets bind the native startup-stack release to allocation events {before['event_cursor']}--{after['event_cursor']}: "
        f"occupied heap increases from {before['occupied_bytes']:,} to {after['occupied_bytes']:,}\\,B. "
        f"The released region has a capacity of {h['released_region_capacity_bytes']:,}\\,B, "
        f"but registration adds {h['new_allocator_metadata_bytes']:,}\\,B of allocator metadata. "
        f"This extension has {build['static_sram_bytes']:,}\\,B of static SRAM and "
        f"{run['software_reserved_and_allocated_peak_bytes']:,}\\,B of static-plus-allocated occupancy; "
        f"its native heap peak remains {run['heap_peak_bytes']:,}\\,B.")


def peak_context_text(result):
    runs = result["runs"]
    phases = runs[0]["allocation_peak_context"]["phases"]
    summary = [(p["phase"], p["native_heap_occupied_bytes"], p["allocation_event_cursor"])
               for p in phases]
    if len(runs) != 5 or [p[0] for p in summary] != [0, 1, 2] or any(
            [(p["phase"], p["native_heap_occupied_bytes"], p["allocation_event_cursor"])
             for p in run["allocation_peak_context"]["phases"]] != summary or
            len(run["allocation_peak_context"]["phases"][-1]["task_contexts"]) != 4 or
            run["tasks"]["created"] != 5 for run in runs):
        raise ValueError("Published allocation-context phase/ownership claim differs")
    return ("A five-reset allocation-context extension binds phase heap high-waters of "
        + ", ".join(f"{p[1]:,}" for p in summary[:2]) + f" and {summary[2][1]:,}\\,B "
        + "to event-prefix lengths " + ", ".join(str(p[2]) for p in summary[:2]) + f" and {summary[2][2]} "
        + "and same-instant native contexts. At the global heap peak, four tasks have recorded native ownership; "
        + "the fifth creation follows after storage is committed. "
        + f"This image contains {result['build']['static_sram_bytes']:,}\\,B static SRAM and "
        + f"{runs[0]['software_reserved_and_allocated_peak_bytes']:,}\\,B static-plus-allocated occupancy, including instrumentation.")


def boot_stage_text(result):
    rows = result["runs"]
    first = rows[0]["boot_stages"]
    if len(rows) != 5 or not result["application_binary_unchanged"] or not result["independent_stdlib_replay"] or any(
            run["boot_stages"] != first for run in rows) or first[0]["guard"] != 64:
        raise ValueError("Published boot-stage repetition or application identity differs")
    return ("Five boot-stage resets keep the application binary unchanged. "
        f"Each verifies {first[0]['verified']:,} marked stack bytes and observes "
        f"{first[0]['touched']:,}\\,B touched after initialization and {first[1]['touched']:,}\\,B "
        "before boot-console deinitialization, with a 64-B unmarked guard.")


def continuous_context_text(result, coverage, paired):
    runs = [r for r in result["runs"] if not r["validation"]]
    summaries = [r["continuous_stack"]["summary"] for r in runs]
    if len(runs) != 5 or any(s != summaries[0] or s["unknown"] or s["bad"] or s["invalid"] or s["limit"]
            for s in summaries) or paired["independent_resets"] != 10 or len(paired["cells"]) != 1:
        raise ValueError("Continuous observation repetition or paired coverage differs")
    heap = [r["native"]["heap_peak_bytes"] for r in runs]
    cell = paired["cells"][0]
    if len(set(heap)) != 1 or len(cell["pairs"]) != 5:
        raise ValueError("Continuous heap or paired repetition differs")
    change = (cell["median_ratio"] - 1) * 100
    lo, hi = [(v - 1) * 100 for v in cell["ratio_range"]]
    return (f"A continuous FreeRTOS extension records {summaries[0]['total']:,} instruction-boundary observations "
        "per reset across five fresh resets, with no unclassified task or ordinary-IRQ context. "
        f"This image has {coverage['static_sram_bytes']:,}\\,B static SRAM and a {heap[0]:,}\\,B allocated-heap peak. "
        f"Five alternating baseline/continuous-observer pairs change the first original count by a median of {change:+.4f}\\% "
        f"(range {lo:+.4f}\\% to {hi:+.4f}\\%).")


def runtime_coverage_text(result):
    runs = result["runs"]
    if len(runs) != 5 or any(r != runs[0] for r in runs) or not runs[0]["exact_available_address_set_match"] or \
            result["new_board_captures"] != 0 or result["whole_live_ram_peak_bytes"] is not None:
        raise ValueError("Address coverage is not the same five reused resets")
    return (f"An address-set replay matches all {runs[0]['native_pool_count']} native heap pools, totaling "
        f"{runs[0]['observed_native_capacity_bytes_not_occupancy']:,}\\,B capacity, to "
        f"{len(result['compiled_descriptors'])} compiled region descriptors minus reservations. "
        f"An additional {result['fixed_reservations_outside_static_and_heap_bytes']:,}\\,B lies in fixed cache/ROM "
        f"reservations or linker padding, and {sum(r['bytes'] for r in result['outside_compiled_layout']):,}\\,B "
        "of RTC slow memory lies outside the allocator layout.")


def native_sp_text(main, separate):
    runs = main["application"]["runs"]
    validation = main["application"]["separate_validation"]
    other = separate["runs"]
    if len(runs) != 5 or len(other) != 6 or not other[0]["validation"] or any(
            a["native_sp"] != b["native_sp"] for a, b in zip([validation] + runs, other)) or \
            main["whole_live_ram_peak_bytes"] is not None or main["ranking_eligible"] or \
            separate["whole_live_ram_peak_bytes"] is not None or separate["ranking_eligible"]:
        raise ValueError("Native SP observation/replay boundary differs")
    summaries = [r["native_sp"]["summary"] for r in runs]
    if any(s != summaries[0] or s["unknown"] or s["bad"] or s["invalid"] or
            any(s["site" + str(i)] <= 0 for i in range(1, 6)) for s in summaries):
        raise ValueError("Native SP reset repetition or classified context differs")
    finite = validation["native_sp"]["summary"]
    return (f"Five reused FreeRTOS message resets record {summaries[0]['total']:,} observations each "
        "at five reviewed native assembly task/IRQ boundaries, with no unclassified or invalid context. "
        f"The observed same-instant joint stack occupancy is {summaries[0]['joint_peak']:,}\\,B in every reset. "
        f"A separate finite validation records {finite['generations']} task generations and {finite['retired']} retirements.")


def combined_stacks_text(result):
    rows = [r for r in result["runs"] if not r["validation"]]
    keys = ("boundary_observations", "native_observations", "boundary_joint_stack_bytes", "native_joint_stack_bytes",
            "boundary_peak_allocation_event", "native_peak_allocation_event", "heap_peak_bytes", "static_and_allocated_peak_bytes")
    if len(rows) != 5 or any(tuple(r[k] for k in keys) != tuple(rows[0][k] for k in keys) or
            not r["same_task_storage_and_generations"] or r["peaks_added_together"] for r in rows) or \
            result["whole_live_ram_peak_bytes"] is not None or result["ranking_eligible"]:
        raise ValueError("Combined stack repetition, identity or peak boundary differs")
    r = rows[0]
    if r["static_and_allocated_peak_bytes"] != result["static_sram_bytes"] + r["heap_peak_bytes"]:
        raise ValueError("Combined static/heap occupancy double-counts storage")
    return ("A combined image passes five message resets and one separate finite validation. "
        f"Each message reset records {r['boundary_observations']:,} C-boundary and {r['native_observations']:,} "
        "native-transition observations with matching task generations and physical storage. "
        f"Observed joint stack spans are {r['boundary_joint_stack_bytes']:,} and {r['native_joint_stack_bytes']:,}\\,B "
        f"at allocation prefixes {r['boundary_peak_allocation_event']} and {r['native_peak_allocation_event']}, respectively. "
        f"This image contains {result['static_sram_bytes']:,}\\,B static SRAM and "
        f"{r['heap_peak_bytes']:,}\\,B peak allocated heap, totaling {r['static_and_allocated_peak_bytes']:,}\\,B.")


def tenon_history_rows(result):
    rows = result["histories"]
    if result["audit"] != "pass" or result["registered_histories"] != 6 or \
            result["registered_rounds"] != 12 or len(rows) != 6 or any(
                h["accepted_rounds"] + h["rejected_rounds"] != 2 or not h["within_history_budget"] for h in rows):
        raise ValueError("Tenon history coverage or budgets differ")
    return [f"{h['id'].split('-')[0]} / {h['method']} & {h['accepted_rounds']}/2 & "
            f"{h['rejected_rounds']}/2 & {h['total_round_wall_s']:.2f}" for h in rows]


def tenon_history_text(result):
    tenon_history_rows(result)
    groups = {m: [h for h in result["histories"] if h["method"] == m] for m in ("direct", "graph")}
    passed = sum(h["accepted_rounds"] for h in groups["direct"])
    failed = sum(h["rejected_rounds"] for h in groups["graph"])
    if any(len(g) != 3 for g in groups.values()) or (passed, failed) != (6, 6):
        raise ValueError("Published Tenon branch outcomes differ")
    return ("Six further two-round histories request the opposite allocator from the actually retained parent. "
        "Direct prompting passes all six modifications; six graph requests truncate and retain their parents. "
        f"Median cumulative attempt and recovery costs are {median(h['total_round_wall_s'] for h in groups['direct']):.2f} "
        f"and {median(h['total_round_wall_s'] for h in groups['graph']):.2f}~s, respectively.")


def tenon_repair_text(result):
    tenon_history_rows(result)
    groups={g['method']:g for g in result['groups']}
    for method,g in groups.items():
        rows=[h for h in result['histories'] if h['method']==method]
        if len(rows)!=3 or g['accepted_rounds']!=sum(h['accepted_rounds'] for h in rows) or \
                g['total_round_wall_median_s']!=median(h['total_round_wall_s'] for h in rows):
            raise ValueError('Repaired history group accounting differs')
    return (f"The serialization-repaired batch uses {result['model_calls']} model calls and "
        f"{result['completion_tokens']:,} output tokens. It captures {result['candidate_guest_captures']} fresh "
        f"candidate guests and {result['parent_check_guest_captures']} initial or recovery checks. "
        f"Direct prompting accepts {groups['direct']['accepted_rounds']}/6 modifications and graph orchestration "
        f"accepts {groups['graph']['accepted_rounds']}/6. Median cumulative attempt and recovery costs are "
        f"{groups['direct']['total_round_wall_median_s']:.2f} and "
        f"{groups['graph']['total_round_wall_median_s']:.2f}~s, respectively.")


def tenon_impact_text(result):
    if result['audit']!='pass' or result['fresh_guests']!=18 or result['native_builds']!=6 or \
            result['whole_live_ram_peak_bytes'] is not None or result['ranking_eligible'] or result['energy_measured']:
        raise ValueError('Different lifecycle-observer impact scope')
    rows=result['profiles']
    if [p['profile'] for p in rows]!=['initial-tlsf','accepted-buddy','accepted-tlsf']:
        raise ValueError('Missing impact profile')
    for p in rows:
        ratios=p['elapsed_observer_over_baseline']
        if len(ratios)!=3 or p['pairs']!=3 or p['median_ratio']!=median(ratios) or p['range']!=[min(ratios),max(ratios)] or \
                p['modes']['baseline']['static_writable']['bytes']!=299008 or p['modes']['observer']['static_writable']['bytes']!=528384:
            raise ValueError('Impact pairs or static extents differ')
    changes=', '.join(f"{(p['median_ratio']-1)*100:+.4f}\\%" for p in rows)
    irq=[v for p in rows for v in p['original_counter_ratios_diagnostic_only']['interrupt_latency_time, in cpu cycles']]
    if len(irq)!=9 or any(v is None for v in irq):raise ValueError('IRQ diagnostic pair coverage differs')
    return (f"A matched lifecycle-observer experiment rebuilds three configurations and runs 18 fresh guests in nine counterbalanced pairs. "
        rf"Both forms time the original six-case suite using CNTVCT\_EL0 and the recorded {result['counter_frequency_hz']:,}-Hz CNTFRQ\_EL0. "
        f"Median observer/baseline elapsed-time changes are {changes} for initial TLSF, accepted buddy and accepted TLSF, respectively. "
        "Writable static storage is 299,008 and 528,384\\,B in the baseline and observer images, respectively. "
        f"Across these pairs, original IRQ-counter ratios range from {min(irq):.6f} to {max(irq):.6f}.")


def require_held_out_claims(source, result):
    policies=result["policies"]
    histories=result["sequence"]["histories"]
    if result["physical_resets"]!=3 or len(policies)!=1 or len(policies[0]["aliases"])!=13 or \
            len(histories)!=3 or result["sequence"]["registered_model_calls"]!=6 or any(
                len(h["rounds"])!=2 or any(r["accepted"] or not r["gates"]["functional"] or
                    r["gates"]["constraints"] for r in h["rounds"]) or
                h["final_options"]!=policies[0]["options"] for h in histories):
        raise ValueError("Published held-out policy/trajectory scope differs")
    counts=policies[0]["original_counts_30s"]
    costs=[h["total_round_wall_s"] for h in histories]
    normalized=" ".join(source.split())
    expected=(
        "All thirteen initial, built-candidate and retained-policy aliases resolve to one policy.",
        f"Three held-out resets produce {counts[0]:,}, {counts[1]:,} and {counts[2]:,} original counts per thirty seconds;",
        f"The new histories' round costs are {costs[0]:.2f}, {costs[1]:.2f} and {costs[2]:.2f}~s,")
    if any(normalized.count(text)!=1 for text in expected):
        raise ValueError("Published held-out counts or trajectory costs differ")


def audit(source_path):
    source_bytes = source_path.read_bytes()
    source = source_bytes.decode('utf-8')
    tables, evidence, source_values = ablation_and_hartstone_tables()
    counts = []
    for title, case, version in CASES:
        name = ("esp32-message" if case == "message_processing" else "esp32-" + case) + "-cohort-b1-v" + str(version)
        result = kernel_audit(REPORTS / name)
        if result["board_mac"] != "34:98:7a:a2:85:28" or result["independent_resets"] != 9:
            raise ValueError("Wrong board or replication for " + case)
        cells = {cell["os"]:cell for cell in result["cells"]}
        values = [cells[system]["median"] for system in SYSTEMS]
        counts.append(title + " & " + " & ".join(f"{value / 1e6:.3f}" for value in values))
        source_values[case] = {system:cells[system]["values"] for system in SYSTEMS}
        evidence[name] = sha(REPORTS / name / "campaign.json")
    tables["tab:throughput"] = counts

    memory = ram_audit()
    tables["tab:ram"] = [" & ".join((cell["os"], f"{cell['static_sram_bytes']:,}",
        f"{cell['observer_static_delta_bytes']:,}", f"{max(cell['observed_allocated_software_bytes']):,}"))
        for cell in memory["cells"]]
    if '\\label{app:allocatedcapacity}' in source:
        from esp32_allocated_capacity_publication import summary as capacity_summary,paper_text as capacity_text
        capacity=capacity_summary(ROOT)
        if capacity is None or source.count(capacity_text(capacity))!=1:
            raise ValueError('Normal-boot observer capacity evidence or manuscript differs')
        tables['tab:ram']=[' & '.join((c['os'],format(c['static_sram_bytes'],','),
            format(c['peak_allocated_occupancy_bytes'],','))) for c in capacity['rows']]
        source_values['normal_boot_observer_capacity']=capacity
        evidence.update(capacity['evidence'])
        if '\\label{tab:ram-bindings}' in source:
            tables['tab:ram-bindings'], bindings = ram_image_rows(capacity)
            evidence.update(bindings)
    source_values["message_ram"] = memory["cells"]
    for cell in memory["cells"]:
        evidence[cell["evidence"]] = cell["campaign_sha256"]

    energy = energy_audit(REPORTS / "esp32-message-energy-b1-v1")
    rows = []
    for cell in energy["cells"]:
        medians = cell["medians"]
        values = [r["paired"]["energy_per_original_count_uj"] for r in cell["runs"]]
        rows.append(" & ".join((cell["os"], f"{medians['steady_average_power_w'] * 1000:.2f}",
            f"{medians['energy_per_original_count_uj']:.5f}", f"{min(values):.5f}--{max(values):.5f}")))
        source_values["energy_" + cell["os"]] = {
            "uj_per_original_count": values,
            "power_w": [r["paired"]["steady_average_power_w"] for r in cell["runs"]]}
    tables["tab:energy"] = rows
    evidence["esp32-message-energy-b1-v1"] = sha(REPORTS / "esp32-message-energy-b1-v1/campaign.json")
    from audit_esp32_energy_window_sensitivity import cadence_audit
    cadence = cadence_audit()
    expected_cadence = (f"Recorded host-query gaps have a {cadence['median_gap_s'] * 1000:.3f}-ms median "
        f"and {cadence['maximum_gap_s'] * 1000:.3f}-ms maximum")
    if source.count(expected_cadence) != 1 or cadence['independent_resets_reused'] != 75 or \
            cadence['nominal_host_poll_interval_s'] != 0.1:
        raise ValueError("Published energy acquisition cadence differs from raw timestamps")
    source_values["energy_acquisition_cadence"] = cadence
    if '\\label{app:energygain}' in source:
        from audit_esp32_energy_gain_scenario import audit as gain_audit, paper_text as gain_text, summary as gain_summary
        gain=gain_audit(ROOT);path=REPORTS/'esp32-energy-gain-scenario-v1.json'
        if gain!=json.loads(path.read_text()) or source.count(gain_text(gain))!=1:
            raise ValueError('Energy gain scenario or manuscript interpretation differs')
        source_values['energy_gain_scenario']=gain_summary(gain)
        evidence['energy-gain-scenario']=sha(path)
    for row in cadence["rows"]:
        evidence[row["campaign"]] = row["campaign_sha256"]
    if '\\label{app:unified-mainboard}' in source:
        from esp32_unified_mainboard_results import audit as unified_audit
        from audit_esp32_resources import static_footprint
        unified=unified_audit();path=REPORTS/'esp32-unified-mainboard-v1.json'
        if unified!=json.loads(path.read_text()):
            raise ValueError('Unified five-system evidence differs')
        for os in ('RIOT','AliOS-Rhino'):
            image=unified['ram_observer_images'][os]
            footprint=static_footprint(ROOT/image['source']/'application.elf')
            row=next(r for r in unified['rows'] if r['os']==os)
            tables['tab:ram'].append(' & '.join((os,format(footprint['static_sram_bytes'],','),
                format(row['peak_allocated_ram_bytes'],',.0f'))))
            message,=[r for r in unified['kernel_energy_raw_cells'] if r['os']==os and r['case']=='message_processing']
            energies=message['energy_uj_per_count']
            tables['tab:energy'].append(' & '.join((os,
                f"{median(message['same_window_mean_input_power_w'])*1000:.2f}",
                f"{median(energies):.5f}",f"{min(energies):.5f}--{max(energies):.5f}")))
        tables['tab:unified-mainboard-raw']=unified_mainboard_rows(unified)
        source_values['unified_mainboard']=unified
        evidence['unified-mainboard']=sha(path)
    for label, rows in tables.items():
        require_rows(source, label, rows)
    from run_esp32_common_tcp import audit as tcp_audit
    tcp_name = "esp32-common-original-tcp-b1-v1"
    tcp = tcp_audit(REPORTS/tcp_name)
    by_system = {c["system"]:c for c in tcp["cells"]}
    order = ("FreeRTOS","NuttX","Zephyr")
    medians = ", ".join(f"{by_system[s]['median_mbit_s']:.3f}" for s in order[:-1]) + ", and " + f"{by_system[order[-1]]['median_mbit_s']:.3f}"
    ranges = ["--".join(f"{v:.3f}" for v in by_system[s]["range_mbit_s"]) for s in order]
    expected = ("Median receiver throughput is " + medians + "~Mbit/s for FreeRTOS, NuttX, and Zephyr; observed ranges are " +
                ", ".join(ranges[:-1]) + ", and " + ranges[-1] + ".")
    if source.count(expected) != 1:
        raise ValueError("Published common TCP paragraph differs from original receiver replay")
    evidence[tcp_name] = sha(REPORTS/tcp_name/"campaign.json")
    source_values["common_original_tcp"] = tcp["cells"]
    udp_name="esp32-common-original-udp-b1-v3"
    udp=tcp_audit(REPORTS/udp_name,protocol="udp")
    by_system={c["system"]:c for c in udp["cells"]}
    rates=", ".join(f"{by_system[s]['median_mbit_s']:.3f}" for s in SYSTEMS[:-1])+", and "+f"{by_system[SYSTEMS[-1]]['median_mbit_s']:.3f}"
    sentence="Five resets per OS give median receiver rates of "+rates+"~Mbit/s for FreeRTOS, Zephyr, and NuttX."
    packets={s:[r["sent_packets"] for r in by_system[s]["runs"]] for s in SYSTEMS}
    counts=("Despite the common request and 100-Hz tick, FreeRTOS sends "+f"{packets['FreeRTOS'][0]:,}"+
        " packets per reset, versus "+f"{min(packets['Zephyr']):,}--{max(packets['Zephyr']):,}"+
        " for Zephyr and "+f"{min(packets['NuttX']):,}--{max(packets['NuttX']):,}"+" for NuttX.")
    if udp["independent_resets"]!=15 or len(set(packets["FreeRTOS"]))!=1 or \
            source.count(sentence)!=1 or source.count(counts)!=1:
        raise ValueError("Published common UDP rates/offered packet counts differ")
    evidence[udp_name]=sha(REPORTS/udp_name/"campaign.json")
    source_values["common_original_udp"]=udp["cells"]
    from run_esp32_common_udp_receiver import source_queue_control
    queue_name="esp32-common-udp-source-queue-control-b1-v2"
    queue=source_queue_control(REPORTS/queue_name)
    if queue["physical_resets"]!=1 or queue["qualified_resets"]!=0 or queue["ranking_eligible"] or \
            queue["before_queue_drop_delta"]["root"]!=4 or len(queue["before_missing_outgoing_ids"])!=4 or \
            queue["source_queue_drop_delta"]["root"]!=0 or queue["result"]["sender_datagrams"]!=73243 or \
            source.count("All 73,243 data packets appeared in the interface capture, with zero additional host-queue drops.")!=1 or \
            "This single-reset intervention supports checking the offered sequence at the interface" not in source:
        raise ValueError("Published single-reset source queue control differs from raw evidence")
    evidence[queue_name]=queue["campaign_sha256"]
    source_values["host_source_queue_control"]=queue
    from run_esp32_common_udp_receiver import audit as receiver_audit
    receiver_name="esp32-common-original-udp-receiver-b1-v6"
    receiver=receiver_audit(REPORTS/receiver_name)
    by_system={c["system"]:c for c in receiver["cells"]}
    medians=[f"{by_system[s]['median_mbit_s']:.3f}" for s in SYSTEMS]
    ranges=["--".join(f"{v:.3f}" for v in by_system[s]["range_mbit_s"]) for s in SYSTEMS]
    sentence=("Median receiver rates are "+", ".join(medians[:-1])+", and "+medians[-1]+
        "~Mbit/s for FreeRTOS, Zephyr, and NuttX, with ranges "+", ".join(ranges[:-1])+", and "+ranges[-1]+".")
    if receiver["independent_resets"]!=15 or receiver["reused_complete_resets"]!=0 or \
            receiver.get("source_queue_profile")!="mq-four-pfifo-10240-v1" or source.count(sentence)!=1 or \
            any(r["sender_datagrams"]!=73243 for c in receiver["cells"] for r in c["runs"]):
        raise ValueError("Published fixed-load UDP receiver comparison differs")
    evidence[receiver_name]=sha(REPORTS/receiver_name/"campaign.json")
    source_values["common_original_udp_receiver"]=receiver["cells"]
    from run_esp32_nuttx_message_lifetimes import audit as address_audit
    address_name = "esp32-nuttx-message-identities-b1-v1"
    address = address_audit(REPORTS/address_name, REPORTS/"esp32-nuttx-message-identities-v1")
    old_nuttx = next(c for c in memory["cells"] if c["os"] == "NuttX")
    if address["independent_resets"] != 5 or any(r["native_heap_peak_bytes"] !=
            old_nuttx["native_heap_peak_bytes"][i] for i,r in enumerate(address["runs"])) or \
            address["build"]["static_sram_bytes"]-old_nuttx["static_sram_bytes"] != 8192:
        raise ValueError("Published address extension reset count, overhead or unchanged heap peak differs")
    evidence[address_name] = sha(REPORTS/address_name/"campaign.json")
    source_values["nuttx_address_extension"] = [{"native_heap_peak_bytes":r["native_heap_peak_bytes"],
        "allocation_transitions":r["allocation_identity_replay"]["transitions"],
        "live_blocks":len(r["allocation_identity_replay"]["live"])} for r in address["runs"]]
    from run_esp32_message_observer_pairs import audit as pairs_audit
    pair_name="esp32-nuttx-address-observer-pairs-b1-v1"
    paired=pairs_audit(REPORTS/pair_name)
    cell=paired["cells"][0]
    median_change=(cell["median_ratio"]-1)*100
    lo,hi=[(v-1)*100 for v in cell["ratio_range"]]
    sentence=(f"Five additional baseline/extension pairs change the first original count by a median of {median_change:+.6f}\\% "
        f"(range {lo:+.6f}\\% to {hi:+.6f}\\%); this whole-image comparison includes code layout.")
    if paired["independent_resets"]!=10 or source.count(sentence)!=1:
        raise ValueError("Published new observer paired count change differs")
    evidence[pair_name]=sha(REPORTS/pair_name/"campaign.json")
    source_values["nuttx_address_observer_pairs"]=cell
    from audit_esp32_message_startup import audit as startup_audit
    startup=startup_audit()
    expected=("Compiled startup maps FreeRTOS's six heap pools to providers minus reservations; "
        "five traces place the startup-stack handoff after main creation.",
        "Zephyr's static heap matches its PRE\\_KERNEL\\_1 entry.")
    if any(source.count(sentence)!=1 for sentence in expected) or len(startup["cells"][0]["native_available_pools"])!=6 or \
            len(startup["cells"][0]["five_reset_handoff_replay"])!=5:
        raise ValueError("Published startup/provider scope claim differs")
    evidence["esp32-message-startup-cohort-v1.json"]=sha(REPORTS/"esp32-message-startup-cohort-v1.json")
    source_values["message_startup_scope"]=startup
    from run_esp32_zephyr_message_lifetimes import audit as stack_audit
    from replay_esp32_message_stack import replay as stack_replay
    name="esp32-zephyr-message-stack-b1-v1"
    prepared=REPORTS/"esp32-zephyr-message-stack-v1"
    observed=stack_audit(REPORTS/name,prepared)
    separate=stack_replay(REPORTS/name,prepared)
    reporter=observed["build"]["reservations"]["threads"][0]+5*96
    for left,right in zip(observed["runs"],separate["runs"],strict=True):
        item=left["native_stack_observations"]
        current=[r["touched"] for r in item["tasks"] if r["phase"]=="message-end" and r["tcb"]==reporter]
        irq=[r["touched"] for r in item["irq"] if r["phase"]=="message-end"]
        if current!=[776] or irq!=[48] or any(item[k]!=right[k] for k in ("irq","tasks")):
            raise ValueError("Published message-task native watermarks differ")
    expected=("Five further Zephyr message-task resets observe current report-thread and ordinary IRQ "
        "touch watermarks (776 and 48\\,B) inside static reservations.")
    if observed["independent_resets"]!=5 or source.count(expected)!=1:
        raise ValueError("Published native message-stack claim differs")
    evidence[name]=sha(REPORTS/name/"campaign.json")
    source_values["zephyr_message_stack"]=separate
    from replay_esp32_followup import replay
    name="esp32-zephyr-stack-observer-pairs-b1-v1"
    paired=pairs_audit(REPORTS/name)
    separate=replay(REPORTS/name)
    cell=paired["cells"][0]
    median_change=(cell["median_ratio"]-1)*100
    lo,hi=[(v-1)*100 for v in cell["ratio_range"]]
    expected=(f"Five alternating baseline/new-Zephyr pairs change the first count by a median of {median_change:+.6f}\\% "
        f"(range {lo:+.6f}\\% to {hi:+.6f}\\%), including code-layout effects.")
    if paired["independent_resets"]!=10 or source.count(expected)!=1 or separate["cells"]!=[
            {k:cell[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
        raise ValueError("Published new Zephyr stack observer count changes differ")
    evidence[name]=sha(REPORTS/name/"campaign.json")
    source_values["zephyr_stack_observer_pairs"]=cell
    from run_esp32_tm_ram_lifetimes import audit as freertos_audit
    from replay_esp32_freertos_message import replay as freertos_replay
    from audit_esp32_freertos_stack_coverage import vector_binding
    name="esp32-freertos-message-stack-b1-v1"
    prepared=REPORTS/"esp32-freertos-message-stack-v1"
    observed=freertos_audit(REPORTS/name,prepared)
    separate=freertos_replay(REPORTS/name,prepared)
    vector=vector_binding(prepared)
    expected=("Five FreeRTOS resets observe 16\\,B touched in its ordinary IRQ stack; linked instructions reserve "
        "a 192-B context frame on the interrupted task stack before switching to it. Untouched frame bytes evade canary measurements.")
    if observed["independent_resets"]!=5 or source.count(expected)!=1 or \
            vector["interrupted_task_frame_reserved_bytes"]!=192:
        raise ValueError("Published FreeRTOS task-frame/IRQ boundary differs")
    for left,right in zip(observed["runs"],separate["runs"],strict=True):
        if left["ordinary_irq_stack"]["touched_watermark_bytes"]!=16 or any(left[k]!=right[k]
                for k in ("ordinary_irq_stack","heap_peak_bytes","live_tasks")):
            raise ValueError("Independent FreeRTOS message memory replay differs")
    evidence[name]=sha(REPORTS/name/"campaign.json")
    source_values["freertos_message_stack"]=separate
    source_values["freertos_irq_vector"]=vector
    name="esp32-freertos-stack-observer-pairs-b1-v1"
    paired=pairs_audit(REPORTS/name)
    separate=replay(REPORTS/name)
    cell=paired["cells"][0]
    median_change=(cell["median_ratio"]-1)*100
    expected=(f"Five baseline/new-FreeRTOS pairs change the first count by {median_change:+.6f}\\% "
        "in every pair, including code layout.")
    if paired["independent_resets"]!=10 or source.count(expected)!=1 or len(set(cell["ratio_range"]))!=1 or \
            separate["cells"]!=[{k:cell[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
        raise ValueError("Published FreeRTOS stack observer paired count changes differ")
    evidence[name]=sha(REPORTS/name/"campaign.json")
    source_values["freertos_stack_observer_pairs"]=cell
    if "An application-entry extension" in source:
        name="esp32-freertos-message-startup-b1-v1"
        prepared=REPORTS/"esp32-freertos-message-startup-v1"
        observed=freertos_audit(REPORTS/name,prepared)
        separate=freertos_replay(REPORTS/name,prepared)
        windows=[r["application_startup_stack"] for r in observed["runs"]]
        if observed["independent_resets"]!=5 or any(w!=windows[0] for w in windows):
            raise ValueError("Application startup reset-level results differ")
        for left,right in zip(observed["runs"],separate["runs"],strict=True):
            if left["application_startup_stack"]!=right["application_startup_stack"]:
                raise ValueError("Independent application startup replay differs")
        w=windows[0]
        expected=(f"An application-entry extension verifies {w['initial_painted_and_verified_bytes']:,} marked bytes before startup and "
            f"observes {w['touched_watermark_bytes']:,}\\,B touched before native heap handoff in each of five further resets, "
            f"excluding a {w['unpainted_guard_bytes']}-B unmarked guard.")
        if source.count(expected)!=1:
            raise ValueError("Published application-entry watermark scope differs")
        evidence[name]=sha(REPORTS/name/"campaign.json")
        source_values["freertos_message_startup"]=separate
        name="esp32-freertos-startup-observer-pairs-b1-v1"
        paired=pairs_audit(REPORTS/name)
        separate=replay(REPORTS/name)
        cell=paired["cells"][0]
        expected=("Five pairs specific to this extension change the first original count by "
            f"{(cell['median_ratio']-1)*100:+.6f}\\%, including code layout.")
        if paired["independent_resets"]!=10 or len(set(cell["ratio_range"]))!=1 or source.count(expected)!=1 or \
                separate["cells"]!=[{k:cell[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
            raise ValueError("Published application startup observer impact differs")
        evidence[name]=sha(REPORTS/name/"campaign.json")
        source_values["freertos_startup_observer_pairs"]=cell
    if "A NuttX extension captures startup" in source:
        from run_esp32_nuttx_message_lifetimes import audit as nuttx_audit
        name="esp32-nuttx-message-startup-b1-v1"
        prepared=REPORTS/"esp32-nuttx-message-startup-v5"
        observed=nuttx_audit(REPORTS/name,prepared)
        separate=replay(REPORTS/name,prepared=prepared)
        windows=[r["application_startup_stack"] for r in observed["runs"]]
        if observed["independent_resets"]!=5 or any(w!=windows[0] for w in windows):
            raise ValueError("Native idle startup results differ across declared resets")
        for left,right in zip(observed["runs"],separate["cells"][0]["runs"],strict=True):
            if left["application_startup_stack"]!=right["application_startup_stack"]:
                raise ValueError("Independent native idle startup watermark/switch differs")
        w=windows[0]
        expected=("A NuttX extension captures startup before native idle recoloring. "
            f"Five resets record a {w['touched_watermark_bytes']}-B watermark in its unchanged "
            f"{w['idle_reserved_bytes']:,}-B idle stack and retain the native {w['inherited_native_frame_bytes']}-B inherited entry frame.")
        if source.count(expected)!=1:
            raise ValueError("Published native idle startup method/value differs")
        evidence[name]=sha(REPORTS/name/"campaign.json")
        source_values["nuttx_message_startup"]=separate
        name="esp32-nuttx-startup-observer-pairs-b1-v1"
        paired=pairs_audit(REPORTS/name)
        separate=replay(REPORTS/name)
        cell=paired["cells"][0]
        expected=("Five baseline/startup-observer pairs change the first NuttX count by a median of "
            f"{(cell['median_ratio']-1)*100:+.6f}\\% (range {(cell['ratio_range'][0]-1)*100:+.6f}\\% to "
            f"{(cell['ratio_range'][1]-1)*100:+.6f}\\%), including code layout.")
        if paired["independent_resets"]!=10 or source.count(expected)!=1 or \
                separate["cells"]!=[{k:cell[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
            raise ValueError("Published native idle startup observer impact differs")
        evidence[name]=sha(REPORTS/name/"campaign.json")
        source_values["nuttx_startup_observer_pairs"]=cell
    if "A Zephyr startup extension" in source:
        from run_esp32_zephyr_message_lifetimes import audit as zephyr_audit
        from replay_esp32_message_stack import replay as stack_replay
        name="esp32-zephyr-message-startup-b1-v1"
        prepared=REPORTS/"esp32-zephyr-message-startup-v2"
        observed=zephyr_audit(REPORTS/name,prepared)
        separate=stack_replay(REPORTS/name,prepared)
        windows=[r["application_startup_stack"] for r in observed["runs"]]
        if observed["independent_resets"]!=5 or any(w!=windows[0] for w in windows) or any(
                a["application_startup_stack"]!=b["application_startup_stack"] for a,b in
                zip(observed["runs"],separate["runs"],strict=True)):
            raise ValueError("Inherited startup reset-level results or separate replay differ")
        w=windows[0]
        expected=(f"A Zephyr startup extension verifies {w['initial_painted_and_verified_bytes']:,} marked bytes on the inherited ROM stack "
            f"and records {w['touched_watermark_bytes']:,}\\,B touched in each of five resets before POST\\_KERNEL initialization "
            f"in the first main context, excluding a {w['unpainted_guard_bytes']}-B guard.")
        if source.count(expected)!=1:
            raise ValueError("Published inherited ROM-stack window differs")
        evidence[name]=sha(REPORTS/name/"campaign.json")
        source_values["zephyr_message_startup"]=separate
        if "Five pairs specific to the Zephyr startup extension" in source:
            name="esp32-zephyr-startup-observer-pairs-b1-v1"
            paired=pairs_audit(REPORTS/name)
            separate=replay(REPORTS/name)
            cell=paired["cells"][0]
            expected=("Five pairs specific to the Zephyr startup extension change the first count by a median of "
                f"{(cell['median_ratio']-1)*100:+.6f}\\% (range {(cell['ratio_range'][0]-1)*100:+.6f}\\% to "
                f"{(cell['ratio_range'][1]-1)*100:+.6f}\\%), including code layout.")
            if paired["independent_resets"]!=10 or source.count(expected)!=1 or separate["cells"]!=[
                    {k:cell[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
                raise ValueError("Published inherited startup observer impact differs")
            evidence[name]=sha(REPORTS/name/"campaign.json")
            source_values["zephyr_startup_observer_pairs"]=cell
    if "Static deltas include layout and linked changes" in source:
        from audit_esp32_ram_scope import observer_ownership
        ownership=observer_ownership()
        name="esp32-message-observer-ownership-v1.json"
        if ownership!=json.loads((REPORTS/name).read_text()) or len(ownership["cells"])!=3 or not any(
                c["other_linked_change_and_alignment_bytes"] for c in ownership["cells"]):
            raise ValueError("Observer input-section ownership claim differs")
        evidence[name]=sha(REPORTS/name)
        source_values["observer_static_ownership"]=ownership
    if "A native GCC5 Rhino replay exposes a startup confound" in source:
        from audit_esp32_rhino_message_reclamation import audit as reclamation_audit
        reclamation=reclamation_audit()
        expected=("five resets yield one 25,000-B and four 33,872-B heap endpoints",
            "The 8,872-B difference is an 8,704-B bootstrap stack, a 136-B control block, and two 16-B allocation headers.",
            "Waiting for native bootstrap reclamation before the unchanged message test yields 25,000\\,B in five further resets.")
        if any(source.count(s)!=1 for s in expected) or reclamation["legacy_heap_before_bytes"]!=[25000]+[33872]*4 or \
                reclamation["legacy_heap_after_bytes"]!=[25000]*5:
            raise ValueError("Published Rhino bootstrap contrast differs")
        name="esp32-rhino-message-boot-reclamation-v1.json"
        if reclamation!=json.loads((REPORTS/name).read_text()):
            raise ValueError("Rhino bootstrap evidence changed")
        evidence[name]=sha(REPORTS/name)
        source_values["rhino_bootstrap_reclamation"]=reclamation
    if "Native 100-Hz context snapshots bind" in source:
        from run_esp32_tm_ram_lifetimes import audit as f_tick_audit
        from run_esp32_zephyr_message_lifetimes import audit as z_tick_audit
        from replay_esp32_freertos_message import replay as f_tick_replay
        from replay_esp32_message_stack import replay as z_tick_replay
        from run_esp32_nuttx_message_lifetimes import audit as n_tick_audit
        from replay_esp32_followup import replay as n_tick_replay
        for system,version,build_name,check,separate in (
                ('freertos','v1','esp32-freertos-message-tick-stacks-v1',f_tick_audit,f_tick_replay),
                ('zephyr','v1','esp32-zephyr-message-tick-stacks-v3',z_tick_audit,z_tick_replay),
                ('nuttx','v2','esp32-nuttx-message-tick-stacks-v2',n_tick_audit,
                    lambda folder,prepared:n_tick_replay(folder,prepared)['cells'][0])):
            name='esp32-'+system+'-message-tick-stacks-b1-'+version
            folder,prepared=REPORTS/name,REPORTS/build_name
            observed=json.loads(json.dumps(check(folder,prepared)))
            independent=separate(folder,prepared)
            if observed!=json.loads((folder/'audit.json').read_text()) or observed['independent_resets']!=5 or \
                    observed['build'].get('profile',observed['build'])['tick_hz']!=100 or any(
                        a['native_tick_stack_snapshots']!=b['native_tick_stack_snapshots']
                        for a,b in zip(observed['runs'],independent['runs'],strict=True)):
                raise ValueError('Published native tick scope/reset evidence differs')
            evidence[name]=sha(folder/'campaign.json')
            source_values[system+'_native_tick_snapshots']=[r['native_tick_stack_snapshots'] for r in observed['runs']]
        from run_esp32_message_observer_pairs import audit as tick_pair_audit
        for system in ('freertos','zephyr','nuttx'):
            name='esp32-'+system+'-tick-observer-pairs-b1-v1'
            folder=REPORTS/name
            paired=tick_pair_audit(folder)
            if paired!=json.loads((folder/'audit.json').read_text()) or n_tick_replay(folder)['cells']!=[
                    {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in paired['cells']]:
                raise ValueError('Published tick-image observer contrast differs')
            change=(paired['cells'][0]['median_ratio']-1)*100
            if system=='nuttx' and (format(change,'.4f')!='-70.2200' or '-70.2200\\%' not in source) or \
                    system!='nuttx' and abs(change)>=0.1:
                raise ValueError('Published tick-image perturbation magnitude differs')
            evidence[name]=sha(folder/'campaign.json')
            source_values[system+'_tick_observer_contrast']=paired
    if 'same-binary off/on/on/off' in source:
        from run_esp32_nuttx_tick_control import audit as control_audit
        from replay_esp32_nuttx_tick_control import replay as control_replay
        from run_esp32_nuttx_message_lifetimes import audit as controlled_census
        from replay_esp32_followup import replay as independent_followup
        from run_esp32_message_observer_pairs import audit as controlled_pairs
        prepared=REPORTS/'esp32-nuttx-message-tick-control-v1'
        name='esp32-nuttx-tick-control-b1-v1';folder=REPORTS/name
        observed=control_audit(folder,prepared)
        if observed!=control_replay(folder,prepared) or observed!=json.loads((folder/'audit.json').read_text()) or any(
                (format((v-1)*100,'.3f')+'\\%') not in source for v in observed['on_off_first_count_ratios']):
            raise ValueError('Published same-image runtime-toggle result differs')
        evidence[name]=sha(folder/'campaign.json');source_values['nuttx_runtime_toggle']=observed
        name='esp32-nuttx-message-tick-control-census-b1-v1';folder=REPORTS/name
        observed=json.loads(json.dumps(controlled_census(folder,prepared)))
        separate=independent_followup(folder,prepared)['cells'][0]['runs']
        if observed!=json.loads((folder/'audit.json').read_text()) or observed['independent_resets']!=5 or any(
                a['native_tick_stack_snapshots']!=b['native_tick_stack_snapshots'] or
                a['native_tick_probe_cost']!=b['native_tick_probe_cost'] for a,b in zip(observed['runs'],separate,strict=True)):
            raise ValueError('Published subsequent five-reset context/cycle result differs')
        evidence[name]=sha(folder/'campaign.json');source_values['nuttx_controlled_census']=observed
        name='esp32-nuttx-tick-control-observer-pairs-b1-v1';folder=REPORTS/name
        observed=controlled_pairs(folder)
        if observed!=json.loads((folder/'audit.json').read_text()) or independent_followup(folder)['cells']!=[
                {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in observed['cells']] or (
                format((observed['cells'][0]['median_ratio']-1)*100,'.4f')+'\\%') not in source:
            raise ValueError('Published subsequent full-image baseline contrast differs')
        evidence[name]=sha(folder/'campaign.json');source_values['nuttx_controlled_pairs']=observed
    if "240 case executions" in source:
        from esp32_waitq_oracle import audit as oracle_audit
        name="esp32-waitq-oracle-b1-v1"
        observed=oracle_audit(REPORTS/name)
        sentence=("Each passes 24 kernel cases in five resets (240 case executions); "
                  "five userspace-only null-pointer cases are outside the profile.")
        if observed!=json.loads((REPORTS/name/'audit.json').read_text()) or source.count(sentence)!=1 or \
                observed['independent_resets']!=10 or observed['original_cases_per_reset']!=24 or \
                observed['passed_case_instances']!=240 or observed['generated_task_runs'] or observed['ranking_eligible']:
            raise ValueError('Published original wait-queue functional results differ')
        evidence[name]=sha(REPORTS/name/'campaign.json')
        source_values['waitq_functional_oracle']={k:observed[k] for k in
            ('independent_resets','original_cases_per_reset','passed_case_instances','generated_task_runs','ranking_eligible')}
    if "\\label{tab:generated}" in source:
        from audit_tenonos_tasks import audit as generated_tenon
        from run_esp32_generated_task import audit as generated_esp32
        tenon=generated_tenon(ROOT/'registry/tenonos_tasks_rpi4_v1.json',
            REPORTS/'tenonos-rpi4-v1/formal-v1',REPORTS/'tenonos-rpi4-v1/rtos-graph/graph.json')
        physical_tasks={}
        task_titles={'A1':'ESP32 basic composition','A2':'ESP32 queue/semaphore/IRQ','B1':'ESP32 image/throughput',
                     'B2':'ESP32 dual-program budget','C1':'ESP32 tree-ready policy',
                     'C2':'ESP32 ready/wait policies'}
        titles={'TC-A':'Component composition','TC-B':'Image-constrained composition','TC-C':'Allocator modification'}
        rows=[]
        for family in tenon['families']:
            counts=family['accounting'];n=counts['applicable_runs']
            stage=counts['unconditional_stage_success_rates']
            values=[round(stage[k]*n) for k in ('generated','built','functional')]+[counts['successful_runs']]
            rows.append(titles[family['task']]+' & '+' & '.join(f'{v}/{n}' for v in values))
        for task_id,title in task_titles.items():
            version='v2' if task_id in {'A2','C2'} else 'v1'
            folder=REPORTS/f'esp32-generated-{task_id.lower()}-{version}'
            physical=generated_esp32(folder)
            if physical['task_id']!=task_id:
                raise ValueError('Published generated task differs from its acquisition')
            physical_tasks[task_id]=physical
            n=physical['registered_trials'];stage=physical['stage_counts']
            values=[stage[k] for k in ('generated','built','functional')]+[physical['successes']]
            rows.append(title+' & '+' & '.join(f'{v}/{n}' for v in values))
            evidence[f'esp32-generated-{task_id}-registration']=sha(folder/'registration.json')
            evidence[f'esp32-generated-{task_id}-campaign']=sha(folder/'campaign.json')
            for trial in physical['trials']:
                for value in trial.get('workloads',[trial]):
                    if f"{value['median_count_30s']:,}" not in source or \
                            f"{value['image_bytes']:,}" not in source:
                        raise ValueError('Published generated ESP32 runtime/image value differs')
        require_rows(source,'tab:generated',rows)
        tables['tab:generated']=rows
        source_values['generated_configurations']={'tenon':tenon,'esp32':physical_tasks['B1'],
                                                  'esp32_tasks':physical_tasks}
        evidence['tenon-task-bank']=sha(ROOT/'registry/tenonos_tasks_rpi4_v1.json')
    if "\\label{tab:sequence}" in source:
        from run_esp32_policy_sequence import audit as sequence_audit
        folder = REPORTS / "esp32-policy-sequence-v1"
        sequence = sequence_audit(folder)
        if sequence != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published policy sequence differs from source replay")
        rows = []
        for history in sequence["histories"]:
            n = len(history["rounds"])
            runnable = sum(r["gates"]["functional"] for r in history["rounds"])
            accepted = sum(r["accepted"] for r in history["rounds"])
            rows.append(f"{history['id']} & {runnable}/{n} & {accepted}/{n} & {history['total_round_wall_s']:.2f}")
        require_rows(source, "tab:sequence", rows)
        tables["tab:sequence"] = rows
        source_values["state_linked_policy_sequence"] = sequence
        evidence["policy-sequence-registration"] = sha(folder / "registration.json")
        evidence["policy-sequence-campaign"] = sha(folder / "campaign.json")
    if "\\label{tab:compact-ram}" in source:
        from run_esp32_tm_ram_lifetimes import audit as compact_audit
        from replay_esp32_freertos_message import history
        from replay_esp32_followup import raw_rows
        name = "esp32-freertos-compact-ram-b1-v2"
        folder = REPORTS / name
        compact = compact_audit(folder, REPORTS / "esp32-freertos-compact-ram-build-v2")
        if compact != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Compact RAM result differs from raw evidence")
        for index, result in enumerate(compact["runs"], 1):
            separate = history([r["line"] for r in raw_rows(folder / "captures" / f"reset{index}.jsonl")])
            if any(result[k] != separate[k] for k in ("events", "heap_peak_bytes", "heap_final_bytes", "live_tasks")):
                raise ValueError("Independent compact RAM history differs")
        build = compact["build"]
        original_ram = next(c for c in memory["cells"] if c["os"] == "FreeRTOS")
        if [r["heap_peak_bytes"] for r in compact["runs"]] != original_ram["native_heap_peak_bytes"] or \
                compact["separate_validation"]["task_lifecycles"]["completed"] != 4:
            raise ValueError("Compact observer heap or finite lifecycle comparison differs")
        row = " & ".join(("FreeRTOS", f"{build['static_sram_bytes']:,}",
            f"{build['static_sram_bytes']-build['baseline_static_sram_bytes']:,}",
            f"{max(r['heap_peak_bytes'] for r in compact['runs']):,}",
            f"{max(r['software_reserved_and_allocated_peak_bytes'] for r in compact['runs']):,}"))
        require_rows(source, "tab:compact-ram", [row])
        tables["tab:compact-ram"] = [row]
        source_values["compact_message_ram"] = compact
        evidence[name] = sha(folder / "campaign.json")
        evidence["compact-message-build"] = sha(REPORTS / "esp32-freertos-compact-ram-build-v2/build.json")
    if '\\label{app:nuttxcompactram}' in source:
        from audit_esp32_allocated_reservations import compact_nuttx_audit, compact_nuttx_paper_text, compact_nuttx_summary
        checked=compact_nuttx_audit(ROOT)
        report=REPORTS/'esp32-nuttx-compact-allocated-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(compact_nuttx_paper_text(checked))!=1:
            raise ValueError('Compact NuttX memory or manuscript values differ')
        source_values['nuttx_compact_ram']=compact_nuttx_summary(checked)
        evidence['nuttx-compact-ram']=sha(report)
    if '\\label{app:esp32loaderhandoff}' in source:
        from audit_esp32_zephyr_loader import audit as loader_audit, paper_text as loader_text
        from measure_esp32_nuttx_bootloader import audit as nuttx_loader_audit
        zreport = REPORTS/'esp32-zephyr-loader-coverage-v1.json'
        nfolder = REPORTS/'esp32-nuttx-observed-loader-b1-v1'
        zchecked, nchecked = loader_audit(ROOT), nuttx_loader_audit(ROOT,nfolder)
        if zchecked != json.loads(zreport.read_text()) or \
                nchecked != json.loads((nfolder/'audit.json').read_text()) or \
                source.count(loader_text(zchecked,nchecked)) != 1:
            raise ValueError('ESP32 loader intervention or manuscript values differ')
        source_values['esp32_loader_coverage'] = {
            'zephyr_reused_resets':zchecked['reused_resets'],
            'zephyr_loader_in_static_bytes':zchecked['simple_loader_already_in_static_bytes'],
            'nuttx_new_resets':nchecked['independent_resets'],
            'nuttx_software_peaks':[r['software_peak_bytes'] for r in nchecked['runs']]}
        evidence['zephyr-loader-coverage'] = sha(zreport)
        evidence['nuttx-observed-loader'] = sha(nfolder/'audit.json')
    if '\\label{app:allocatedbookkeeping}' in source:
        from audit_esp32_allocated_reservations import bookkeeping_audit, bookkeeping_paper_text, bookkeeping_summary
        checked=bookkeeping_audit(ROOT)
        report=REPORTS/'esp32-allocated-bookkeeping-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(bookkeeping_paper_text(checked))!=1:
            raise ValueError('Allocated software bookkeeping or manuscript values differ')
        source_values['allocated_software_bookkeeping']=bookkeeping_summary(checked)
        evidence['allocated-software-bookkeeping']=sha(report)
    if '\\label{app:allocatedlifecycle}' in source:
        from audit_esp32_allocated_lifecycle import audit as lifecycle_audit, paper_text as lifecycle_text, summary as lifecycle_summary
        checked=lifecycle_audit(ROOT)
        report=REPORTS/'esp32-allocated-lifecycle-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(lifecycle_text(checked))!=1:
            raise ValueError('Provisional allocated-capacity model or manuscript values differ')
        source_values['allocated_lifecycle_model']=lifecycle_summary(checked)
        evidence['allocated-lifecycle-model']=sha(report)
    if '\\label{app:zephyrownershippairs}' in source:
        from run_esp32_message_observer_pairs import audit as ownership_audit, ownership_paper_text
        from replay_esp32_followup import replay as ownership_replay
        path=REPORTS/'esp32-zephyr-ownership-observer-pairs-b1-v2'
        checked=ownership_audit(path);separate=ownership_replay(path)
        if checked!=json.loads((path/'audit.json').read_text()) or separate['cells']!=[
                {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in checked['cells']] or \
                source.count(ownership_paper_text(checked))!=1:
            raise ValueError('Entry-vector image matched control or manuscript values differ')
        source_values['zephyr_ownership_pairs']=checked
        evidence['zephyr-ownership-pairs']=sha(path/'audit.json')
    if '\\label{app:nuttxloaderpairs}' in source:
        from run_esp32_message_observer_pairs import audit as nuttx_pair_audit, nuttx_loader_paper_text
        from replay_esp32_followup import replay as nuttx_pair_replay
        path=REPORTS/'esp32-nuttx-compact-loader-observer-pairs-b1-v1'
        checked=nuttx_pair_audit(path);separate=nuttx_pair_replay(path)
        if checked!=json.loads((path/'audit.json').read_text()) or separate['cells']!=[
                {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in checked['cells']] or \
                source.count(nuttx_loader_paper_text(checked))!=1:
            raise ValueError('Compact NuttX matched-loader control or manuscript values differ')
        source_values['nuttx_loader_pairs']=checked
        evidence['nuttx-loader-pairs']=sha(path/'audit.json')
    if '\\label{app:startupcohort}' in source:
        from audit_esp32_allocated_reservations import cohort_audit, cohort_paper_text, cohort_summary
        checked=cohort_audit(ROOT)
        report=REPORTS/'esp32-startup-reservation-cohort-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(cohort_paper_text(checked))!=1:
            raise ValueError('Startup software reservation cohort or manuscript values differ')
        source_values['startup_reservation_cohort']=cohort_summary(checked)
        evidence['startup-reservation-cohort']=sha(report)
    if '\\label{app:startupreservations}' in source:
        from audit_esp32_allocated_reservations import audit as reservation_audit, paper_text, summary
        checked=reservation_audit(ROOT)
        report=REPORTS/'esp32-freertos-allocated-reservations-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(paper_text(checked))!=1:
            raise ValueError('Startup reservation lifecycle or manuscript values differ')
        source_values['freertos_allocated_reservations']=summary(checked)
        evidence['freertos-allocated-reservations']=sha(report)
    if "Five further resets bind the native startup-stack release" in source:
        from run_esp32_tm_ram_lifetimes import audit as handoff_audit, EVENT
        from replay_esp32_followup import raw_rows
        folder = REPORTS / "esp32-freertos-startup-handoff-b1-v1"
        result = handoff_audit(folder, REPORTS / "esp32-freertos-startup-handoff-build-v1")
        if result != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Startup-heap handoff replay changed")
        for index, run in enumerate(result["runs"], 1):
            h = run["startup_heap_handoff"]
            events = [tuple(map(int, m.groups())) for row in raw_rows(folder / "captures" / ("reset%d.jsonl" % index))
                      if (m := EVENT.fullmatch(row["line"]))]
            for phase in ("before_release", "after_release"):
                current = maximum = 0
                for _, kind, _, _, delta in events[:h[phase]["event_cursor"]]:
                    if kind < 5:
                        current += delta
                        maximum = max(maximum, current)
                if (current, maximum) != (h[phase]["occupied_bytes"], h[phase]["allocated_peak_through_boundary_bytes"]):
                    raise ValueError("Independent handoff prefix sums disagree")
            if startup_handoff_text(result["build"], run) not in source:
                raise ValueError("Published startup-heap handoff numbers differ")
        source_values["startup_heap_handoff"] = result
        evidence["startup-heap-handoff"] = sha(folder / "audit.json")
        evidence["startup-heap-handoff-build"] = sha(REPORTS / "esp32-freertos-startup-handoff-build-v1/build.json")
    if "A five-reset allocation-context extension" in source:
        from run_esp32_tm_ram_lifetimes import audit as peak_audit
        from replay_esp32_freertos_message import replay as peak_replay
        folder = REPORTS / "esp32-freertos-peak-context-b1-v1"
        prepared = REPORTS / "esp32-freertos-peak-context-build-v1"
        result = peak_audit(folder, prepared)
        if result != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published allocation-context source replay differs")
        separate = peak_replay(folder, prepared)
        if any(a["allocation_peak_context"]["phases"] != b["allocation_peak_contexts"] for a, b in
               zip(result["runs"], separate["runs"], strict=True)) or peak_context_text(result) not in source:
            raise ValueError("Published allocation-context numbers or independent replay differ")
        source_values["allocation_peak_context"] = result
        evidence["allocation-peak-context"] = sha(folder / "audit.json")
        evidence["allocation-peak-context-build"] = sha(prepared / "build.json")
    if "Five boot-stage resets" in source:
        from audit_esp32_bootloader_ram import audit as boot_stage_audit
        folder = REPORTS / "esp32-boot-stage-b1-v1"
        result = boot_stage_audit(folder, REPORTS / "esp32-boot-stage-build-v3")
        if result != json.loads((folder / "audit.json").read_text()) or boot_stage_text(result) not in source:
            raise ValueError("Published boot-stage observations differ from raw-source replay")
        source_values["boot_stage_stack"] = result
        evidence["boot-stage-stack"] = sha(folder / "audit.json")
    if "A continuous FreeRTOS extension records" in source:
        from audit_esp32_message_steps import audit as continuous_audit
        from replay_esp32_message_steps import replay as continuous_replay
        from audit_esp32_runtime_reservations import audit as coverage_audit
        from replay_esp32_runtime_reservations import replay as coverage_replay
        from replay_esp32_followup import replay as pairs_replay
        prepared = REPORTS / "esp32-message-steps-build-v5"
        folder = REPORTS / "esp32-message-steps-b1-v5"
        retained = REPORTS / "esp32-message-steps-b1-v5-audit.json"
        continuous = continuous_audit(prepared, folder)
        if json.loads(json.dumps(continuous)) != json.loads(retained.read_text()):
            raise ValueError("Continuous observations differ from retained audit")
        separate = continuous_replay(folder)
        if any(a["continuous_stack"] != b["continuous_stack"] for a, b in
                zip(continuous["runs"], separate["runs"], strict=True)):
            raise ValueError("Independent continuous contexts differ")
        coverage_path = REPORTS / "esp32-message-runtime-coverage-v1.json"
        coverage = coverage_audit(prepared, folder, retained)
        if json.loads(json.dumps(coverage)) != json.loads(coverage_path.read_text()):
            raise ValueError("Runtime physical address coverage changed")
        coverage_replay(prepared, folder, coverage_path)
        paired_folder = REPORTS / "esp32-message-steps-observer-pairs-b1-v1"
        paired = pairs_audit(paired_folder)
        independent = pairs_replay(paired_folder)
        if paired["independent_resets"] != independent["independent_resets"] or any(
                any(a[k] != b[k] for k in ("os", "pairs", "median_ratio", "ratio_range"))
                for a, b in zip(paired["cells"], independent["cells"], strict=True)):
            raise ValueError("Independent continuous-observer pairs differ")
        for text in (continuous_context_text(continuous, coverage, paired), runtime_coverage_text(coverage)):
            if source.count(text) != 1:
                raise ValueError("Published continuous observation or address-coverage values differ")
        source_values["continuous_contexts"] = continuous
        source_values["continuous_context_address_coverage"] = coverage
        source_values["continuous_observer_pairs"] = paired
        evidence["continuous-context-build"] = sha(prepared / "build.json")
        evidence["continuous-context-campaign"] = sha(folder / "campaign.json")
        evidence["continuous-context-audit"] = sha(retained)
        evidence["runtime-address-coverage-audit"] = sha(coverage_path)
        evidence["continuous-observer-pairs-campaign"] = sha(paired_folder / "campaign.json")
    if "In a separate five-reset NuttX validation" in source:
        from run_esp32_nuttx_message_lifetimes import audit as lifecycle_audit
        from replay_esp32_followup import raw_rows, native_allocation_addresses
        folder = REPORTS / "esp32-nuttx-task-lifecycle-validation-b1-v3"
        result = lifecycle_audit(folder, REPORTS / "esp32-nuttx-task-lifecycle-validation-build-v3")
        if json.loads(json.dumps(result)) != json.loads((folder / "audit.json").read_text()) or result["independent_resets"] != 5:
            raise ValueError("NuttX finite lifecycle evidence changed")
        total = sum(r["task_lifecycles"]["completed"] for r in result["runs"])
        for index, run in enumerate(result["runs"], 1):
            separate = native_allocation_addresses([r["line"] for r in raw_rows(folder / "validation" / ("reset%d.jsonl" % index))])
            if separate["native_heap_peak_bytes"] != run["peak"] or separate["events"] != run["events"]:
                raise ValueError("Independent NuttX validation allocation replay differs")
            for cycle in run["task_lifecycles"]["cycles"]:
                if (total,cycle["joined_occupied"]-cycle["final"],cycle["joined_occupied"],cycle["final"]) != (20,4288,20488,16200):
                    raise ValueError("Published NuttX deferred reclamation values differ")
        expected = ("In a separate five-reset NuttX validation, twenty finite thread lifecycles retire their stacks "
            "but retain 4,288\\,B until native deferred reclamation. A subsequent 1-B allocation/free restores "
            "occupied heap from 20,488 to 16,200\\,B.")
        if source.count(expected) != 1:
            raise ValueError("Published NuttX lifecycle paragraph differs from native replay")
        source_values["nuttx_finite_task_lifecycles"] = result
        evidence["nuttx-finite-task-lifecycle-campaign"] = sha(folder / "campaign.json")
        evidence["nuttx-finite-task-lifecycle-build"] = sha(REPORTS / "esp32-nuttx-task-lifecycle-validation-build-v3/build.json")
    if "Dedicated finite-lifecycle campaigns for FreeRTOS" in source:
        finite=memory["followup_validation"]["finite_task_lifecycles"]
        if [r["os"] for r in finite]!=list(SYSTEMS) or any(r["status"]!="complete" or
                r["independent_resets"]!=5 or r["completed_lifetimes"]!=20 or r["benchmark_result"] for r in finite):
            raise ValueError("Published three-OS finite lifecycle coverage differs")
        expected="Dedicated finite-lifecycle campaigns for FreeRTOS, Zephyr and NuttX each use five resets and four thread lifecycles per reset."
        if source.count(expected)!=1:
            raise ValueError("Published finite lifecycle reset/cycle statement differs")
        source_values["finite_task_lifecycle_coverage"]=finite
        for row in finite:
            evidence[row["os"]+"-finite-task-lifecycle-audit"]=sha(ROOT/row["evidence"])
    if "Three held-out resets produce" in source:
        from run_esp32_policy_holdout import audit as held_out_audit
        from audit_esp32_policy_trajectory import audit as trajectory_audit
        folder=REPORTS/"esp32-policy-holdout-v1"
        result=held_out_audit(folder)
        if result!=json.loads((folder/"audit.json").read_text()):
            raise ValueError("Published held-out campaign differs from complete source replay")
        trajectory=trajectory_audit(folder)
        if trajectory!=json.loads((REPORTS/"esp32-policy-trajectory-contrast-v1.json").read_text()):
            raise ValueError("Published endpoint/trajectory raw replay differs")
        require_held_out_claims(source,result)
        source_values["prospective_policy_holdout"]=result
        source_values["endpoint_trajectory_contrast"]=trajectory
        evidence["policy-holdout-registration"]=sha(folder/"registration.json")
        evidence["policy-holdout-campaign"]=sha(folder/"campaign.json")
        evidence["policy-holdout-recovery"]=sha(folder/"post-sequence-recovery.json")
    if "Five reused FreeRTOS message resets" in source:
        from measure_esp32_boot_handoff_ram import audit as native_audit
        from replay_esp32_native_sp import replay as native_replay
        name = "esp32-native-sp-audit-v1"
        main = native_audit(REPORTS / "esp32-message-native-sp-b1-v1", REPORTS / "esp32-message-native-sp-build-v1")
        separate = native_replay(REPORTS / "esp32-message-native-sp-b1-v1")
        if json.loads(json.dumps(main)) != json.loads((REPORTS / name / "main.json").read_text()) or \
                separate != json.loads((REPORTS / name / "independent.json").read_text()) or \
                source.count(native_sp_text(main, separate)) != 1:
            raise ValueError("Published native assembly SP observations differ from source replay")
        source_values["native_assembly_sp"] = separate
        evidence[name] = sha(REPORTS / name / "main.json")
        if "Five matched baseline/native-transition-observer pairs" in source:
            from run_esp32_message_observer_pairs import audit as native_pairs_audit
            from replay_esp32_followup import replay as native_pairs_replay
            folder = REPORTS / "esp32-native-sp-observer-pairs-b1-v2"
            paired, independent = native_pairs_audit(folder), native_pairs_replay(folder)
            if paired != json.loads((folder / "audit.json").read_text()) or independent["cells"] != [
                    {k: c[k] for k in ("os", "pairs", "median_ratio", "ratio_range")} for c in paired["cells"]] or \
                    source.count(native_sp_pairs_text(paired)) != 1:
                raise ValueError("Native-transition observer paired control differs from published text")
            source_values["native_sp_observer_pairs"] = paired
            evidence["native-sp-observer-pairs"] = sha(folder / "audit.json")
    if "A combined image passes five message resets" in source:
        from audit_esp32_combined_stacks import audit as combined_audit
        result = combined_audit(REPORTS / "esp32-message-native-sp-combined-b1-v1",
                                REPORTS / "esp32-message-native-sp-combined-build-v1")
        path = REPORTS / "esp32-combined-stacks-audit-v1.json"
        if result != json.loads(path.read_text()) or source.count(combined_stacks_text(result)) != 1:
            raise ValueError("Published combined stack observations differ from independent replay")
        evidence["combined-stack-identities"] = sha(path)
        source_values["combined_stack_identities"] = result
        if "Five matching baseline/combined-image pairs" in source:
            from run_esp32_message_observer_pairs import audit as pairs_audit
            from replay_esp32_followup import replay as pairs_replay
            path = REPORTS / "esp32-combined-stack-observer-pairs-b1-v1"
            paired = pairs_audit(path)
            separate = pairs_replay(path)
            if paired != json.loads((path / "audit.json").read_text()) or paired["independent_resets"] != 10 or \
                    separate["cells"] != [{k:c[k] for k in ("os", "pairs", "median_ratio", "ratio_range")} for c in paired["cells"]]:
                raise ValueError("Combined observer paired replay differs")
            cell = paired["cells"][0]
            lo, hi = [(v-1)*100 for v in cell["ratio_range"]]
            text = ("Five matching baseline/combined-image pairs change the first original count by a median of "
                    f"{(cell['median_ratio']-1)*100:+.4f}\\% (range {lo:+.4f}\\% to {hi:+.4f}\\%).")
            if source.count(text) != 1:
                raise ValueError("Published combined observer perturbation differs")
            evidence["combined-stack-pairs"] = sha(path / "campaign.json")
            source_values["combined_stack_observer_pairs"] = paired
    if "\\label{tab:tenonhistory}" in source:
        from audit_tenonos_tasks import configuration
        parent = REPORTS / "tenonos-author-engine-20261027-v1"
        report = parent / "policy-sequence-audit-v1.json"
        checked = json.loads(report.read_text())
        folder = parent / "policy-sequence-v1"
        for name, expected in checked["evidence_manifest"].items():
            path = (folder / name).resolve()
            path.relative_to(folder.resolve())
            if sha(path) != expected:
                raise ValueError("Tenon history evidence changed: " + name)
        campaign = json.loads((folder / "campaign.json").read_text())
        for history in campaign["histories"]:
            initial = configuration(ROOT / history["rounds"][0]["parent_build"] / ".config")
            final = configuration(ROOT / history["rounds"][-1]["retained_build"] / ".config")
            changes = {k: [initial.get(k, "n"), final.get(k, "n")] for k in initial.keys() | final.keys()
                       if initial.get(k, "n") != final.get(k, "n")}
            expected = {"TLSF_LOG2_SLI": ["2", "5"]} if history["method"] == "direct" else {}
            if changes != expected or final.get("LIBUKBOOT_INITTLSF") != "y":
                raise ValueError("Published Tenon endpoint allocator/configuration difference changed")
        if source.count(tenon_history_text(checked)) != 1 or checked["finish_reasons"] != {"stop": 6, "length": 6}:
            raise ValueError("Published Tenon cumulative cost or truncation outcomes differ")
        token_words = f"The six histories use twelve model calls and {checked['completion_tokens']:,} output tokens;"
        guests = f"Eighteen fresh candidate guest executions are separate from {checked['parent_check_guest_captures']} initial-parent or recovery checks."
        if checked["model_calls"] != 12 or checked["candidate_guest_captures"] != 18 or \
                source.count(token_words) != 1 or source.count(guests) != 1:
            raise ValueError("Published Tenon call/token/guest accounting differs")
        tables["tab:tenonhistory"] = tenon_history_rows(checked)
        require_rows(source, "tab:tenonhistory", tables["tab:tenonhistory"])
        source_values["tenon_policy_histories"] = {k: v for k, v in checked.items() if k != "evidence_manifest"}
        evidence["tenon-policy-histories"] = sha(report)
    if "\\label{tab:tenonenergy}" in source:
        from audit_tenonos_energy import audit as tenon_energy_audit
        folder = REPORTS / "tenonos-rpi4-activation-energy-v1"
        checked = tenon_energy_audit(folder, ROOT)
        if checked != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published Pi energy differs from signed packet and guest replay")
        tables["tab:tenonenergy"] = tenon_energy_rows(checked)
        require_rows(source, "tab:tenonenergy", tables["tab:tenonenergy"])
        source_values["tenon_activation_energy"] = checked
        evidence["tenon-activation-energy"] = sha(folder / "audit.json")
    if "\\label{tab:tenonbuildenergy}" in source:
        from audit_tenonos_build_energy import audit as build_energy_audit
        folder = REPORTS / "tenonos-rpi4-build-energy-v1"
        checked = build_energy_audit(ROOT, folder)
        if checked != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published native-build energy differs from signed packet/build/guest replay")
        tables["tab:tenonbuildenergy"] = tenon_build_energy_rows(checked)
        require_rows(source, "tab:tenonbuildenergy", tables["tab:tenonbuildenergy"])
        build_values = [r["build_energy_j_median"] for r in checked["summary"]]
        boot_values = [r["boot_energy_j_median"] for r in checked["summary"]]
        text = (f"Median build-request energies are {build_values[0]:.2f}, {build_values[1]:.2f} and {build_values[2]:.2f}~J "
                "for initial TLSF, accepted buddy and accepted TLSF; guest-validation-request energies are "
                f"{boot_values[0]:.2f}, {boot_values[1]:.2f} and {boot_values[2]:.2f}~J.")
        if source.count(text) != 1:
            raise ValueError("Published build/guest subwindow medians differ")
        source_values["tenon_build_energy"] = checked
        evidence["tenon-build-energy"] = sha(folder / "audit.json")
    if "\\label{tab:tenonscale}" in source:
        from audit_tenonos_scale_validation import audit as scale_audit
        folder = REPORTS / "tenonos-rpi4-scale-validation-v2"
        checked = scale_audit(folder, ROOT)
        if checked != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published Tenon scale validation differs from source and guest replay")
        tables["tab:tenonscale"] = tenon_scale_rows(checked)
        require_rows(source, "tab:tenonscale", tables["tab:tenonscale"])
        source_values["tenon_scale_validation"] = checked
        evidence["tenon-scale-validation"] = sha(folder / "audit.json")
    if "\\label{tab:tenonmemory}" in source:
        from audit_tenonos_memory import audit as memory_audit
        folder = REPORTS / "tenonos-rpi4-native-memory-v3"
        checked = memory_audit(ROOT, folder)
        if checked != json.loads((folder / "audit.json").read_text()):
            raise ValueError("Published Tenon native memory differs from source/image/guest replay")
        tables["tab:tenonmemory"] = tenon_memory_rows(checked)
        require_rows(source, "tab:tenonmemory", tables["tab:tenonmemory"])
        source_values["tenon_native_memory"] = checked
        evidence["tenon-native-memory"] = sha(folder / "audit.json")
        if "The public semaphore-delete adapter compiles to a single return instruction" in source:
            from audit_tenonos_sem_lifecycle import audit as lifecycle_audit
            lifecycle = lifecycle_audit(ROOT, folder)
            path = REPORTS / "tenonos-sem-lifecycle-scope-v1.json"
            if lifecycle != json.loads(path.read_text()) or len(lifecycle["profiles"]) != 3 or \
                    any(not p["delete_returns_without_releasing"] or p["normal_test_path_requests_delete"]
                        for p in lifecycle["profiles"]):
                raise ValueError("Published semaphore lifecycle scope differs from compiled/source evidence")
            source_values["tenon_semaphore_lifecycle"] = lifecycle
            evidence["tenon-semaphore-lifecycle"] = sha(path)
    if '\\label{app:tenonlifecycle}' in source:
        from audit_tenonos_memory_lifecycle import audit as native_lifecycle_audit
        folder = REPORTS/'tenonos-native-memory-lifecycle-v2'
        checked = native_lifecycle_audit(ROOT,folder)
        if checked!=json.loads((folder/'audit.json').read_text()):
            raise ValueError('Native lifecycle replay differs from recorded audit')
        source_values['tenon_memory_lifecycle'] = require_tenon_lifecycle_claims(source,checked)
        evidence['tenon-memory-lifecycle'] = sha(folder/'audit.json')
    if '\\label{app:tenonnativethreads}' in source:
        from audit_tenonos_memory_lifecycle import audit as thread_audit
        from audit_tenonos_native_threads import paper_text,summary as thread_summary
        folder=REPORTS/'tenonos-native-threads-rpi4-v2'
        checked=thread_audit(ROOT,folder,native_threads=True)
        if checked!=json.loads((folder/'audit.json').read_text()) or source.count(paper_text(checked))!=1:
            raise ValueError('Published native thread storage claims differ')
        source_values['tenon_native_threads']=thread_summary(checked)
        evidence['tenon-native-threads']=sha(folder/'audit.json')
    if '\\label{app:tenonallocmeta}' in source:
        from tenonos_allocator_metadata import audit as metadata_audit,paper_text as metadata_text
        folder=REPORTS/'tenonos-allocator-metadata-rpi4-v1';checked=metadata_audit(ROOT,folder)
        if checked!=json.loads((folder/'audit.json').read_text()) or source.count(metadata_text(checked))!=1:
            raise ValueError('Native allocator metadata or manuscript values differ')
        if 'buddy requested-page statistics' not in source:
            raise ValueError('Buddy native-counter scope is not requested pages')
        source_values['tenon_allocator_metadata']=checked
        evidence['tenon-allocator-metadata']=sha(folder/'audit.json')
    if '\\label{app:tenonallocpeak}' in source:
        from tenonos_allocator_metadata import audit as peak_audit,peak_paper_text
        folder=REPORTS/'tenonos-allocator-peak-rpi4-v2';checked=peak_audit(ROOT,folder)
        if checked!=json.loads((folder/'audit.json').read_text()) or source.count(peak_paper_text(checked))!=1:
            raise ValueError('Native allocated-block peak or manuscript values differ')
        source_values['tenon_allocator_peak']=checked
        evidence['tenon-allocator-peak']=sha(folder/'audit.json')
        if '\\label{tab:ram-order}' in source:
            tables['tab:ram-order'] = allocator_order_rows(checked)
            require_rows(source, 'tab:ram-order', tables['tab:ram-order'])
    if '\\label{app:tenonallocatedram}' in source:
        from audit_tenonos_allocated_ram import audit as allocated_audit, paper_text as allocated_text, summary
        checked=allocated_audit(ROOT)
        report=REPORTS/'tenonos-allocated-occupancy-rpi4-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(allocated_text(checked))!=1:
            raise ValueError('Allocated guest RAM or manuscript values differ')
        source_values['tenon_allocated_ram']=summary(checked)
        evidence['tenon-allocated-ram']=sha(report)
    if '\\label{app:tenonramhistory}' in source:
        from audit_tenonos_allocated_ram import trajectory_audit, trajectory_paper_text, trajectory_summary
        checked=trajectory_audit(ROOT)
        report=REPORTS/'tenonos-allocated-history-profiles-v1.json'
        if checked!=json.loads(report.read_text()) or source.count(trajectory_paper_text(checked))!=1:
            raise ValueError('History reference RAM mapping or manuscript values differ')
        main=('Relative to the initial profile, reduced TLSF is 12.70\\% smaller and buddy is '
              '46.66\\% larger; not every history visits all three states.')
        if source.count(main)!=1:raise ValueError('Main-text reference RAM trajectory differs')
        source_values['tenon_ram_histories']=trajectory_summary(checked)
        evidence['tenon-ram-histories']=sha(report)
    if '\\label{app:tenonmemoryimpact}' in source:
        from audit_tenonos_memory_impact import audit as impact_audit,bind_histories
        folder=REPORTS/'tenonos-memory-impact-rpi4-v1'
        checked=impact_audit(ROOT,folder)
        if checked!=json.loads((folder/'audit.json').read_text()) or source.count(tenon_impact_text(checked))!=1:
            raise ValueError('Published memory-observer impact differs')
        linked=bind_histories(ROOT);binding=REPORTS/'tenonos-repaired-profile-binding-v1.json'
        if linked!=json.loads(binding.read_text()) or linked['state_aliases']!=24 or linked['candidate_energy_reassigned']:
            raise ValueError('Repaired-history profile reuse differs')
        source_values['tenon_memory_impact']=checked
        evidence['tenon-memory-impact']=sha(folder/'audit.json')
        evidence['tenon-repaired-profile-binding']=sha(binding)
    if '\\label{app:tenonruntime}' in source:
        from audit_tenonos_runtime_oracle import audit as runtime_oracle_audit
        folder = REPORTS/'tenonos-runtime-oracle-rpi4-v6'
        checked = runtime_oracle_audit(ROOT, folder)
        if checked != json.loads((folder/'audit.json').read_text()):
            raise ValueError('Tenon runtime record replay differs')
        source_values['tenon_runtime_oracle'] = require_tenon_runtime_claims(source, checked)
        evidence['tenon-runtime-oracle'] = sha(folder/'audit.json')
    if '\\label{app:tenoncandidates}' in source:
        from bind_tenonos_runtime_candidates import bind as candidate_binding
        checked = candidate_binding(ROOT)
        report = REPORTS/'tenonos-runtime-candidate-binding-v1.json'
        if checked != json.loads(report.read_text()):
            raise ValueError('Generated-candidate behavioral binding replay differs')
        source_values['tenon_runtime_candidates'] = require_tenon_candidate_claims(source,checked)
        evidence['tenon-runtime-candidates'] = sha(report)
    if "\\label{tab:tenonbudget}" in source:
        from audit_tenonos_budget_sensitivity import audit as budget_audit
        from audit_tenonos_paper_tasks import published_rows
        parent = REPORTS / "tenonos-author-engine-20261027-v1"
        checked = budget_audit(ROOT, parent / "budget-sensitivity-pipeline-v2", parent / "budget-v4-campaign-v1",
                               parent / "budget-v4-task-audit-v1.json")
        report = parent / "budget-v4-sensitivity-audit-v1.json"
        if checked != json.loads(report.read_text()):
            raise ValueError("Published budget sensitivity differs from its independent audit")
        tables["tab:tenonbudget"] = published_rows({"runtime_audit": {"registered_task_outcomes_audited": True,
                                                                   "groups": checked["groups"]}})
        require_rows(source, "tab:tenonbudget", tables["tab:tenonbudget"])
        accounting = (f"The {checked['model_calls']} model responses all finish normally, using "
                      f"{checked['completion_tokens']:,} output tokens in total. Eighteen builds yield "
                      f"{checked['raw_guest_captures']} fresh guest captures.")
        medians = {method: [g["observed_wall_median_s"] for g in checked["groups"] if g["method"] == method]
                   for method in ("direct", "graph")}
        durations = ("Median all-attempt completion times for composition, image budget and modification are respectively "
                     + ", ".join(f"{v:.2f}" for v in medians["direct"][:2]) + " and " + f"{medians['direct'][2]:.2f}"
                     + "~s for direct prompting, and " + ", ".join(f"{v:.2f}" for v in medians["graph"][:2])
                     + " and " + f"{medians['graph'][2]:.2f}" + "~s for graph orchestration.")
        if source.count(accounting) != 1 or source.count(durations) != 1 or checked["finish_reasons"] != {"stop": 36}:
            raise ValueError("Published sensitivity accounting or durations differ")
        source_values["tenon_budget_sensitivity"] = checked
        evidence["tenon-budget-sensitivity"] = sha(report)
    if "\\label{tab:tenonhistorybudget}" in source:
        from audit_tenonos_policy_budget import audit as policy_budget_audit
        from bind_tenonos_policy_scale import bind as bind_scale
        parent = REPORTS / "tenonos-author-engine-20261027-v1"
        pipeline, campaign = parent / "policy-budget-pipeline-v1", parent / "policy-budget-campaign-v1"
        native = parent / "policy-budget-native-audit-v1.json"
        checked = policy_budget_audit(ROOT, pipeline, campaign, native)
        report = parent / "policy-budget-audit-v1.json"
        if checked != json.loads(report.read_text()):
            raise ValueError("Published larger-budget histories differ from independent replay")
        tables["tab:tenonhistorybudget"] = tenon_history_rows({**checked, "audit": "pass"})
        require_rows(source, "tab:tenonhistorybudget", tables["tab:tenonhistorybudget"])
        counts = (f"The new histories use {checked['model_calls']} model calls and {checked['completion_tokens']:,} "
                  "output tokens, all responses ending normally.")
        groups = {g["method"]: g for g in checked["groups"]}
        costs = (f"Median cumulative costs are {groups['direct']['total_round_wall_median_s']:.2f}~s for direct prompting "
                 f"and {groups['graph']['total_round_wall_median_s']:.2f}~s for graph orchestration;")
        guests = (f"New candidate runs comprise {checked['candidate_guest_captures']} fresh guests; "
                  f"{checked['parent_check_guest_captures']} further guests check initial or recovered parents.")
        if source.count(counts) != 1 or source.count(costs) != 1 or source.count(guests) != 1 or checked["finish_reasons"] != {"stop": 24} or \
                len(checked["inherited_tlsf_choice_conflict_rounds"]) != 6 or \
                (checked["candidate_guest_captures"], checked["parent_check_guest_captures"]) != (18, 36):
            raise ValueError("Larger-budget history accounting, conflict or cost differs")
        linked = bind_scale(ROOT, pipeline, campaign, native, REPORTS / "tenonos-rpi4-scale-validation-v2")
        binding = parent / "policy-budget-scale-binding-v1.json"
        if linked != json.loads(binding.read_text()) or not linked["pass"] or \
                (linked["retained_state_aliases"], linked["distinct_configurations"], linked["reused_guest_boots"],
                 linked["new_guest_boots"], linked["new_model_calls"]) != (24, 3, 9, 0, 0):
            raise ValueError("Larger-budget retained-state scale reuse differs")
        source_values["tenon_budget_histories"] = checked
        source_values["tenon_budget_scale_reuse"] = linked
        evidence["tenon-budget-histories"] = sha(report)
        evidence["tenon-budget-scale-reuse"] = sha(binding)
    if '\\label{tab:tenonhistoryrepair}' in source:
        from tenonos_choice_adapter import audit as choice_audit
        parent=REPORTS/'tenonos-author-engine-20261027-v1'
        report=parent/'policy-choice-audit-v1.json'
        checked=choice_audit(ROOT,parent/'policy-choice-pipeline-v1',parent/'policy-choice-campaign-v1',
                             parent/'policy-choice-native-audit-v1.json',None)
        if checked!=json.loads(report.read_text()):
            raise ValueError('Repaired history audit differs')
        tables['tab:tenonhistoryrepair']=tenon_history_rows(checked)
        require_rows(source,'tab:tenonhistoryrepair',tables['tab:tenonhistoryrepair'])
        if source.count(tenon_repair_text(checked))!=1:
            raise ValueError('Repaired history accounting differs')
        source_values['tenon_repaired_histories']=checked
        evidence['tenon-repaired-histories']=sha(report)
    if '\\label{tab:checker-validation}' in source:
        from validate_sensys_checkers import replay as checker_replay
        folder = REPORTS / 'sensys-checker-validation-v1'
        result = checker_replay(ROOT, folder)
        rows = []
        for kind, label in (('esp32', 'ESP32 windows'), ('tenon', 'Tenon behavior')):
            records = [r for r in result['records'] if r['input'] == kind]
            invalid = [r for r in records if not r['accept']]
            valid = [r for r in records if r['accept']]
            rows.append(f"{label} & {sum(not r['observed_accept'] for r in invalid)}/{len(invalid)} & "
                        f"{sum(r['observed_accept'] for r in valid)}/{len(valid)}")
        tables['tab:checker-validation'] = rows
        require_rows(source, 'tab:checker-validation', rows)
        words = {4: 'four', 6: 'six'}
        claim = (f"rejection of all {words.get(result['invalid_rejected'], result['invalid_rejected'])} "
                 f"prespecified invalid variants and acceptance of all "
                 f"{words.get(result['valid_accepted'], result['valid_accepted'])} valid controls")
        if result['invalid_rejected'] != result['invalid_total'] or \
                result['valid_accepted'] != result['valid_total'] or source.count(claim) != 1:
            raise ValueError('Post-freeze validation claim differs')
        source_values['postfreeze_checker_validation'] = result
        evidence['postfreeze-checker-validation'] = sha(folder / 'result.json')
    if 'Localizing a Configuration-Path Failure' in source:
        parent = REPORTS / 'tenonos-author-engine-20261027-v1/budget-v4-campaign-v1'
        records = []
        for task in ('TC-A', 'TC-B'):
            for repeat in (1, 2, 3):
                folder = parent / f'{task}-{repeat}-graph/candidate'
                request = json.loads((folder / 'configurations-request.json').read_text())
                content = json.loads(request['messages'][1]['content'])
                candidate = json.loads((folder / 'candidate-0.json').read_text())
                if 'tlsf' not in json.dumps(content['parsed_objective']).lower() or \
                        content['permitted_controls'] != ['LIBUKBOOT_INITSCHEDPRIO'] or \
                        candidate['options'] != {'LIBUKBOOT_INITSCHEDPRIO': 'y'}:
                    raise ValueError('Reconstruction failure localization differs')
                records.append({'task': task, 'repeat': repeat, 'request_sha256': sha(folder / 'configurations-request.json'),
                                'candidate_sha256': sha(folder / 'candidate-0.json')})
        source_values['configuration_path_diagnostic'] = records
    if '\\label{fig:category-scores}' in source:
        if '\\label{app:unified-mainboard}' in source:
            from esp32_mainboard_figure import chart_view
            scores=source_values['unified_mainboard']
            receipt_path=REPORTS/'esp32-unified-mainboard-figure-v4.json'
            receipt=json.loads(receipt_path.read_text())
            figure=ROOT/'paper/sensys2027/figures/category-scores.pdf'
            if receipt['input_sha256']!=sha(REPORTS/'esp32-unified-mainboard-v1.json') or \
                    receipt['figure_sha256']!=sha(figure) or receipt['view']!=chart_view(scores) or \
                    receipt['renderer_sha256']!=sha(ROOT/'tools/esp32_mainboard_figure.py'):
                raise ValueError('Unified five-system figure differs from raw-bound scores')
            evidence['category-score-figure']=sha(receipt_path)
        else:
            from esp32_category_scores import from_audit
            scores = from_audit({'reset_level_values': source_values})
            score_path = REPORTS / 'esp32-category-indices-v2.json'
            receipt_path = REPORTS / 'esp32-category-figure-v2.json'
            receipt = json.loads(receipt_path.read_text())
            figure = ROOT / 'paper/sensys2027/figures/category-scores.pdf'
            if scores != json.loads(score_path.read_text()) or scores != receipt['scores'] or \
                    receipt['scores_json_sha256'] != sha(score_path) or receipt['pdf_sha256'] != sha(figure) or \
                    receipt['renderer_sha256'] != sha(ROOT / 'tools/esp32_category_scores.py'):
                raise ValueError('Category indices or published figure differ from source replay')
            source_values['category_scores'] = scores
            evidence['category-score-inputs'] = sha(score_path)
            evidence['category-score-figure'] = sha(receipt_path)
    return {"audit":"pass", "manuscript_sha256":checked_manuscript_sha(source_path, source_bytes), "tables":tables,
            "source_campaign_sha256":evidence, "reset_level_values":source_values,
            "scope":"B1 runtime and matched adapter-intervention tables; separate B0 Hartstone PH3; common TCP/UDP and source-queue control, RAM observations, native tick/startup controls, wait-queue functionality, registered one-shot configuration and prospective policy-sequence tables where reported; not a complete manuscript or citation review",
            "new_physical_measurements":0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "paper/sensys2027/iotosbench.tex")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.source)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("reset_level_values", "source_campaign_sha256")}, indent=2))
