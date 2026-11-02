#!/usr/bin/env python3
"""Qualify retained same-window work/energy for the five-OS mainboard protocol."""
import argparse
import hashlib
import json
import math
from itertools import product
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / 'registry/esp32_unified_mainboard_v1.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def overall_scores(rows, weights=None):
    protocol = json.loads(PROTOCOL.read_text())
    keys = [c['id'] for c in protocol['categories']]
    weights = weights if weights is not None else {c['id']: c['weight'] for c in protocol['categories']}
    if set(weights) != set(keys) or any(not math.isfinite(w) or w < 0 for w in weights.values()) or \
            not math.isclose(sum(weights.values()), 1, abs_tol=1e-12):
        raise ValueError('Four declared category weights must sum to one')
    if len(rows) != 5 or {r['os'] for r in rows} != set(protocol['systems']):
        raise ValueError('All five systems required; no incomplete main table')
    for row in rows:
        for key in keys:
            value = row.get(key + '_index')
            if value is None or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError('Every mandatory category must qualify, including zero-weight sensitivity categories')
            if row['os'] == 'FreeRTOS' and not math.isclose(value, 100, abs_tol=1e-9):
                raise ValueError('The fixed reference cannot change when adding systems')
    return {r['os']: 100 * math.exp(sum(weights[k] * math.log(r[k + '_index'] / 100) for k in keys))
            for r in rows}


def weight_sensitivity(rows):
    keys = [c['id'] for c in json.loads(PROTOCOL.read_text())['categories']]
    profiles = [dict(zip(keys, [n / 20 for n in integers]))
                for integers in product(range(2, 9), repeat=4) if sum(integers) == 20]
    profiles += [{k: (0 if k == removed else 1 / 3) for k in keys} for removed in keys]
    ranks = {r['os']: [] for r in rows}
    for weights in profiles:
        totals = overall_scores(rows, weights)
        for os, score in totals.items():
            ranks[os].append(1 + sum(v > score and not math.isclose(v, score, rel_tol=1e-10) for v in totals.values()))
    return {'weight_profiles': len(profiles), 'rank_ranges': {os: [min(v), max(v)] for os, v in ranks.items()},
            'interpretation': 'Application-preference sensitivity, not measurement uncertainty or confidence intervals'}


def qualify_cell(cell):
    if cell['independent_resets'] != 3 or len(cell['runs']) != 3:
        raise ValueError('Three independent complete resets required')
    rates, energies, powers, intervals = [], [], [], []
    for run in cell['runs']:
        original, paired = run['original_workload'], run['paired']
        times, counts = original['host_window_seconds'], original['original_window_totals']
        if original['audit'] != 'pass' or len(times) != 3 or len(counts) != 3:
            raise ValueError('Incomplete original report sequence')
        spans = [b - a for a, b in zip(times, times[1:])]
        if any(not math.isfinite(t) or abs(t - 30) > .25 for t in spans):
            raise ValueError('Native timebase fails the external 30-second drift check')
        if paired['completed_original_counts'] != counts[1] + counts[2] or \
                abs(paired['steady_duration_s'] - sum(spans)) > .003:
            raise ValueError('Work, energy and host timestamp boundaries differ')
        rate = paired['completed_original_counts'] / paired['steady_duration_s']
        energy = paired['steady_energy_j'] * 1e6 / paired['completed_original_counts']
        if not math.isclose(rate, paired['original_counts_per_s'], rel_tol=1e-12) or \
                not math.isclose(energy, paired['energy_per_original_count_uj'], rel_tol=1e-12) or \
                not all(math.isfinite(v) and v > 0 for v in (rate, energy)):
            raise ValueError('Recomputed work/energy rate differs')
        rates.append(rate)
        energies.append(energy)
        powers.append(paired['steady_energy_j'] / paired['steady_duration_s'])
        intervals.append(spans)
    return {'os': cell['os'], 'case': cell['case'], 'count_rates_per_s': rates,
            'median_count_rate_per_s': median(rates), 'energy_uj_per_count': energies,
            'median_energy_uj_per_count': median(energies), 'external_report_intervals_s': intervals,
            'same_window_mean_input_power_w': powers,
            'independent_resets': 3, 'same_window_work_energy': True}


def work_energy_relationships(rows, scores):
    systems = json.loads(PROTOCOL.read_text())['systems']
    messages = [r for r in rows if r['case'] == 'message_processing']
    if len(messages) != len(systems) or {r['os'] for r in messages} != set(systems) or \
            len(scores) != len(systems) or {r['os'] for r in scores} != set(systems):
        raise ValueError('Five unique message observations and category indices required')
    by_os, indices = {r['os']:r for r in messages}, {r['os']:r for r in scores}

    def pearson(x, y):
        if any(not math.isfinite(v) for v in x+y):
            raise ValueError('Nonfinite descriptive correlation input')
        x_mean, y_mean = math.fsum(x)/len(x), math.fsum(y)/len(y)
        a, b = [v-x_mean for v in x], [v-y_mean for v in y]
        denominator = math.sqrt(math.fsum(v*v for v in a) * math.fsum(v*v for v in b))
        return math.fsum(v*w for v,w in zip(a,b)) / denominator if denominator else None

    return {'system_count': len(systems), 'systems': systems,
        'kernel_energy_index_pearson_r': pearson([indices[s]['kernel_index'] for s in systems],
                                               [indices[s]['energy_index'] for s in systems]),
        'message_rate_efficiency_pearson_r': pearson([by_os[s]['median_count_rate_per_s'] for s in systems],
            [1e6/by_os[s]['median_energy_uj_per_count'] for s in systems]),
        'interpretation': 'Descriptive association across five configurations, not independent evidence, causation or a significance test. Energy/count = mean input power / count rate for each paired reset; kernel and energy categories can reward related behavior.'}


def audit():
    from audit_esp32_b1_controlled_energy import audit as controlled_audit
    from audit_esp32_b1_native_energy import audit as native_audit, equal_observation
    from audit_esp32_native_irq_semantics import audit as irq_audit
    protocol = json.loads(PROTOCOL.read_text())
    reports, rows, bindings = ROOT / 'artifacts/reports', [], {}
    for case in protocol['kernel_cases']:
        for native in (False, True):
            name = ('esp32-native-' + case if native else
                    'esp32-' + ('message' if case == 'message_processing' else case)) + '-energy-b1-v1'
            folder = reports / name
            result = (native_audit if native else controlled_audit)(folder)
            recorded = json.loads((folder / 'audit.json').read_text())
            # Older controlled records predate the cross-version validator fields.
            keys = ('numeric_validation', 'validator_sha256')
            if not equal_observation({k:v for k,v in result.items() if k not in keys},
                                     {k:v for k,v in recorded.items() if k not in keys}) or \
                    result['board_mac'] != protocol['hardware']['board_mac']:
                raise ValueError('Frozen source/capture/board replay differs: ' + name)
            rows.extend(qualify_cell(c) for c in result['cells'])
            bindings[name] = {'campaign_sha256': sha(folder / 'campaign.json'),
                              'audit_sha256': sha(folder / 'audit.json')}
    required = {(os, case) for os in protocol['systems'] for case in protocol['kernel_cases']}
    if len(rows) != len(required) or {(r['os'], r['case']) for r in rows} != required:
        raise ValueError('Missing or repeated OS/case cells')
    irq = irq_audit()
    if irq != json.loads((reports / 'esp32-native-irq-semantics-b1-v1/audit.json').read_text()):
        raise ValueError('Native hardware IRQ/exit-dispatch binding differs')
    index = {(r['os'], r['case']): r for r in rows}
    scores = []
    for os in protocol['systems']:
        ratios = [index[os, k]['median_count_rate_per_s'] / index['FreeRTOS', k]['median_count_rate_per_s']
                  for k in protocol['kernel_cases']]
        message = index[os, 'message_processing']
        scores.append({'os': os, 'kernel_index': 100 * math.exp(sum(map(math.log, ratios)) / len(ratios)),
            'energy_index': 100 * index['FreeRTOS', 'message_processing']['median_energy_uj_per_count'] /
                            message['median_energy_uj_per_count'],
            'network_index': None, 'ram_index': None, 'overall_score': None})
    return {'audit': 'pass', 'protocol_sha256': sha(PROTOCOL), 'auditor_sha256': sha(Path(__file__)),
            'board_mac': protocol['hardware']['board_mac'],
            'stage': 'same_window_kernel_energy_qualified_not_full_mainboard', 'rows': rows,
            'source_campaigns': bindings, 'qualified_os_case_cells': len(rows), 'reused_independent_resets': 75,
            'new_measurements': 0, 'scores': scores,
            'category_relationships': work_energy_relationships(rows, scores),
            'pending': ['RIOT/Rhino common IPv4 original UDP receiver and fixed offered-load acquisition',
                        'RIOT/Rhino message-image whole-lifecycle peak allocated occupancy',
                        'five-system overall scores, sensitivity and publication after all categories qualify'],
            'historical_eligibility_flags_modified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Run on leon and preserve existing reports')
    result = audit()
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows', 'source_campaigns')}, indent=2))
