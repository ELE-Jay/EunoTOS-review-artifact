#!/usr/bin/env python3
"""Audit the proposed score policy, not new benchmark measurements."""
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'artifacts/reports/esp32-benchmark-v1.json'
OUTPUT = ROOT / 'artifacts/reports/esp32-ranking-method-review-v1.json'
OSES = ('FreeRTOS', 'Zephyr', 'NuttX')
GROUPS = ('throughput', 'realtime', 'energy')


def geometric(values):
    if not values or any(not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError('Missing/non-positive score input')
    return math.exp(sum(math.log(v) for v in values) / len(values))


def components(data, omit=None):
    cases = {'throughput': list(data['comparisons']['thread_metric']),
             'realtime': ['PH1', 'PH2', 'PH3', 'PH4'],
             'energy': [r['case'] for r in data['comparisons']['energy_observed_only'] if r['observed_order_eligible']]}
    result = {}
    for group, metrics in cases.items():
        columns = []
        for metric in metrics:
            if omit == (group, metric):
                continue
            values = {}
            for os_id in OSES:
                section = {'throughput': 'tm', 'realtime': 'hartstone', 'energy': 'energy'}[group]
                name = '每原操作整板能耗' if group == 'energy' else metric
                rows = [r for r in data['rows'] if r['section'] == section and r['metric'] == name and r['os'] == os_id
                        and (group != 'energy' or r['extra']['workload'] == metric)]
                if len(rows) != 1 or not rows[0]['measurement_eligible']:
                    raise ValueError('No unique measured input')
                values[os_id] = rows[0]['extra']['corrected_count'] if group == 'throughput' else rows[0]['median']
            columns.append({os_id: min(values.values()) / v if group == 'energy' else v / max(values.values())
                            for os_id, v in values.items()})
        result[group] = {os_id: 100 * geometric([column[os_id] for column in columns]) for os_id in OSES}
    return result, cases


def scores(values, weights):
    if len(weights) != 3 or any(not math.isfinite(w) or w < 0 for w in weights) or not math.isclose(sum(weights), 1):
        raise ValueError('Weights must be three finite nonnegative shares summing to one')
    return {os_id: math.exp(sum(w * math.log(values[group][os_id]) for group, w in zip(GROUPS, weights))) for os_id in OSES}


def ranked(values):
    return sorted(values, key=lambda os_id: (-values[os_id], os_id))


def review(data):
    values, cases = components(data)
    equal = scores(values, (1/3, 1/3, 1/3))
    grid = []
    for a in range(21):
        for b in range(21 - a):
            shares = (a/20, b/20, (20-a-b)/20)
            totals = scores(values, shares)
            grid.append({'weights': dict(zip(GROUPS, shares)), 'scores': totals, 'order': ranked(totals)})
    balanced = [row for row in grid if all(.2 <= w <= .6 for w in row['weights'].values())]

    def summarize(rows):
        counts = {os_id: 0 for os_id in OSES}
        ranges = {os_id: [] for os_id in OSES}
        orders = {}
        for row in rows:
            top = max(row['scores'].values())
            for os_id, value in row['scores'].items():
                if math.isclose(value, top, rel_tol=1e-12):
                    counts[os_id] += 1
                ranges[os_id].append(1 + sum(other > value + 1e-10 for other in row['scores'].values()))
            key = ' > '.join(row['order'])
            orders[key] = orders.get(key, 0) + 1
        return {'grid_points': len(rows), 'first_place_grid_count': counts,
                'rank_ranges': {os_id: [min(v), max(v)] for os_id, v in ranges.items()}, 'orders': orders,
                'interpretation': 'Policy grid counts, not probabilities, confidence intervals or statistical significance.'}

    omissions = []
    for group, metrics in cases.items():
        for metric in metrics:
            changed, _ = components(data, (group, metric))
            totals = scores(changed, (1/3, 1/3, 1/3))
            omissions.append({'omitted_group': group, 'omitted_metric': metric, 'scores': totals, 'order': ranked(totals)})
    return {'status': 'POLICY_REVIEW_NOT_A_PUBLISHED_RANKING', 'new_board_boots': 0, 'new_metrics': False,
            'adopted_weights': None, 'ranking_publishable': False, 'cohort': list(OSES),
            'excluded_pending_alignment': ['RIOT', 'AliOS-Rhino'], 'group_cases': cases,
            'draft_equal_weight_scores': [{'os': os_id, 'components': {g: values[g][os_id] for g in GROUPS},
                                           'total': equal[os_id]} for os_id in ranked(equal)],
            'weight_grid_step': .05, 'full_simplex': summarize(grid),
            'balanced_20_to_60_percent': summarize(balanced), 'leave_one_metric_out': omissions,
            'input_weight_each': {'throughput': 1/18, 'realtime': 1/12, 'energy': 1/15},
            'coupling': 'Within the same energy window E/N = average_power / completion_rate. Energy per work and throughput share a rate input; they are not independent evidence. The separate TM score uses its own earlier windows, so the whole composite is not exactly a rate-squared formula.',
            'remaining': ['Choose an application objective before adopting weights; do not select weights to favor an OS.',
                          'Complete RIOT/Rhino contract and compiler controls; retain native tickless as a declared design variable.',
                          'Do not reuse old-board or old-image power for a changed adapter.',
                          'Resource, delay, network and sleep-energy scopes are not represented by this draft total.'],
            'grid': grid}


if __name__ == '__main__':
    data = json.loads(INPUT.read_text())
    result = review(data)
    result['input_sha256'] = hashlib.sha256(INPUT.read_bytes()).hexdigest()
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('status', 'full_simplex', 'balanced_20_to_60_percent')}, ensure_ascii=False))
