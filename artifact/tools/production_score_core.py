# Unchanged numerical functions and constants extracted from the production scorer.
from itertools import product
import math

ENTITIES = (
    ('FreeRTOS', 'FreeRTOS-absolute-v1', 'FreeRTOS-ram-absolute-v1'),
    ('Zephyr', 'Zephyr-absolute-v1', 'Zephyr-ram-absolute-v3'),
    ('NuttX', 'NuttX-ap4-absolute-v1', 'NuttX-ram-paired-absolute-v1'),
    ('RIOT', 'RIOT-absolute-v1', 'RIOT-ram-absolute-v4'),
    ('AliOS Things', 'AliOS-absolute-v1', 'AliOS-ram-paired-absolute-v1'),
    ('Zephyr C2-1 (Qwen)', 'Zephyr-qwen-absolute-v1', 'Zephyr-qwen-ram-absolute-v2'),
    ('Zephyr (AutoOS-adapted)', 'Zephyr-autoos-absolute-v1', 'Zephyr-autoos-ram-absolute-v2'),
    ('Contiki-NG + ESP-IDF/FreeRTOS', 'Contiki-IDF-absolute-v1', 'Contiki-IDF-ram-absolute-v1'))

KEYS = ('task', 'network', 'energy', 'ram')

def positive(values):
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError('All mandatory scored values must be positive finite measurements')

def indices(phases, reference_phases, transactions, reference_transactions, ram_bytes, reference_ram_bytes):
    """The original four-category policy, shared by baseline and new products."""
    task_ratios, energy_ratios = [], []
    for phase in ('1', '2'):
        current, reference = phases[phase], reference_phases[phase]
        latency, energy = current['median_submission_to_completion_us'], current['median_joules_per_completed_job']
        ref_latency, ref_energy = reference['median_submission_to_completion_us'], reference['median_joules_per_completed_job']
        positive([latency, energy, ref_latency, ref_energy])
        task_ratios.append(ref_latency / latency); energy_ratios.append(ref_energy / energy)
    positive([transactions, reference_transactions, ram_bytes, reference_ram_bytes])
    return {'task_index': math.sqrt(math.prod(task_ratios)),
        'energy_index': math.sqrt(math.prod(energy_ratios)),
        'network_index': transactions / reference_transactions,
        'ram_index': reference_ram_bytes / ram_bytes}

def totals(rows, weights=(.25, .25, .25, .25), expected_names=None):
    # A future extension supplies the frozen product universe explicitly. The
    # original eight remain mandatory, and every row still needs all categories.
    baseline = {s for s, _, _ in ENTITIES}
    expected = tuple(s for s, _, _ in ENTITIES) if expected_names is None else tuple(expected_names)
    if len(expected) != len(set(expected)) or not baseline <= set(expected) or \
            len(rows) != len(expected) or {r['os'] for r in rows} != set(expected) or \
            len(weights) != 4 or any(not math.isfinite(w) or w < 0 for w in weights) or \
            not math.isclose(sum(weights), 1, abs_tol=1e-12):
        raise ValueError('One complete declared leaderboard, all original baselines and fixed four-category policy required')
    result = {}
    for row in rows:
        values = [row.get(k + '_index') for k in KEYS]; positive(values)
        if row['os'] == 'FreeRTOS' and any(not math.isclose(v, 1, abs_tol=1e-12) for v in values):
            raise ValueError('Fixed-reference indices must remain 1')
        result[row['os']] = math.exp(sum(w * math.log(v) for w, v in zip(weights, values)))
    return result

def rank(value, scores):
    return 1 + sum(v > value and not math.isclose(v, value, rel_tol=1e-10) for v in scores.values())

def sensitivity(rows, expected_names=None):
    profiles = [tuple(n / 20 for n in x) for x in product(range(2, 9), repeat=4) if sum(x) == 20]
    profiles += [tuple(0 if i == j else 1 / 3 for i in range(4)) for j in range(4)]
    ranges = {r['os']: [] for r in rows}
    for weights in profiles:
        scores = totals(rows, weights, expected_names)
        for name, value in scores.items(): ranges[name].append(rank(value, scores))
    return {'weight_profiles': len(profiles), 'rank_ranges': {n: [min(v), max(v)] for n, v in ranges.items()},
        'scope': 'Existing bounded application-preference grid and leave-one-category-out analysis; not measurement confidence intervals.'}
