#!/usr/bin/env python3
"""Versioned, reviewed resource admission in front of the frozen v1 matchers."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ('.config', 'runtime-image', 'compiler.stdout', 'build-result.json', 'build.json', 'build.stdout')
CONTEXT = ('observer', 'workload', 'guest', 'boundary', 'recipe')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fingerprint(build):
    return {name: sha(build / name) for name in REQUIRED}


def admission(build, plan, destination, maximum, review, context, kind='history'):
    """Unknown context is review-required; this entry never initiates profiling."""
    from bind_tenonos_runtime_candidates import build_identity
    pending = {'status': 'review_required', 'profile_reused': False, 'peak_bytes': None,
               'new_independent_ram_sample': False, 'fresh_resource_guests': 0,
               'energy_inherited': False, 'review_policy': 'tenon-reviewed-resource-v2'}
    try:
        if review.get('policy') != pending['review_policy'] or not all(context.get(k) for k in CONTEXT):
            raise ValueError('Missing versioned review or required context')
        files = fingerprint(build)
        key, _ = build_identity(build)
        permits = [p for p in review['permits'] if p['identity'] == key and
                   p['build_files'] == files and p['context_sha256'] == digest(context)]
        if len(permits) != 1:
            raise ValueError('Build or context lacks an unambiguous reviewed binding')
        permit = permits[0]
        for name, expected in permit['support'].items():
            path = (ROOT / name).resolve()
            path.relative_to(ROOT)
            if sha(path) != expected:
                raise ValueError('Reviewed support changed: ' + name)
        recorded = json.loads((plan / 'catalog.json').read_text())
        profile = next((p for p in recorded if p['identity'] == key), None)
        if profile is None or profile['memory_sha256'] != permit['memory_sha256']:
            raise ValueError('Reviewed profile is not in the requested frozen catalog')
    except (KeyError, OSError, ValueError) as error:
        return {**pending, 'reason': str(error)}
    # This is the real frozen matcher; the preflight does not reimplement its RAM verdict.
    if kind == 'history':
        from tenonos_resource_histories import judge_resource
        result = judge_resource(build, plan, destination, maximum)
    elif kind == 'completion' and maximum == 8388608:
        from tenonos_complete_resource import judge_resource
        result = judge_resource(build, plan, destination)
    else:
        return {**pending, 'reason': 'Unsupported registered admission context'}
    if not result['profile_reused']:
        raise ValueError('Reviewed catalog hit unexpectedly left the reuse path')
    return {**result, 'review_policy': pending['review_policy'], 'review_id': permit['review_id'],
            'review_timing': '2026-10-31 offline review; not a historical online timing component'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'plan', 'destination', 'review', 'context'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--maximum', type=int, required=True)
    parser.add_argument('--kind', choices=('history', 'completion'), default='history')
    args = parser.parse_args()
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace'):
        parser.error('Run evidence-dependent admission on leon')
    result = admission(args.build.resolve(), args.plan.resolve(), args.destination.resolve(), args.maximum,
                       json.loads(args.review.read_text()), json.loads(args.context.read_text()), args.kind)
    print(json.dumps(result, indent=2))
