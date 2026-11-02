#!/usr/bin/env python3
"""Offline adapter for the explicitly bounded EunoTOS review subset."""
import argparse
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import shutil
import socket
import statistics
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vendor'))


def load(path):
    return json.loads(path.read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def blocked(*args, **kwargs):
    raise AssertionError('No network, device, process, model or fresh profiling in subset replay')


def integrity():
    rows = (ROOT / 'SHA256SUMS').read_text().splitlines()
    expected = set()
    for row in rows:
        digest, name = row.split('  ', 1)
        p = (ROOT / name).resolve()
        p.relative_to(ROOT)
        require(name not in expected and not (ROOT / name).is_symlink(), 'Invalid manifest member')
        expected.add(name)
        require(hashlib.sha256(p.read_bytes()).hexdigest() == digest, 'Changed input: ' + name)
    actual = {str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file()}
    require(actual == expected | {'SHA256SUMS'}, 'Missing or extra artifact input')


def energy(spec):
    from replay_esp32_b1_energy import paired_trace
    from replay_esp32_followup import raw_rows
    from audit_esp32_unified_mainboard import qualify_cell
    folder = ROOT / spec['energy_campaign']
    setup, plan = load(folder / 'operator-setup.json'), load(folder / 'plan.json')
    require(setup['board_mac'] == plan['board_mac'] and
            setup['sole_board_supply_through_meter'] and setup['no_unmetered_data_usb_supply'],
            'Board/supply declaration mismatch')
    cells = []
    for system in ('FreeRTOS', 'Zephyr', 'NuttX'):
        runs = []
        for index in (1, 2, 3):
            run = folder / system / ('run%d' % index)
            original = load(run / 'energy-result.json')
            capture = run / 'capture'
            require(original['board_mac'] == setup['board_mac'] and original['whole_board_path'] and
                    original['source_proof'] == plan['source_proofs'][system],
                    'Saved source/image/board binding differs')
            rows = raw_rows(capture / 'reset1.jsonl')
            require((capture / 'reset1.jsonl').read_bytes() == (capture / 'uart.jsonl').read_bytes(),
                    'UART alias differs')
            metadata = load(capture / 'metadata.json')
            require(metadata['meter_serial'] == setup['meter_serial'] and
                    metadata['uart_unterminated_bytes'] == 0, 'Meter or raw coverage differs')
            paired = paired_trace(capture, rows, setup['polarity'], system)
            for key, value in paired.items():
                if key != 'paired_intervals':
                    require(abs(value-original['paired'][key]) <= max(1e-10*abs(value), 1e-12),
                            'Recomputed packet/work result differs')
            runs.append({**original, 'paired': paired})
        qualified = qualify_cell({'os': system, 'case': 'message_processing',
                                  'independent_resets': 3, 'runs': runs})
        cells.append({'os': system, 'resets': 3, 'counts_per_s': qualified['median_count_rate_per_s'],
                      'energy_uj_per_count': qualified['median_energy_uj_per_count'],
                      'power_w': statistics.median(qualified['same_window_mean_input_power_w'])})
    return cells


def build_check(build):
    from bind_tenonos_runtime_candidates import build_identity
    return build_identity(build)


def boots_check(folder, image_sha):
    from audit_tenonos_paper_tasks import guest_outcome
    from replay_esp32_followup import digest
    verdict = load(folder / 'boot-result.json')
    require(verdict['image_sha256'] == image_sha, 'Guest and image identity differ')
    outcomes = []
    for index in range(1, len(verdict['runs']) + 1):
        receipt = load(folder / ('boot%d.json' % index))
        out, err = folder / ('boot%d.stdout' % index), folder / ('boot%d.stderr' % index)
        require(digest(out) == receipt['stdout_sha256'] and digest(err) == receipt['stderr_sha256'],
                'Raw guest bytes differ')
        outcomes.append(guest_outcome(out.read_text(), err.read_text(), receipt['returncode']))
    require(len(outcomes) == 3, 'Three recorded guest boots required')
    return all(o['booted'] and o['complete'] for o in outcomes)


def decisions(spec):
    from audit_tenonos_tasks import configuration
    from audit_tenonos_paper_tasks import constraint_outcome
    from audit_tenonos_resource_histories import admitted, clock_endpoint
    from iotos_task_benchmark import summarize_accounting
    complete, g1_rows = 0, []
    for name in spec['g1_trials']:
        folder = ROOT / name
        record = load(folder / 'trial.json')
        build = folder / 'evaluation/build'
        _, proof = build_check(build)
        functional = boots_check(folder / 'evaluation/boots', proof['image_sha256'])
        complete += functional
        task = load(folder / 'candidate/task.json')
        baseline = (configuration(folder / 'candidate/starting-reference.config')
                    if task.get('preserve_reference') else None)
        constraints = constraint_outcome(task, configuration(build / '.config'),
                                        (build / 'runtime-image').stat().st_size, baseline)
        gates = {**record['gates'], 'booted': functional, 'functional': functional,
                 'constraints': constraints}
        require(gates == record['gates'], 'G1 recorded decision differs from config/raw output')
        g1_rows.append({**record, 'gates': gates})
    require(len(g1_rows) == 18, 'Registered G1 denominator differs')
    g1 = summarize_accounting(g1_rows)

    plan, campaign = ROOT / spec['history_plan'], ROOT / spec['history_campaign']
    profiles = {p['identity']: p for p in load(plan / 'catalog.json')}
    state = load(campaign / 'campaign.json')
    independent = load(plan / 'native-independent-audit.json')
    native = {(r['history'], r['round']): r['native_gates'] for r in independent['rows']}
    ticks = [json.loads(line) for line in (plan / 'clock.jsonl').read_text().splitlines()]
    require([r['index'] for r in ticks] == list(range(len(ticks))) and
            all(a['s'] < b['s'] for a, b in zip(ticks, ticks[1:])), 'Invalid monotonic journal')
    histories, rows = [], []
    for history in state['histories']:
        retained = None
        for record in history['rounds']:
            folder = campaign / history['id'] / ('R%d' % record['round'])
            require(record == load(folder / 'round.json'), 'History/round disagreement')
            parent = ROOT / record['parent_build']
            if retained is not None:
                require(parent == retained, 'Recorded next parent differs from retained state')
            _, parent_proof = build_check(parent)
            require(parent_proof['image_sha256'] == record['parent_image_sha256'] and
                    parent_proof['config_sha256'] == record['parent_config_sha256'], 'Wrong parent')
            raw = dict(native[history['id'], record['round']])
            native_pass = all(raw.values())
            if raw['built']:
                build = folder / 'evaluation/build'
                key, proof = build_check(build)
                task = load(folder / 'task.json')
                require(raw['functional'] == boots_check(folder / 'evaluation/boots', proof['image_sha256']) and
                        raw['constraints'] == constraint_outcome(task, configuration(build / '.config'),
                            (build / 'runtime-image').stat().st_size, configuration(parent / '.config')),
                        'Native output/configuration verdict differs')
            if native_pass:
                resource = load(folder / 'resource.json')
                profile = profiles[key]
                require(resource['identity'] == key and resource['profile'] == profile and
                        not resource['energy_inherited'], 'Resource identity differs')
                raw['functional'] &= profile['behavior_pass']
                raw['constraints'] &= profile['peak_bytes'] <= resource['maximum_bytes']
            gates = admitted(raw)
            accepted = all(gates.values()) and record['decision_wall_s'] <= 1800
            require(gates == record['gates'] and accepted == record['accepted'], 'Full decision differs')
            retained = folder / 'evaluation/build' if accepted else parent
            key, proof = build_check(retained)
            require(str(retained.relative_to(ROOT)) == record['retained_build'] and
                    proof['image_sha256'] == record['retained_image_sha256'] and
                    proof['config_sha256'] == record['retained_config_sha256'], 'Wrong retained identity')
            if not accepted:
                require(boots_check(folder / 'recovery/boots', proof['image_sha256']), 'Recorded parent recovery failed')
            begin = load(folder / 'completion-start.json')
            require(ticks[begin['index']] == begin, 'Changed completion clock')
            end = clock_endpoint(ticks, begin, record['observed_wall_s'])
            rows.append({'history': history['id'], 'method': history['method'], 'round': record['round'],
                         'native': native_pass, 'accepted': accepted, 'retained_bytes': profiles[key]['peak_bytes'],
                         'start_index': begin['index'], 'end_index': end['index']})
        group = [r for r in rows if r['history'] == history['id']]
        outer = ticks[group[-1]['end_index']+1]['s']-ticks[group[0]['start_index']-1]['s']
        require(abs(outer-history['total_round_wall_s']) < 1e-9, 'Outer history time differs')
        last_task = load(campaign / history['id'] / 'R2/task.json')
        final = profiles[key]['peak_bytes'] <= last_task['external_resource_requirements']['maximum_bytes']
        histories.append({'id': history['id'], 'method': history['method'], 'final_compliant': final,
                          'outer_elapsed_s': outer})
    require(len(rows) == 12 and len(histories) == 6, 'Requests or histories omitted')
    return {'g1': {'output_complete': complete, 'request_pass': g1['successful_runs'], 'n': len(g1_rows)},
            'requests': {'native_pass': sum(r['native'] for r in rows),
                         'full_pass': sum(r['accepted'] for r in rows), 'n': len(rows)},
            'methods': {m: {'accepted': sum(r['accepted'] for r in rows if r['method'] == m),
                           'final_compliant': sum(h['final_compliant'] for h in histories if h['method'] == m),
                           'requests': sum(r['method'] == m for r in rows),
                           'histories': sum(h['method'] == m for h in histories)} for m in ('direct', 'graph')},
            'histories': histories}


def controls(spec, output):
    import tenonos_resource_histories as histories
    import tenonos_complete_resource as completion
    from tenonos_profile_review import admission
    catalog = load(ROOT / spec['history_plan'] / 'catalog.json')
    review = load(ROOT / 'review.json')
    permit = review['permits'][0]
    source = ROOT / permit['build']
    build = output / 'control-build'
    build.mkdir()
    for name in permit['build_files']:
        shutil.copy2(source / name, build / name)
    results = []
    with patch.object(histories, 'catalog', return_value=catalog), \
            patch.object(completion, 'fresh_profile', side_effect=blocked), \
            patch.object(completion, 'replay_fresh_profile', side_effect=blocked):
        for case in ('valid', 'build_flags', 'workload', 'observer', 'missing_context'):
            context = deepcopy(permit['context'])
            if case == 'build_flags':
                data = load(build / 'build.json')
                data['argv'].append('CFLAGS=-O0')
                save(build / 'build.json', data)
            elif case == 'workload':
                context['workload']['iterations'] = 2000
            elif case == 'observer':
                context['observer']['code_sha256'] = '0'*64
            elif case == 'missing_context':
                del context['recipe']
            result = admission(build, ROOT / spec['history_plan'], output / (case+'.json'),
                               8388608, review, context)
            expected = 'qualified' if case == 'valid' else 'review_required'
            require(result['status'] == expected and result['fresh_resource_guests'] == 0,
                    'Formal review entry failed: ' + case)
            results.append({'case': case, 'status': result['status'], 'profile_reused': result['profile_reused']})
            shutil.copy2(source / 'build.json', build / 'build.json')
        declaration = load(ROOT / 'cohort-declaration.json')
        require(not declaration['acquisition_enabled'] and declaration['status'] == 'declaration_only' and
                declaration['image_map'] == {}, 'Example must not register a measured cohort')
        new_context = deepcopy(permit['context'])
        new_context['guest']['board_id'] = declaration['board_id']
        result = admission(build, ROOT / spec['history_plan'], output / 'cohort.json',
                           8388608, review, new_context)
        require(result['status'] == 'review_required' and not result['profile_reused'],
                'An unmeasured declaration must not borrow a profile')
    shutil.rmtree(build)
    return {'production_entry': 'tenonos_profile_review.admission', 'checks': results,
            'new_cohort': result['status'], 'catalog': 'frozen reviewed input, not raw-RAM replay'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    integrity()
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT) and not output.exists(), 'Use a new output directory outside artifact')
    output.mkdir(parents=True)
    spec = load(ROOT / 'subset.json')
    with patch.object(socket.socket, 'connect', side_effect=blocked):
        energy_rows = energy(spec)
        decision_rows = decisions(spec)
        check_rows = controls(spec, output)
    with (output / 'message-energy.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(energy_rows[0]))
        writer.writeheader()
        writer.writerows(energy_rows)
    save(output / 'decision-increment.json', decision_rows)
    save(output / 'admission-controls.json', check_rows)
    save(output / 'receipt.json', {'pass': True, 'scope': spec['scope'], 'excluded': spec['excluded'],
        'new_model_calls': 0, 'new_hardware_runs': 0, 'external_human_replication': False})
    print(json.dumps({'pass': True, 'output': str(output), 'energy_rows': len(energy_rows),
                      'decision_table': decision_rows, 'controls': check_rows}, indent=2))


if __name__ == '__main__':
    main()
