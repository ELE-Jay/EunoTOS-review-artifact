#!/usr/bin/env python3
"""Bind joint task records to separately audited behavior and allocated RAM."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics

from audit_tenonos_tasks import require, configuration
from audit_tenonos_budget_sensitivity import request_limit
from audit_tenonos_runtime_oracle import audit as behavior_audit
from bind_tenonos_runtime_candidates import build_identity, identity
from prepare_tenonos_joint_tasks import runner_metadata
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = 'artifacts/reports/tenonos-joint-resource-pipeline-v1'
CAMPAIGN = 'artifacts/reports/tenonos-joint-resource-campaign-v1'
NATIVE_AUDIT = 'artifacts/reports/tenonos-joint-resource-native-audit-v3.json'
INVENTORY = 'artifacts/reports/tenonos-joint-candidate-inventory-v1'


def rejection_auditor(raw):
    old_import = b'parse_objective, retrieved_paths, select_paths, strict_object\n'
    old = b'                    try:\n                        options, _ = submitted_options(graph, json.dumps({"options": value["options"]}), task)\n'
    new = b'                    try:\n                        if not isinstance(value, dict) or set(value) != {"options", "utility"}:\n                            raise ValueError("Malformed candidate")\n                        finite_score(value["utility"])\n                        options, _ = submitted_options(graph, json.dumps({"options": value["options"]}), task)\n'
    require(raw.count(old_import) == raw.count(old) == 1, 'Expected exact retained input-rejection audit boundary')
    return raw.replace(old_import,old_import.replace(b'strict_object',b'strict_object, finite_score')).replace(old,new)


def prepare_auditor(output):
    pipeline = ROOT/PIPELINE
    require(not output.exists() and output.parent == pipeline, 'Preserve registered audit sources; add a separate audit-only file')
    original = pipeline/'audit_tenonos_paper_tasks.py'
    output.write_bytes(rejection_auditor(original.read_bytes()))
    save(pipeline/'audit-only-rejection-fix.json', {'prepared_utc':utc(),
        'original_sha256':sha(original),'corrected_sha256':sha(output),'corrected_file':output.name,
        'recipe_sha256':sha(Path(__file__)), 'new_model_calls':0,'new_builds':0,'new_guests':0,
        'scope':'Audit-only replay of candidate structure and finite utility before option parsing, matching the unchanged recorded generator. No changed requests, model outputs, native validation or experiment outcomes.'})
    return {'audit_only_file':str(output.relative_to(ROOT)),'original_generator_unchanged':True,'new_model_calls':0}


def native_evidence(root):
    pipeline, campaign = root/PIPELINE,root/CAMPAIGN
    spec = json.loads((pipeline/'protocol.json').read_text())
    source = json.loads((pipeline/'source-variant.json').read_text())
    base = root/spec['base_pipeline']
    require(source['specification_sha256'] == sha(pipeline/'protocol.json') and
            source['base_proof_sha256'] == sha(base/'source-variant.json'), 'Frozen pipeline changed')
    for name,digest in source['variant_sha256'].items():
        raw = (base/name).read_bytes()
        require(sha(base/name) == source['base_source_sha256'][name], 'Base generator changed')
        if name == 'run_tenonos_paper_tasks.py':
            raw = runner_metadata(raw,source['previous_protocol'],spec['id'])
        require(raw == (pipeline/name).read_bytes() and sha(pipeline/name) == digest,
                'Generator, budget or native judge changed')
    native = json.loads((root/NATIVE_AUDIT).read_text())
    fix = json.loads((pipeline/'audit-only-rejection-fix.json').read_text())
    require(sha(pipeline/'audit_tenonos_paper_tasks.py') == fix['original_sha256'] and
            sha(pipeline/fix['corrected_file']) == fix['corrected_sha256'] == native['audit_code_sha256'] and
            (pipeline/fix['corrected_file']).read_bytes() == rejection_auditor((pipeline/'audit_tenonos_paper_tasks.py').read_bytes()),
            'Audit-only rejection correction differs from retained original')
    registration = json.loads((campaign/'registration.json').read_text())
    bank = pipeline/'task-bank.json'
    require(sha(bank) == registration['historical_task_bank_sha256'] and
            json.loads(bank.read_text())['specification_sha256'] == sha(pipeline/'protocol.json'),
            'Registered task bank changed')
    module_spec = importlib.util.spec_from_file_location('joint_retained_auditor',pipeline/fix['corrected_file'])
    module = importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module)
    fresh = module.audit(campaign)
    require(all(native[k] == v for k,v in fresh.items()), 'Saved request/response replay differs')
    require(native['generation_interface_admissible'] and native['runtime_audit']['registered_task_outcomes_audited'] and
            native['registered_trials'] == source['registered_trials'] == 10 and
            native['campaign_registration_sha256'] == sha(campaign/'registration.json') and
            native['campaign_results_sha256'] == sha(campaign/'results.json') and
            registration['aggregate_completion_tokens_per_trial'] == spec['maximum_output_tokens'],
            'Native request/outcome replay is incomplete')
    for name,digest in native['campaign_evidence_manifest'].items():
        path = (campaign/name).resolve();path.relative_to(campaign.resolve())
        require(sha(path) == digest, 'Native audited bytes changed')
    count,tokens = 0,0
    for trial in registration['trials']:
        folder = campaign/trial['id']/'candidate'
        calls = json.loads((folder/'model-calls.json').read_text())
        expected = ['configurations'] if trial['method'] == 'direct' else ['objective','paths','configurations']
        require([c['stage'] for c in calls] == expected[:len(calls)], 'Unexpected extra generation stages')
        used = 0
        for call in calls:
            count += 1
            request = json.loads((folder/(call['stage']+'-request.json')).read_text())
            request_limit(trial['method'],call['stage'],request['max_tokens'],used)
            response = folder/(call['stage']+'-response.json')
            if response.exists():
                used += json.loads(response.read_text())['usage']['completion_tokens']
        tokens += used
    require((count,tokens) == (native['model_attempts'],native['completion_tokens']) and
            count <= spec['maximum_model_calls'] and tokens <= spec['maximum_completion_tokens'],
            'Frozen model budget differs')
    return spec,native


def inventory_data(root,native):
    campaign = root/CAMPAIGN
    groups,variants,rows = {},[],[]
    for record in native['runtime_audit']['audited_records']:
        row = {'trial':record['id'],'method':record['method'], 'gates':record['gates'],
               'native_stage_pass':record['end_to_end_pass'], 'native_observed_wall_s':record['observed_wall_s']}
        if record['end_to_end_pass']:
            build = campaign/record['id']/'evaluation/build'
            key,proof = build_identity(build)
            if key not in groups:
                name = 'joint-candidate-'+str(len(groups)+1)
                groups[key] = name
                variants.append({'id':name,'identity':key,'build':str(build.relative_to(root)),
                    'image_sha256':proof['image_sha256'],'config_sha256':proof['config_sha256']})
            row.update(identity=key,profile=groups[key])
        rows.append(row)
    return {'registered_trials':len(rows),'rows':rows,'variants':variants,
        'native_audit_sha256':sha(root/NATIVE_AUDIT), 'pipeline_proof_sha256':sha(root/PIPELINE/'source-variant.json'),
        'model_calls':0,'boundary':'Only candidates passing all native task gates require subsequent resource admission. This inventory assigns no final success.'}


def inventory(output):
    require(not output.exists(), 'Preserve previous inventories')
    spec,native = native_evidence(ROOT)
    recorded = inventory_data(ROOT,native)
    rows,variants = recorded['rows'],recorded['variants']
    output.mkdir()
    save(output/'inventory.json',recorded)
    save(output/'ram-references.json',{'variants':variants})
    behavior = json.loads((ROOT/'registry/tenonos_runtime_oracle_v2.json').read_text())
    behavior.update(id=spec['id']+'-candidate-behavior',profiles=[v['id'] for v in variants],
        reference_registry=str((output/'ram-references.json').relative_to(ROOT)),
        reference_registry_sha256=sha(output/'ram-references.json'))
    save(output/'behavior-protocol.json',behavior)
    memory = json.loads((ROOT/'registry/tenonos_joint_ram_rpi4_v1.json').read_text())
    memory.update(id=spec['id']+'-candidate-memory',profiles=[v['id'] for v in variants],
        reference_registry=str((output/'ram-references.json').relative_to(ROOT)),
        selection='Distinct actual generated configurations passing native joint-task requirements; no reference RAM substitution.',
        scope='Configuration-matched observer RAM of retained generated joint-task candidates; final admission requires all four supporting captures.')
    save(output/'memory-protocol.json',memory)
    return {'registered_trials':len(rows),'native_passes':sum(r['native_stage_pass'] for r in rows),
            'distinct_candidates_requiring_qualification':len(variants),'new_model_calls':0}


def bind(behavior_folder,ram_folder):
    spec,native = native_evidence(ROOT)
    folder = ROOT/INVENTORY
    recorded = json.loads((folder/'inventory.json').read_text())
    require(recorded == inventory_data(ROOT,native), 'Native inventory changed')
    behavior = behavior_audit(ROOT,behavior_folder,folder/'behavior-protocol.json')
    from tenonos_size_memory import audit as ram_audit
    ram = ram_audit(ram_folder)
    require(ram == json.loads((ram_folder/'allocated-occupancy.json').read_text()), 'Candidate RAM replay differs')
    admitted = {p['profile']:p for p in behavior['profiles']}
    capacities = {p['profile']:p for p in ram['profiles']}
    variants = {p['id']:p for p in recorded['variants']}
    rows = []
    for row in recorded['rows']:
        if not row['native_stage_pass']:
            rows.append({**row,'joint_pass':False,'ram_qualification':'not required after native failure'})
            continue
        name = row['profile'];variant = variants[name]
        build = ROOT/variant['build']
        require(build_identity(build)[0] == row['identity'] == variant['identity'], 'Candidate identity differs')
        observed = behavior_folder/name
        proof = json.loads((observed/'source-proof.json').read_text())
        require(identity(configuration(observed/'input.config'),proof['identity'],sha(observed/'build/compiler.stdout')) == row['identity'],
                'Behavior observer does not match full candidate configuration/source/compiler version')
        peak = capacities[name]
        require(peak['reference_image_sha256'] == variant['image_sha256'] and
                peak['reference_config_sha256'] == variant['config_sha256'], 'RAM observer candidate alias differs')
        passes = peak['peak_allocated_occupancy_bytes'] <= spec['task']['external_resource_requirements']['maximum_bytes']
        rows.append({**row,'behavior_admitted':admitted[name]['admitted'],
            'ram_allocated_occupancy_bytes':peak['peak_allocated_occupancy_bytes'], 'ram_budget_pass':passes,
            'ram_qualification':'complete configuration-matched observer',
            'joint_pass':admitted[name]['admitted'] and passes})
    groups = []
    for method in spec['methods']:
        group = [r for r in rows if r['method'] == method]
        require(len(group) == spec['fresh_requests_per_task_method'], 'Registered denominator differs')
        times = [r['native_observed_wall_s'] for r in group]
        groups.append({'method':method,'n':len(group),'native_passes':sum(r['native_stage_pass'] for r in group),
            'joint_passes':sum(r['joint_pass'] for r in group),
            'native_stage_wall_median_s':statistics.median(times),'native_stage_wall_range_s':[min(times),max(times)]})
    return {'audit':'pass','groups':groups,'rows':rows,'registered_trials':len(rows),
        'model_calls':native['model_attempts'],'completion_tokens':native['completion_tokens'],
        'new_original_guest_captures':native['runtime_audit']['raw_guest_captures'],
        'distinct_qualified_configurations':len(variants),'new_behavior_guests':sum(len(p['guests']) for p in behavior['profiles']),
        'new_memory_observer_guests':ram['new_guests_in_observer_campaign'],
        'new_memory_supporting_guests':ram['new_guests_in_supporting_captures'],
        'reused_early_memory_guests':ram['reused_early_guests'],
        'native_audit_sha256':sha(ROOT/NATIVE_AUDIT),'inventory_sha256':sha(folder/'inventory.json'),
        'behavior_campaign_sha256':sha(behavior_folder/'campaign.json'),
        'ram_report_sha256':sha(ram_folder/'allocated-occupancy.json'),'new_model_calls_by_audit':0,
        'author_engine':False,'rsi':False,'ranking_eligible':False,
        'boundary':'Five repetitions per branch of one joint task. Profile aliases are not new RAM samples. '
            'The native online duration excludes post-generation behavior/RAM qualification and is not full end-to-end resource-verified latency. '
            'No new energy result, whole-Pi RAM or cross-hardware ranking.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare-auditor','inventory','bind'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--behavior',type=Path)
    parser.add_argument('--ram',type=Path)
    args = parser.parse_args()
    require(ROOT == Path('/home/reviewer/esp32-pilot/audit-workspace'), 'Retain evidence on leon')
    if args.action == 'prepare-auditor':
        value = prepare_auditor(args.output.resolve())
    elif args.action == 'inventory':
        value = inventory(args.output.resolve())
    else:
        require(args.behavior is not None and args.ram is not None and not args.output.exists(), 'Use complete captures and a new output')
        value = bind(args.behavior.resolve(),args.ram.resolve());save(args.output.resolve(),value)
    print(json.dumps({k:v for k,v in value.items() if k != 'rows'}),flush=True)
