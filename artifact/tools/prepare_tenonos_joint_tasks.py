#!/usr/bin/env python3
"""Freeze a resource task using measured feasibility and the unchanged generator."""
import argparse
import json
from pathlib import Path
import shutil

from audit_tenonos_tasks import configuration, require
from prepare_tenonos_budget_profile import SOURCES, CAMPAIGN_SOURCES
from prepare_tenonos_expanded_references import audit as feasible_audit
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
SPEC = 'registry/tenonos_joint_constraints_v1.json'


def runner_metadata(raw, previous, identifier):
    require(raw.count(previous.encode()) == 1, 'Expected one frozen protocol identifier')
    return raw.replace(previous.encode(),identifier.encode())


def prepare(output):
    require(ROOT == Path('/home/reviewer/esp32-pilot/audit-workspace') and not output.exists(),
            'Freeze evidence-dependent tasks on leon in a new folder')
    output.relative_to(ROOT/'artifacts/reports')
    spec = json.loads((ROOT/SPEC).read_text())
    reference = ROOT/spec['reference_campaign']
    feasible = feasible_audit(reference)
    require(feasible == json.loads((reference/'audit.json').read_text()) and
            any(r['id'] == spec['reference'] and r['feasible'] for r in feasible['references']),
            'Missing admitted joint reference')
    from measure_tenonos_joint_ram import audit as ram_audit
    ram_folder = ROOT/spec['reference_ram_campaign']
    ram = ram_audit(ram_folder)
    require(ram == json.loads((ram_folder/'allocated-occupancy.json').read_text()) and
            ram['feasible_ram_reference'], 'Joint reference RAM has not passed complete replay')
    measured = next(p for p in ram['profiles'] if p['profile'] == spec['reference'])
    build = reference/spec['reference']/'evaluation/build'
    task = spec['task']
    require(all(configuration(build/'.config').get(k,'n') == v for k,v in task['required_options'].items()) and
            (build/'runtime-image').stat().st_size <= task['maximum_image_bytes'] and
            measured['peak_allocated_occupancy_bytes'] <= task['external_resource_requirements']['maximum_bytes'],
            'Reference misses a prospective task constraint')
    base = ROOT/spec['base_pipeline']
    proof = json.loads((base/'source-variant.json').read_text())
    previous = json.loads((base/'protocol.json').read_text())['id']
    require(sha(ROOT/spec['graph']) == spec['graph_sha256'] and
            sha(ROOT/spec['index']/'run.json') == spec['index_run_sha256'], 'Graph/index changed')
    output.mkdir(parents=True)
    shutil.copyfile(ROOT/SPEC,output/'protocol.json')
    shutil.copyfile(Path(__file__),output/'preparer-source.py')
    hashes, originals = {}, {}
    for name in SOURCES+CAMPAIGN_SOURCES:
        source = base/name
        require(sha(source) == proof['variant_sha256'][name], 'Qualified numeric pipeline changed: '+name)
        raw = source.read_bytes()
        if name == 'run_tenonos_paper_tasks.py':
            raw = runner_metadata(raw,previous,spec['id'])
        (output/name).write_bytes(raw)
        hashes[name],originals[name] = sha(output/name),sha(source)
    old = json.loads((reference/'protocol.json').read_text())
    fixed = {**old['fixed_options'], 'LIBUKLOCK':'y','LIBUKLOCK_MUTEX':'n','LIBUKLOCK_RWLOCK':'n'}
    files = [p for folder in (reference/spec['reference'],reference/'behavior'/spec['reference'],ram_folder)
             for p in folder.rglob('*') if p.is_file() and not p.is_symlink() and '__pycache__' not in p.parts]
    registered_task = {**task, 'application':'app-rtos-benchmark-abi', 'fixed_options':fixed,
        'candidate_controls':spec['candidate_controls'], 'generation_budget_s':spec['generation_budget_s'],
        'maximum_attempts':1, 'reference_profile':spec['reference'],
        'reference_files':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in sorted(set(files))]}
    bank = {k:spec[k] for k in ('id','scope','maximum_output_tokens','generation_budget_s','wall_budget_s',
        'attempts_per_trial','independent_guest_boots_per_candidate','statistics','model')}
    bank.update(seeds=list(range(42,42+spec['fresh_requests_per_task_method'])),
        seed_interpretation='Repetition labels only; no API seed transmitted.',tasks=[registered_task],
        specification_sha256=sha(ROOT/SPEC), reference_audit_sha256=sha(reference/'audit.json'),
        reference_ram_sha256=sha(ram_folder/'allocated-occupancy.json'))
    save(output/'task-bank.json',bank)
    save(output/'source-variant.json',{'prepared_utc':utc(),'specification_sha256':sha(ROOT/SPEC),
        'base_pipeline':spec['base_pipeline'],'base_proof_sha256':sha(base/'source-variant.json'),
        'base_source_sha256':originals,'variant_sha256':hashes,'previous_protocol':previous,
        'changes':'Task bank and one runner protocol-label string only; generator, numeric adapter, prompts, retrieval, budgets and runtime/native judges byte-identical.',
        'reference_audit_sha256':sha(reference/'audit.json'), 'reference_ram_sha256':sha(ram_folder/'allocated-occupancy.json'),
        'registered_tasks':1,'registered_trials':2*spec['fresh_requests_per_task_method'],'model_calls':0,
        'external_resource_admission_required':True})
    return {'prepared':str(output.relative_to(ROOT)), 'tasks':1,
            'trials':2*spec['fresh_requests_per_task_method'],'model_calls':0,
            'external_resource_admission_required':True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.resolve())))
