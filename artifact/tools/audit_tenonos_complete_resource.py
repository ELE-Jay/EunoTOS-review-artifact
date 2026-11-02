#!/usr/bin/env python3
"""Independently replay native outcomes, resource certificates and completion clocks."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def retained_auditor():
    from tenonos_complete_resource import BASE
    path=ROOT/BASE/'audit_tenonos_paper_tasks_rejection_fix.py'
    spec=importlib.util.spec_from_file_location('completion_retained_native_auditor',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,path


def audit_native(plan,campaign):
    from tenonos_complete_resource import source_guard,load,require
    from tenonos_kvm_reproduce import sha,save
    registration=source_guard(plan)
    spec=load(ROOT/'registry/tenonos_joint_constraints_v1.json')
    result,path=retained_auditor()
    checked=result.audit(campaign)
    with tempfile.TemporaryDirectory(prefix='iotos-completion-native-',dir='/dev/shm') as tmp:
        checked['runtime_audit']=result.audit_runtime(campaign,
            ROOT/'artifacts/reports/tenonos-joint-resource-pipeline-v1/task-bank.json',
            ROOT/spec['graph'],Path(registration['validation_workspace']),Path(tmp)/'replay')
    checked.update(campaign_registration_sha256=sha(campaign/'registration.json'),
        campaign_results_sha256=sha(campaign/'results.json'),audit_code_sha256=sha(path),
        campaign_evidence_manifest={str(p.relative_to(campaign)):sha(p) for p in campaign.rglob('*')
                                    if p.is_file() and not p.is_symlink()})
    require(not (plan/'native-independent-audit.json').exists(),'Preserve existing native audits')
    save(plan/'native-independent-audit.json',checked)
    return {'native_outcomes_independently_replayed':True,'trials':checked['registered_trials'],
            'original_guests':checked['runtime_audit']['raw_guest_captures'],'new_model_calls':0}


def audit(plan,campaign):
    import audit_tenonos_joint_tasks as native
    from bind_tenonos_runtime_candidates import build_identity
    from tenonos_complete_resource import source_guard,load,require,catalog,completion_rows,replay_fresh_profile
    from tenonos_kvm_reproduce import sha
    source_guard(plan)
    execution=load(plan/'execution.json')
    require(execution['status']=='complete' and execution['governor_restored'] and
            not execution['host_after_restore']['qemu_running'] and
            execution['host_after_restore']['throttled']=='throttled=0x0' and
            execution['host_after_restore']['serial']==['10000000c1b4a936'], 'Campaign or restoration incomplete')
    previous=native.CAMPAIGN,native.NATIVE_AUDIT
    try:
        native.CAMPAIGN=str(campaign.relative_to(ROOT))
        native.NATIVE_AUDIT=str((plan/'native-independent-audit.json').relative_to(ROOT))
        specification,native_result=native.native_evidence(ROOT)
    finally:
        native.CAMPAIGN,native.NATIVE_AUDIT=previous
    require(native_result['registered_trials']==10, 'Registered denominator changed')
    rows=completion_rows(campaign,plan)
    require(rows==load(campaign/'complete-results.json')['rows'], 'Completion timing changed')
    existing=catalog();require(existing==load(plan/'catalog.json'), 'Initial profile catalog changed')
    online=load(plan/'online-profiles.json') if (plan/'online-profiles.json').exists() else []
    by_key={p['identity']:p for p in existing+online}
    require(len(by_key)==len(existing)+len(online),'Duplicate resource identity')
    for profile in online:
        replay_fresh_profile(profile)
    for row in rows:
        trial=campaign/row['id'];resource_path=trial/'resource.json'
        if row['native_pass']:
            require(resource_path.exists(),'Native-qualified output lacks external verdict')
            resource=load(resource_path);key,_=build_identity(trial/'evaluation/build')
            require(resource['identity']==key and resource['profile']==by_key[key] and
                    resource['maximum_bytes']==specification['task']['external_resource_requirements']['maximum_bytes'] and
                    not resource['energy_inherited'], 'Resource/input binding differs')
            profile=resource['profile']
            expected=('behavior_failed' if not profile.get('behavior_pass',True) else
                      'qualified' if profile['peak_bytes']<=resource['maximum_bytes'] else 'constraint_failed')
            require(resource['status']==expected and row['full_pass']==(expected=='qualified'), 'External admission differs')
    groups=[]
    for method in ('direct','graph'):
        group=[r for r in rows if r['method']==method]
        require(len(group)==5,'Failure or denominator was dropped')
        times=[r['failed_or_completed_wall_s'] for r in group]
        successes=[r['successful_completion_s'] for r in group if r['full_pass']]
        costs=[r['external_qualification_s'] for r in group if r['native_pass']]
        groups.append({'method':method,'n':len(group),'full_passes':len(successes),
            'all_attempt_median_s':statistics.median(times),'all_attempt_range_s':[min(times),max(times)],
            'successful_completion_median_s':statistics.median(successes) if successes else None,
            'successful_completion_range_s':[min(successes),max(successes)] if successes else None,
            'external_qualification_median_s':statistics.median(costs) if costs else None})
    registration=load(plan/'registration.json')
    return {'audit':'pass','registered_trials':10,'groups':groups,'rows':rows,
        'model_calls':native_result['model_attempts'],'output_tokens':native_result['completion_tokens'],
        'original_guests':native_result['runtime_audit']['raw_guest_captures'],
        'new_resource_guests':sum(r['fresh_resource_guests'] for r in rows),
        'distinct_new_profiles':len(online),'premeasured_profiles':len(existing),
        'setup_catalog_s':registration['setup_catalog_s'],
        'native_independent_audit_sha256':sha(plan/'native-independent-audit.json'),
        'clock_sha256':sha(plan/'clock.jsonl'),'completion_registration_sha256':sha(plan/'registration.json'),
        'author_engine':False,'rsi':False,'ranking_eligible':False,
        'new_model_calls_by_audit':0,'new_guests_by_audit':0,
        'scope':'Ten fresh trials of the unchanged joint task/generator. Online completion includes external '
            'behavior/RAM verification, with exact configuration/source/compiler-version profile reuse or fresh acquisition. '
            'Setup/catalog construction is separate. Failure termination is not successful completion; no P95, '
            'population ranking, inherited energy, instruction-exact stack use or author-engine claim.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('native','audit'))
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--campaign',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    from tenonos_complete_resource import BASE,LEON,require
    require(ROOT==LEON,'Evidence audits remain on leon')
    sys.path.insert(0,str(ROOT/BASE))
    if args.action=='native':
        result=audit_native(args.plan.resolve(),args.campaign.resolve())
    else:
        from tenonos_kvm_reproduce import save
        require(args.output is not None and not args.output.exists(),'Preserve earlier audits')
        result=audit(args.plan.resolve(),args.campaign.resolve());save(args.output,result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}),flush=True)
