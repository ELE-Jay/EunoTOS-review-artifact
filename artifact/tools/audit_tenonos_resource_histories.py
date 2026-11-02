#!/usr/bin/env python3
"""Independently check native outcomes, resource decisions, clocks and retained parents."""
import argparse
from collections import Counter
import json
from pathlib import Path
import statistics
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
STAGES=('generated','built','booted','functional','constraints')


def native(plan,campaign):
    from tenonos_resource_histories import source_guard,load,require
    import audit_tenonos_policy_sequence as original
    from audit_tenonos_paper_tasks import constraint_outcome
    from audit_tenonos_tasks import configuration
    from tenonos_kvm_reproduce import sha,save
    registration=source_guard(plan);cohort=load(campaign/'registration.json');state=load(campaign/'campaign.json')
    require(state['status']=='collection_complete','Incomplete registered collection')
    rows=[];calls=0;tokens=0;finishes=Counter();guests=0
    with tempfile.TemporaryDirectory(prefix='tenon-resource-native-',dir='/dev/shm') as tmp:
        for history in state['histories']:
            for record in history['rounds']:
                folder=campaign/history['id']/('R'+str(record['round']))
                generated,n,used,reasons=original.generation_check(folder/'candidate',folder/'task.json',
                    ROOT/registration['graph'],Path(registration['workspace']),
                    Path(tmp)/history['id']/str(record['round']),history['method'],'deepseek-v4-pro')
                calls+=n;tokens+=used;finishes.update(reasons)
                gates=dict.fromkeys(STAGES,False);gates['generated']=generated['valid_candidate']
                if gates['generated']:
                    original.transferred(folder);build=folder/'evaluation/build'
                    require(sha(folder/'candidate/starting-reference.config')==record['parent_config_sha256'],
                            'Wrong preservation parent')
                    if (build/'build-result.json').exists():
                        proof=load(build/'build-result.json')
                        require(proof['source_commits']==cohort['source_commits']['source_commits'] and
                            proof['source_worktrees_unchanged'] and sha(build/'runtime-image')==proof['image_sha256'] and
                            sha(build/'.config')==proof['config_sha256'] and sha(build/'input.defconfig')==
                            proof['input_defconfig_sha256']==generated['candidate_sha256'] and
                            sha(build/'compiler.stdout')==proof['compiler_version_stdout_sha256'],'Build identity differs')
                        outcomes,complete=original.guest_checks(folder/'evaluation/boots',proof['image_sha256'])
                        guests+=len(outcomes)
                        gates.update(built=True,booted=bool(outcomes) and outcomes[0]['booted'],functional=complete,
                            constraints=constraint_outcome(load(folder/'task.json'),configuration(build/'.config'),
                                (build/'runtime-image').stat().st_size,
                                configuration(ROOT/record['parent_build']/'.config')))
                        observed=load(folder/'candidate/evaluation.json')
                        require(all(observed[k]==v for k,v in gates.items()),'Native checker differs from raw replay')
                    else:
                        failed=load(build/'build.json')
                        require(failed['state']=='finished' and failed['returncode']!=0,'Missing build failure')
                    require(all(load(folder/'native-verdict.json')[k]==v for k,v in gates.items()),
                            'Saved native verdict differs')
                rows.append({'history':history['id'],'round':record['round'],'native_gates':gates,
                    'model_calls':n,'output_tokens':used})
    require(len(rows)==12 and (calls,tokens)==(state['model_calls'],state['completion_tokens']) and
            calls<=24 and tokens<=13824,'Native coverage or budget differs')
    result={'audit':'pass','rows':rows,'model_calls':calls,'output_tokens':tokens,
        'original_guests':guests,'finish_reasons':dict(finishes),'audit_code_sha256':sha(Path(__file__)),
        'campaign_manifest':{str(p.relative_to(campaign)):sha(p) for p in campaign.rglob('*')
            if p.is_file() and not p.is_symlink()}}
    require(not (plan/'native-independent-audit.json').exists(),'Keep previous independent audits')
    save(plan/'native-independent-audit.json',result)
    return {k:v for k,v in result.items() if k not in ('rows','campaign_manifest')}


def clock_endpoint(ticks,start,duration):
    matches=[r for r in ticks[start['index']+1:] if abs((r['s']-start['s'])-duration)<1e-9]
    if len(matches)!=1:
        raise ValueError('Round duration has no unique captured clock endpoint')
    return matches[0]


def admitted(raw):
    result={};previous=True
    for stage in STAGES:
        result[stage]=previous and raw[stage];previous=result[stage]
    return result


def audit(plan,campaign):
    from tenonos_resource_histories import source_guard,load,require,catalog,task_round,SPEC
    from tenonos_complete_resource import replay_fresh_profile
    from audit_tenonos_tasks import configuration
    from bind_tenonos_runtime_candidates import build_identity
    import audit_tenonos_policy_sequence as original
    import run_tenonos_policy_sequence as runner
    from tenonos_kvm_reproduce import sha
    registration=source_guard(plan);spec=load(ROOT/SPEC);protocol=load(plan/'protocol.json')
    cohort=load(campaign/'registration.json');state=load(campaign/'campaign.json');execution=load(plan/'execution.json')
    require(execution['status']=='complete' and execution['governor_restored'] and
        execution['initial_host']['serial']==execution['host_after_restore']['serial']==['10000000c1b4a936'] and
        execution['host_after_restore']['throttled']=='throttled=0x0' and not execution['host_after_restore']['qemu_running'],
        'Collection or host restoration incomplete')
    require(state['status']=='collection_complete' and load(campaign/'protocol.json')==protocol and
        cohort['plan_sha256']==sha(plan/'protocol.json') and cohort['graph_sha256']==registration['graph_sha256'] and
        cohort['bank_sha256']==sha(campaign/'task-bank.json')==protocol['task_bank_sha256'] and
        registration['registered_utc']<=cohort['registered_utc'],'Registration differs')
    for name,digest in cohort['source_sha256'].items():
        require(sha(campaign/'sources'/name)==sha(plan/'pipeline'/name)==digest,'Frozen runner source differs')
    independent=load(plan/'native-independent-audit.json')
    require(independent['audit']=='pass' and independent['audit_code_sha256']==sha(Path(__file__)),
            'Independent native audit code differs')
    for name,digest in independent['campaign_manifest'].items():
        p=(campaign/name).resolve();p.relative_to(campaign.resolve())
        require(sha(p)==digest,'Independently audited capture changed')
    known=catalog();require(known==load(plan/'catalog.json'),'Premeasured catalog differs')
    online=load(plan/'online-profiles.json') if (plan/'online-profiles.json').exists() else []
    for p in online:
        replay_fresh_profile(p)
    profiles={p['identity']:p for p in known+online}
    require(len(profiles)==len(known)+len(online),'Ambiguous memory profile')
    native_rows={(r['history'],r['round']):r for r in independent['rows']}
    ticks=[json.loads(line) for line in (plan/'clock.jsonl').read_text().splitlines()]
    require([r['index'] for r in ticks]==list(range(len(ticks))) and
            all(a['s']<b['s'] for a,b in zip(ticks,ticks[1:])),'Invalid monotonic journal')
    base=next(t for t in load(campaign/'task-bank.json')['tasks'] if t['id']==protocol['source_task'])
    graph=load(ROOT/registration['graph']);rows=[];histories=[];parent_guests=0
    expected=['H%d-%s'%(i,m) for i in (1,2,3) for m in (('direct','graph') if i%2 else ('graph','direct'))]
    require([h['id'] for h in state['histories']]==expected,'Registered histories omitted')
    for h in state['histories']:
        directory=campaign/h['id'];parent=ROOT/protocol['initial_reference']/'build'
        parent_guests+=original.parent_check(directory/'initial',parent,cohort['source_commits']['source_commits'])
        feedback={'accepted':None,'gates':None,'required_configuration':[]};history_rows=[];states=[]
        initial_key,_=build_identity(parent);states.append(profiles[initial_key]['peak_bytes'])
        require(len(h['rounds'])==2,'Missing registered round')
        for index,record in enumerate(h['rounds'],1):
            folder=directory/('R'+str(index));task=load(folder/'task.json')
            require(record==load(folder/'round.json') and record['round']==index and
                record['parent_build']==str(parent.relative_to(ROOT)) and
                record['parent_image_sha256']==sha(parent/'runtime-image') and
                record['parent_config_sha256']==sha(parent/'.config') and
                task==task_round(base,parent/'.config',graph,feedback,index,runner.round_task,spec) and
                record['feedback']==feedback,'Task, retained parent or feedback differs')
            native_row=native_rows[h['id'],index];raw=dict(native_row['native_gates']);resource=None
            if all(raw.values()):
                resource=load(folder/'resource.json');key,_=build_identity(folder/'evaluation/build')
                require(resource['identity']==key and resource['profile']==profiles[key] and
                    resource['maximum_bytes']==spec['rounds'][index-1]['maximum_ram_bytes'] and
                    not resource['energy_inherited'],'Resource admission identity differs')
                p=profiles[key];status=('behavior_failed' if not p['behavior_pass'] else
                    'qualified' if p['peak_bytes']<=resource['maximum_bytes'] else 'constraint_failed')
                require(status==resource['status'],'RAM decision differs from independently replayed occupancy')
                raw['functional']=raw['functional'] and p['behavior_pass']
                raw['constraints']=raw['constraints'] and status=='qualified'
            elif (folder/'resource.json').exists():
                require(load(folder/'resource.json')['status']=='not reached','Rejected native output borrowed RAM')
            gates=admitted(raw);accepted=all(gates.values()) and record['decision_wall_s']<=1800
            require(gates==record['gates'] and accepted==record['accepted'],'Full admission differs')
            begin=load(folder/'completion-start.json');require(ticks[begin['index']]==begin,'Round start changed')
            decision=clock_endpoint(ticks,begin,record['decision_wall_s'])
            end=clock_endpoint(ticks,begin,record['observed_wall_s'])
            require(decision['s']<=end['s'],'Decision follows termination')
            if resource:
                require(begin['s']<=resource['native_end_s']<=resource['qualification_end_s']<=decision['s'],
                        'Resource verification is outside the timed decision')
            before=parent
            if accepted:
                parent=folder/'evaluation/build'
                require(configuration(parent/'.config')!=configuration(before/'.config'),'Accepted edit is a no-op')
            else:
                parent_guests+=original.parent_check(folder/'recovery',parent,cohort['source_commits']['source_commits'])
            require(record['retained_build']==str(parent.relative_to(ROOT)) and
                record['retained_image_sha256']==sha(parent/'runtime-image') and
                record['retained_config_sha256']==sha(parent/'.config') and
                record['policy_changed']==(configuration(parent/'.config')!=configuration(before/'.config')),
                'Retention or recovery differs')
            evaluation=load(folder/'candidate/evaluation.json') if (folder/'candidate/evaluation.json').exists() else {}
            feedback=runner.configuration_feedback(gates,accepted,evaluation)
            require(feedback==record['next_feedback'],'Hidden or changed feedback')
            retained_key,_=build_identity(parent);states.append(profiles[retained_key]['peak_bytes'])
            row={'history':h['id'],'method':h['method'],'round':index,'native_gates':native_row['native_gates'],
                'gates':gates,'accepted':accepted,'decision_s':record['decision_wall_s'],
                'successful_completion_s':record['decision_wall_s'] if accepted else None,
                'all_attempt_with_recovery_s':record['observed_wall_s'],
                'resource_status':resource['status'] if resource else 'not reached',
                'candidate_peak_bytes':resource['profile']['peak_bytes'] if resource else None,
                'retained_peak_bytes':states[-1],'start_index':begin['index'],'end_index':end['index'],
                'fresh_resource_guests':resource.get('fresh_resource_guests',0) if resource else 0}
            rows.append(row);history_rows.append(row)
        history_begin=ticks[history_rows[0]['start_index']-1]['s']
        history_end=ticks[history_rows[-1]['end_index']+1]['s']
        require(abs(history_end-history_begin-h['total_round_wall_s'])<1e-9 and
            h['final_image_sha256']==sha(parent/'runtime-image') and h['final_config_sha256']==sha(parent/'.config') and
            h['within_history_budget']==(h['total_round_wall_s']<=3600),'Cumulative cost or endpoint differs')
        histories.append({'id':h['id'],'method':h['method'],'accepted_rounds':sum(r['accepted'] for r in history_rows),
            'total_round_wall_s':h['total_round_wall_s'],'retained_allocation_bytes':states,
            'within_history_budget':h['within_history_budget']})
    require(len(rows)==12 and (independent['model_calls'],independent['output_tokens'])==
        (state['model_calls'],state['completion_tokens']),'Failure or usage omitted')
    return {'audit':'pass','registered_histories':6,'registered_rounds':12,'histories':histories,'rows':rows,
        'model_calls':independent['model_calls'],'output_tokens':independent['output_tokens'],
        'original_guests':independent['original_guests'],'parent_check_guests':parent_guests,
        'new_resource_guests':sum(r['fresh_resource_guests'] for r in rows),'distinct_new_profiles':len(online),
        'groups':[{'method':m,'accepted_rounds':sum(r['accepted'] for r in rows if r['method']==m),
            'rounds':6,'history_cost_median_s':statistics.median(h['total_round_wall_s'] for h in histories if h['method']==m),
            'native_constraint_passes':sum(all(r['native_gates'].values()) for r in rows if r['method']==m),
            'ram_rejections':sum(r['resource_status']=='constraint_failed' for r in rows if r['method']==m)} for m in ('direct','graph')],
        'clock_sha256':sha(plan/'clock.jsonl'),'native_independent_audit_sha256':sha(plan/'native-independent-audit.json'),
        'specification_sha256':registration['specification_sha256'],'author_engine':False,'rsi':False,
        'energy_inherited':False,'ranking_eligible':False,'new_calls_by_audit':0,'new_guests_by_audit':0,
        'scope':spec['scope']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('native','audit'))
    parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--campaign',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    from tenonos_resource_histories import bootstrap,require
    from tenonos_kvm_reproduce import save
    require(ROOT==Path('/home/reviewer/esp32-pilot/audit-workspace'),'Real evidence stays on leon')
    bootstrap(args.plan.resolve())
    result=native(args.plan.resolve(),args.campaign.resolve()) if args.action=='native' else audit(args.plan.resolve(),args.campaign.resolve())
    if args.action=='audit':
        require(args.output is not None and not args.output.exists(),'Preserve all prior audits')
        save(args.output,result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','histories')},indent=2),flush=True)
