#!/usr/bin/env python3
"""Time the unchanged Tenon runner through external behavior/RAM qualification."""
import argparse
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
SPEC = 'registry/tenonos_complete_resource_v1.json'
BASE = 'artifacts/reports/tenonos-joint-resource-pipeline-v1'
SOCKET = '/tmp/iotos-pi-energy.sock'
HOST = 'pi@192.168.31.76'
PI = '/home/pi/tenonos-benchmark-v1'
PROFILE_SCOPE = ('Matched observer-inclusive guest occupancy, native entry through termination entry. '
                 'Three behavior guests, three lifecycle guests and four supporting guests; no model feedback or extra generation.')


def require(value, message):
    if not value:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def catalog():
    from audit_tenonos_joint_tasks import bind
    from prepare_tenonos_expanded_references import audit as feasible_audit
    from measure_tenonos_joint_ram import audit as memory_audit
    from bind_tenonos_runtime_candidates import build_identity
    from tenonos_kvm_reproduce import sha
    specification = load(ROOT/'registry/tenonos_joint_constraints_v1.json')
    reference = ROOT/specification['reference_campaign']
    feasible = feasible_audit(reference)
    require(feasible == load(reference/'audit.json'), 'Feasibility reference differs')
    memory_folder = ROOT/specification['reference_ram_campaign']
    memory = memory_audit(memory_folder)
    require(memory == load(memory_folder/'allocated-occupancy.json'), 'Reference RAM differs')
    build = reference/specification['reference']/'evaluation/build'
    key, _ = build_identity(build)
    peak = next(p for p in memory['profiles'] if p['profile'] == specification['reference'])
    rows = [{'identity':key, 'provider':'reference', 'peak_bytes':peak['peak_allocated_occupancy_bytes'],
             'memory_evidence':str((memory_folder/'allocated-occupancy.json').relative_to(ROOT)),
             'memory_sha256':sha(memory_folder/'allocated-occupancy.json')}]
    generated = bind(ROOT/'artifacts/reports/tenonos-joint-candidate-behavior-rpi4-v1',
                     ROOT/'artifacts/reports/tenonos-joint-candidates-allocated-rpi4-v2')
    require(generated == load(ROOT/'artifacts/reports/tenonos-joint-qualified-v1.json'), 'Generated admission differs')
    for row in generated['rows']:
        if row['joint_pass'] and not any(r['identity'] == row['identity'] for r in rows):
            name = 'artifacts/reports/tenonos-joint-candidates-allocated-rpi4-v2/allocated-occupancy.json'
            rows.append({'identity':row['identity'], 'provider':'generated',
                         'peak_bytes':row['ram_allocated_occupancy_bytes'],
                         'memory_evidence':name, 'memory_sha256':sha(ROOT/name)})
    require(len(rows) == 2, 'Expected the two premeasured joint configurations')
    return rows


@contextmanager
def memory_context(native, registry):
    import measure_tenonos_joint_ram as method
    import tenonos_exit_memory as abi
    import tenonos_allocator_metadata as metadata
    import audit_tenonos_exit_memory as exit_audit
    from tenonos_size_memory import layout
    previous = method.NATIVE, method.REGISTRY, abi.layout, metadata.observer_layout, exit_audit.layout
    method.NATIVE, method.REGISTRY = native, registry
    abi.layout = metadata.observer_layout = exit_audit.layout = layout
    try:
        yield method
    finally:
        method.NATIVE, method.REGISTRY, abi.layout, metadata.observer_layout, exit_audit.layout = previous


def fresh_memory_audit(folder):
    native = str((folder/'native').relative_to(ROOT))
    registry = '../'+str((folder/'memory-protocol.json').relative_to(ROOT))
    with memory_context(native,registry) as method:
        result = method.audit(folder/'allocated')
    result.update(analysis='Online allocated-occupancy qualification of a new generated configuration',scope=PROFILE_SCOPE)
    return result


def fresh_profile(folder, build):
    from audit_tenonos_runtime_oracle import audit as behavior_audit
    from tenonos_runtime_oracle import collect as behavior_collect
    from tenonos_memory_observer import collect as memory_collect
    from tenonos_kvm_reproduce import save, sha
    folder.mkdir()
    name = 'online-candidate'
    reference = folder/'references.json'
    save(reference, {'variants':[{'id':name, 'build':str(build.relative_to(ROOT)),
        'image_sha256':sha(build/'runtime-image'), 'config_sha256':sha(build/'.config')}]})
    behavior = load(ROOT/'registry/tenonos_runtime_oracle_v2.json')
    behavior.update(id='online-resource-behavior-v1', profiles=[name],
        reference_registry=str(reference.relative_to(ROOT)), reference_registry_sha256=sha(reference))
    save(folder/'behavior-protocol.json', behavior)
    behavior_collect(folder/'behavior', SOCKET, HOST, Path(PI), folder/'behavior-protocol.json')
    checked = behavior_audit(ROOT, folder/'behavior', folder/'behavior-protocol.json')
    save(folder/'behavior-audit.json', checked)
    if not all(p['admitted'] for p in checked['profiles']):
        return {'identity':None,'provider':'fresh_profile','behavior_pass':False,'peak_bytes':None,
                'folder':str(folder.relative_to(ROOT)),
                'behavior_evidence':str((folder/'behavior-audit.json').relative_to(ROOT)),
                'fresh_resource_guests':3}
    plan = load(ROOT/'registry/tenonos_joint_ram_rpi4_v1.json')
    plan.update(id='online-resource-memory-v1', profiles=[name],
                reference_registry=str(reference.relative_to(ROOT)))
    registry = folder/'memory-protocol.json'
    save(registry,plan)
    memory_collect(registry,folder/'native',SOCKET,HOST,PI,lifecycle=True,native_threads=True)
    native = str((folder/'native').relative_to(ROOT))
    relative_registry = '../'+str(registry.relative_to(ROOT))
    with memory_context(native,relative_registry) as method:
        method.prepare(folder/'allocated')
        for stage in method.TEMPLATES:
            method.capture(folder/'allocated',stage,SOCKET,HOST)
    result = fresh_memory_audit(folder)
    save(folder/'allocated/allocated-occupancy.json',result)
    return {'identity':None, 'provider':'fresh_profile', 'behavior_pass':True,
            'folder':str(folder.relative_to(ROOT)),
            'peak_bytes':result['profiles'][0]['peak_allocated_occupancy_bytes'],
            'memory_evidence':str((folder/'allocated/allocated-occupancy.json').relative_to(ROOT)),
            'memory_sha256':sha(folder/'allocated/allocated-occupancy.json'),
            'fresh_resource_guests':10}


def replay_fresh_profile(profile):
    from audit_tenonos_runtime_oracle import audit as behavior_audit
    from bind_tenonos_runtime_candidates import build_identity
    from tenonos_kvm_reproduce import sha
    folder=(ROOT/profile['folder']).resolve();folder.relative_to(ROOT/'artifacts/reports')
    ref=load(folder/'references.json')['variants'][0]
    require(build_identity(ROOT/ref['build'])[0]==profile['identity'],'Online profile input identity differs')
    observed=behavior_audit(ROOT,folder/'behavior',folder/'behavior-protocol.json')
    require(observed==load(folder/'behavior-audit.json') and
            all(p['admitted'] for p in observed['profiles'])==profile['behavior_pass'],'Online behavioral replay differs')
    if profile['behavior_pass']:
        measured=fresh_memory_audit(folder)
        require(measured==load(folder/'allocated/allocated-occupancy.json') and
                measured['profiles'][0]['peak_allocated_occupancy_bytes']==profile['peak_bytes'] and
                sha(ROOT/profile['memory_evidence'])==profile['memory_sha256'],'Online complete RAM replay differs')
    else:
        require(profile['peak_bytes'] is None and profile['fresh_resource_guests']==3,'Behavior failure acquired an unsupported RAM value')
    return profile


def prepare(output, workspace):
    from tenonos_kvm_reproduce import save, sha, utc
    from tenonos_config_validation import verify_sources
    from importlib.metadata import version
    require(ROOT == LEON and not output.exists(), 'Prepare on leon in a new directory')
    output.relative_to(ROOT/'artifacts/reports')
    before = time.monotonic()
    registered = catalog()
    plan = load(ROOT/SPEC)
    task_specification = load(ROOT/plan['task_specification'])
    graph_path = ROOT/task_specification['graph']
    verify_sources(load(graph_path),graph_path,workspace)
    bank = load(ROOT/plan['task_bank'])
    require((len(bank['seeds']),bank['maximum_output_tokens'],bank['wall_budget_s']) == (5,1152,1800), 'Original budgets changed')
    output.mkdir()
    for name in ('tenonos_complete_resource.py',):
        shutil.copyfile(ROOT/'tools'/name,output/name)
    save(output/'protocol.json',plan)
    save(output/'catalog.json',registered)
    sources = {str(p.relative_to(ROOT)):sha(p) for p in (ROOT/BASE).iterdir()
               if p.is_file() and p.suffix != '.pyc'}
    names = ['tenonos_complete_resource.py','audit_tenonos_complete_resource.py','measure_tenonos_joint_ram.py','tenonos_size_memory.py',
             'tenonos_memory_observer.py','tenonos_runtime_oracle.py','audit_tenonos_runtime_oracle.py']
    sources.update({'tools/'+n:sha(ROOT/'tools'/n) for n in names})
    sources[plan['task_specification']] = sha(ROOT/plan['task_specification'])
    save(output/'registration.json', {'registered_utc':utc(),'specification_sha256':sha(ROOT/SPEC),
        'protocol_sha256':sha(output/'protocol.json'),'catalog_sha256':sha(output/'catalog.json'),
        'source_sha256':sources,'validation_workspace':str(workspace), 'task_bank_sha256':sha(ROOT/plan['task_bank']),
        'python_version':sys.version,'dependencies':{name:version(name) for name in
            ('lightrag-hku','fastembed','kconfiglib','pyelftools')},
        'setup_catalog_s':time.monotonic()-before,'registered_trials':10,'model_calls_by_preparation':0})
    return {'prepared':True,'registered_trials':10,'premeasured_configurations':len(registered),'model_calls':0}


def source_guard(plan_folder):
    from tenonos_kvm_reproduce import sha
    registration = load(plan_folder/'registration.json')
    require(sha(plan_folder/'protocol.json') == registration['protocol_sha256'] and
            sha(plan_folder/'catalog.json') == registration['catalog_sha256'] and
            sha(ROOT/SPEC) == registration['specification_sha256'], 'Completion protocol changed')
    for name,digest in registration['source_sha256'].items():
        require(sha(ROOT/name) == digest, 'Completion source changed: '+name)
    return registration


def judge_resource(build, plan_folder, destination):
    from bind_tenonos_runtime_candidates import build_identity
    from tenonos_kvm_reproduce import save
    key, _ = build_identity(build)
    registered = load(plan_folder/'catalog.json')
    current = catalog()
    require(current == registered, 'Previously registered resource profiles changed')
    profile = next((p for p in current if p['identity'] == key),None)
    online_file=plan_folder/'online-profiles.json'
    online=load(online_file) if online_file.exists() else []
    if profile is None:
        prior=next((p for p in online if p['identity']==key),None)
        if prior is not None:
            profile=replay_fresh_profile(prior)
    reused = profile is not None
    if not reused:
        profile = fresh_profile(destination.with_name(destination.stem+'-profile'),build)
        profile['identity'] = key
        online.append(profile);save(online_file,online)
    status = ('behavior_failed' if not profile.get('behavior_pass',True) else
              'qualified' if profile['peak_bytes'] <= 8388608 else 'constraint_failed')
    result = {'status':status,
        'identity':key,'profile':profile,'profile_reused':reused,'maximum_bytes':8388608,
        'fresh_resource_guests':0 if reused else profile['fresh_resource_guests'],
        'new_independent_ram_sample':not reused,'energy_inherited':False}
    save(destination,result)
    return result


def completion_rows(campaign, plan_folder):
    report = load(campaign/'results.json');starts=[]
    clocks = [json.loads(line) for line in (plan_folder/'clock.jsonl').read_text().splitlines()]
    require(all(b['s'] >= a['s'] for a,b in zip(clocks,clocks[1:])), 'Clock reversed')
    for record in report['records']:
        starts.append(load(campaign/record['id']/'completion-start.json'))
    rows=[]
    for i,(record,start) in enumerate(zip(report['records'],starts)):
        end_index = starts[i+1]['clock_index']-1 if i+1<len(starts) else len(clocks)-1
        end=clocks[end_index]['s'];begin=clocks[start['clock_index']]['s']
        require(abs(begin-start['s'])<1e-8 and abs(end-begin-record['observed_wall_s'])<1e-8,
                'Task duration differs from actual monotonic endpoints')
        resource_file=campaign/record['id']/'resource.json'
        resource=load(resource_file) if resource_file.exists() else None
        qualified = bool(resource and resource['status']=='qualified')
        native_end=resource['native_end_s'] if resource else None
        if resource:
            require(begin <= native_end <= resource['qualification_end_s'] <= end,'External judge outside completion window')
        rows.append({'id':record['id'],'method':record['method'],'native_pass':record['end_to_end_pass'],
            'full_pass':record['end_to_end_pass'] and qualified,'failed_or_completed_wall_s':end-begin,
            'successful_completion_s':end-begin if record['end_to_end_pass'] and qualified else None,
            'external_qualification_s':resource['qualification_end_s']-native_end if resource else 0,
            'resource_profile_reused':resource.get('profile_reused') if resource else None,
            'resource_status':resource['status'] if resource else 'not reached',
            'fresh_resource_guests':resource.get('fresh_resource_guests',0) if resource else 0})
    return rows


def run(plan_folder,campaign):
    import run_tenonos_paper_tasks as runner
    from run_tenonos_energy import host_state,governor
    from tenonos_kvm_reproduce import save,utc
    registration=source_guard(plan_folder);plan=load(plan_folder/'protocol.json')
    require(not campaign.exists() and not (plan_folder/'clock.jsonl').exists(),'Do not restart an existing campaign')
    require(shutil.disk_usage(ROOT).free >= 192*1024**2,'Insufficient persistent space before new calls')
    ssh=['ssh','-S',SOCKET,'-o','BatchMode=yes',HOST]
    initial=host_state(ssh)
    require(initial['serial']==['10000000c1b4a936'] and initial['throttled']=='throttled=0x0' and not initial['qemu_running'],
            'Wrong, busy or throttled Pi')
    execution={'started_utc':utc(),'campaign':str(campaign.relative_to(ROOT)),
        'initial_host':initial,'status':'running','resource_feedback_to_generator':False,
        'clock_implementation':time.get_clock_info('monotonic').implementation,
        'clock_resolution_s':time.get_clock_info('monotonic').resolution,
        'leon_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    save(plan_folder/'execution.json',execution)
    calls=[];original_generate=runner.generate;original_evaluate=runner.evaluate_pi;original_time=runner.time
    with (plan_folder/'clock.jsonl').open('x') as clock_file:
        def tick():
            value=time.monotonic();row={'index':len(calls),'s':value};calls.append(row)
            clock_file.write(json.dumps(row)+'\n');clock_file.flush()
            return value
        def generate(*args,**kwargs):
            folder=Path(args[4]).parent
            save(folder/'completion-start.json',{'s':calls[-1]['s'],'clock_index':calls[-1]['index']})
            try:
                source_guard(plan_folder)
            except ValueError as error:
                raise ConnectionError('Experimental source/protocol changed; stop further requests') from error
            return original_generate(*args,**kwargs)
        def evaluate(folder,*args,**kwargs):
            checked=original_evaluate(folder,*args,**kwargs);native_end=time.monotonic()
            if all(checked[k] for k in ('generated','built','booted','functional','constraints')):
                try:
                    result=judge_resource(folder/'evaluation/build',plan_folder,folder/'resource.json')
                except Exception as error:
                    save(folder/'resource.json',{'status':'infrastructure_failed','error':repr(error),
                        'native_end_s':native_end,'qualification_end_s':time.monotonic()})
                    raise ConnectionError('External measurement failed; preserve evidence and stop requests') from error
            else:
                result={'status':'not required after native rejection','fresh_resource_guests':0}
            result.update(native_end_s=native_end,qualification_end_s=time.monotonic())
            save(folder/'resource.json',result)
            return checked
        runner.time=SimpleNamespace(monotonic=tick);runner.generate=generate;runner.evaluate_pi=evaluate
        failure=None
        try:
            governor(ssh,'performance')
            runner.run(ROOT/plan['task_bank'],Path(registration['validation_workspace']),
                ROOT/load(ROOT/'registry/tenonos_joint_constraints_v1.json')['graph'],
                ROOT/load(ROOT/'registry/tenonos_joint_constraints_v1.json')['index'],campaign,SOCKET,HOST,PI)
        except BaseException as error:
            failure=repr(error)
            raise
        finally:
            runner.time=original_time;runner.generate=original_generate;runner.evaluate_pi=original_evaluate
            governor(ssh,initial['governor']);after=host_state(ssh)
            execution.update(status='failed' if failure else 'complete',error=failure,ended_utc=utc(),
                host_after_restore=after,governor_restored=initial['governor']==after['governor'])
            save(plan_folder/'execution.json',execution)
            if failure and (campaign/'results.json').exists():
                save(campaign/'complete-results.json',{'status':'incomplete',
                    'rows':completion_rows(campaign,plan_folder),'scope':plan['scope']})
    result={'status':'complete','rows':completion_rows(campaign,plan_folder),'scope':plan['scope']}
    save(campaign/'complete-results.json',result)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','run'))
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--workspace',type=Path)
    parser.add_argument('--campaign',type=Path)
    args=parser.parse_args()
    require(ROOT==LEON,'Experiments remain on leon')
    sys.path.insert(0,str(ROOT/BASE))
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=prepare(args.plan.resolve(),args.workspace.resolve()) if args.action=='prepare' else run(args.plan.resolve(),args.campaign.resolve())
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}),flush=True)
