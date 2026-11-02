#!/usr/bin/env python3
"""Add prospective resource admission to the unchanged state-linked Tenon runner."""
import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
LEON=Path('/home/reviewer/esp32-pilot/audit-workspace')
SPEC='registry/tenonos_resource_histories_v1.json'
SOCKET='/tmp/iotos-pi-energy.sock'
HOST='pi@192.168.31.76'
PI='/home/pi/tenonos-benchmark-v1'


def require(value,message):
    if not value:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def task_round(base,parent,graph,feedback,index,original,spec):
    task=original(base,parent,graph,feedback,index)
    requirement=spec['rounds'][index-1]
    tlsf,buddy='LIBUKBOOT_INITTLSF','LIBUKBOOT_INITBBUDDY'
    task['required_options'].pop(tlsf,None);task['required_options'].pop(buddy,None)
    if requirement['required_allocator']=='buddy':
        task['required_options'].update({buddy:'y',tlsf:'n'})
    task['candidate_controls']=list(dict.fromkeys(task['candidate_controls']+[spec['additional_public_control']]))
    task['maximum_image_bytes']=spec['maximum_image_bytes']
    task['external_resource_requirements']={'metric':'peak allocated guest RAM occupancy',
        'maximum_bytes':requirement['maximum_ram_bytes'],'observer_included':True}
    task['target_allocator_option']=buddy if requirement['required_allocator']=='buddy' else None
    task['objective']=(
        ('Change the retained runtime allocator to native binary buddy. ' if index==1 else
         'Reduce the retained runtime allocation capacity to meet the new RAM limit. No particular allocator is required. ')+
        'Keep priority scheduling, same-priority preemption, the periodic 1000-Hz tick, optimization and all unrelated options. '
        'All six original RTOS cases and external behavioral checks must pass. '
        'Peak allocated guest RAM, including its matched observer, must not exceed '+str(requirement['maximum_ram_bytes'])+
        ' bytes; the image must not exceed '+str(spec['maximum_image_bytes'])+' bytes. '
        'Only change the permitted allocator options; do not change application or adapter source. '
        'Prior configuration-check feedback: '+json.dumps(feedback,sort_keys=True))
    return task


def catalog():
    from audit_tenonos_allocated_ram import audit as memory_audit
    from audit_tenonos_runtime_oracle import audit as behavior_audit
    from audit_tenonos_tasks import configuration
    from bind_tenonos_runtime_candidates import build_identity,identity
    from audit_tenonos_policy_sequence import guest_checks
    from tenonos_kvm_reproduce import sha
    spec=load(ROOT/SPEC);reports=ROOT/'artifacts/reports'
    memory=memory_audit(ROOT);memory_path=reports/'tenonos-allocated-occupancy-rpi4-v1.json'
    require(memory==load(memory_path),'Complete reference RAM changed')
    behavior_folder=reports/'tenonos-runtime-oracle-rpi4-v6'
    behavior=behavior_audit(ROOT,behavior_folder)
    require(behavior==load(behavior_folder/'audit.json'),'Behavioral reference changed')
    behavior_keys=set()
    for p in behavior['profiles']:
        folder=behavior_folder/p['profile'];proof=load(folder/'source-proof.json')
        if p['admitted']:
            behavior_keys.add(identity(configuration(folder/'input.config'),proof['identity'],sha(folder/'build/compiler.stdout')))
    rows=[]
    for p in memory['profiles']:
        name=p['profile'];native=reports/'tenonos-native-threads-rpi4-v2'/name
        proof=load(native/'source-proof.json')
        key=identity(configuration(native/'input.config'),proof['identity'],sha(native/'build/compiler.stdout'))
        build=ROOT/spec['reference_builds'][name];actual,result=build_identity(build)
        require(actual==key and key in behavior_keys and not proof['test_bodies_changed'],'Reference binding differs')
        require(guest_checks(build.parent/'boots',result['image_sha256'])[1],'Reference original outputs fail')
        require((build/'runtime-image').stat().st_size<=spec['maximum_image_bytes'],'Infeasible image limit')
        rows.append({'identity':key,'profile':name,'provider':'premeasured','peak_bytes':p['peak_allocated_occupancy_bytes'],
            'behavior_pass':True,'build':spec['reference_builds'][name],
            'memory_evidence':str(memory_path.relative_to(ROOT)),'memory_sha256':sha(memory_path),
            'behavior_evidence':str((behavior_folder/'audit.json').relative_to(ROOT)),
            'behavior_sha256':sha(behavior_folder/'audit.json')})
    by_name={r['profile']:r for r in rows}
    require(set(by_name)=={'initial-tlsf','accepted-buddy','accepted-tlsf'},'Missing feasible reference')
    require(by_name['accepted-buddy']['peak_bytes']<=spec['rounds'][0]['maximum_ram_bytes'] and
            by_name['accepted-tlsf']['peak_bytes']<=spec['rounds'][1]['maximum_ram_bytes']<by_name['initial-tlsf']['peak_bytes'],
            'Prospective constraints do not have the declared witnesses')
    return rows


def source_guard(plan):
    from tenonos_kvm_reproduce import sha
    registration=load(plan/'registration.json')
    for name,digest in registration['sources'].items():
        require(sha(ROOT/name)==digest,'Registered resource-history source changed: '+name)
    require(sha(ROOT/SPEC)==registration['specification_sha256'] and
            sha(plan/'catalog.json')==registration['catalog_sha256'] and
            sha(plan/'protocol.json')==registration['protocol_sha256'],'Registered resource protocol changed')
    return registration


def prepare(plan):
    from tenonos_kvm_reproduce import sha,save,utc
    from tenonos_config_validation import verify_sources
    spec=load(ROOT/SPEC);require(ROOT==LEON and not plan.exists(),'Prepare a new plan on leon')
    plan.relative_to(ROOT/'artifacts/reports')
    before=time.monotonic();known=catalog()
    graph=load(ROOT/spec['graph_specification'])
    workspace=Path('/home/reviewer/esp32-pilot/tenonos-reproduction-v1')
    verify_sources(load(ROOT/graph['graph']),ROOT/graph['graph'],workspace)
    require(any(n['name']==spec['additional_public_control'] for n in load(ROOT/graph['graph'])['nodes']),
            'Public allocator metadata control is absent')
    plan.mkdir();pipeline=plan/'pipeline';pipeline.mkdir()
    backend=ROOT/spec['backend_pipeline'];backend_proof=load(backend/'source-variant.json')
    history=ROOT/spec['history_pipeline'];history_proof=load(history/'source-variant.json')
    origins={}
    for name,digest in backend_proof['variant_sha256'].items():
        require(sha(backend/name)==digest,'Qualified numeric backend changed')
        shutil.copyfile(backend/name,pipeline/name);origins[name]={'path':str((backend/name).relative_to(ROOT)),'sha256':digest}
    for name in ('run_tenonos_policy_sequence.py','audit_tenonos_policy_sequence.py'):
        digest=history_proof['variant_sha256'][name]
        require(sha(history/name)==digest,'Existing state-linked runner changed')
        shutil.copyfile(history/name,pipeline/name);origins[name]={'path':str((history/name).relative_to(ROOT)),'sha256':digest}
    protocol=load(ROOT/spec['base_protocol']);protocol.update(id=spec['id'],resource_specification=SPEC)
    save(plan/'protocol.json',protocol);save(plan/'catalog.json',known);save(plan/'pipeline-origins.json',origins)
    files=[p for p in pipeline.iterdir() if p.is_file()]+[ROOT/'tools'/n for n in
        ('tenonos_resource_histories.py','audit_tenonos_resource_histories.py','tenonos_complete_resource.py',
         'measure_tenonos_joint_ram.py','tenonos_size_memory.py','tenonos_memory_observer.py')]
    save(plan/'registration.json',{'registered_utc':utc(),'specification_sha256':sha(ROOT/SPEC),
        'protocol_sha256':sha(plan/'protocol.json'),'catalog_sha256':sha(plan/'catalog.json'),
        'sources':{str(p.relative_to(ROOT)):sha(p) for p in files},'workspace':str(workspace),
        'graph':graph['graph'],'index':graph['index'],'graph_sha256':sha(ROOT/graph['graph']),
        'index_sha256':sha(ROOT/graph['index']/'run.json'),'setup_catalog_s':time.monotonic()-before,
        'registered_histories':6,'registered_rounds':12,'model_calls_by_preparation':0})
    return {'prepared':True,'histories':6,'rounds':12,'feasible_profiles':len(known),'model_calls':0}


def bootstrap(plan):
    sys.path.insert(0,str(plan/'pipeline'))


def judge_resource(build,plan,destination,maximum):
    from bind_tenonos_runtime_candidates import build_identity
    from tenonos_complete_resource import fresh_profile,replay_fresh_profile
    from tenonos_kvm_reproduce import save
    key,_=build_identity(build);known=catalog()
    require(known==load(plan/'catalog.json'),'Prepared resource catalog changed')
    online=load(plan/'online-profiles.json') if (plan/'online-profiles.json').exists() else []
    profile=next((r for r in known+online if r['identity']==key),None);reused=profile is not None
    if profile is None:
        profile=fresh_profile(destination.parent/'new-resource-profile',build);profile['identity']=key
        online.append(profile);save(plan/'online-profiles.json',online)
    if profile['provider']=='fresh_profile':
        replay_fresh_profile(profile)
    status=('behavior_failed' if not profile['behavior_pass'] else
            'qualified' if profile['peak_bytes']<=maximum else 'constraint_failed')
    return {'identity':key,'profile':profile,'profile_reused':reused,'maximum_bytes':maximum,'status':status,
        'fresh_resource_guests':0 if reused else profile['fresh_resource_guests'],'energy_inherited':False}


def run(plan,campaign):
    bootstrap(plan)
    import run_tenonos_policy_sequence as runner
    from run_tenonos_energy import host_state,governor
    from tenonos_kvm_reproduce import save,utc
    registration=source_guard(plan);spec=load(ROOT/SPEC)
    require(not campaign.exists() and not (plan/'clock.jsonl').exists(),'Inspect existing work, never restart it')
    require(shutil.disk_usage(ROOT).free>=192*1024**2,'Insufficient persistent space')
    ssh=['ssh','-S',SOCKET,'-o','BatchMode=yes',HOST];initial=host_state(ssh)
    require(initial['serial']==['10000000c1b4a936'] and initial['throttled']=='throttled=0x0' and not initial['qemu_running'],
            'Wrong, throttled or busy Pi')
    originals=runner.round_task,runner.generate,runner.evaluate_pi,runner.time
    ticks=[];start={};execution={'started_utc':utc(),'status':'running','initial_host':initial,
        'leon_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    save(plan/'execution.json',execution)
    with (plan/'clock.jsonl').open('x') as stream:
        def tick():
            row={'index':len(ticks),'s':time.monotonic()};ticks.append(row)
            stream.write(json.dumps(row)+'\n');stream.flush();return row['s']
        def task(*args):
            start.update(ticks[-1]);return task_round(*args,originals[0],spec)
        def generate(*args,**kwargs):
            source_guard(plan);folder=Path(args[0]).parent
            save(folder/'completion-start.json',dict(start));return originals[1](*args,**kwargs)
        def evaluate(folder,*args,**kwargs):
            native=originals[2](folder,*args,**kwargs);save(folder/'native-verdict.json',native)
            result={'status':'not reached','fresh_resource_guests':0};before=time.monotonic()
            if all(native[k] for k in ('generated','built','booted','functional','constraints')):
                maximum=load(folder/'task.json')['external_resource_requirements']['maximum_bytes']
                try:
                    result=judge_resource(folder/'evaluation/build',plan,folder/'resource.json',maximum)
                except Exception as error:
                    save(folder/'resource.json',{'status':'infrastructure_failed','error':repr(error)})
                    raise ConnectionError('Resource infrastructure failed; stop the registered history') from error
            result.update(native_end_s=before,qualification_end_s=time.monotonic())
            save(folder/'resource.json',result);checked=dict(native)
            if result['status']!='not reached':
                checked['functional']=native['functional'] and result['profile']['behavior_pass']
                checked['constraints']=native['constraints'] and result['status']=='qualified'
            return checked
        runner.round_task,runner.generate,runner.evaluate_pi,runner.time=task,generate,evaluate,SimpleNamespace(monotonic=tick)
        error=None
        try:
            governor(ssh,'performance')
            runner.run(plan/'protocol.json',Path(registration['workspace']),ROOT/registration['graph'],
                ROOT/registration['index'],campaign,SOCKET,HOST,PI)
        except BaseException as failure:
            error=repr(failure);raise
        finally:
            runner.round_task,runner.generate,runner.evaluate_pi,runner.time=originals
            governor(ssh,initial['governor']);after=host_state(ssh)
            execution.update(status='failed' if error else 'complete',error=error,ended_utc=utc(),
                host_after_restore=after,governor_restored=after['governor']==initial['governor'])
            save(plan/'execution.json',execution)
    return {'status':'complete','histories':6,'rounds':12}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','run'))
    parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--campaign',type=Path)
    args=parser.parse_args();require(ROOT==LEON,'Real evidence stays on leon')
    with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=prepare(args.plan.resolve()) if args.action=='prepare' else run(args.plan.resolve(),args.campaign.resolve())
    print(json.dumps(result),flush=True)
