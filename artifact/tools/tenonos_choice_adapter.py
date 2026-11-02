#!/usr/bin/env python3
"""Check/fix parent-fragment serialization, without changing generation policy."""
import argparse
import json
from pathlib import Path


def layered_options(inherited, proposed):
    return {**{k:v for k,v in inherited.items() if k not in proposed}, **proposed}


def corrected_source(raw):
    old = b'"CONFIG_" + k + "=" + v + "\\n" for k, v in requested.items()))'
    new = b'"CONFIG_" + k + "=" + v + "\\n" for k, v in [*[(k,v) for k,v in requested.items() if k not in proposed], *proposed.items()]))'
    if raw.count(old)!=1:
        raise ValueError('Expected exactly the original defconfig serializer')
    return raw.replace(old,new)


def differential(root, output):
    import kconfiglib
    from tenonos_orchestrator import kconfig
    from tenonos_config_validation import submitted_options
    from tenonos_kvm_reproduce import sha
    parent = root/'artifacts/reports/tenonos-author-engine-20261027-v1'
    candidate = parent/'policy-budget-campaign-v1/H1-graph/R1/candidate'
    generation = json.loads((candidate/'registration.json').read_text())
    graph_path = parent/'rtos-lib-graph-v3/lib-graph.json'
    if sha(graph_path)!=generation['graph_sha256']:
        raise ValueError('Graph identity differs')
    graph = json.loads(graph_path.read_text()); task = json.loads((candidate/'task.json').read_text())
    proposed, combined = submitted_options(graph,(candidate/'candidate-0.json').read_text(),task)
    output.mkdir(parents=True,exist_ok=False)
    before = {**task['starting_options'], **task['fixed_options']}
    configurations = {
        'historical-flattened': ''.join('CONFIG_%s=%s\n'%x for x in combined.items()),
        'explicit-last': ''.join('CONFIG_%s=%s\n'%x for x in layered_options(combined,proposed).items()),
        'parent-then-fragment': ''.join('CONFIG_%s=%s\n'%x for x in before.items()) +
                                ''.join('CONFIG_%s=%s\n'%x for x in proposed.items())}
    results = {}
    workspace = Path('/home/reviewer/esp32-pilot/tenonos-reproduction-v1')
    for name,text in configurations.items():
        folder = output/name; folder.mkdir(); source = folder/'input.defconfig'; source.write_text(text)
        parsed = kconfig(workspace,task['application'],folder/'kconfig'); parsed.load_config(str(source))
        parsed.write_config(str(folder/'resolved.config'))
        values = {s.name:s.str_value for s in parsed.unique_defined_syms}
        from tenonos_kvm_reproduce import command
        from import_iotos_subjects import config_text
        configured = command(folder, 'native-configure', [
            'timeout', '--kill-after=5', '90', 'make', '-C', workspace/'tenon-c11',
            'A='+str(workspace/'apps'/task['application']), 'L='+str(workspace/'libs'),
            'O='+str(folder/'build'), 'C='+str(folder/'native.config'), 'ARCH=arm64',
            'UK_DEFCONFIG='+str(source), 'defconfig'])
        if configured['returncode']:
            raise RuntimeError('Native configure failed; inspect retained logs')
        native, duplicates = config_text((folder/'native.config').read_text())
        independent, _ = config_text((folder/'resolved.config').read_text())
        environment_symbols = {'CONFIG_HOST_ARCH','CONFIG_TN_FULLVERSION',
                               'CONFIG_UK_CODENAME','CONFIG_UK_FULLVERSION'}
        differences = {n:[independent.get(n),native.get(n)] for n in set(native)|set(independent)
                       if independent.get(n)!=native.get(n)}
        if duplicates or set(differences)-environment_symbols:
            raise ValueError('Native and independent Kconfig parsers differ')
        results[name] = {'input_sha256':sha(source),'resolved_sha256':sha(folder/'resolved.config'),
            'native_config_sha256':sha(folder/'native.config'),'native_policy_parser_agrees':True,
            'parser_environment_differences':differences,
            'allocator':{n:values.get(n,'n') for n in ('LIBUKBOOT_INITBBUDDY','LIBUKBOOT_INITTLSF')},
            'all_resolved_values':values,'warnings':parsed.warnings}
    same = results['explicit-last']['all_resolved_values']==results['parent-then-fragment']['all_resolved_values']
    report = {'scope':'Offline native Kconfig fragment-order differential, not new model/runtime scores',
        'candidate':str(candidate.relative_to(root)),'candidate_sha256':sha(candidate/'candidate-0.json'),
        'task_sha256':sha(candidate/'task.json'),'graph_sha256':sha(graph_path),
        'parser_version':list(kconfiglib.VERSION),'proposed':proposed,'results':results,
        'explicit_last_matches_parent_then_fragment':same,
        'serialization_changes_allocator':results['historical-flattened']['allocator']!=results['explicit-last']['allocator'],
        'model_calls':0,'guest_boots':0}
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def prepare(root, output):
    from tenonos_kvm_reproduce import save, sha, utc
    parent=root/'artifacts/reports/tenonos-author-engine-20261027-v1'
    base=parent/'policy-budget-pipeline-v1'
    proof=json.loads((base/'source-variant.json').read_text())
    differential_path=parent/'choice-order-differential-v3/result.json'
    checked=json.loads(differential_path.read_text())
    if not checked['serialization_changes_allocator'] or not checked['explicit_last_matches_parent_then_fragment']:
        raise ValueError('Native differential must establish the repair first')
    output.resolve().relative_to((root/'artifacts/reports').resolve())
    output.mkdir(parents=True,exist_ok=False)
    before,after={},{}
    for name,expected in proof['variant_sha256'].items():
        source=base/name
        if sha(source)!=expected:
            raise ValueError('Frozen wider-budget pipeline changed')
        raw=source.read_bytes()
        if name=='tenonos_config_validation.py':raw=corrected_source(raw)
        (output/name).write_bytes(raw)
        before[name],after[name]=expected,sha(output/name)
    plan=json.loads((base/'protocol.json').read_text())
    plan.update(id='tenon-paper-policy-explicit-fragment-v1',
        change='Adapter repair only relative to the wider-budget history protocol: serialize explicit fragment entries after inherited options. No generation, retrieval, selection, task, budget or gate changes.',
        adapter_semantics='Native Kconfig parent followed by explicit fragment; inherited choice entries cannot override an explicit new choice. No manually added option or candidate retry.',
        prior_protocol_sha256=sha(base/'protocol.json'))
    save(output/'protocol.json',plan)
    save(output/'source-variant.json',{'prepared_utc':utc(),'protocol_sha256':sha(output/'protocol.json'),
        'base_pipeline':str(base.relative_to(root)),'base_proof_sha256':sha(base/'source-variant.json'),
        'original_sha256':before,'variant_sha256':after,'differential_sha256':sha(differential_path),
        'changed_files':[n for n in before if before[n]!=after[n]],'model_calls':0})
    return {'prepared':str(output.relative_to(root)),'changed_files':['tenonos_config_validation.py'],'model_calls':0}


def audit(root, pipeline, campaign, underlying, output):
    from tenonos_kvm_reproduce import save,sha
    from audit_tenonos_budget_sensitivity import request_limit
    proof=json.loads((pipeline/'source-variant.json').read_text())
    base=root/proof['base_pipeline']
    if sha(base/'source-variant.json')!=proof['base_proof_sha256']:
        raise ValueError('Base source proof changed')
    differential_path=base.parent/'choice-order-differential-v3/result.json'
    if sha(differential_path)!=proof['differential_sha256']:
        raise ValueError('Native differential changed')
    for name,before in proof['original_sha256'].items():
        raw=(base/name).read_bytes()
        if sha(base/name)!=before:raise ValueError('Original source changed')
        if name=='tenonos_config_validation.py':raw=corrected_source(raw)
        if (pipeline/name).read_bytes()!=raw or sha(pipeline/name)!=proof['variant_sha256'][name]:
            raise ValueError('More than serialization changed')
    plan=json.loads((pipeline/'protocol.json').read_text())
    original=json.loads((base/'protocol.json').read_text())
    excluded={'id','change','adapter_semantics','prior_protocol_sha256'}
    if any(plan[k]!=v for k,v in original.items() if k not in excluded):
        raise ValueError('Experimental conditions changed')
    registration=json.loads((campaign/'registration.json').read_text())
    if not proof['prepared_utc']<=registration['registered_utc'] or registration['plan_sha256']!=sha(pipeline/'protocol.json'):
        raise ValueError('Unregistered repair batch')
    value=json.loads(underlying.read_text())
    if value['audit']!='pass' or value['registered_histories']!=6 or value['registered_rounds']!=12:
        raise ValueError('Incomplete raw/native history audit')
    for name,digest in value['evidence_manifest'].items():
        path=(campaign/name).resolve();path.relative_to(campaign.resolve())
        if sha(path)!=digest:raise ValueError('Evidence changed after replay')
    for history in json.loads((campaign/'campaign.json').read_text())['histories']:
        for number in (1,2):
            folder=campaign/history['id']/('R'+str(number))/'candidate'
            used=0
            for call in json.loads((folder/'model-calls.json').read_text()):
                payload=json.loads((folder/(call['stage']+'-request.json')).read_text())
                request_limit(history['method'],call['stage'],payload['max_tokens'],used)
                path=folder/(call['stage']+'-response.json')
                if path.exists():used+=json.loads(path.read_text())['usage']['completion_tokens']
    if value['model_calls']>24 or value['completion_tokens']>13824:
        raise ValueError('Registered batch budget exceeded')
    reanalysis=base.parent/'historical-choice-reanalysis-v1'
    historical=json.loads((reanalysis/'result.json').read_text())
    expected={('H%d-graph'%n,i) for n in (1,2,3) for i in (1,2)}
    if {(v['history'],v['round']) for v in historical['rows']}!=expected or len(historical['rows'])!=6:
        raise ValueError('Historical native reanalysis coverage differs')
    for row in historical['rows']:
        old=base.parent/'policy-budget-campaign-v1'/row['history']/('R'+str(row['round']))/'candidate'
        folder=reanalysis/(row['history'].removesuffix('-graph')+'-R'+str(row['round']))
        validation=json.loads((folder/'validation.json').read_text())
        if row['original_dependency_valid'] or not row['repaired_dependency_valid'] or \
                not validation['dependency_valid'] or sha(old/'candidate-0.json')!=row['candidate_sha256'] or \
                sha(old/'task.json')!=row['task_sha256'] or \
                not sha(folder/'.config')==row['repaired_config_sha256']==validation['native_config_sha256'] or \
                validation['response_sha256']!=row['candidate_sha256'] or validation['task_sha256']!=row['task_sha256']:
            raise ValueError('Historical native fragment reanalysis changed')
    value.pop('evidence_manifest')
    value.update(adapter='Explicit fragment serialized after inherited options',
        source_variant_sha256=sha(pipeline/'source-variant.json'),
        underlying_audit_sha256=sha(underlying),whole_live_ram_peak_bytes=None,
        adapter_auditor_sha256=sha(Path(__file__)),
        historical_reanalysis_sha256=sha(reanalysis/'result.json'),historical_repaired_native_fragments=6,
        aggregate_output_cap=plan['maximum_output_tokens_per_round'],
        graph_stage_caps=plan['graph_stage_token_caps'])
    if output is not None:save(output,value)
    return value


def package(root, output):
    import os
    import subprocess
    import sys
    import tempfile
    import zipfile
    from tenonos_kvm_reproduce import sha,save
    output.relative_to(root/'reproduction')
    parent=root/'artifacts/reports/tenonos-author-engine-20261027-v1'
    pipeline,campaign=parent/'policy-choice-pipeline-v1',parent/'policy-choice-campaign-v1'
    names={p.relative_to(root).as_posix() for p in (root/'tools').glob('*.py')}
    for folder in (pipeline,campaign,parent/'policy-budget-pipeline-v1',parent/'policy-budget-campaign-v1',
                   parent/'historical-choice-reanalysis-v1',
                   parent/'choice-order-differential-v2',parent/'choice-order-differential-v3'):
        names.update(p.relative_to(root).as_posix() for p in folder.rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts)
    for name in ('policy-choice-audit-v1.json','policy-choice-native-audit-v1.json',
                 'public-source-recheck-20261028-v1.json','choice-order-differential-v1.log',
                 'choice-order-differential-v2.log','choice-order-differential-v3.log'):
        names.add((parent/name).relative_to(root).as_posix())
    names.update(('registry/tenonos_tasks_rpi4_v1.json','TENONOS_RPI4_REPRODUCTION.md',
                  'DATA_STORAGE_POLICY.md','paper/sensys2027/iotosbench.tex',
                  'paper/sensys2027/build/iotosbench.pdf','benchmark_esp32.html'))
    manifest={n:sha(root/n) for n in sorted(names)}
    with zipfile.ZipFile(output,'x',zipfile.ZIP_DEFLATED) as stream:
        for name in manifest:stream.write(root/name,arcname=name)
        stream.writestr('increment-manifest.json',json.dumps({'scope':'private fragment-adapter repair and matched history increment','files':manifest},indent=2)+'\n')
    log=output.with_suffix('.replay.log')
    with tempfile.TemporaryDirectory(prefix='tenon-choice-replay-',dir='/dev/shm') as temporary:
        replay=Path(temporary)
        with zipfile.ZipFile(output) as stream:
            for name in stream.namelist():(replay/name).resolve().relative_to(replay.resolve())
            stream.extractall(replay)
        if any(sha(replay/n)!=h for n,h in manifest.items()):raise ValueError('Extracted bytes differ')
        rel=parent.relative_to(root).as_posix()
        code=("import sys,json;from pathlib import Path;r=Path(sys.argv[1]);sys.path.insert(0,str(r/'tools'));"
              "from tenonos_choice_adapter import audit;p=r/sys.argv[2];"
              "v=audit(r,p/'policy-choice-pipeline-v1',p/'policy-choice-campaign-v1',p/'policy-choice-native-audit-v1.json',None);"
              "assert v==json.loads((p/'policy-choice-audit-v1.json').read_text());print('pass')")
        env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'};env['PYTHONDONTWRITEBYTECODE']='1'
        with log.open('x') as stream:
            subprocess.run([sys.executable,'-s','-c',code,str(replay),rel],check=True,env=env,stdout=stream,stderr=subprocess.STDOUT)
        if any(sha(replay/n)!=h or sha(root/n)!=h for n,h in manifest.items()):raise ValueError('Package/source changed')
    receipt={'pass':True,'files':len(manifest),'archive_bytes':output.stat().st_size,
        'archive_sha256':sha(output),'audit_sha256':sha(parent/'policy-choice-audit-v1.json'),
        'isolated_archive_replay_equal':True,'new_model_calls':0,'new_guest_boots':0,
        'boundary':'Scoped private increment; replays captured bytes, serialization-only source binding and prior native/runtime audit. No native toolchain replay inside archive and not external independent reproduction.'}
    save(output.with_suffix('.receipt.json'),receipt)
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--action',choices=('differential','prepare','audit','package'),default='differential')
    for name in ('pipeline','campaign','underlying'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();r=Path(__file__).resolve().parents[1]
    if r!=Path('/home/reviewer/esp32-pilot/audit-workspace'):
        p.error('Run evidence work on leon')
    if a.action=='prepare':value=prepare(r,a.output.resolve())
    elif a.action=='package':value=package(r,a.output.resolve())
    elif a.action=='audit':
        if not all((a.pipeline,a.campaign,a.underlying)):p.error('Audit needs pipeline, campaign and underlying')
        value=audit(r,a.pipeline.resolve(),a.campaign.resolve(),a.underlying.resolve(),a.output.resolve())
    else:value=differential(r,a.output.resolve())
    print(json.dumps({k:v for k,v in value.items() if k not in ('results','histories')},indent=2))
    if 'results' in value:print(json.dumps({k:v['allocator'] for k,v in value['results'].items()}))
