#!/usr/bin/env python3
"""Replay matched original-suite intervals and lifecycle-observer image identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

from audit_tenonos_tasks import configuration,require
from audit_tenonos_memory import writable_image,MAIN,RENAMED
from audit_tenonos_memory_lifecycle import linked_image,replay
from tenonos_kvm_reproduce import sha,original_results


def interval(text):
    rows=re.findall(r'(?m)^IOTOS_SUITECOST start=(\d+) end=(\d+) hz=(\d+) after_hz=(\d+) result=(-?\d+)\r?$',text)
    require(len(rows)==1,'Missing/duplicate original-suite interval')
    start,end,hz,after,status=map(int,rows[0])
    require(0<start<end and hz==after and 1000000<=hz<=1000000000 and status==0,'Invalid suite interval/frequency')
    require(text.index('RST: task switch benchmark')<text.index('IOTOS_SUITECOST '),'Interval record precedes original suite')
    return {'start':start,'end':end,'frequency_hz':hz,'elapsed_s':(end-start)/hz}


def image_code(elf_path,image_path):
    from elftools.elf.elffile import ELFFile
    with elf_path.open('rb') as stream:
        elf=ELFFile(stream);require(elf['e_machine']=='EM_AARCH64','Wrong architecture')
        table=elf.get_section_by_name('.symtab')
        def body(name):
            entries=table.get_symbol_by_name(name);require(entries is not None and len(entries)==1,'Missing/ambiguous symbol '+name)
            s=entries[0];section=elf.get_section(s['st_shndx']);offset=s['st_value']-section['sh_addr']
            return s['st_value'],section.data()[offset:offset+s['st_size']]
        pc,raw=body('iotos_original_main');flat=image_path.read_bytes();offset=flat.find(raw)
        require(len(raw)>=32 and offset>=0 and flat.find(raw,offset+1)==-1,'Main does not uniquely bind ELF to flat image')
        base=pc-offset;count=0
        for s in table.iter_symbols():
            if s['st_info']['type']!='STT_FUNC' or not s['st_size'] or not isinstance(s['st_shndx'],int):continue
            section=elf.get_section(s['st_shndx']);offset=s['st_value']-section['sh_addr'];raw=section.data()[offset:offset+s['st_size']]
            require(s['st_value']>=base and flat[s['st_value']-base:s['st_value']-base+len(raw)]==raw,'Function/image mismatch '+s.name)
            count+=1
        def targets(name):
            pc,raw=body(name);out=set()
            for i in range(0,len(raw)-3,4):
                word=int.from_bytes(raw[i:i+4],'little')
                if word&0x7c000000==0x14000000:
                    delta=word&0x3ffffff
                    if delta&(1<<25):delta-=1<<26
                    out.add(pc+i+4*delta)
            return out
        address,raw=body('__wrap_iotos_original_main')
        words=[int.from_bytes(raw[i:i+4],'little') for i in range(0,len(raw)-3,4)]
        require(sum(w&0xffffffe0==0xd53be040 for w in words)==2 and
                sum(w&0xffffffe0==0xd53be000 for w in words)==2 and words.count(0xd5033fdf)==2,
                'Architectural counter/frequency reads or barriers differ')
        require(address in targets('main') and body('iotos_original_main')[0] in targets('__wrap_iotos_original_main'),
                'Timing interval does not wrap the original suite')
        return {'functions_bound_to_image':count,'cntvct_reads':2,'cntfrq_reads':2,'isb_barriers':2}


def audit(root,folder):
    plan=json.loads((folder/'protocol.json').read_text());state=json.loads((folder/'campaign.json').read_text())
    refs=json.loads((folder/'references.json').read_text())
    require(plan==json.loads((root/'registry/tenonos_memory_impact_rpi4_v1.json').read_text()) and
        state['status']=='complete' and state['completed']==plan['profiles'] and state['protocol_sha256']==sha(folder/'protocol.json') and
        state['model_calls']==0 and state['governor_restored'] and
        state['initial_host']['serial']==['10000000c1b4a936'] and
        state['initial_host']['governor']==state['host_after_restore']['governor'],'Incomplete or different impact experiment')
    for n,h in state['source_sha256'].items():require(sha(folder/'helpers'/n)==h,'Frozen helper changed')
    manifest=json.loads((root/'artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark/manifest.json').read_text())
    original={v['path']:v for v in manifest['files']}
    require(manifest['commit']=='0b71b8e722acfab4733eb99b07b67fbe8472c31d' and not manifest['truncated'],'Different original suite')
    profiles=[];frequencies=set()
    for name in plan['profiles']:
        p=folder/name;ref=next(v for v in refs['variants'] if v['id']==name)
        require(sha(p/'input.config')==ref['config_sha256'],'Reference changed')
        transfer=json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode']==0,'Failed or unverified runtime transfer')
        for rel,h in transfer['files'].items():
            file=(p/rel).resolve();file.relative_to(p.resolve());require(sha(file)==h,'Transferred bytes changed')
        for which in ('host-before.json','host-after.json'):
            host=json.loads((p/which).read_text());require(host['governor']=='performance' and
                host['throttled']=='throttled=0x0' and not host['qemu_running'],'Host envelope differs')
        mode_results={}
        for mode in ('baseline','observer'):
            d=p/mode;source=d/'source/app-rtos-benchmark-memory';proof=json.loads((d/'source-proof.json').read_text())
            require(proof['mode']==mode and set(proof['original_app_sha256'])==set(original),'Source coverage differs')
            patched=proof['identity']['rtos_adapter_patch']['files']
            reference_build=root/ref['build']
            expected_identity=json.loads((reference_build/'build-result.json').read_text())['source_commits']
            require(proof['identity']==expected_identity and sha(d/'build/compiler.stdout')==sha(reference_build/'compiler.stdout'),
                    'Reference source/adapter/compiler-version differs')
            for rel in original:
                raw=(source/rel).read_bytes();require(sha(source/rel)==proof['observed_app_sha256'][rel],'Compiled app source changed')
                if rel=='main.c':require(raw.count(RENAMED)==1,'Original entry changed');raw=raw.replace(RENAMED,MAIN)
                if rel=='Makefile.uk':
                    addition=proof['makefile_addition'].encode();require(raw.endswith(addition),'Makefile binding changed');raw=raw[:-len(addition)]
                require(hashlib.sha256(raw).hexdigest()==proof['original_app_sha256'][rel],'Original body modified')
                if rel in patched:require(hashlib.sha256(raw).hexdigest()==patched[rel],'ABI adapter changed')
                else:require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==original[rel]['sha'],'Wrong original Git blob')
            require(sha(source/'iotos_timing.c')==sha(folder/'helpers/tenonos_memory_impact.c'),'Timing source differs between arms')
            if mode=='observer':require(sha(source/'iotos_memory.c')==sha(folder/'helpers/tenonos_memory_lifecycle.c'),'Lifecycle observer changed')
            else:require((source/'iotos_memory.c').read_bytes()==b'extern int iotos_original_main(int, char **);\nint main(int n, char **v) { return iotos_original_main(n, v); }\n','Baseline contains extra instrumentation')
            for n,h in proof['native_statistics'].items():require(sha(d/'source'/n)==h,'Native statistics source changed')
            if mode=='observer' and proof['tlsf']:
                from tenonos_memory_observer import unrepaired_tlsf
                require(unrepaired_tlsf((d/'source/tlsf-compiled.c').read_bytes())==
                        (d/'source/tlsf-before-statistics-fix.c').read_bytes(),'More than native statistics repair changed')
            before,after=configuration(p/'input.config'),configuration(d/'build/.config')
            differences={k:[before.get(k,'n'),after.get(k,'n')] for k in set(before)|set(after) if before.get(k,'n')!=after.get(k,'n')}
            expected={'UK_APP'}|({'LIBUKALLOC_IFSTATS'} if mode=='observer' and not proof['tlsf'] else set())
            require(set(differences)==expected and differences=={k.removeprefix('CONFIG_'):v for k,v in proof['config_changes'].items()},'Runtime policy changed')
            b=d/'build';built=json.loads((b/'build-result.json').read_text())
            require(sha(b/'runtime-image')==built['image_sha256'] and sha(b/'.config')==built['config_sha256'] and
                    sha(b/'linked-symbols.elf')==built['elf_sha256'] and sha(b/'compiler.stdout')==built['compiler_version_stdout_sha256'],
                    'Build/image/config/compiler identity changed')
            linked=image_code(b/'linked-symbols.elf',b/'runtime-image')
            if mode=='observer':linked_image(b/'linked-symbols.elf',b/'runtime-image',proof['tlsf'])
            runs=[]
            for i in (1,2,3):
                f=p/('P%d-%s'%(i,mode));step=json.loads((f/'guest.json').read_text())
                require(step['state']=='finished' and sha(f/'guest.stdout')==step['stdout_sha256'] and sha(f/'guest.stderr')==step['stderr_sha256'],'Raw guest record changed')
                argv=step['argv'];require(all(argv[argv.index(k)+1]==v for k,v in (('-accel','kvm'),('-m','128M'),('-smp','1'))) and
                    argv[-1].endswith('/'+mode+'/build/runtime-image'),'Guest envelope/image differs')
                text=(f/'guest.stdout').read_text();out=original_results(text.encode(),(f/'guest.stderr').read_bytes(),step['returncode'])
                require(out['original_output_complete'],'Original output incomplete')
                timing=interval(text);frequencies.add(timing['frequency_hz'])
                require(text.rindex('R-Rhealstone: ')<text.index('IOTOS_SUITECOST ') and
                        timing['elapsed_s']<step['elapsed_seconds'],'Suite interval includes invalid boundaries')
                if mode=='observer':require(replay(text)==json.loads((f/'lifecycle.json').read_text()),'Lifecycle replay differs')
                runs.append({'pair':i,**timing,'original_printed_values':out['original_printed_values']})
            mode_results[mode]={'runs':runs,'static_writable':writable_image(b/'linked-symbols.elf'),
                'image_sha256':built['image_sha256'],'linked_timing':linked}
        ratios=[b['elapsed_s']/a['elapsed_s'] for a,b in zip(mode_results['baseline']['runs'],mode_results['observer']['runs'])]
        chronological=[json.loads((p/('P%d-%s'%(i,m))/'guest.json').read_text()) for i,pair in enumerate(plan['pairs'],1) for m in pair]
        require(all(a['finished_utc']<=b['started_utc'] for a,b in zip(chronological,chronological[1:])),
                'Counterbalanced pair order differs')
        metrics=list(mode_results['baseline']['runs'][0]['original_printed_values'])
        native_ratios={metric:[b['original_printed_values'][metric][0]['value']/a['original_printed_values'][metric][0]['value']
            if a['original_printed_values'][metric][0]['value']>0 else None
            for a,b in zip(mode_results['baseline']['runs'],mode_results['observer']['runs'])] for metric in metrics}
        profiles.append({'profile':name,'pairs':3,'modes':mode_results,'elapsed_observer_over_baseline':ratios,
            'median_ratio':statistics.median(ratios),'range':[min(ratios),max(ratios)],
            'original_counter_ratios_diagnostic_only':native_ratios})
    require(len(frequencies)==1,'Counter frequency changed across guests')
    return {'audit':'pass','profiles':profiles,'fresh_guests':18,'native_builds':6,'counter_frequency_hz':next(iter(frequencies)),
        'model_calls':0,'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'energy_measured':False,
        'campaign_sha256':sha(folder/'campaign.json'),'auditor_sha256':sha(Path(__file__)),
        'scope':plan['interpretation'],'timing_boundary':plan['timing']}


def bind_histories(root):
    from bind_tenonos_runtime_candidates import build_identity,identity
    from audit_tenonos_runtime_oracle import audit as behavior_audit
    from audit_tenonos_memory_lifecycle import audit as life_audit
    from audit_tenonos_scale_validation import audit as scale_audit
    from audit_tenonos_build_energy import audit as energy_audit
    from tenonos_choice_adapter import audit as history_audit
    parent=root/'artifacts/reports/tenonos-author-engine-20261027-v1'
    current=history_audit(root,parent/'policy-choice-pipeline-v1',parent/'policy-choice-campaign-v1',parent/'policy-choice-native-audit-v1.json',None)
    require(current==json.loads((parent/'policy-choice-audit-v1.json').read_text()),'Repaired history audit changed')
    reports={};profiles={}
    experiments=(('behavior','tenonos-runtime-oracle-rpi4-v6',behavior_audit),
        ('lifecycle','tenonos-native-memory-lifecycle-v2',life_audit),
        ('scale','tenonos-rpi4-scale-validation-v2',lambda r,p:scale_audit(p,r)))
    for kind,name,check in experiments:
        folder=root/'artifacts/reports'/name;value=check(root,folder)
        require(value==json.loads((folder/'audit.json').read_text()),'Existing '+kind+' audit changed')
        reports[kind]=sha(folder/'audit.json');profiles[kind]={}
        for row in value['profiles']:
            p=folder/row['profile'];proof=json.loads((p/'source-proof.json').read_text())
            source=proof.get('identity',proof.get('upstream_and_adapter_identity'))
            key=identity(configuration(p/'input.config'),source,sha(p/'build/compiler.stdout'))
            require(key not in profiles[kind],'Ambiguous reused configuration')
            profiles[kind][key]=row['profile']
    energy=root/'artifacts/reports/tenonos-rpi4-build-energy-v1';value=energy_audit(root,energy)
    require(value==json.loads((energy/'audit.json').read_text()),'Existing energy audit changed')
    energy_profiles={build_identity(root/v['build'])[0]:v['id'] for v in json.loads((energy/'references.json').read_text())['variants']}
    measured_images={json.loads((energy/v['id']/'runtime/build/build-result.json').read_text())['image_sha256']
                     for v in json.loads((energy/'campaign.json').read_text())['trials']}
    rows=[]
    for history in json.loads((parent/'policy-choice-campaign-v1/campaign.json').read_text())['histories']:
        for step in history['rounds']:
            for role in ('parent_build','retained_build'):
                key,build=build_identity(root/step[role])
                require(all(key in known for known in profiles.values()) and key in energy_profiles,'Unmeasured configuration requires actual collection')
                rows.append({'history':history['id'],'round':step['round'],'role':role,'build':step[role],
                    'identity':key,'config_sha256':build['config_sha256'],'image_sha256':build['image_sha256'],
                    **{kind:known[key] for kind,known in profiles.items()},'energy_reference_profile':energy_profiles[key],
                    'exact_image_has_synchronized_energy':build['image_sha256'] in measured_images})
    require(len(rows)==24 and len({r['identity'] for r in rows})==3,'Repaired-state coverage differs')
    return {'audit':'pass','state_aliases':24,'distinct_configurations':3,'aliases':rows,
        'reused_behavior_guests':9,'reused_lifecycle_guests':9,'reused_scale_guests':9,
        'energy_reference_profiles':3,'candidate_energy_reassigned':False,'new_model_calls':0,'new_guest_boots':0,
        'source_audit_sha256':{**reports,'energy':sha(energy/'audit.json'),'history':sha(parent/'policy-choice-audit-v1.json')},
        'boundary':'Configuration/source/adapter/compiler-version matching, not exact-image timing or energy remeasurement. Observer and scale aliases are not independent samples. Existing energy is a reference-configuration experiment, not synchronized energy for new candidate images.',
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bind-histories',action='store_true')
    a=p.parse_args();r=Path(__file__).resolve().parents[1]
    if r!=Path('/home/reviewer/esp32-pilot/audit-workspace'):p.error('Audit evidence on leon')
    if not a.bind_histories and a.folder is None:p.error('Audit requires a folder')
    value=bind_histories(r) if a.bind_histories else audit(r,a.folder.resolve())
    a.output.write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({**{k:v for k,v in value.items() if k not in ('profiles','aliases')},'profiles':[
        {'profile':v['profile'],'median_ratio':v['median_ratio'],'range':v['range']} for v in value.get('profiles',[])]}))
