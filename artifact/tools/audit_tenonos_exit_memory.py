#!/usr/bin/env python3
"""Replay native memory bytes through termination, separately from guest stdout."""
import argparse
import copy
import json
from pathlib import Path

from audit_tenonos_memory_lifecycle import require,linked_image
from audit_tenonos_native_threads import replay as native_replay
from tenonos_exit_memory import FIELDS,decode,layout,verify_prefix
from tenonos_kvm_reproduce import original_results,sha


def independent_events(raw):
    require(len(raw)%56==0,'Partial independent native event')
    return [dict(seq=i//56,**{name:int.from_bytes(raw[i+j*8:i+(j+1)*8],'little')
                for j,name in enumerate(FIELDS)}) for i in range(0,len(raw),56)]


def live_allocations(rows):
    live={};allocations=frees=0
    for r in rows:
        p,n=r['p'],r['n']
        if r['op'] in (1,3) and p:
            require(n and all(p+n<=a or a+v<=p for a,v in live.items()),'Independent allocation overlap')
            live[p]=n;allocations+=1
        elif r['op'] in (2,4) and p:
            require(p in live and (r['op']!=4 or live[p]==n),'Independent unmatched native release')
            del live[p];frees+=1
    return {'allocations':allocations,'frees':frees,'live_allocations':len(live),
            'live_requested_extent_bytes':sum(live.values())}


def tail_lifecycle(rows,prefix_count,printed):
    generations=copy.deepcopy(printed['legacy_lifecycle']['allocations'])
    live={g['pointer']:g for g in generations if g['freed'] is None}
    threads=copy.deepcopy(printed['threads']);active={t['thread']:t for t in threads};pending={}
    for r in rows[prefix_count:]:
        op,p,n=r['op'],r['p'],r['n']
        if op in (1,3) and p:
            require(n and all(p+n<=a or a+g['size']<=p for a,g in live.items()),'Tail allocation overlap')
            g={'generation':len(generations),'pointer':p,'size':n,'allocated':r['seq'],'freed':None}
            generations.append(g);live[p]=g
        elif op in (2,4) and p:
            require(p in live and (op!=4 or n==live[p]['size']),'Tail unmatched native free')
            live.pop(p)['freed']=r['seq']
        elif op==33:
            require(p in active and active[p]['phase']==0 and active[p]['release_enter'] is None,
                    'Tail release is not an unreleased startup thread')
            active[p]['release_enter']=r['seq'];pending[p]=active[p]
        elif op==34:
            require(p in pending,'Tail release returned without native entry');t=pending.pop(p)
            require(all(generations[i]['freed'] is not None and t['release_enter']<generations[i]['freed']<r['seq']
                        for i in t['storage']),'Tail native release returned before complete owned frees')
            t['release_return']=r['seq']
        else:
            require(op in (1,2,3,4),'Unexpected post-return native event')
    owned={i for t in threads for i in t['storage']};outstanding=[g for g in generations if g['freed'] is None]
    return {'native_thread_generations':len(threads),'native_threads_reclaimed':sum(t['release_return'] is not None for t in threads),
            'end_live_thread_owned_allocations':sum(g['generation'] in owned for g in outstanding),
            'end_live_other_allocations':sum(g['generation'] not in owned for g in outstanding),
            'pending_startup_releases_at_termination':[{'thread':t['thread'],'kind':t['kind'],
                'main_stack':t['main_stack'],'release_enter':t['release_enter'],
                'still_owned_allocations':sum(generations[i]['freed'] is None for i in t['storage'])} for t in pending.values()]}


def thread_return_target(path):
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        found=elf.get_section_by_name('.symtab').get_symbol_by_name('uk_sched_thread_exit')
        require(found and len(found)==1,'Native thread-return target missing')
        return found[0]['st_value']


def audit(root,folder,registry=None):
    plan=json.loads((folder/'protocol.json').read_text());state=json.loads((folder/'campaign.json').read_text())
    require(plan==json.loads((root/'registry'/(registry or 'tenonos_exit_memory_rpi4_v2.json')).read_text()) and
        state['status']=='complete' and state['completed']==plan['profiles'] and state['governor_restored'] and
        state['protocol_sha256']==sha(folder/'protocol.json') and state['new_builds']==state['model_calls']==0,
        'Incomplete or different exit-memory campaign')
    require(state['host_initial']['serial']==['10000000c1b4a936'] and
        state['host_after_restore']['governor']==state['host_initial']['governor'] and
        not state['host_after_restore']['qemu_running'],'Pi identity/restore differs')
    for n,h in state['source_sha256'].items():require(sha(folder/'helpers'/n)==h,'Frozen exit recorder changed')
    reference=root/plan['reference_campaign'];repair=root/plan['bootinfo_repair']
    require(sha(reference/'audit.json')==state['reference_audit_sha256'] and
            sha(repair/'repair.json')==state['repair_sha256'],'Existing source audit changed')
    from tenonos_bootinfo_abi import audit as repair_audit
    repair_audit(root,repair)
    results=[]
    for name in plan['profiles']:
        p=folder/name;old=reference/name/'build'
        require(sha(p/'linked.elf')==sha(old/'linked-symbols.elf') and sha(p/'input.config')==sha(old/'.config') and
            sha(p/'runtime-image')==sha(repair/name/'runtime-image'),'Existing code/config/image changed')
        transfer=json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode']==0 and
            all(sha(p/n)==h for n,h in transfer['files'].items()),'Returned exit evidence changed')
        tlsf='CONFIG_LIBTLSF=y\n' in (p/'input.config').read_text()
        compiled=layout(p/'linked.elf',tlsf);setup=json.loads((p/'gdb-input.json').read_text())
        require(compiled==json.loads((p/'exit-layout.json').read_text())==setup['exit_layout'],'Compiled observer ABI differs')
        debug=json.loads((p/'debug-result.json').read_text());stages=debug['stages']
        require(debug['pass'] and [s['stage'] for s in stages]==plan['snapshots'] and
            debug['inferior_function_calls']==debug['target_code_writes']==0 and debug['observer_data_writes']==1 and
            debug['native_activity_during_disabled_gap'] is False,'Exit control coverage differs')
        entry,dump,returned,final=stages
        require(entry['pc']==compiled['functions']['main']['address'] and
            dump['pc']==compiled['disable_transition']['pc'] and returned['pc']==entry['x30'] and returned['x0']==0 and
            final['pc']==compiled['functions']['ukplat_terminate']['address'],'Native stage/return identity differs')
        transition=compiled['disable_transition'];base=dump['disable_base_register_value']
        require(base+transition['disabled_offset']==compiled['variables']['disabled']['address'] and
            base+transition['count_offset']==compiled['variables']['count']['address'],'Runtime disable store has different owner')
        require(entry['x30']==thread_return_target(p/'linked.elf') and returned['sp']==entry['sp'],
                'Main did not return with restored SP to the native thread exit target')
        expected=[entry['pc'],dump['pc'],*compiled['leaf_entries'],compiled['functions']['register']['address'],
                  returned['pc'],compiled['functions']['register']['address'],final['pc']]
        require([c['address'] for c in debug['controls']]==expected and
            [c['temporary'] for c in debug['controls']]==[True,True,False,False,False,False,True,False,True] and
            all(c['hardware'] and 'Hardware assisted breakpoint' in c['output'] for c in debug['controls']),
            'Native gap/termination breakpoint coverage differs')
        for s in stages:
            c=s['counters'];require(c['overflow']==0 and c['registrations']==1 and c['allocator']==entry['counters']['allocator'],
                                  'Observer overflow/allocator replacement')
            expected_callbacks=[f['expected'] for f in compiled['callbacks']]
            require(s['callbacks'][:2]==expected_callbacks[:2] and s['callbacks'][2] in (0,expected_callbacks[2]),'Native callbacks differ')
        require([s['counters']['disabled'] for s in stages]==[0,1,1,0] and
            all(s['counters']['completed']==4 for s in stages[1:]),'Native phase coverage differs')
        require(returned['counters']==dump['counters'] and returned['native']==dump['native'] and
            returned['callbacks']==dump['callbacks']==final['callbacks'],'Observer-off state changed')
        intervention=debug['continuation']
        require(intervention['address']==compiled['variables']['disabled']['address'] and
            intervention['before_hex']=='01000000' and intervention['after_hex']=='00000000' and
            intervention['pc']==returned['pc'] and intervention['event_prefix']==returned['counters']['count'],
            'Observer continuation write differs')
        stdout=(p/'guest.stdout').read_text();raw=(p/'termination.events').read_bytes();prefix=(p/'dump-start.events').read_bytes()
        require(prefix==(p/'main-return.events').read_bytes() and raw.startswith(prefix) and
            prefix.startswith((p/'main-enter.events').read_bytes()),'Native event prefix changed')
        prefix_rows=verify_prefix(stdout,prefix,dump['counters']);rows=decode(raw,final['counters']['count'])
        require(rows==independent_events(raw),'Independent raw-byte decoding differs')
        printed=native_replay(stdout);replayed=tail_lifecycle(rows,len(prefix_rows),printed)
        require(printed==json.loads((p/'native-lifecycle.json').read_text()),'Printed lifecycle differs')
        allocations=printed['legacy_lifecycle']['allocations']
        application=[t for t in printed['threads'] if t['phase']==0 and t['main_stack'] and
            any(allocations[i]['pointer']<=t['main_stack']<=entry['sp']<=allocations[i]['pointer']+allocations[i]['size']
                for i in t['storage'])]
        require(len(application)==1,'Application entry SP lacks a unique native thread stack owner')
        require(rows[-1]['current']==final['native']['current'] and rows[-1]['peak']==final['native']['peak'],
                'Termination native statistics differ from final leaf events')
        guest=json.loads((p/'guest.json').read_text())
        require(guest['status']=='complete' and sha(p/'guest.stdout')==guest['stdout_sha256'] and
            sha(p/'guest.stderr')==guest['stderr_sha256'] and
            original_results((p/'guest.stdout').read_bytes(),(p/'guest.stderr').read_bytes(),guest['returncode'])['original_output_complete'],
            'Original six-case guest output incomplete')
        for label in ('before','after'):
            h=json.loads((p/('host-'+label+'.json')).read_text())
            require(h['serial']==['10000000c1b4a936'] and not h['qemu_running'] and h['governor']=='performance' and
                h['throttled']=='throttled=0x0','Host controls differ')
        results.append({'profile':name,'printed_events':len(prefix_rows),'termination_events':len(rows),
            'post_return_events':len(rows)-len(prefix_rows),'native_thread_generations':replayed['native_thread_generations'],
            'native_threads_reclaimed':replayed['native_threads_reclaimed'],
            'native_statistics_at_termination':final['native'],'independent_allocation_replay':live_allocations(rows),
            'end_live_thread_owned_allocations':replayed['end_live_thread_owned_allocations'],
            'end_live_other_allocations':replayed['end_live_other_allocations'],
            'pending_startup_releases_at_termination':replayed['pending_startup_releases_at_termination'],
            'application_thread':application[0]['thread'],
            'application_release_entered':any(t['thread']==application[0]['thread']
                for t in replayed['pending_startup_releases_at_termination']),
            'disabled_gap_native_leaf_entries':0,'observer_flag_writes':1,
            'main_return_boundary':'uk_sched_thread_exit: native thread LR target, not a BL caller site',
            'linked_image':linked_image(p/'linked.elf',p/'runtime-image',tlsf)})
    return {'audit':'pass','profiles':results,'fresh_diagnostic_guests':3,'new_builds':0,'model_calls':0,
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'scope':plan['scope'],
        'reference_audit_sha256':state['reference_audit_sha256'],'campaign_sha256':sha(folder/'campaign.json')}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    parser.add_argument('--output',type=Path,required=True);a=parser.parse_args();root=Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not a.output.exists(),'Use leon and a new output')
    result=audit(root,a.folder.resolve());a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
