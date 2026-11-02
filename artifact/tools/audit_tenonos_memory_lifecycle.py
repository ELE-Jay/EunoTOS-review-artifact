#!/usr/bin/env python3
"""Replay native leaf allocations and bind task storage to actual frees."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

CASES = ('rst_task_switch_init','rst_task_switch_multi_threaded_init','rst_task_preempt_init',
         'rst_semaphore_shuffle_init','rst_interrupt_latency_init','rst_set_timer_offset_init')
WRAPPED = CASES + ('rst_task_create','rst_task_delete')


def require(value, message):
    if not value:
        raise ValueError(message)


def linked_preflight(elf, output, tlsf):
    symbols = {}
    for line in subprocess.check_output(['nm','-S','--defined-only',str(elf)]).decode().splitlines():
        f = line.split()
        if len(f) == 4: symbols[f[3]] = (int(f[0],16),int(f[1],16))
    def targets(name):
        start,size = symbols[name]
        raw = subprocess.check_output(['objdump','-d','--start-address='+hex(start),
                                      '--stop-address='+hex(start+size),str(elf)]).decode()
        with output.open('a') as stream: stream.write(raw)
        result = set()
        for pc,encoded in re.findall(r'(?m)^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+',raw):
            w = int(encoded,16)
            if w & 0x7c000000 == 0x14000000:
                d = w & 0x3ffffff
                if d & (1<<25): d -= 1<<26
                result.add(int(pc,16)+4*d)
        return result
    init = 'uk_tlsf_init' if tlsf else 'uk_allocbbuddy_init'
    require(symbols['__wrap_uk_alloc_register'][0] in targets(init),'Native registration bypasses observer')
    calls = targets('iotos_original_main')
    require(all(symbols['__wrap_'+n][0] in calls for n in CASES),'Original case bypasses observer')
    for name in WRAPPED:
        require(symbols[name][0] in targets('__wrap_'+name),'Native body bypassed by wrapper')


def parse(text):
    rows = []
    fields = {'seq','op','phase','p','q','n','current','peak'}
    for line in text.splitlines():
        if not line.startswith('IOTOS_LIFE '): continue
        pairs = [v.split('=') for v in line.split()[1:]]
        require(len(pairs) == 8 and all(len(p)==2 and re.fullmatch('[0-9]+',p[1]) for p in pairs) and
                {p[0] for p in pairs} == fields, 'Malformed lifecycle event')
        rows.append({k:int(v) for k,v in pairs})
    end = re.findall(r'(?m)^IOTOS_LIFE_END events=(\d+) overflow=(\d+) registrations=(\d+) completed=(\d+)\r?$',text)
    require(len(end)==1 and tuple(map(int,end[0]))==(len(rows),0,1,4) and rows and
            [r['seq'] for r in rows]==list(range(len(rows))), 'Incomplete lifecycle sequence')
    return rows


def linked_image(elf_path, image_path, tlsf):
    from elftools.elf.elffile import ELFFile
    with elf_path.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf['e_machine']=='EM_AARCH64','Wrong memory-observer architecture')
        table = elf.get_section_by_name('.symtab')
        def body(name):
            found = table.get_symbol_by_name(name)
            require(found is not None and len(found)==1,'Missing/ambiguous linked observer symbol')
            s = found[0]; section = elf.get_section(s['st_shndx'])
            return s['st_value'],section.data()[s['st_value']-section['sh_addr']:s['st_value']-section['sh_addr']+s['st_size']]
        anchor,raw = body('iotos_original_main'); flat = image_path.read_bytes(); offset = flat.find(raw)
        require(len(raw)>=32 and offset>=0 and flat.find(raw,offset+1)==-1,'ELF does not uniquely bind to guest image')
        base = anchor-offset
        functions = 0
        for s in table.iter_symbols():
            if s['st_info']['type']!='STT_FUNC' or not s['st_size'] or not isinstance(s['st_shndx'],int): continue
            section = elf.get_section(s['st_shndx']); start = s['st_value']-section['sh_addr']
            data = section.data()[start:start+s['st_size']]
            require(s['st_value']>=base and flat[s['st_value']-base:s['st_value']-base+len(data)]==data,
                    'Linked function differs from measured image: '+s.name)
            functions += 1
        def targets(name):
            pc,data = body(name); result = set()
            for i in range(0,len(data)-3,4):
                word = int.from_bytes(data[i:i+4],'little')
                if word & 0x7c000000 == 0x14000000:
                    d = word & 0x3ffffff
                    if d & (1<<25): d -= 1<<26
                    result.add(pc+i+4*d)
            return result
        init = 'uk_tlsf_init' if tlsf else 'uk_allocbbuddy_init'
        require(body('__wrap_uk_alloc_register')[0] in targets(init),'Native allocator bypasses registration wrapper')
        for name in WRAPPED:
            require(body(name)[0] in targets('__wrap_'+name),'Wrapped native implementation missing')
        require(all(body('__wrap_'+n)[0] in targets('iotos_original_main') for n in CASES),'Original main bypasses case wrappers')
        return {'functions_bound_to_measured_image':functions,'native_registration_wrapped':True,'original_cases_wrapped':6}


def replay(text):
    rows = parse(text)
    require(rows[0]['op']==5 and sum(r['op']==5 for r in rows)==1,'Missing allocator initialization')
    live, freed, generations, tasks, active_tasks = {}, set(), [], [], {}
    peak_events, maximum, previous_peak = [], 0, 0
    starts, ends = [], []
    for e in rows:
        op,p,n = e['op'],e['p'],e['n']
        require(0 <= e['current'] <= e['peak'] < 134217728 and e['peak'] >= previous_peak,
                'Invalid native current/peak statistics')
        previous_peak = e['peak']
        if e['phase'] <= 6 and e['current'] > maximum:
            maximum,peak_events = e['current'],[e['seq']]
        elif e['phase'] <= 6 and e['current']==maximum: peak_events.append(e['seq'])
        if op in (1,3) and p:
            require(n > 0 and all(p+n <= a or a+b['size'] <= p for a,b in live.items()),'Overlapping native allocation')
            g = {'generation':len(generations),'pointer':p,'size':n,'allocated':e['seq'],'freed':None}
            generations.append(g); live[p] = g
        elif op in (2,4) and p:
            require(p in live,'Unmatched native free')
            g = live.pop(p)
            require(op != 4 or n == g['size'],'Native page-free extent changed')
            g['freed'] = e['seq']; freed.add(g['generation'])
        elif op==11:
            slots = []
            for address in (p,e['q'],n):
                if not address: continue
                owners = [g['generation'] for base,g in live.items() if base <= address < base+g['size']]
                require(len(owners)==1,'Task storage lacks a unique live allocation')
                slots += owners
            require(p not in active_tasks or all(generations[i]['freed'] is not None for i in active_tasks[p]['storage']),
                    'Task address reused before native storage reclamation')
            t = {'task':p,'phase':e['phase'],'created':e['seq'],'storage':sorted(set(slots)),'delete':None}
            tasks.append(t); active_tasks[p] = t
        elif op==14:
            require(p in active_tasks,'TLS storage before task identity')
            if e['q']:
                owners = [g['generation'] for base,g in live.items() if base <= e['q'] < base+g['size']]
                require(len(owners)==1,'Task TLS lacks unique live allocation')
                active_tasks[p]['storage'] = sorted(set(active_tasks[p]['storage']+owners))
        elif op==12:
            require(p in active_tasks and active_tasks[p]['delete'] is None,'Missing or duplicate task deletion')
            active_tasks[p]['delete'] = e['seq']
        elif op==7: starts.append(e['phase'])
        elif op==8:
            require(n==0,'Original test returned failure'); ends.append(e['phase'])
        elif op in (20,21): pass
        elif op not in (1,2,3,4,5,6): raise ValueError('Unknown lifecycle operation')
    require(starts == ends == list(range(1,7)),'Original suite phase coverage differs')
    require([sum(t['phase']==p for t in tasks) for p in range(1,8)]==[2,51,2,4,1,2,4],
            'Original/finite task generation coverage differs')
    finite = [t for t in tasks if t['phase']==7]
    head = [t for t in tasks if t['phase']==2][-1]
    for task in tasks:
        task['reclaimed'] = all(generations[i]['freed'] is not None for i in task['storage'])
        # The original multi-thread head resumes main and has no delete call.
        require(task['delete'] is not None or task is head,'Task deletion request not observed')
        for i in task['storage']:
            f = generations[i]['freed']
            require(f is None or f > (task['delete'] if task['delete'] is not None else task['created']),
                    'Task storage freed before deletion/creation')
    require(all(t['reclaimed'] for t in finite),'Finite validation task storage not reclaimed')
    a,b = [r for r in rows if r['op'] in (20,21)]
    require(a['op']==20 and b['op']==21 and b['n']==4 and a['current']==b['current'],
            'Finite validation occupancy did not return to baseline')
    original = [r for r in rows if r['op']==8 and r['phase']==6]
    require(original and maximum == original[0]['peak'],'Recorded leaf events miss the suite native high-water')
    return {'events':len(rows),'native_allocations':len(generations),'native_frees':len(freed),
        'suite_peak_bytes_native_convention':maximum,'suite_peak_event_sequences':peak_events,
        'task_generations':len(tasks),'original_task_generations':len(tasks)-4,
        'original_tasks_without_adapter_delete':sum(t['delete'] is None for t in tasks if t['phase']!=7),
        'reclaimed_original_tasks':sum(t['reclaimed'] for t in tasks if t['phase']!=7),
        'finite_tasks':4,'finite_reclaimed':4,'finite_task_address_reuses':4-len({t['task'] for t in finite}),
        'task_storage_generations':tasks,'allocations':generations,'end_live_native_allocations':len(live),
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False}


def audit(root, folder, native_threads=False, registry=None):
    from tenonos_kvm_reproduce import sha
    from audit_tenonos_memory import observations, writable_image
    from audit_tenonos_policy_sequence import guest_checks
    from audit_tenonos_tasks import configuration
    state = json.loads((folder/'campaign.json').read_text())
    plan = json.loads((folder/'protocol.json').read_text())
    registry = registry or ('tenonos_native_threads_rpi4_v1.json' if native_threads else 'tenonos_memory_lifecycle_rpi4_v2.json')
    require(state['status']=='complete' and state['governor_restored'] and
        state['protocol_sha256']==sha(folder/'protocol.json') and
        plan==json.loads((root/'registry'/registry).read_text()),'Incomplete lifecycle campaign')
    require([p['profile'] for p in state['completed']]==plan['profiles'],'Profile coverage differs')
    require(state['host_initial']['serial']==['10000000c1b4a936'] and state['model_calls']==0 and
            state['host_after_restore']['governor']==state['host_initial']['governor'],'Pi identity/restore differs')
    for name,digest in state['source_sha256'].items(): require(sha(folder/'helpers'/name)==digest,'Frozen helper changed')
    manifest = json.loads((root/'artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark/manifest.json').read_text())
    refs = {r['id']:r for r in json.loads((folder/'references.json').read_text())['variants']}
    reports = []
    for profile in state['completed']:
        p = folder/profile['profile']; build = p/'build'
        transfer = json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode']==0 and
            all(sha(p/n)==d for n,d in transfer['files'].items()),'Returned evidence changed')
        proof = json.loads((p/'source-proof.json').read_text()); app = p/'source/app-rtos-benchmark-memory'
        suffix = b'\nAPPRHEALSTONEBENCHMARK_SRCS-y += $(APPRHEALSTONEBENCHMARK_BASE)/iotos_memory.c\n' + \
            ('APPRHEALSTONEBENCHMARK_LDFLAGS-y += '+' '.join('-Wl,--wrap='+n for n in WRAPPED)+'\n').encode()
        patches = proof['identity']['rtos_adapter_patch']['files']
        require(patches=={'adapter/os/tenonos/rst_isr.c':'738792173125d862712cf17d40640a3f1c3488a761d2ac321cfe537982d1a707',
                          'adapter/os/tenonos/rst_task.c':'71c41a94f0ccdf644b0afb0f266afe072e3048df42816bf2a8893dcece304bed'},'Compatibility adapter differs')
        for entry in manifest['files']:
            name = entry['path']; raw = (app/name).read_bytes()
            require(sha(app/name)==proof['observer_app_sha256'][name],'Observed source changed')
            if name=='main.c': raw = raw.replace(b'int iotos_original_main(',b'int main(')
            if name=='Makefile.uk':
                require(raw.endswith(suffix),'Observer link registration differs'); raw = raw[:-len(suffix)]
            require(hashlib.sha256(raw).hexdigest()==proof['original_app_sha256'][name],'Original body changed')
            expected = patches.get(name)
            require(hashlib.sha256(raw).hexdigest()==expected if expected else
                hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['sha'],'Pinned public source differs')
        observer=(folder/'helpers/tenonos_memory_lifecycle.c').read_bytes()
        if native_threads:
            observer+=b'\n'+(folder/'helpers/tenonos_native_threads.c').read_bytes()
        require((app/'iotos_memory.c').read_bytes()==observer,'Compiled observer differs')
        native = json.loads((p/'native-statistics.json').read_text())
        require(all(sha(p/'source/native-statistics'/n)==d for n,d in native.items()),'Native source changed')
        if proof['tlsf']:
            from tenonos_memory_observer import unrepaired_tlsf
            unrepaired_tlsf((p/'source/native-statistics/tlsf.c').read_bytes())
            require(all('-DTLSF_STATISTIC=1' in (p/'source/native-statistics'/name).read_text()
                        for name in ('libtlsf-tlsf.o.cmd','libtlsf-glue.o.cmd')),'Native statistics flag missing')
        before,after = configuration(p/'input.config'),configuration(build/'.config')
        diff = {k:[before.get(k,'n'),after.get(k,'n')] for k in before.keys()|after.keys() if before.get(k,'n')!=after.get(k,'n')}
        require(diff=={k.removeprefix('CONFIG_'):v for k,v in proof['config_changes'].items()} and
            set(diff)==({'UK_APP'} if proof['tlsf'] else {'UK_APP','LIBUKALLOC_IFSTATS'}),'Native controls changed')
        require(sha(p/'input.config')==refs[profile['profile']]['config_sha256'],'Reference config changed')
        require(sha(build/'compiler.stdout')==sha(root/refs[profile['profile']]['build']/'compiler.stdout'),
                'Compiler version record differs')
        if native_threads:
            reference=json.loads((root/refs[profile['profile']]['build']/'build-result.json').read_text())
            require(proof['identity']==reference['source_commits'],'Native thread source/adapter identity differs')
        linked = json.loads((build/'linked-inputs.json').read_text())
        require(all(sha(build/n)==d for n,d in linked['files'].items()) and
            sha(build/'runtime-image')==linked['measured_image_sha256'],'Linked/measured identity differs')
        code = linked_image(build/'linked-symbols.elf',build/'runtime-image',proof['tlsf'])
        if native_threads:
            from audit_tenonos_native_threads import linked_native
            code['native_threads']=linked_native(build/'linked-symbols.elf')
            require(code['native_threads']==json.loads((build/'native-thread-code.json').read_text()),'Native thread call graph changed')
        complete,passed = guest_checks(p/'boots',linked['measured_image_sha256'])
        require(passed and len(complete)==3,'Original guest output incomplete')
        outcomes = []
        for i in (1,2,3):
            text = (p/('boots/boot%d.stdout'%i)).read_text()
            observations(text)
            secondary = [{k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',line)} for line in text.splitlines()
                         if line.startswith('IOTOS_LIFE ')]
            require(secondary==parse(text),'Independent raw field parser differs')
            args = json.loads((p/('boots/boot%d.json'%i)).read_text())['argv']
            require(all(args[args.index(k)+1]==v for k,v in (('-accel','kvm'),('-smp','1'),('-m','128M'),('-nic','none'))),
                    'Guest controls differ')
            # Recompute from raw records rather than trust the stored verdict.
            if native_threads:
                from audit_tenonos_native_threads import replay as native_replay
                outcomes.append(native_replay(text))
            else:
                outcomes.append(replay(text))
        require(outcomes==json.loads((p/'lifecycle-result.json').read_text()),'Stored lifecycle summary differs')
        for boundary in ('host_before','host_after'):
            h = profile[boundary]
            require(h['governor']=='performance' and h['throttled']=='throttled=0x0' and not h['qemu_running'],'Host controls differ')
        reports.append({'profile':profile['profile'],'guests':outcomes,'linked_code':code,
                        'static_writable':writable_image(build/'linked-symbols.elf')})
    return {'audit':'pass','profiles':reports,'fresh_guests':3*len(reports),'new_model_calls':0,
        'scope':plan['scope'],'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'campaign_sha256':sha(folder/'campaign.json')}


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder',type=Path); p.add_argument('--output',type=Path,required=True)
    a = p.parse_args(); root = Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not a.output.exists(),'Use leon and new output')
    result = audit(root,a.folder.resolve()); a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='profiles'}))
