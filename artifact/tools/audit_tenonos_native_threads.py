#!/usr/bin/env python3
"""Bind native startup, scheduler and suite thread storage to leaf lifetimes."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from audit_tenonos_memory_lifecycle import parse, replay as legacy_replay, require

NATIVE_WRAPPED = tuple('uk_thread_' + n for n in
    ('create_bare','create_fn0','create_fn1','create_prio_fn1','create_fn2','release'))


def linked_native(path):
    symbols={}
    for line in subprocess.check_output(['nm','-S','--defined-only',str(path)]).decode().splitlines():
        fields=line.split()
        if len(fields)==4 and fields[2] in ('t','T'):
            symbols[fields[3]]=(int(fields[0],16),int(fields[1],16))
    addresses={address:name for name,(address,_) in symbols.items()}
    objdump=shutil.which('aarch64-linux-gnu-objdump') or 'objdump'
    raw=subprocess.check_output([objdump,'-d',str(path)]).decode()
    calls=[];name=''
    for line in raw.splitlines():
        heading=re.fullmatch(r'([0-9a-f]+) <([^>]+)>:',line)
        if heading:name=heading[2]
        row=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+',line)
        if not row or name not in symbols:continue
        pc,w=int(row[1],16),int(row[2],16)
        if w & 0x7c000000 != 0x14000000:continue
        d=w&0x3ffffff
        if d&(1<<25):d-=1<<26
        target=addresses.get(pc+4*d,'')
        if target.startswith('uk_thread_create_') or target=='uk_thread_release':
            require(name=='__wrap_'+target or name.startswith(('uk_thread_','_uk_thread_')),
                    'External native thread constructor/release bypass: '+name+' -> '+target)
            calls.append({'from':name,'to':target})
    for native in NATIVE_WRAPPED:
        # Unreferenced functions may be discarded by the native link.
        if '__wrap_'+native in symbols:
            require({'from':'__wrap_'+native,'to':native} in calls,'Native wrapper bypasses original body: '+native)
    require(any(r['from']=='__wrap_uk_thread_create_bare' for r in calls) and
            any(r['from']=='__wrap_uk_thread_create_prio_fn1' for r in calls) and
            any(r['from']=='__wrap_uk_thread_release' for r in calls),'Native startup/scheduler wrappers absent')
    return {'external_direct_call_bypass':False,'native_edges':calls,
            'indirect_function_pointer_coverage_established':False}


def legacy_projection(text, rows):
    selected=[r for r in rows if not 30<=r['op']<=34]
    lines=['IOTOS_LIFE '+' '.join('%s=%d'%(k,i if k=='seq' else v) for k,v in r.items())
           for i,r in enumerate(selected)]
    return '\n'.join(lines)+'\nIOTOS_LIFE_END events=%d overflow=0 registrations=1 completed=4\n'%len(selected)


def replay(text):
    rows=parse(text)
    legacy=legacy_replay(legacy_projection(text,rows))
    live={};generations=[];threads=[];active={};pending=None;releasing={}
    for e in rows:
        op,p,q,n=e['op'],e['p'],e['q'],e['n']
        if op in (1,3) and p:
            require(not any(p<a+g['size'] and a<p+n for a,g in live.items()),'Overlapping allocation')
            g={'generation':len(generations),'pointer':p,'size':n,'allocated':e['seq'],'freed':None}
            generations.append(g);live[p]=g
        elif op in (2,4) and p:
            require(p in live,'Unmatched native free');live.pop(p)['freed']=e['seq']
        elif op==30:
            require(p not in active or active[p]['release_return'] is not None,'Native thread reused before release')
            def owner(address):
                matches=[g['generation'] for a,g in live.items() if a<=address<a+g['size']]
                require(len(matches)==1,'Native thread storage has no unique live owner')
                return matches[0]
            t={'thread':p,'phase':e['phase'],'created':e['seq'],'storage':sorted(set(owner(a) for a in (p,q,n) if a)),
               'main_stack':q,'auxiliary_stack':n,'tls':None,'kind':None,'release_enter':None,'release_return':None}
            threads.append(t);active[p]=t;pending=t
        elif op==31:
            require(pending is not None and pending['thread']==p and pending['kind'] is None and n in range(1,6),
                    'Native constructor metadata out of order')
            pending['kind']=n;pending['tls']=q
            if q:
                matches=[g['generation'] for a,g in live.items() if a<=q<a+g['size']]
                require(len(matches)==1,'Native TLS lacks live owner')
                pending['storage']=sorted(set(pending['storage']+matches))
        elif op==32:
            require(pending is not None and pending['thread']==p and pending['kind'] is not None,
                    'Native constructor lengths out of order')
            pending.update(requested_stack_bytes=q,requested_auxiliary_bytes=n);pending=None
        elif op==33:
            require(p in active and active[p]['release_enter'] is None,'Unknown/duplicate native release')
            t=active[p];t['release_enter']=e['seq'];releasing[p]=t
        elif op==34:
            require(p in releasing,'Native release returned without entry');t=releasing.pop(p)
            require(all(generations[i]['freed'] is not None and t['release_enter']<generations[i]['freed']<e['seq']
                        for i in t['storage']),'Native release failed to free complete owned storage')
            t['release_return']=e['seq']
    require(pending is None and not releasing and len(threads)>66,'Incomplete native thread census')
    originals=[t for t in threads if 1<=t['phase']<=6]
    finite=[t for t in threads if t['phase']==7]
    require(len(originals)==62 and len(finite)==4 and
            all(t['release_return'] is not None for t in originals+finite),'Original/finite native thread release incomplete')
    startup=[t for t in threads if t['phase']==0]
    require(startup and any(t['kind']==1 and not t['main_stack'] for t in startup),
            'Inherited startup stack not identified')
    owned={i for t in threads for i in t['storage']}
    outstanding=[g for g in generations if g['freed'] is None]
    return {'legacy_lifecycle':legacy,'events':len(rows),'native_thread_generations':len(threads),
        'startup_thread_generations':len(startup),'original_thread_generations':len(originals),
        'finite_thread_generations':len(finite),'threads':threads,
        'native_threads_reclaimed':sum(t['release_return'] is not None for t in threads),
        'end_live_thread_owned_allocations':sum(g['generation'] in owned for g in outstanding),
        'end_live_other_allocations':[g for g in outstanding if g['generation'] not in owned],
        'inherited_main_stack_threads':sum(t['main_stack']==0 for t in threads),
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False}


def summary(result):
    require(result['audit']=='pass' and result['fresh_guests']==9,'Native thread audit incomplete')
    keys=('events','native_thread_generations','startup_thread_generations','original_thread_generations',
          'finite_thread_generations','native_threads_reclaimed','end_live_thread_owned_allocations',
          'inherited_main_stack_threads')
    return {'fresh_guests':result['fresh_guests'],'new_model_calls':0,
        'profiles':[{'profile':p['profile'],'runs':[{**{k:g[k] for k in keys},
            'end_live_other_allocations':len(g['end_live_other_allocations'])} for g in p['guests']],
            'static_writable_bytes':p['static_writable']['bytes']} for p in result['profiles']],
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False,'scope':result['scope']}


def paper_text(result):
    view=summary(result);runs=[r for p in view['profiles'] for r in p['runs']]
    require(len(runs)==9 and all(r==runs[0] for r in runs) and runs[0]['inherited_main_stack_threads']==1,
            'Paper requires matching native-thread counts and one inherited stack')
    r=runs[0]
    return ('An additional three-configuration campaign observes native thread constructors and release paths. '
        f'Each of nine fresh guests records {r["events"]:,} events for {r["native_thread_generations"]} thread generations: '
        f'{r["startup_thread_generations"]} startup/scheduler threads, {r["original_thread_generations"]} original-test tasks '
        f'and {r["finite_thread_generations"]} finite validation tasks. '
        f'The {r["native_threads_reclaimed"]} test/validation threads have complete storage reclamation; '
        f'{r["end_live_thread_owned_allocations"]} allocations remain owned by startup/scheduler threads and '
        f'{r["end_live_other_allocations"]} remain outside this thread ownership set. '
        'One startup thread inherits a stack rather than owning a heap-allocated main stack. '
        'Linked direct-call checks and the unchanged leaf-event projection agree with raw replay. '
        'The record ends before application return and final guest teardown; inherited-stack depth, pre-allocator '
        'memory and continuous live-stack coverage remain open. This new observation image does not acquire '
        'the preceding image\'s measured overhead or energy.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not a.output.exists(),'Use leon and a new output')
    from audit_tenonos_memory_lifecycle import audit
    result=audit(root,a.folder.resolve(),native_threads=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='profiles'}))
