#!/usr/bin/env python3
"""Capture preallocator SP and boot-region ownership in existing KVM images."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import time

from tenonos_kvm_reproduce import command, original_results, save, sha, utc

ROOT=Path(__file__).resolve().parents[1]
PLAN='registry/tenonos_boot_memory_rpi4_v1.json'
HELPERS=('tenonos_boot_memory.py','tenonos_boot_memory_gdb.py','tenonos_kvm_reproduce.py',
    'import_iotos_subjects.py','audit_tenonos_memory_lifecycle.py','audit_tenonos_native_threads.py','tenonos_bootinfo_abi.py',
    'audit_tenonos_boot_memory.py','tenonos_exit_memory.py','tenonos_exit_memory_gdb.py',
    'tenonos_allocator_metadata.py','tenonos_allocator_metadata_gdb.py')


def symbol_table(text):
    result={}
    for line in text.splitlines():
        row=line.split()
        if len(row)==4:result[row[3]]=(int(row[0],16),int(row[1],16))
        elif len(row)==3:result[row[2]]=(int(row[0],16),0)
    return result


def boundary_sites(disassembly):
    sites=[]
    for line in disassembly.splitlines():
        row=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)',line)
        if not row:continue
        pc,word,op,args=int(row[1],16),int(row[2],16),row[3],row[4].split('//')[0].strip()
        writes_sp=args.split(',')[0].strip() in ('sp','wsp') and op not in ('cmp','cmn','tst')
        writeback=re.search(r'\[sp(?:,[^\]]*)?\](?:!|,)',args) is not None
        if writes_sp or writeback or op=='msr' or op.startswith('eret'):
            sites.append({'pc':pc,'word':word,'op':op,'args':args})
    if not sites:raise ValueError('No native SP/system boundaries')
    return sites


def reviewed_offset_leaf(symbols,disassembly,selected):
    from audit_tenonos_boot_memory import direct_targets
    start,size=symbols['fdt_offset_ptr'];decoded={}
    for line in disassembly.splitlines():
        row=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)',line)
        if row:decoded[int(row[1],16)]=(int(row[2],16),row[3],row[4].split('//')[0].strip())
    allowed={'ldr','rev','adds','cset','cmp','ccmp','sxtw','add','mov','b'}
    pending=[start];nodes={};returns=[]
    while pending:
        pc=pending.pop()
        if pc in nodes:continue
        if not start<=pc<start+size or pc not in decoded or pc in selected:
            raise ValueError('Reviewed leaf leaves its SP-neutral compiled function')
        word,op,args=decoded[pc];nodes[pc]=word
        if word==0xd65f03c0:returns.append(pc);continue
        if not (op in allowed or op.startswith('b.')) or re.search(r'\b(?:sp|wsp|x30|w30|lr)\b',args):
            raise ValueError('Reviewed leaf contains an unapproved stack/LR/system operation')
        targets=direct_targets(pc,word)
        if targets is None or any(target<=pc for target in targets):
            raise ValueError('Reviewed leaf contains a call, indirect edge or loop')
        pending.extend(targets)
    if not returns:raise ValueError('Reviewed leaf has no native RET x30')
    return {'entry':start,'symbol_bytes':size,'nodes':{str(p):nodes[p] for p in sorted(nodes)},'returns':sorted(returns)}


def reviewed_tag_frame(symbols,disassembly,selected,leaf):
    from audit_tenonos_boot_memory import direct_targets
    start,size=symbols['fdt_next_tag'];decoded={}
    for line in disassembly.splitlines():
        row=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)',line)
        if row:decoded[int(row[1],16)]=(int(row[2],16),row[3],row[4].split('//')[0].strip())
    if decoded[start][0]!=0xaa0203e9 or decoded[start+4][0]!=0x128000e3 or decoded[start+8][0]!=0xa9bf7bfd:
        raise ValueError('Output pointer is not copied from argument x2 to x9')
    for pc,word in leaf['nodes'].items():
        actual=decoded[int(pc)]
        if actual[0]!=word or re.search(r'\b[wx]9\b',actual[2]):
            raise ValueError('Reviewed callee may change the protected output pointer')
    allowed={'mov','ldr','ldrb','str','ubfx','lsr','lsl','orr','cmp','ccmp','add','and','sub',
             'cbz','cbnz','b','nop','tst','rev','cset','sxtw'}
    pending=[(start,0,0)];states={};nodes={};returns=[]
    while pending:
        pc,offset,phase=pending.pop()
        if pc in states:
            if states[pc]!=(offset,phase):raise ValueError('Control-flow join has inconsistent stack state')
            continue
        if not start<=pc<start+size or pc not in decoded:
            raise ValueError('Fixed-frame function has an external control-flow edge')
        if phase==0 and pc not in (start,start+4,start+8):
            raise ValueError('Unknown pre-frame pointer state')
        states[pc]=(offset,phase);word,op,args=decoded[pc];nodes[pc]=word
        if word==0xa9bf7bfd:
            if phase!=0 or offset!=0:raise ValueError('Repeated or nested frame allocation')
            offset,phase=-16,1;targets={pc+4}
        elif word==0xa8c17bfd:
            if phase!=1 or offset!=-16:raise ValueError('Unmatched native frame restoration')
            offset,phase=0,2;targets={pc+4}
        elif word==0xd65f03c0:
            if phase!=2 or offset!=0:raise ValueError('Native return without restored SP/LR')
            returns.append(pc);continue
        elif pc in selected:
            raise ValueError('Unproved SP/system operation in fixed-frame function')
        elif word&0xfc000000==0x94000000:
            if phase!=1 or direct_targets(pc,word)!={leaf['entry']}:
                raise ValueError('Unproved fixed-frame callee or unprotected LR')
            targets={pc+4}
        else:
            if not (op in allowed or op.startswith('b.')):
                raise ValueError('Unapproved fixed-frame operation')
            if re.search(r'\b(?:x30|w30|lr)\b',args):raise ValueError('Unproved LR modification')
            if re.search(r'\b(?:sp|wsp)\b',args) and not (word==0x910003fd and phase==1):
                raise ValueError('Unproved stack access')
            output_store=op=='str' and re.fullmatch(r'w\d+,\s*\[x9\]',args) is not None
            if op=='str' and not output_store:raise ValueError('Unproved non-frame memory store')
            if re.search(r'\b[wx]9\b',args) and not (pc==start or output_store):
                raise ValueError('Output register identity can change')
            targets=direct_targets(pc,word)
            if targets is None:raise ValueError('Unproved indirect return in fixed-frame function')
        if offset not in (0,-16):raise ValueError('Unknown frame span')
        pending.extend((target,offset,phase) for target in targets)
    if not returns:raise ValueError('Fixed-frame function has no proved native return')
    return {'entry':start,'symbol_bytes':size,'maximum_stack_span_bytes':16,
        'output_pointer_argument':2,'output_pointer_bytes':4,
        'nodes':{str(p):nodes[p] for p in sorted(nodes)},'returns':sorted(returns)}


def bounded_call_guard(before,minimum,known,proof,code_span):
    if not known or before['cpsr']&0x1c0!=0x1c0:return False
    sp=before['sp'];bottom=sp-proof['maximum_stack_span_bytes']
    pointer=before['gprs'][proof['output_pointer_argument']];end=pointer+proof['output_pointer_bytes']
    return (bottom>=minimum and 0<=pointer<end<=1<<64 and
            (end<=bottom or pointer>=sp) and (end<=code_span[0] or pointer>=code_span[1]))


def on_pi(folder):
    if folder.parent!=Path('/dev/shm') or not folder.name.startswith('iotos-tenon-v4-boot-memory-'):
        raise ValueError('Unsafe temporary capture path')
    plan=json.loads((folder/'protocol.json').read_text())
    runtime={}
    for tool in ('gdb','objdump','qemu-system-aarch64'):
        executable=Path(shutil.which(tool)).resolve()
        runtime[tool]={'executable_sha256':sha(executable),
            'version':subprocess.check_output([str(executable),'--version']).decode().splitlines()[0]}
    save(folder/'runtime-tools.json',{'tools':runtime,'kernel':os.uname().release,
                                    'gdb_debug_symbols_loaded':False})
    symbols=symbol_table(subprocess.check_output(['nm','-S','--defined-only',str(folder/'linked.elf')]).decode())
    entry=symbols['_libkvmplat_entry'][0]
    disassembly=subprocess.check_output(['objdump','-d','--disassemble=_libkvmplat_entry',str(folder/'linked.elf')]).decode()
    (folder/'entry-disassembly.txt').write_text(disassembly)
    switches=re.findall(r'(?m)^\s*([0-9a-f]+):\s+9100035f\s+mov\s+sp, x26\s*$',disassembly)
    if len(switches)!=1:raise ValueError('Unknown linked boot-stack initialization')
    init='uk_tlsf_init' if 'uk_tlsf_init' in symbols else 'uk_allocbbuddy_init'
    with socket.socket() as port:
        port.bind(('127.0.0.1',0));number=port.getsockname()[1]
    setup={'entry_address':entry,'stack_switch_address':int(switches[0],16),
        'boot_stack_top':symbols['lcpu_bootstack'][0],'boot_stack_bytes':4096,
        'bootinfo_address':symbols['bi_bootinfo_sec'][0],'bootinfo_bytes':symbols['bi_bootinfo_sec'][1],
        'registration_address':symbols['__wrap_uk_alloc_register'][0],'bounds':plan['bounds'],
        'gdb_port':number,'trace_stages':{n:symbols[s][0] for n,s in
            (('_ukplat_entry','_ukplat_entry'),('ukplat_entry','ukplat_entry'),
             ('native_allocator_init',init),('__wrap_uk_alloc_register','__wrap_uk_alloc_register'))},
        'later_stages':{n:symbols[n][0] for n in ('main','ukplat_terminate')}}
    setup['stage_only']=plan.get('trace_mode')=='hardware-stage-census'
    if plan.get('observer_mode') in ('exit-lifecycle','allocator-metadata','allocator-peak'):
        setup['exit_layout']=json.loads((folder/'exit-layout.json').read_text())
    if plan.get('observer_mode')=='allocator-peak':
        setup['peak_target']=json.loads((folder/'peak-target.json').read_text())
    if plan.get('trace_mode') in ('all-sp-and-system-boundaries','hardware-neutral-blocks','hardware-neutral-regions','hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers'):
        raw=subprocess.check_output(['objdump','-d',str(folder/'linked.elf')]).decode()
        (folder/'image-disassembly.txt').write_text(raw)
        setup['boundary_sites']=boundary_sites(raw)
        if plan['trace_mode'] in ('hardware-neutral-blocks','hardware-neutral-regions','hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers'):
            setup['hardware_neutral_blocks']=True
            setup['hardware_neutral_regions']=plan['trace_mode'] in ('hardware-neutral-regions','hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers')
            setup['code_words']={int(m[1],16):int(m[2],16) for line in raw.splitlines()
                if (m:=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+([^\s.][^\s]*)',line))}
            setup['exception_guards']={n:symbols[n][0] for n in ('el1_sync','el1_irq')}
            if plan['trace_mode'] in ('hardware-neutral-leaf-regions','hardware-peak-bounded-calls','hardware-peak-required-registers'):
                setup['reviewed_leaf']=reviewed_offset_leaf(symbols,raw,{s['pc'] for s in setup['boundary_sites']})
            if plan['trace_mode'] in ('hardware-peak-bounded-calls','hardware-peak-required-registers'):
                setup['reviewed_tag_frame']=reviewed_tag_frame(symbols,raw,{s['pc'] for s in setup['boundary_sites']},setup['reviewed_leaf'])
            setup['required_registers_only']=plan['trace_mode']=='hardware-peak-required-registers'
        setup['debug_reset_prefix']=plan.get('debug_reset_prefix',False)
        if setup['debug_reset_prefix']:
            resets=[s for s in setup['boundary_sites'] if s['op']=='msr' and s['args'].startswith('mdscr_el1,')]
            if len(resets)!=1:raise ValueError('Unknown native debug-control reset')
            setup['enable_breakpoints_at']=resets[0]['pc']+4
            setup['synchronous_exception_address']=symbols['el1_sync'][0]
    save(folder/'gdb-input.json',setup)
    argv=['sudo','-n','setpriv','--reuid='+subprocess.check_output(['id','-un']).decode().strip(),
        '--regid=kvm','--init-groups','qemu-system-aarch64','-machine','virt,gic-version=2',
        '-accel','kvm','-cpu','host','-smp','1','-m','128M','-nographic','-monitor','none',
        '-nic','none','-no-reboot','-S','-gdb','tcp:127.0.0.1:'+str(number),'-kernel',str(folder/'runtime-image')]
    started=utc();begin=time.monotonic();status={'argv':argv,'started_utc':started,'status':'incomplete'}
    save(folder/'guest.json',status)
    with (folder/'guest.stdout').open('xb') as out,(folder/'guest.stderr').open('xb') as err:
        proc=subprocess.Popen(argv,stdout=out,stderr=err,start_new_session=True)
        try:
            env=dict(os.environ,IOTOS_BOOT_CAPTURE=str(folder))
            time.sleep(.5)
            with (folder/'gdb.stdout').open('xb') as gout,(folder/'gdb.stderr').open('xb') as gerr:
                debug=subprocess.run(['timeout','--kill-after=5',str(plan['bounds']['gdb_timeout_s']),
                    'gdb','-nx','--readnever','--batch','-q',str(folder/'linked.elf'),
                    '-ex','source '+str(Path(__file__).with_name({'exit-lifecycle':'tenonos_exit_memory_gdb.py',
                        'allocator-metadata':'tenonos_allocator_metadata_gdb.py',
                        'allocator-peak':'tenonos_allocator_metadata_gdb.py'}.get(plan.get('observer_mode'),'tenonos_boot_memory_gdb.py')))],
                    env=env,stdout=gout,stderr=gerr,timeout=plan['bounds']['gdb_timeout_s']+10)
            if debug.returncode or not (folder/'debug-result.json').exists():
                raise RuntimeError('Debug capture failed; retain all bytes')
            rc=proc.wait(timeout=plan['bounds']['guest_timeout_s'])
            verdict=original_results((folder/'guest.stdout').read_bytes(),(folder/'guest.stderr').read_bytes(),rc)
            if not verdict['original_output_complete']:raise RuntimeError('Original six-case guest output failed')
            from audit_tenonos_native_threads import replay
            save(folder/'native-lifecycle.json',replay((folder/'guest.stdout').read_text()))
            status.update(status='complete',returncode=rc,original_output=verdict)
        finally:
            # sudo may leave its uid-dropped child alive after the parent exits.
            for child in Path('/proc').iterdir():
                if not child.name.isdigit():continue
                try:
                    args=(child/'cmdline').read_bytes().split(b'\0')
                    ours=(child.stat().st_uid==os.getuid() and args and
                          Path(os.fsdecode(args[0])).name=='qemu-system-aarch64' and
                          os.fsencode(folder/'runtime-image') in args)
                    if ours:
                        os.kill(int(child.name),signal.SIGTERM)
                        until=time.monotonic()+5
                        while child.exists() and time.monotonic()<until:time.sleep(.1)
                        if child.exists():os.kill(int(child.name),signal.SIGKILL)
                except (FileNotFoundError,ProcessLookupError):pass
            if proc.poll() is None:
                subprocess.run(['sudo','-n','kill','-TERM',str(proc.pid)],check=False)
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    subprocess.run(['sudo','-n','kill','-KILL',str(proc.pid)],check=False);proc.wait()
            status.update(finished_utc=utc(),elapsed_seconds=time.monotonic()-begin,
                          stdout_sha256=sha(folder/'guest.stdout'),stderr_sha256=sha(folder/'guest.stderr'))
            save(folder/'guest.json',status)


def collect(output,socket_path,host,plan_path):
    from run_tenonos_energy import host_state,governor
    from tenonos_memory_observer import retain_pi_evidence
    from audit_tenonos_memory_lifecycle import audit
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or output.exists():
        raise ValueError('Use leon and a new persistent folder')
    if shutil.disk_usage(ROOT).free<128*1024*1024:
        raise ValueError('Insufficient persistent evidence space; retain current evidence before collecting')
    output.resolve().relative_to((ROOT/'artifacts/reports').resolve())
    plan=json.loads(plan_path.read_text());reference=ROOT/plan['reference_campaign']
    if audit(ROOT,reference,native_threads=True,registry=plan.get('reference_protocol_registry'))!=json.loads((reference/'audit.json').read_text()):
        raise ValueError('Existing image/lifecycle evidence changed')
    repaired=None
    if plan.get('bootinfo_repair'):
        from tenonos_bootinfo_abi import audit as repair_audit
        repaired=repair_audit(ROOT,ROOT/plan['bootinfo_repair'])
    ssh=['ssh','-S',socket_path,'-o','BatchMode=yes','-o','ConnectTimeout=10',host]
    initial=host_state(ssh)
    if initial['serial']!=['10000000c1b4a936'] or initial['qemu_running'] or initial['throttled']!='throttled=0x0':
        raise ValueError('Wrong or busy/throttled Pi')
    output.mkdir(parents=True);shutil.copyfile(plan_path,output/'protocol.json')
    (output/'helpers').mkdir()
    for name in HELPERS:shutil.copyfile(ROOT/'tools'/name,output/'helpers'/name)
    state={'status':'incomplete','registered_utc':utc(),'host_initial':initial,'protocol_sha256':sha(output/'protocol.json'),
        'reference_audit_sha256':sha(reference/'audit.json'),'source_sha256':{n:sha(output/'helpers'/n) for n in HELPERS},
        'model_calls':0,'new_builds':0,'completed':[]}
    if repaired:state['repair_sha256']=sha(ROOT/plan['bootinfo_repair']/'repair.json')
    if plan.get('peak_reference_campaign'):
        from tenonos_allocator_metadata import audit as metadata_audit
        prior=ROOT/plan['peak_reference_campaign']
        if metadata_audit(ROOT,prior,registry=plan.get('peak_reference_registry'))!=json.loads((prior/'audit.json').read_text()):raise ValueError('Peak reference does not replay')
        state['peak_reference_audit_sha256']=sha(prior/'audit.json')
    save(output/'campaign.json',state)
    try:
        governor(ssh,'performance')
        for name in plan['profiles']:
            if shutil.disk_usage(ROOT).free<128*1024*1024:
                raise RuntimeError('Insufficient persistent space for the next profile; prior evidence retained')
            p=output/name;p.mkdir();source=reference/name/'build'
            for origin,target in (('runtime-image','runtime-image'),('linked-symbols.elf','linked.elf'),('.config','input.config')):
                path=ROOT/plan['bootinfo_repair']/name/'runtime-image' if repaired and origin=='runtime-image' else source/origin
                shutil.copyfile(path,p/target)
            if plan.get('observer_mode')=='exit-lifecycle':
                from tenonos_exit_memory import layout
                save(p/'exit-layout.json',layout(p/'linked.elf','CONFIG_LIBTLSF=y\n' in (p/'input.config').read_text()))
            elif plan.get('observer_mode') in ('allocator-metadata','allocator-peak'):
                from tenonos_allocator_metadata import layout
                save(p/'exit-layout.json',layout(p/'linked.elf','CONFIG_LIBTLSF=y\n' in (p/'input.config').read_text()))
                if plan.get('peak_reference_campaign'):
                    from tenonos_allocator_metadata import peak_target
                    save(p/'peak-target.json',peak_target(p/'linked.elf',ROOT/plan['peak_reference_campaign']/name))
            shutil.copyfile(output/'protocol.json',p/'protocol.json')
            remote='/dev/shm/iotos-tenon-v4-boot-memory-'+output.name+'-'+name
            subprocess.run([*ssh,shlex.join(['mkdir','-m','700',remote])],check=True,timeout=20)
            subprocess.run(['rsync','-a','-e',shlex.join(ssh[:-1]),str(p)+'/',host+':'+remote+'/'],check=True,timeout=120)
            subprocess.run([*ssh,shlex.join(['mkdir',remote+'/helpers'])],check=True,timeout=20)
            subprocess.run(['scp','-o','ControlPath='+socket_path,'-o','BatchMode=yes',
                *[str(output/'helpers'/n) for n in HELPERS],host+':'+remote+'/helpers/'],check=True,timeout=60)
            before=host_state(ssh);save(p/'host-before.json',before)
            outer=plan['bounds']['gdb_timeout_s']+plan['bounds']['guest_timeout_s']+80
            argv=['timeout','--kill-after=10',str(outer),'python3',remote+'/helpers/tenonos_boot_memory.py','on-pi','--output',remote]
            with (p/'remote.stdout').open('xb') as out,(p/'remote.stderr').open('xb') as err:
                step=subprocess.run([*ssh,shlex.join(argv)],stdout=out,stderr=err,timeout=outer+30)
            retain_pi_evidence(ssh,host,socket_path,remote,p,step.returncode,prefix='iotos-tenon-v4-boot-memory-')
            after=host_state(ssh);save(p/'host-after.json',after)
            if step.returncode or after['qemu_running'] or after['throttled']!='throttled=0x0' or after['governor']!='performance':
                raise RuntimeError('Preallocator capture failed; no automatic retry')
            state['completed'].append(name);save(output/'campaign.json',state)
            print(json.dumps({'profile':name,'fresh_guests':1,'pass':True}),flush=True)
        state['status']='complete'
    except BaseException as error:
        state.update(status='failed',error=repr(error));raise
    finally:
        governor(ssh,initial['governor']);state['host_after_restore']=host_state(ssh)
        state['governor_restored']=state['host_after_restore']['governor']==initial['governor']
        save(output/'campaign.json',state)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('collect','on-pi'))
    p.add_argument('--output',type=Path,required=True);p.add_argument('--socket',default='/tmp/iotos-pi-energy.sock')
    p.add_argument('--plan',type=Path,default=ROOT/PLAN)
    p.add_argument('--host',default='pi@192.168.31.76');a=p.parse_args()
    if a.action=='on-pi':on_pi(a.output.resolve())
    else:
        with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);collect(a.output.resolve(),a.socket,a.host,a.plan.resolve())
