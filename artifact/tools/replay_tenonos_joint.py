#!/usr/bin/env python3
"""Isolate the joint-task evidence replay on leon; no API, device or rebuild."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from package_sensys_paper_evidence import installed_python, local_file, offline, live_tool_bytecode
from tenonos_kvm_reproduce import save, sha

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
RESULT = 'artifacts/reports/tenonos-joint-qualified-v1.json'


def check_command(executable,command,tools,root):
    if not isinstance(command,(list,tuple)) or not command:
        raise RuntimeError('Undeclared replay subprocess')
    name = Path(os.fsdecode(executable)).name
    flags = ['-S','--defined-only'] if name == 'nm' else ['-d'] if name == 'aarch64-linux-gnu-objdump' else None
    tool = tools.get(name)
    path = Path(shutil.which(os.fsdecode(executable)) or os.fsdecode(executable)).resolve()
    if flags is None or not tool or list(command[1:-1]) != flags or \
            str(path) != tool['path'] or sha(path) != tool['sha256']:
        raise RuntimeError('Only the recorded read-only binutils are allowed')
    target = Path(command[-1]).resolve()
    if not target.is_relative_to(root) or target.suffix != '.elf' or not target.is_file():
        raise RuntimeError('Binutils may inspect only copied ELF evidence')


def evaluate():
    from audit_tenonos_joint_tasks import bind
    return bind(ROOT/'artifacts/reports/tenonos-joint-candidate-behavior-rpi4-v1',
                ROOT/'artifacts/reports/tenonos-joint-candidates-allocated-rpi4-v2')


def capture(folder):
    if ROOT != LEON or folder.exists():
        raise ValueError('Capture on leon in a new persistent folder')
    folder.relative_to(ROOT/'artifacts/reports');folder.mkdir()
    seen,active = set(),True
    def observe(event,args):
        if active and event == 'open' and isinstance(args[0],(str,bytes,os.PathLike)) and not \
                args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC):
            path = Path(os.fsdecode(args[0])).resolve()
            if path.is_relative_to(ROOT) and not installed_python(path) and not live_tool_bytecode(ROOT,path):
                seen.add(path)
    sys.addaudithook(observe)
    expected = json.loads((ROOT/RESULT).read_text())
    if evaluate() != expected:
        raise ValueError('Current joint result does not replay')
    active = False
    for module in tuple(sys.modules.values()):
        name = getattr(module,'__file__',None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT) and not installed_python(path) and not live_tool_bytecode(ROOT,path):
                seen.add(path)
    seen.update((Path(__file__).resolve(),ROOT/'tools/package_sensys_paper_evidence.py'))
    files = {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(seen) if p.is_file()}
    tools = {n:{'path':str(Path(shutil.which(n)).resolve()),'sha256':sha(Path(shutil.which(n)).resolve())}
             for n in ('nm','aarch64-linux-gnu-objdump')}
    save(folder/'input-index.json',{'files':files,'expected':expected,'installed_read_only_tools':tools,
        'scope':'Joint task source binding, saved API records, behavior and matched allocated RAM only; recorded installed binutils are dependencies. No native toolchain rebuild or full-paper ZIP claim.'})
    return {'captured_files':len(files),'logical_bytes':sum((ROOT/n).stat().st_size for n in files)}


def replay():
    if ROOT == LEON:
        raise ValueError('Use an actual isolated copy')
    index = json.loads((ROOT/'JOINT_REPLAY_MANIFEST.json').read_text())
    def guard(event,args):
        offline(event,args)
        if event == 'subprocess.Popen':
            check_command(args[0],args[1],index['installed_read_only_tools'],ROOT)
        if event == 'open' and isinstance(args[0],(str,bytes,os.PathLike)):
            path = os.fsdecode(args[0])
            if path.startswith(('/dev/tty','/dev/serial')):
                raise RuntimeError('Target-device access is forbidden')
    sys.addaudithook(guard)
    def verify():
        for name,digest in index['files'].items():
            if sha(local_file(ROOT,name)) != digest:
                raise ValueError('Changed isolated input: '+name)
    verify()
    if evaluate() != index['expected']:
        raise ValueError('Isolated joint replay differs')
    verify()
    counts={k:index['expected'][k] for k in ('registered_trials','retained_independent_resets') if k in index['expected']}
    return {'audit':'pass','checked_files':len(index['files']), **counts,
            'actual_isolated_copy_replay':True,'new_model_calls':0,'new_guests':0,
            'original_evidence_network_devices_unapproved_subprocess_prohibited':True,
            'installed_read_only_tools':index['installed_read_only_tools']}


def copy_replay(folder, launcher='tools/replay_tenonos_joint.py', scope=None):
    if ROOT != LEON:
        raise ValueError('Retain copied evidence and logs on leon')
    index = json.loads((folder/'input-index.json').read_text())
    if (folder/'receipt.json').exists():
        raise ValueError('Preserve the completed replay receipt')
    required = sum(local_file(ROOT,n).stat().st_size for n in index['files'])
    if shutil.disk_usage('/dev/shm').free < required+128*1024**2:
        raise ValueError('Insufficient isolated-copy space')
    with tempfile.TemporaryDirectory(prefix='iotos-joint-replay-',dir='/dev/shm') as temporary:
        root = Path(temporary)
        for name,digest in index['files'].items():
            source = local_file(ROOT,name)
            if sha(source) != digest:
                raise ValueError('Input changed before copying')
            target = root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        save(root/'JOINT_REPLAY_MANIFEST.json',index)
        if launcher not in index['files']:
            raise ValueError('Replay launcher must belong to the verified input closure')
        entry = local_file(root,launcher)
        environment = dict(os.environ,PYTHONDONTWRITEBYTECODE='1');environment.pop('PYTHONPATH',None)
        with (folder/'isolated.stdout').open('x') as out,(folder/'isolated.stderr').open('x') as err:
            step = subprocess.run([sys.executable,str(entry),'replay'],
                cwd=root,env=environment,stdout=out,stderr=err,timeout=900)
        if step.returncode:
            raise RuntimeError('Isolated replay failed; retained logs must be inspected')
        result = json.loads((folder/'isolated.stdout').read_text())
    result.update(input_index_sha256=sha(folder/'input-index.json'),temporary_copy_removed=True,
                  scope=scope or 'Same-host isolated input-copy replay, not ZIP, full-paper replay or an external researcher reproduction.')
    save(folder/'receipt.json',result)
    return result


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('capture','copy-replay','replay'))
    parser.add_argument('--folder',type=Path)
    args = parser.parse_args()
    if args.action == 'replay':
        result = replay()
    else:
        if args.folder is None:
            parser.error('Supply --folder')
        result = (capture if args.action == 'capture' else copy_replay)(args.folder.resolve())
    print(json.dumps(result),flush=True)
