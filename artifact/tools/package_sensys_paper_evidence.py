#!/usr/bin/env python3
"""Freeze and replay the current paper's measured evidence without devices or APIs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LEON = Path('/home/reviewer/esp32-pilot/audit-workspace')
PREFIX = 'IoTOSBench-ESP32-reproduction/'
MANIFEST = 'paper-evidence-manifest.json'
SCOPE = ('Current paper numerical tables and audited HTML evidence closure, including separate '
         'ESP32 and Pi/KVM tracks. Installed Python dependencies and cross-binutils are required. '
         'Not a toolchain rebuild, author-engine identity, external acquisition, or proof that '
         'unmeasured research requirements are complete.')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_python(path):
    return any(path.resolve().is_relative_to(Path(p).resolve()) for p in (sys.prefix,sys.base_prefix))


def live_tool_bytecode(root,path):
    return path.resolve().parent == (root/'tools/__pycache__').resolve() and path.suffix == '.pyc'


def original_evidence(path):
    return any(path.resolve().is_relative_to(p.resolve()) for p in
               (LEON.parent,Path('/home/reviewer/IoTOSBench-data'),Path('/dev/shm')))


def local_file(root, name):
    path = root / name
    if not name or Path(name).is_absolute() or '..' in Path(name).parts or '\\' in name or \
            not path.resolve().is_relative_to(root.resolve()) or path.is_symlink() or not path.is_file():
        raise ValueError('Unsafe or missing input: '+name)
    if path.name == 'original-flash.bin' or path.suffix == '.key':
        raise ValueError('Private device backup or credential cannot be packaged')
    return path


def checks(root, reference):
    from audit_sensys_runtime_tables import audit
    from check_tenonos_expanded_publication import check_expanded
    from render_esp32_benchmark import render, validate
    measured = json.loads(json.dumps(audit(root/'paper/sensys2027/iotosbench.tex')))
    if measured != json.loads(local_file(root, reference).read_text()):
        raise ValueError('Current manuscript differs from its source-bound audit')
    expanded = check_expanded(root, measured)
    data = json.loads((root/'artifacts/reports/esp32-benchmark-v1.json').read_text())
    validate(data)
    html = render(data).encode('utf-8')
    if html != (root/'benchmark_esp32.html').read_bytes():
        raise ValueError('HTML differs from complete evidence-dependent regeneration')
    labels = set(measured['tables']) | set(expanded['additionally_checked_tables'])
    return {'pass':True,'numeric_tables':len(labels),
        'table_labels':sorted(labels), 'historical_rows':len(data['rows']),
        'manuscript_sha256':measured['manuscript_sha256'],
        'paper_audit_sha256':sha(root/reference), 'html_sha256':hashlib.sha256(html).hexdigest(),
        'pdf_sha256':sha(root/'paper/sensys2027/build/iotosbench.pdf'),
        'new_board_boots':0,'new_guest_boots':0,'new_model_calls':0,'scope':SCOPE}


def capture(folder, reference):
    if ROOT != LEON:
        raise ValueError('Read real evidence only in the leon workspace')
    folder.resolve().relative_to(ROOT/'artifacts/reports')
    folder.mkdir(exist_ok=False)
    seen = set()
    active = True

    def observe(event, args):
        if not active or event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)) or \
                args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            return
        path = Path(os.fsdecode(args[0])).resolve()
        if path.is_relative_to(ROOT) and not installed_python(path) and not live_tool_bytecode(ROOT,path):
            seen.add(path)

    sys.addaudithook(observe)
    result = checks(ROOT, reference)
    active = False
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT) and not installed_python(path) and not live_tool_bytecode(ROOT,path):
                seen.add(path)
    extras = ('tools/package_sensys_paper_evidence.py', 'tools/test_sensys_paper_evidence.py',
        'tools/package_esp32_followup.py', 'paper/sensys2027/build/iotosbench.pdf',
        'paper/sensys2027/README.md', 'paper/sensys2027/review/claim-evidence-ledger.md',
        'paper/sensys2027/review/nearest-work-matrix.md', 'TENONOS_RPI4_REPRODUCTION.md',
        'DATA_STORAGE_POLICY.md', 'reproduction/USE_POLICY.md')
    seen.update(local_file(ROOT,n) for n in extras)
    files = {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(seen) if p.is_file()}
    index = {'status':'verified','files':files,'paper_audit':reference,'checks':result,'scope':SCOPE,
             'installed_python_version':sys.version}
    (folder/'input-index.json').write_text(json.dumps(index,indent=2)+'\n')
    print(json.dumps({'status':'verified','files':len(files),
        'logical_bytes':sum((ROOT/n).stat().st_size for n in files),'checks':result}))


def replay():
    index = json.loads((ROOT/MANIFEST).read_text())
    if index.get('installed_python_version') != sys.version:
        raise ValueError('Use the recorded Python runtime version')
    for name,digest in index['files'].items():
        if sha(local_file(ROOT,name)) != digest:
            raise ValueError('Changed packaged input: '+name)
    if checks(ROOT,index['paper_audit']) != index['checks']:
        raise ValueError('Isolated paper or HTML replay differs')
    if any(sha(ROOT/n) != h for n,h in index['files'].items()):
        raise ValueError('Offline replay changed packaged inputs')
    print(json.dumps(index['checks']))


def package(folder, archive):
    from package_esp32_followup import verify_archive_members, extract_private_archive
    if ROOT != LEON:
        raise ValueError('Package evidence on leon')
    archive.resolve().relative_to(ROOT/'reproduction')
    if archive.exists():
        raise ValueError('Refusing to overwrite a package')
    index = json.loads((folder/'input-index.json').read_text())
    if index['status'] != 'verified':
        raise ValueError('Unverified read closure')
    payloads = dict(index['files'])
    for name,digest in payloads.items():
        if sha(local_file(ROOT,name)) != digest:
            raise ValueError('Indexed source changed: '+name)
    manifest = json.dumps(index,indent=2)+'\n'
    readme = ('# Private IoTOSBench paper evidence\n\n'+SCOPE+'\n\n'
        'Run on leon, from this extracted directory:\n\n'
        '    /home/reviewer/esp32-pilot/reproduction-audit-runtime/bin/python '
        'tools/package_sensys_paper_evidence.py replay\n\n'
        'No API or hardware is required. Original Qwen and failed records remain unchanged; '
        'the archive covers the inputs actually used by the current paper/HTML audits, '
        'not every historical experiment in the private repository. '
        'The shared legacy directory prefix does not combine the ESP32 and ARM64 tracks.\n')
    if shutil.disk_usage('/dev/shm').free < sum((ROOT/n).stat().st_size for n in payloads)+128*1024**2:
        raise ValueError('Insufficient isolated replay space')
    with tempfile.TemporaryDirectory(prefix='sensys-paper-archive-',dir=archive.parent) as staging, \
            tempfile.TemporaryDirectory(prefix='sensys-paper-evidence-',dir='/dev/shm') as tmp:
        temporary = Path(tmp)
        packed = Path(staging)/'paper.zip'
        with zipfile.ZipFile(packed,'x',zipfile.ZIP_DEFLATED) as stream:
            for name,digest in sorted(payloads.items()):
                raw = (ROOT/name).read_bytes()
                if hashlib.sha256(raw).hexdigest() != digest or re.search(rb'\bsk-[A-Za-z0-9_-]{24,}',raw):
                    raise ValueError('Changed input or potential credential: '+name)
                stream.writestr(PREFIX+name,raw)
            for name,raw in ((MANIFEST,manifest),('PAPER_REPLAY.md',readme)):
                stream.writestr(PREFIX+name,raw)
                payloads[name] = hashlib.sha256(raw.encode()).hexdigest()
            stream.writestr(PREFIX+'SHA256SUMS',''.join(h+'  '+n+'\n' for n,h in sorted(payloads.items())))
        if shutil.disk_usage(archive.parent).free < 96*1024**2:
            raise ValueError('Insufficient persistent leon space for the verified ZIP')
        with zipfile.ZipFile(packed) as stream:
            verify_archive_members(stream)
            extract_private_archive(stream,temporary/'extracted')
        env = {k:v for k,v in os.environ.items() if k not in
               ('PYTHONPATH','PYTHONHOME','DEEPSEEK_API_KEY','OPENROUTER_API_KEY')}
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        with (folder/'isolated-replay.log').open('x') as output:
            subprocess.run([sys.executable,'-s','tools/package_sensys_paper_evidence.py','replay'],
                cwd=temporary/'extracted'/PREFIX,env=env,check=True,stdout=output,stderr=subprocess.STDOUT)
        digest = sha(packed)
        os.link(packed,archive)
        if sha(archive) != digest:
            raise ValueError('Persistent ZIP differs from the replayed archive')
    receipt = {'pass':True,'archive':str(archive),'files':len(payloads),
        'archive_sha256':digest,'archive_bytes':archive.stat().st_size,
        'isolated_actual_zip_replay':True,'checks':index['checks'],'scope':SCOPE}
    (folder/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


def offline(event,args):
    if event in ('socket.connect','socket.getaddrinfo'):
        raise RuntimeError('Paper evidence replay must remain offline')
    if ROOT != LEON:
        if event == 'open' and isinstance(args[0],(str,bytes,os.PathLike)) and \
                original_evidence(Path(os.fsdecode(args[0]))) and \
                not Path(os.fsdecode(args[0])).resolve().is_relative_to(ROOT.resolve()) and \
                not installed_python(Path(os.fsdecode(args[0]))):
            raise RuntimeError('Isolated replay cannot read the original evidence workspace')
        if event == 'subprocess.Popen':
            command = args[1] if isinstance(args[1],(list,tuple)) else [args[1]]
            if any(any(str(p) in os.fsdecode(v) for p in (LEON.parent,Path('/home/reviewer/IoTOSBench-data')))
                   for v in [*command,args[2]]
                   if isinstance(v,(str,bytes,os.PathLike))):
                raise RuntimeError('Isolated subprocess cannot use original workspace paths')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('capture','package','replay'))
    p.add_argument('--folder',type=Path)
    p.add_argument('--paper-audit')
    p.add_argument('--archive',type=Path)
    a = p.parse_args()
    if sys.platform == 'darwin':
        p.error('Real evidence and packages must remain on leon')
    sys.addaudithook(offline)
    if a.mode == 'replay':
        replay()
    elif a.mode == 'capture' and a.folder and a.paper_audit:
        capture(a.folder,a.paper_audit)
    elif a.mode == 'package' and a.folder and a.archive:
        package(a.folder,a.archive)
    else:
        p.error('Supply --folder plus --paper-audit or --archive')
