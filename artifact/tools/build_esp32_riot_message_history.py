#!/usr/bin/env python3
"""Observe the matched original RIOT message test, including free-list metadata."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
OBSERVER=ROOT/'firmware/bsp/esp32/resource_census'


def source():
    text=(OBSERVER/'riot_lifetimes/census.c').read_text()
    prefix=text[:text.index('int __real__sema_wait_ztimer')]
    prefix=prefix.replace('static kernel_pid_t main_pid;\n','').replace(
        'static unsigned validating, validation_peak, returned, complete;',
        'static unsigned validating, validation_peak, complete;')
    prefix=prefix.replace('static uint32_t observe(void)',
        'static uint32_t allocated(uint32_t, uint32_t);\n\nstatic uint32_t observe(void)')
    before='    uint32_t occupied=committed-(uint32_t)info.fordblks;'
    if prefix.count(before)!=1:
        raise ValueError('Original native allocator observation anchor changed')
    prefix=prefix.replace(before,'    uint32_t occupied=allocated(committed,(uint32_t)info.fordblks);')
    prefix=prefix.replace('if (observing) { __real___malloc_unlock(r); return; }',
        'if (observing || complete) { __real___malloc_unlock(r); return; }')
    return prefix+(OBSERVER/'riot_message_history.inc').read_text()


def build(root,work,output):
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or work.exists() or output.exists():
        raise ValueError('Build only on leon in fresh directories')
    reference=ROOT/'artifacts/reports/esp32-riot-gcc13-legacy-v1'
    metadata=json.loads((reference/'build.json').read_text())
    app=work/'source';app.mkdir(parents=True);output.mkdir(parents=True)
    names=('main.c','port.c','test.c','tm_override.h','riot_tm_baseline.inc','Makefile')
    for name in names:
        path=reference/'source'/name
        key=next(k for k in metadata['source_sha256'] if k.endswith('/source/'+name))
        if sha(path)!=metadata['source_sha256'][key]:
            raise ValueError('Matched original source changed: '+name)
        shutil.copyfile(path,app/name)
    with (app/'Makefile').open('a') as f:
        f.write('\nCFLAGS += -DSCHED_TEST_STACK=1\nLINKFLAGS += '+
            ' '.join('-Wl,--wrap='+n for n in ('_sbrk_r','__malloc_unlock','thread_create','main','tm_thread_sleep'))+'\n')
    (app/'census.c').write_text(source())
    gcc=root/'idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin'
    headers=app/'native-compiler-headers';headers.mkdir()
    shutil.copyfile(gcc.parent/'lib/gcc/xtensa-esp-elf/13.2.0/include/stdatomic.h',headers/'stdatomic.h')
    with (app/'Makefile').open('a') as f:
        f.write('CFLAGS += -I$(CURDIR)/native-compiler-headers\n')
    command=['make','-C',str(app),'-j2','TEST=message_processing','QUIET=0',
        'RIOTBASE='+str(root/'RIOT-2024.10-devel'),
        'TM_SOURCE='+str(root/'threadx-6.2.1_rel/utility/benchmarks/thread_metric'),
        'CC='+str(ROOT/'tools/gcc13-legacy-newlib.sh'),'BINDIRBASE='+str(work/'bin'),
        'FLASH_MODE=dio','FLASH_SIZE=4','RIOT_VERSION=2024.10-devel']
    env=dict(os.environ,PATH=str(gcc)+':'+str(root/'bin')+':'+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
    for key in ('CPATH','C_INCLUDE_PATH','LINKFLAGS'):
        env.pop(key,None)
    with (output/'build.log').open('x') as log:
        result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
    shutil.copytree(app,output/'application-source')
    shutil.copyfile(__file__,output/'builder.py')
    if result.returncode==0:
        binary=work/'bin/esp32-wroom-32'
        for src,dst in (('thread-metric-message_processing.elf','application.elf'),
            ('thread-metric-message_processing.elf.bin','application.bin'),('thread-metric-message_processing.map','application.map'),
            ('esp_bootloader/bootloader.bin','bootloader.bin'),('partitions.bin','partitions.bin'),('riotbuild/riotbuild.h','config')):
            shutil.copyfile(binary/src,output/dst)
        for name in ('bootloader.elf','bootloader.map'):
            shutil.copyfile(binary/'esp_bootloader'/name,output/name)
        for name,args in (('nm',['-S']),('objdump',['-d'])):
            with (output/(name+'.txt')).open('x') as f:
                subprocess.run([str(gcc/('xtensa-esp32-elf-'+name)),*args,str(output/'application.elf')],
                    env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
    record={'status':'build_pass_not_measured' if result.returncode==0 else 'build_failed',
        'returncode':result.returncode,'os':'RIOT','case':'message_processing','command':command,
        'reference_build_sha256':sha(reference/'build.json'),'board_resets':0,'ranking_eligible':False,
        'scope':'Original message source and native port retained; startup allocator unlocks through the third original report; metadata retained in free blocks included; observer included; actual stack watermark auxiliary',
        'files':{p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k!='files'}))
    return result.returncode


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    raise SystemExit(build(args.root,args.workspace,args.output))
