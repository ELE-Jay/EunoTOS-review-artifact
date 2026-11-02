#!/usr/bin/env python3
"""Build the matched GCC13 Rhino message observer, including retained free metadata."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from run_esp32_followup import sha
from build_esp32_rhino_ram_lifetimes import NATIVE,patched
from build_esp32_rhino_message_history import FILES,WRAPS

ROOT=Path(__file__).resolve().parents[1]
REFERENCE='artifacts/reports/esp32-rhino-gcc13-legacy-v1'
OBSERVER=ROOT/'firmware/bsp/esp32/resource_census'


def replace_once(text,old,new):
    if text.count(old)!=1: raise ValueError('Native observation anchor differs: '+old[:70])
    return text.replace(old,new)


def sources():
    core=(OBSERVER/'rhino_lifetimes/census.c').read_text()
    core=core.replace('records[64]','records[16]').replace('record_count==64','record_count==16')
    core=core.replace('timers[64]','timers[16]').replace('timer_count==64','timer_count==16')
    core=replace_once(core,'/* Invoked before the native whole-heap spinlock is released. No allocation. */',
        'static unsigned message_frozen;\n'+(OBSERVER/'rhino_gcc13_message_phases.inc').read_text()+
        '\n/* Invoked before the native whole-heap spinlock is released. No allocation. */')
    core=replace_once(core,'    if (!ready) return;','    if (!ready || message_frozen) return;')
    core=replace_once(core,'    unsigned capacity=0, free_bytes=0, regions=0;',
        '    unsigned capacity=0, free_bytes=0, regions=0, free_headers=0;')
    core=replace_once(core,'            if (b->buf_size & RHINO_MM_FREE) free_bytes+=MM_GET_BLK_SIZE(b);',
        '            if (b->buf_size & RHINO_MM_FREE) { free_bytes+=MM_GET_BLK_SIZE(b); free_headers++; }')
    core=replace_once(core,'    if (occupied!=head->used_size+bias) invalid++;',
        '    if (occupied!=head->used_size+bias) invalid++;\n'
        '    allocated_base=occupied; retained_headers=free_headers; retained_cells=count;\n'
        '    occupied+=free_headers*MMLIST_HEAD_SIZE+count*sizeof(void *);\n'
        '    allocated_phase();')
    message=(OBSERVER/'rhino_message_history.c').read_text()
    message=message.replace('history[512]','history[128]').replace('history_count==512','history_count==128')
    message=message.replace('live_blocks[256]','live_blocks[128]').replace('live_count==256','live_count==128')
    message=message.replace('occupied+fixed_free','allocated_base+fixed_free')
    message=replace_once(message,'    unsigned final_used=occupied, final_legacy=allocated_base+fixed_free, final_fixed=fixed_free;',
        '    unsigned final_used=occupied, final_legacy=allocated_base+fixed_free, final_fixed=fixed_free;\n'
        '    message_frozen=1;')
    message=replace_once(message,'legacy_fixed_pool_reserved=1\\n','retained_free_metadata=1\\n')
    message=replace_once(message,'    for (unsigned i=0;i<4;i++)\n        printf("RHINO_MESSAGE_RAM boundary=',
        '    allocated_phase_report();\n    for (unsigned i=0;i<4;i++)\n        printf("RHINO_MESSAGE_RAM boundary=')
    return core,message


def native_copy(source,target):
    target.mkdir()
    for path in source.iterdir():
        if path.name in ('.git','out','__pycache__','.config','.config.cmd','.defconfig'): continue
        destination=target/path.name
        if path.is_dir():
            if source.name=='mcu' and path.name!='esp32': destination.symlink_to(path,target_is_directory=True)
            else: native_copy(path,destination)
        else: shutil.copy2(path,destination)


def build(root,work,output):
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or work.exists() or output.exists():
        raise ValueError('Use fresh build/evidence directories on leon')
    if shutil.disk_usage('/dev/shm').free<600*1024**2:
        raise ValueError('Insufficient temporary native build capacity')
    reference=ROOT/REFERENCE;metadata=json.loads((reference/'build.json').read_text())
    work.mkdir();output.mkdir(parents=True)
    native=work/'source';native_copy(root/'AliOS-Things-bacc144bdc5df8fe8e302e3732675a920aa40bc5',native)
    app=native/'app/example/thread_metric';app.mkdir(exist_ok=True)
    for name in FILES:
        shutil.copyfile(reference/name,app/name)
    for name in ('sdkconfig.h','k_config.h'):
        shutil.copyfile(reference/name,native/'board/esp32bench'/name)
    shutil.copyfile(reference/'examples-Config.in',native/'app/example/Config.in')
    for name,pinned in (('port.c','rhino-port-pinned.c'),('portasm.S','rhino-portasm-pinned.S'),
            ('xtensa_vectors.S','rhino-vectors-pinned.S')):
        shutil.copyfile(reference/pinned,native/'platform/arch/xtensa/lx6'/name)
    for name in ('tm_api.h','tm_porting_layer.h'):
        shutil.copyfile(root/'threadx-6.2.1_rel/utility/benchmarks/thread_metric'/name,app/name)
    core,message=sources();(app/'rhino_lifetimes_core.c').write_text(core);(app/'census.c').write_text(message)
    make=(reference/'app-aos.mk').read_text()
    make=re.sub(r'^GLOBAL_LDFLAGS.*$','',make,flags=re.M)
    make+='\n$(NAME)_SOURCES += census.c\nGLOBAL_LDFLAGS += '+' '.join('-Wl,--wrap='+n for n in WRAPS)+'\n'
    (app/'aos.mk').write_text(make)
    allocator=native/'kernel/rhino/k_mm.c'
    original=allocator.read_bytes()
    if sha(allocator)!='eabff1b7db1f9b802a5c4cb656047b7e534283aa1d88c95cef6f47428f120fc3':
        raise ValueError('Native allocator source changed')
    shutil.copyfile(allocator,output/'original-k_mm.c');allocator.write_bytes(patched(original))
    tools=work/'tools';tools.mkdir()
    gcc=root/'idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin'
    wrapper=ROOT/'firmware/bsp/esp32/alios_board/xtensa-esp32-elf-gcc-legacy-newlib.sh'
    shutil.copyfile(wrapper,tools/'xtensa-esp32-elf-gcc');(tools/'xtensa-esp32-elf-gcc').chmod(0o755)
    for path in gcc.glob('xtensa-esp32-elf-*'):
        if path.name!='xtensa-esp32-elf-gcc': (tools/path.name).symlink_to(path)
    env=dict(os.environ,ESP32_PILOT_ROOT=str(root),PYTHONDONTWRITEBYTECODE='1',
        PATH=str(tools)+':'+str(root/'alios-build-tools/bin')+':'+os.environ['PATH'])
    commands=[['aos','make','thread_metric@esp32bench','-c','config','TOOLCHAIN_PATH='+str(tools)+'/'],
        ['aos','make','TM_TEST=message_processing','wifi=0','VERBOSE=1','TOOLCHAIN_PATH='+str(tools)+'/']]
    passed=True
    for name,command in zip(('configure.log','build.log'),commands):
        with (output/name).open('x') as log:
            result=subprocess.run(command,cwd=native,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        if result.returncode or re.search(r'Traceback|\[ERROR\]|make: \*\*\*|Error [1-9]',(output/name).read_text()):
            passed=False;break
        if name=='configure.log' and 'AOS_BUILD_APP="thread_metric"' not in (native/'.config').read_text().splitlines():
            passed=False;break
    if passed and (native/'.config').read_bytes()!=(reference/'config').read_bytes():
        raise ValueError('Original native configuration changed')
    shutil.copytree(app,output/'application-source')
    shutil.copyfile(__file__,output/'builder.py');shutil.copyfile(wrapper,output/'compiler-wrapper.sh')
    if passed:
        binary=native/'out/thread_metric@esp32bench/binary'
        for src,dst in (('thread_metric@esp32bench.elf','application.elf'),
            ('thread_metric@esp32bench.bin','application.bin'),('thread_metric@esp32bench.map','application.map'),('link.opts','link.opts')):
            shutil.copyfile(binary/src,output/dst)
        for src,dst in (('platform/mcu/esp32/bsp/bootloader.bin','bootloader.bin'),
            ('platform/mcu/esp32/bsp/custom_partitions.bin','partitions.bin'),('.config','config'),
            ('board/esp32bench/sdkconfig.h','sdkconfig.h'),('board/esp32bench/k_config.h','k_config.h')):
            shutil.copyfile(native/src,output/dst)
        for name in NATIVE:
            destination=output/'native-source'/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(native/name,destination)
        for name in ('port.c','portasm.S','xtensa_vectors.S'):
            destination=output/'native-source/platform/arch/xtensa/lx6'/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(native/'platform/arch/xtensa/lx6'/name,destination)
        for command,args,name in (('gcc',['--version'],'compiler.txt'),('nm',['-S',str(output/'application.elf')],'symbols.txt'),
                ('objdump',['-d',str(output/'application.elf')],'disassembly.txt')):
            with (output/name).open('x') as log:
                subprocess.run([str(tools/('xtensa-esp32-elf-'+command)),*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    record={'status':'build_pass_not_measured' if passed else 'build_failed','os':'AliOS-Rhino',
        'compiler':'GCC13 / original legacy Newlib and SDK ABI','commands':commands,'board_resets':0,'ranking_eligible':False,
        'reference_build_sha256':sha(reference/'build.json'),'bootstrap_readiness_gate':False,
        'scope':'Unchanged native GCC13 original-message workload; no forced main retirement; native initialized-heap unlock hooks include retained free headers and fixed-cell pointers, record pre-scheduler/native-scheduler peaks; observer included and actual stack auxiliary',
        'files':{p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k!='files'}))
    return 0 if passed else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();raise SystemExit(build(args.root,args.workspace,args.output))
