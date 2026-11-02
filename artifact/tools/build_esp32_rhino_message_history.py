#!/usr/bin/env python3
"""Build the original GCC5 Rhino message case with buffered heap diagnostics."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from build_esp32_rhino_ram_lifetimes import NATIVE, patched

WRAPS=("tm_main","tm_thread_sleep","krhino_task_create_hook","krhino_task_del_hook",
       "krhino_mm_alloc","krhino_mm_free","krhino_mm_realloc")
FILES=("main.c","port.c","test.c","tm_override.h","tm_message_processing_test.c")


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def observer_source(body,extension=None):
    if extension is None:
        return body
    points=(('static struct { unsigned pointer, usable; } live_blocks[256];',
             extension+'\nstatic struct { unsigned pointer, usable; } live_blocks[256];'),
            ('    controller=krhino_cur_task_get();\n    boundary(0);',
             '    controller=krhino_cur_task_get();\n    if (!wait_bootstrap()) { puts("RHINO_MESSAGE_RAM readiness=FAIL"); return; }\n    boundary(0);'),
            ('    printf("RHINO_MESSAGE_RAM END events=',
             '    report_bootstrap();\n    printf("RHINO_MESSAGE_RAM END events='))
    for anchor,replacement in points:
        if body.count(anchor)!=1:
            raise ValueError("Bootstrap gate source anchor changed")
        body=body.replace(anchor,replacement)
    return body


def build(root,work,output,reference,observer,boot_ready=False):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite source or evidence")
    base=root/"ram-alios-work-v2"
    for name in ("sdkconfig.h","k_config.h"):
        if (base/"board/esp32bench"/name).read_bytes()!=(reference/name).read_bytes():
            raise ValueError("Original GCC5 board configuration differs: "+name)
    for name,pinned in (("port.c","rhino-port-pinned.c"),("portasm.S","rhino-portasm-pinned.S"),
                        ("xtensa_vectors.S","rhino-vectors-pinned.S")):
        if (base/"platform/arch/xtensa/lx6"/name).read_bytes()!=(reference/pinned).read_bytes():
            raise ValueError("Original GCC5 native port differs: "+name)
    shutil.copytree(base,work,ignore=shutil.ignore_patterns("out",".git","__pycache__"))
    output.mkdir(parents=True)
    app=work/"app/example/thread_metric"
    for name in FILES:
        shutil.copyfile(reference/name,app/name)
        shutil.copyfile(reference/name,output/name)
    extension=(observer/"rhino_message_boot_ready.inc").read_text() if boot_ready else None
    (app/"census.c").write_text(observer_source((observer/"rhino_message_history.c").read_text(),extension))
    if boot_ready:
        shutil.copyfile(observer/"rhino_message_boot_ready.inc",output/"boot-ready.inc")
    shutil.copyfile(observer/"rhino_lifetimes/census.c",app/"rhino_lifetimes_core.c")
    make=(reference/"app-aos.mk").read_text()
    make=re.sub(r"^GLOBAL_LDFLAGS.*$","GLOBAL_LDFLAGS += "+" ".join("-Wl,--wrap="+n for n in WRAPS),make,flags=re.M)
    (app/"aos.mk").write_text(make)
    original=root/"downloads/ram-hartstone-alios-v1/alios/ph4/original-k_mm.c"
    if digest(original)!="eabff1b7db1f9b802a5c4cb656047b7e534283aa1d88c95cef6f47428f120fc3":
        raise ValueError("Pinned original allocator differs")
    shutil.copyfile(original,output/"original-k_mm.c")
    (work/"kernel/rhino/k_mm.c").write_bytes(patched(original.read_bytes()))
    tool=root/"alios-gcc5/xtensa-esp32-elf/bin"
    env=dict(os.environ,PATH=str(root/"alios-build-tools/bin")+":"+str(tool)+":"+os.environ["PATH"],
             PYTHONDONTWRITEBYTECODE="1")
    commands=[["aos","make","thread_metric@esp32bench","-c","config"],
              ["aos","make","TM_TEST=message_processing","wifi=0","VERBOSE=1"]]
    for command,name in zip(commands,("configure.log","build.log")):
        with (output/name).open("x") as log:
            subprocess.run(command,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,check=True)
        if re.search(r"Traceback|Error [1-9]|\[ERROR\]|recipe.*failed",(output/name).read_text()):
            raise ValueError("Legacy build failure: "+name)
    if (work/".config").read_bytes()!=(reference/"config").read_bytes():
        raise ValueError("Original GCC5 configuration changed")
    binary=work/"out/thread_metric@esp32bench/binary"
    for name,dest in (("thread_metric@esp32bench.elf","application.elf"),
        ("thread_metric@esp32bench.bin","application.bin"),("thread_metric@esp32bench.map","application.map"),("link.opts","link.opts")):
        shutil.copyfile(binary/name,output/dest)
    for src,dest in (("platform/mcu/esp32/bsp/bootloader.bin","bootloader.bin"),
        ("platform/mcu/esp32/bsp/custom_partitions.bin","partitions.bin"),
        ("board/esp32bench/sdkconfig.h","sdkconfig.h"),("board/esp32bench/k_config.h","k_config.h"),(".config","config")):
        shutil.copyfile(work/src,output/dest)
    for name in ("census.c","rhino_lifetimes_core.c","aos.mk","tm_api.h","tm_porting_layer.h"):
        shutil.copyfile(app/name,output/name)
    for name in NATIVE:
        target=output/"native-source"/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(work/name,target)
    for name in ("port.c","portasm.S","xtensa_vectors.S"):
        target=output/"native-source/platform/arch/xtensa/lx6"/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(work/"platform/arch/xtensa/lx6"/name,target)
    for name,args,logname in (("gcc",["--version"],"compiler.txt"),
        ("nm",["-S",str(output/"application.elf")],"symbols.txt"),
        ("objdump",["-d",str(output/"application.elf")],"disassembly.txt")):
        with (output/logname).open("x") as log:
            subprocess.run([str(tool/("xtensa-esp32-elf-"+name)),*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    shutil.copyfile(__file__,output/"build-script.py")
    report={"status":"build_pass_not_measured","diagnostic_only":True,"original_workload_unchanged":True,
        "compiler":"GCC5 native legacy","ranking_eligible":False,"board_resets":0,"whole_live_ram_peak_bytes":None,
        "bootstrap_readiness_gate":boot_ready,
        "commands":commands,"files":{p.relative_to(output).as_posix():digest(p) for p in output.rglob("*") if p.is_file()}}
    (output/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Original GCC5 Rhino message history built; zero measurements",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    for name in ("workspace","output","reference","observer"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--boot-ready",action="store_true")
    args=parser.parse_args()
    build(args.root,args.workspace,args.output,args.reference,args.observer,args.boot_ready)
