#!/usr/bin/env python3
"""Build original Rhino PH4 with initialized-heap and native task lifetimes."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

NATIVE=("kernel/rhino/k_mm.c","kernel/rhino/k_mm_blk.c","kernel/rhino/k_task.c",
    "kernel/rhino/k_sem.c","kernel/rhino/k_sys.c","kernel/rhino/k_dyn_mem_proc.c",
    "kernel/rhino/k_idle.c","kernel/rhino/include/k_task.h","kernel/rhino/include/k_sem.h",
    "kernel/rhino/include/k_mm.h","kernel/rhino/include/k_mm_blk.h","kernel/rhino/include/k_obj.h",
    "kernel/rhino/include/k_default_config.h","kernel/rhino/include/k_internal.h","platform/mcu/esp32/aos/hook_impl.c",
    "platform/mcu/esp32/aos/soc_impl.c","platform/mcu/esp32/aos/heap_wrapper.c",
    "platform/mcu/esp32/hal/uart.c","platform/mcu/esp32/bsp/include/driver/include/driver/uart.h",
    "platform/mcu/esp32/espos/platform/rhino/espos_task.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_context.h",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h",
    "platform/mcu/esp32/bsp/include/esp32/include/esp_timer.h")
ORIGINAL=("main.c","workload.c","small_whetstone.c","small_whetstone.h","ph_us_schedule.h")
WRAPS=("application_start","krhino_task_suspend","krhino_task_create_hook","krhino_task_del_hook",
    "krhino_mm_free","krhino_sem_take","esp_timer_create","esp_timer_delete","krhino_idle_hook")
ADDITIONS="\n$(NAME)_SOURCES += census.c\nGLOBAL_DEFINES += BENCH_RAM_LIFETIMES=1\nGLOBAL_LDFLAGS += "+" ".join("-Wl,--wrap="+n for n in WRAPS)+"\n"


def patched(body):
    text=body.decode()
    anchor='#include "k_api.h"\n'
    observer='''
extern void bench_h_observe(k_mm_head *);
extern void bench_h_heap_ready(k_mm_head *);
#undef MM_CRITICAL_EXIT
#define MM_CRITICAL_EXIT(head,state) do { bench_h_observe(head); krhino_spin_unlock_irq_restore(&(head)->mm_lock,state); } while (0)
'''
    end='    }\n}\n\n/* init a region'
    if text.count(anchor)!=1 or text.count(end)!=1:
        raise ValueError("Native initialized-heap/unlock observation anchor differs")
    return text.replace(anchor,anchor+observer).replace(end,'    }\n    bench_h_heap_ready(g_kmm_head);\n}\n\n/* init a region').encode()


def build(root,work,output,observer):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite source/evidence")
    base=Path("/dev/shm/iotos-rhino-gcc13-work-v1")
    shutil.copytree(base,work,ignore=shutil.ignore_patterns("out",".git","__pycache__"))
    output.mkdir(parents=True)
    reference=root/"downloads/hartstone-alios-native-v4/ph4"
    app=work/"app/example/hartstone"
    app.mkdir(parents=True,exist_ok=True)
    for name in ORIGINAL:
        shutil.copyfile(reference/name,app/name)
        shutil.copyfile(reference/name,output/name)
    shutil.copyfile(observer/"census.c",app/"census.c")
    (app/"aos.mk").write_bytes((reference/"aos.mk").read_bytes()+ADDITIONS.encode())
    shutil.copyfile(root/"hartstone_alios/Config.in",app/"Config.in")
    shutil.copyfile(root/"hartstone_alios/examples-Config.in",work/"app/example/Config.in")
    for name in ("sdkconfig.h","k_config.h"):
        shutil.copyfile(reference/name,work/"board/esp32bench"/name)
    shutil.copyfile(reference/"config",work/".config")
    for name,dest in (("rhino-port-pinned.c","port.c"),("rhino-portasm-pinned.S","portasm.S"),
                      ("rhino-vectors-pinned.S","xtensa_vectors.S")):
        shutil.copyfile(reference/name,work/"platform/arch/xtensa/lx6"/dest)
    allocator=work/"kernel/rhino/k_mm.c"
    shutil.copyfile(root/"downloads/ram-hartstone-alios-v1/alios/ph4/original-k_mm.c",allocator)
    if sha256(allocator.read_bytes()).hexdigest()!="eabff1b7db1f9b802a5c4cb656047b7e534283aa1d88c95cef6f47428f120fc3":
        raise ValueError("Pinned native allocator input differs")
    shutil.copyfile(allocator,output/"original-k_mm.c")
    allocator.write_bytes(patched(allocator.read_bytes()))
    toolchain=Path("/dev/shm/iotos-rhino-gcc13-legacy-tools")
    env=dict(os.environ,PATH=str(root/"alios-build-tools/bin")+":"+str(toolchain)+":"+os.environ["PATH"],
             PYTHONDONTWRITEBYTECODE="1",ESP32_PILOT_ROOT=str(root))
    (work/"tmp").mkdir()
    env["TMPDIR"]=str(work/"tmp")
    commands=[["aos","make","hartstone@esp32bench","-c","config","TOOLCHAIN_PATH="+str(toolchain)+"/"],
              ["aos","make","PH_EXPERIMENT=4","wifi=0","VERBOSE=1","TOOLCHAIN_PATH="+str(toolchain)+"/"]]
    for command,name in zip(commands,("configure.log","build.log")):
        with (output/name).open("x") as log:
            subprocess.run(command,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,check=True)
        if re.search(r"Traceback|Error [1-9]|\[ERROR\]|recipe.*failed",(output/name).read_text()):
            raise ValueError("Legacy build reported a failure: "+name)
        if name=="configure.log" and ('AOS_BUILD_BOARD="esp32bench"' not in (work/".config").read_text() or
                                      'AOS_BUILD_APP="hartstone"' not in (work/".config").read_text()):
            raise ValueError("Legacy configuration selected a different app")
    binary=work/"out/hartstone@esp32bench/binary"
    for name,dest in (("hartstone@esp32bench.elf","application.elf"),("hartstone@esp32bench.bin","application.bin"),
                      ("hartstone@esp32bench.map","application.map"),("link.opts","link.opts")):
        shutil.copyfile(binary/name,output/dest)
    for name,dest in (("platform/mcu/esp32/bsp/bootloader.bin","bootloader.bin"),
        ("platform/mcu/esp32/bsp/custom_partitions.bin","partitions.bin"),
        ("board/esp32bench/sdkconfig.h","sdkconfig.h"),("board/esp32bench/k_config.h","k_config.h"),
        (".config","config"),("app/example/Config.in","examples-Config.in")):
        shutil.copyfile(work/name,output/dest)
    for name in ("aos.mk","census.c","Config.in"):
        shutil.copyfile(app/name,output/name)
    for name in ("aos.mk","config"):
        shutil.copyfile(reference/name,output/("original-"+name))
    for name in NATIVE:
        dest=output/"native-source"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(work/name,dest)
    for name,src in (("rhino-port-pinned.c","port.c"),("rhino-portasm-pinned.S","portasm.S"),
                     ("rhino-vectors-pinned.S","xtensa_vectors.S")):
        shutil.copyfile(work/"platform/arch/xtensa/lx6"/src,output/name)
    for name in ("platform/mcu/esp32/libc.a","platform/mcu/esp32/lib/libnewlib.a","platform/mcu/esp32/lib/libesp32.a"):
        shutil.copyfile(work/name,output/Path(name).name)
    from prepare_esp32_rhino_abi import prepare
    prepare(root,work,output,root/"audit-workspace/firmware/bsp/esp32/alios_board/newlib_abi_probe.c",
            root/"audit-workspace/firmware/bsp/esp32/alios_board/xtensa-esp32-elf-gcc-legacy-newlib.sh")
    for name,args,logname in (("gcc",["--version"],"compiler.txt"),("nm",["-S",str(output/"application.elf")],"symbols.txt"),
        ("objdump",["-d",str(output/"application.elf")],"disassembly.txt")):
        with (output/logname).open("x") as log:
            subprocess.run([str(toolchain/("xtensa-esp32-elf-"+name)),*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    shutil.copyfile(__file__,output/"build-script.py")
    (output/"image.sha256").write_text("".join(sha256(p.read_bytes()).hexdigest()+"  "+p.relative_to(output).as_posix()+"\n"
        for p in sorted(output.rglob("*")) if p.is_file()))
    report={"status":"build_pass_not_measured","board_resets":0,"ranking_eligible":False,"os":"AliOS-Rhino",
        "compiler":"GCC13 / legacy GCC5 Newlib headers and pinned precompiled SDK libraries",
        "original_workload_unchanged":True,"whole_live_ram_peak_bytes":None,"commands":commands,
        "window":"native heap initialized through original controller suspended, observed from existing idle",
        "files":{p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in output.rglob("*") if p.is_file()}}
    (output/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Original Rhino PH4 + native lifetimes built; zero measurements",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    for name in ("workspace","output","observer"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    build(args.root,args.workspace,args.output,args.observer)
