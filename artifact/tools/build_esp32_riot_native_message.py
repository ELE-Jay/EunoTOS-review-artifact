#!/usr/bin/env python3
"""Rebuild the unmodified native RIOT message benchmark with the B1 GCC13 route."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess

NATIVE=("core/msg.c","core/thread.c","core/sched.c","core/include/msg.h","core/include/thread.h",
    "core/include/sched.h","sys/include/xtimer.h","sys/include/ztimer/xtimer_compat.h","sys/include/ztimer.h",
    "sys/ztimer/core.c","sys/ztimer/init.c","sys/ztimer/convert.c","sys/ztimer/convert_frac.c",
    "sys/ztimer/convert_shift.c","sys/ztimer/periph_timer.c","cpu/esp32/periph/timer.c",
    "cpu/esp_common/esp-xtensa/thread_arch.c","cpu/esp_common/syscalls.c","cpu/esp32/startup.c",
    "sys/test_utils/interactive_sync/interactive_sync.c")


def build(root,work,output):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite original build/evidence")
    work.mkdir(parents=True); output.mkdir(parents=True)
    riot=root/"RIOT-2024.10-devel"
    original=riot/"tests/bench/msg_pingpong"
    baseline=root/"downloads/riot-original-v1/msg_pingpong"
    for p in (baseline/"source").iterdir():
        if p.is_file() and p.read_bytes()!=(original/p.name).read_bytes():
            raise ValueError("Original benchmark source changed")
    gcc=root/"idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    wrapper=root/"audit-workspace/tools/gcc13-legacy-newlib.sh"
    native_headers=work/"native-compiler-headers"
    native_headers.mkdir()
    atomic=gcc.parent/"lib/gcc/xtensa-esp-elf/13.2.0/include/stdatomic.h"
    (native_headers/"stdatomic.h").symlink_to(atomic)
    env=dict(os.environ,PATH=str(gcc)+":"+str(root/"bin")+":"+os.environ["PATH"],
             PYTHONDONTWRITEBYTECODE="1",CFLAGS="-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1 -I"+str(native_headers),TMPDIR=str(work))
    command=["make","-C",str(original),"-j2","QUIET=0","V=1","BOARD=esp32-wroom-32",
        "BINDIRBASE="+str(work/"bin"),"RIOT_VERSION=2024.10-devel","FLASH_MODE=dio","FLASH_SIZE=4","CC="+str(wrapper)]
    with (output/"build.log").open("x") as log:
        subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=work/"bin/esp32-wroom-32"
    for src,dest in (("tests_msg_pingpong.elf","application.elf"),("tests_msg_pingpong.elf.bin","application.bin"),
        ("tests_msg_pingpong.map","application.map"),("esp_bootloader/bootloader.bin","bootloader.bin"),
        ("partitions.bin","partitions.bin"),("riotbuild/riotbuild.h","config")):
        shutil.copyfile(binary/src,output/dest)
    (output/"source").mkdir()
    for p in (baseline/"source").iterdir():
        if p.is_file(): shutil.copyfile(p,output/"source"/p.name)
    for src,dest in (("tests/bench/Makefile.bench_common","Makefile.bench_common"),
        ("tests/Makefile.tests_common","Makefile.tests_common")):
        shutil.copyfile(riot/src,output/dest)
    for name in NATIVE:
        dest=output/"native-source"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(riot/name,dest)
    shutil.copyfile(wrapper,output/"compiler-wrapper.sh")
    shutil.copyfile(atomic,output/"compiler-stdatomic.h")
    shutil.copyfile(gcc.parent/"xtensa-esp-elf/lib/esp32/libg_nano.a",output/"libg_nano.a")
    shutil.copyfile(Path("/dev/shm/iotos-riot-lifetimes-v7/official-native-library.json"),output/"official-native-library.json")
    shutil.copyfile(__file__,output/"build-script.py")
    for name,args,dest in (("gcc",["--version"],"compiler.txt"),("nm",["-S",str(output/"application.elf")],"symbols.txt"),
                           ("objdump",["-d",str(output/"application.elf")],"disassembly.txt")):
        with (output/dest).open("x") as log:
            subprocess.run([str(gcc/("xtensa-esp32-elf-"+name)),*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    report={"status":"build_pass_not_measured","board_resets":0,"ranking_eligible":False,"os":"RIOT",
        "command":command,"original_body_unchanged":True,"compiler":"GCC13 / GCC12 headers / GCC13 Newlib-nano",
        "clock_hz":240000000,"cores":1,"tick_hz":0,"original_duration_us":1000000,
        "files":{p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in output.rglob("*") if p.is_file()}}
    (output/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Unchanged native RIOT msg_pingpong built; no board measurements",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    build(args.root,args.workspace,args.output)
