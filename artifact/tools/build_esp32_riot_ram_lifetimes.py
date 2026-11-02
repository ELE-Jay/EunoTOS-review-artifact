#!/usr/bin/env python3
"""Build the original persistent-worker PH4 with native RIOT lifetime evidence."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess

NATIVE=("core/lib/init.c","core/thread.c","core/sched.c","core/include/thread.h","core/include/sched.h",
    "core/include/mutex.h","core/mutex.c","sys/include/sema.h","sys/sema/sema.c",
    "sys/newlib_syscalls_default/syscalls.c","cpu/esp_common/syscalls.c",
    "cpu/esp_common/esp-xtensa/thread_arch.c","cpu/esp_common/vendor/xtensa/portasm.S")
SDK_FILES=("components/esp_hw_support/esp_clk.c","components/esp_hw_support/include/esp_private/esp_clk.h",
           "components/esp_rom/include/esp_rom_uart.h")
SUPPORT=("cpu/esp_common/freertos/task.c","cpu/esp32/startup.c")
SUPPORT_SDK=("components/esp_timer/src/esp_timer.c",)


def patched(original):
    before="    while (1) {\n        if (IS_USED(MODULE_PERIPH_PM)) {"
    after="    extern void bench_r_idle(void);\n    while (1) {\n        bench_r_idle();\n        if (IS_USED(MODULE_PERIPH_PM)) {"
    text=original.decode()
    if text.count(before)!=1:
        raise ValueError("Native idle observation anchor differs")
    return text.replace(before,after).encode()


def build(root,work,output,observer):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite source/evidence")
    work.mkdir(parents=True); output.mkdir(parents=True)
    riot=work/"RIOT"
    riot.mkdir()
    for path in (root/"RIOT-2024.10-devel").iterdir():
        if path.name=="core":
            shutil.copytree(path,riot/path.name,ignore=shutil.ignore_patterns("__pycache__"))
        else:
            (riot/path.name).symlink_to(path,target_is_directory=path.is_dir())
    original=riot/"core/lib/init.c"
    shutil.copyfile(original,output/"original-init.c")
    original.write_bytes(patched(original.read_bytes()))
    app=work/"app"
    app.mkdir()
    for name in ("Makefile","census.c"):
        shutil.copyfile(observer/name,app/name)
    reference=root/"downloads/hartstone-riot-native-v4/ph4"
    for name in ("main.c","workload.c"):
        actual=root/"hartstone_riot"/name
        if actual.read_bytes()!=(reference/name).read_bytes():
            raise ValueError("Original workload changed")
        shutil.copyfile(actual,app/name); shutil.copyfile(actual,output/name)
    for name in ("small_whetstone.c","small_whetstone.h","ph_us_schedule.h"):
        actual=root/("hartstone_common" if name=="ph_us_schedule.h" else "hartstone_freertos/main")/name
        if actual.read_bytes()!=(reference/name).read_bytes():
            raise ValueError("Original math/release schedule changed")
        shutil.copyfile(actual,output/name)
    shutil.copyfile(reference/"config.h",output/"reference-config")
    shutil.copyfile(root/"hartstone_riot/Makefile",output/"original-Makefile")
    compiler=root/"audit-workspace/tools/gcc13-legacy-newlib.sh"
    gcc=root/"idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env=dict(os.environ,PATH=str(gcc)+":"+str(root/"bin")+":"+os.environ["PATH"],PYTHONDONTWRITEBYTECODE="1")
    for key in ("CPATH","C_INCLUDE_PATH","LINKFLAGS"):
        env.pop(key,None)
    (work/"tmp").mkdir()
    env["TMPDIR"]=str(work/"tmp")
    command=["make","-C",str(app),"-j2","V=1","QUIET=0","RIOT_VERSION=2024.10-devel",
        "RIOTBASE="+str(riot),"CC="+str(compiler),"FLASH_MODE=dio","FLASH_SIZE=4"]
    with (output/"build.log").open("x") as log:
        subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=app/"bin/riot-lifetimes/ph4/esp32-wroom-32"
    for src,dst in (("hartstone-ph4.elf","application.elf"),("hartstone-ph4.elf.bin","application.bin"),
                    ("hartstone-ph4.map","application.map"),("esp_bootloader/bootloader.bin","bootloader.bin"),
                    ("partitions.bin","partitions.bin"),("riotbuild/riotbuild.h","config")):
        shutil.copyfile(binary/src,output/dst)
    for name in NATIVE:
        dest=output/"native-source"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(riot/name,dest)
    for name in SDK_FILES:
        dest=output/"native-source/sdk"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(riot/"build/pkg/esp32_sdk"/name,dest)
    for name in SUPPORT:
        dest=output/"supporting-source"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(riot/name,dest)
    for name in SUPPORT_SDK:
        dest=output/"supporting-source/sdk"/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(riot/"build/pkg/esp32_sdk"/name,dest)
    shutil.copyfile(riot/"pkg/esp32_sdk/Makefile",output/"sdk-package-Makefile")
    shutil.copyfile(gcc.parent/"xtensa-esp-elf/lib/esp32/libg_nano.a",output/"libg_nano.a")
    shutil.copyfile(compiler,output/"compiler-wrapper.sh")
    (output/"observer").mkdir()
    for name in ("Makefile","census.c"):
        shutil.copyfile(observer/name,output/"observer"/name)
    shutil.copyfile(__file__,output/"build-script.py")
    for name,args,logname in (("gcc",["--version"],"compiler.txt"),("nm",["-S",str(output/"application.elf")],"symbols.txt"),
                              ("objdump",["-d",str(output/"application.elf")],"disassembly.txt")):
        with (output/logname).open("x") as log:
            subprocess.run([str(gcc/("xtensa-esp32-elf-"+name)),*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    report={"status":"build_pass_not_measured","board_resets":0,"ranking_eligible":False,"os":"RIOT",
        "compiler":"GCC13 with GCC12 Newlib headers and the actually linked GCC13 Newlib-nano library, same compatibility route as native B1 Thread-Metric",
        "original_workload_unchanged":True,"observer_changes":"original thread-create calls add native stack-test flag; original idle gains one observation call; first native allocator unlock through main exit; no forced worker deletion",
        "command":command,"files":{p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in output.rglob("*") if p.is_file()}}
    (output/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("RIOT PH4 observer built; zero measurements")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--observer",type=Path,required=True)
    args=parser.parse_args()
    build(args.root,args.workspace,args.output,args.observer)
