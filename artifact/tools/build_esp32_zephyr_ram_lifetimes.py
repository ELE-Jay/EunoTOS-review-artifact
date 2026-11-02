#!/usr/bin/env python3
"""Isolate two native observation points around unchanged Zephyr PH4."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from hashlib import sha256

NATIVE = ("kernel/init.c", "kernel/thread.c", "kernel/sched.c", "kernel/idle.c", "kernel/kheap.c",
    "lib/heap/heap.c", "lib/heap/heap.h", "lib/heap/heap_stats.c", "lib/heap/heap_validate.c",
    "lib/libc/common/source/stdlib/malloc.c", "include/zephyr/kernel.h", "include/zephyr/kernel/thread.h",
    "include/zephyr/kernel/thread_stack.h", "include/zephyr/sys/sys_heap.h", "include/zephyr/sys/mem_stats.h",
    "arch/xtensa/core/thread.c", "arch/xtensa/core/window_vectors.S", "lib/os/thread_entry.c", "kernel/Kconfig")


def native_edits():
    return {
        "kernel/thread.c": ("\tSYS_PORT_TRACING_OBJ_FUNC(k_thread, create, new_thread);\n\n\treturn stack_ptr;",
            "\tSYS_PORT_TRACING_OBJ_FUNC(k_thread, create, new_thread);\n"
            "\textern void bench_z_create(struct k_thread *, k_thread_stack_t *, size_t);\n"
            "\tbench_z_create(new_thread, stack, stack_size);\n\n\treturn stack_ptr;"),
        "kernel/idle.c": ("\twhile (true) {", "\textern void bench_z_idle(void);\n\twhile (true) {\n\t\tbench_z_idle();"),
    }


def patched(original, edits):
    text = original.decode()
    before, after = edits
    if text.count(before) != 1:
        raise ValueError("Native observation anchor differs")
    return text.replace(before, after).encode()


def build(root, work, output, observer):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite source/evidence")
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    workspace = root / "zephyr-v3.7.0-work"
    zephyr = work / "zephyr"
    zephyr.mkdir()
    for path in (workspace / "zephyr").iterdir():
        if path.name == "kernel":
            shutil.copytree(path, zephyr / path.name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            (zephyr / path.name).symlink_to(path, target_is_directory=path.is_dir())
    app = work / "zephyr_lifetimes"
    shutil.copytree(observer, app)
    for name, edits in native_edits().items():
        original = output / "original-native" / name
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(zephyr / name, original)
        (zephyr / name).write_bytes(patched(original.read_bytes(), edits))
    reference = root / "downloads/hartstone-native-us-v1/zephyr/ph4"
    for name in ("series.c", "math_compat.h", "errno_bridge.c", "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h"):
        actual = root / "hartstone_zephyr/src" / name if name in ("series.c","math_compat.h","errno_bridge.c") else \
            root / "hartstone_common" / name if name == "ph_us_schedule.h" else root / "hartstone_freertos/main" / name
        if actual.read_bytes() != (reference / name).read_bytes():
            raise ValueError("Original PH4 source changed: " + name)
        shutil.copyfile(actual, output / name)
    shutil.copyfile(reference / "config", output / "reference-config")
    for name in NATIVE:
        dest = output / "native-source" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(zephyr / name, dest)
    for name in ("west.yml", "VERSION"):
        shutil.copyfile(zephyr / name, output / name)
    for name in ("components/esp_hw_support/esp_clk.c", "components/esp_hw_support/include/esp_private/esp_clk.h"):
        dest = output / "native-source/hal" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(workspace / "modules/hal/espressif" / name, dest)
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf"
    for name in ("tmp", "cache"):
        (work / name).mkdir()
    env = dict(os.environ, ZEPHYR_BASE=str(zephyr), ZEPHYR_TOOLCHAIN_VARIANT="espressif",
        ESPRESSIF_TOOLCHAIN_PATH=str(gcc), CPATH=str(workspace / "modules/hal/espressif/components/xtensa/esp32/include"),
        PATH=str(workspace / "pyenv/bin") + ":" + str(gcc / "bin") + ":" + str(root / "bin") + ":" + os.environ["PATH"],
        PYTHONDONTWRITEBYTECODE="1", XDG_CACHE_HOME=str(work / "cache"), TMPDIR=str(work / "tmp"))
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    build_dir = work / "build"
    def run(args, name):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    run([cmake,"-G","Ninja","-S",str(app),"-B",str(build_dir),"-DBOARD=esp32_devkitc_wroom/esp32/procpu",
        "-DZEPHYR_MODULES=" + str(workspace / "modules/hal/espressif"),
        "-DCONF_FILE=" + str(root / "hartstone_zephyr/prj.conf"),
        "-DEXTRA_CONF_FILE=" + str(root / "hartstone_zephyr/ph_native_us.conf") + ";" + str(app / "observer.conf"),
        "-DKCONFIG_ROOT=" + str(app / "Kconfig"), "-DCONFIG_SIZE_OPTIMIZATIONS=y", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log")
    run([cmake,"--build",str(build_dir),"--parallel","2"], "build.log")
    for src, dest in (("zephyr/zephyr.elf","application.elf"),("zephyr/zephyr.bin","application.bin"),
        ("zephyr/zephyr.map","application.map"),("zephyr/.config","config"),("compile_commands.json","compile_commands.json")):
        shutil.copyfile(build_dir / src, output / dest)
    shutil.copytree(observer, output / "observer")
    shutil.copyfile(__file__, output / "build-script.py")
    for tool, args, name in (("gcc",["--version"],"compiler.txt"),("objdump",["-d",str(output / "application.elf")],"disassembly.txt"),
                              ("nm",["-S",str(output / "application.elf")],"symbols.txt")):
        run([str(gcc / "bin" / ("xtensa-esp32-elf-" + tool)),*args],name)
    report = {"status":"build_pass_not_measured", "board_resets":0, "ranking_eligible":False, "os":"Zephyr",
        "original_workload_unchanged":True, "scope":"native heap initialization through original main exit observed from existing idle",
        "observer_config_changes":["CONFIG_INIT_STACKS","CONFIG_SYS_HEAP_RUNTIME_STATS","CONFIG_THREAD_ABORT_HOOK","CONFIG_BENCH_Z_LIFETIMES"],
        "files":{p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in output.rglob("*") if p.is_file()}}
    (output / "build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Zephyr PH4 observer built; zero measurements")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--observer",type=Path,required=True)
    args = parser.parse_args()
    build(args.root,args.workspace,args.output,args.observer)
