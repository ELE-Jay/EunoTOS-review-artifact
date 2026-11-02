#!/usr/bin/env python3
"""Observe the unchanged 100-Hz message test using native heap notifications."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_esp32_zephyr_ram_lifetimes import NATIVE, native_edits, patched
from run_esp32_followup import sha

BASE = "zephyr-gcc13-align/message_processing"
EXTRA = ("lib/heap/heap_listener.c", "include/zephyr/sys/heap_listener.h")
ALLOWED = {"CONFIG_INIT_STACKS", "CONFIG_SYS_HEAP_RUNTIME_STATS", "CONFIG_THREAD_ABORT_HOOK",
           "CONFIG_BENCH_Z_LIFETIMES", "CONFIG_SYS_HEAP_LISTENER", "CONFIG_HEAP_LISTENER",
           "CONFIG_TAINT", "CONFIG_TAINT_BLOBS"}
STACK_NATIVE = "arch/xtensa/include/kernel_arch_func.h"
STACK_INIT_EDIT = ("\tarch_kernel_init();", "\tarch_kernel_init();\n"
    "\textern void bench_z_message_stack_begin(void);\n\tbench_z_message_stack_begin();")
STARTUP_MAIN_EDIT = ("\tARG_UNUSED(unused3);", "\tARG_UNUSED(unused3);\n"
    "\textern void bench_z_startup_finish(void);\n\tbench_z_startup_finish();")
STARTUP_NATIVE = ("soc/espressif/common/loader.c", "soc/espressif/esp32/soc.c",
    "soc/espressif/esp32/memory.h", "soc/espressif/esp32/default.ld")
STARTUP_ROM = "components/esp_rom/esp32/ld/esp32.rom.ld"
TICK_NATIVE = ("arch/xtensa/core/vector_handlers.c", "arch/xtensa/core/xtensa_asm2_util.S",
    "arch/xtensa/include/xtensa_asm2_s.h", "arch/xtensa/include/xtensa_asm2_context.h",
    "drivers/timer/xtensa_sys_timer.c")


def startup_init_source(original):
    return patched(patched(original, STACK_INIT_EDIT), STARTUP_MAIN_EDIT)


def config(path):
    return dict(s.split("=", 1) for s in path.read_text().splitlines() if s.startswith("CONFIG_"))


def startup_observer_sources(folder, vectors=False):
    files = {n:(folder / n).read_text() for n in ('startup-entry.S','startup-stack.inc')}
    if not vectors:
        return files
    edits = {
        'startup-entry.S': [('    l32r a3, .Lmagic\n',
            '    rsr a3, vecbase\n    s32i a3, a2, 8\n    l32r a3, .Lmagic\n')],
        'startup-stack.inc': [
            ('s[2] != 0x3ffe1320', '(s[2] != 0x40000000 && s[2] != 0x40080000)'),
            ('s[3] - s[2]', 's[3] - 0x3ffe1320u'),
            ('uintptr_t p = s[2];', 'uintptr_t p = 0x3ffe1320u;'),
            ('s[7] = p - s[2];', 's[7] = p - 0x3ffe1320u;'),
            ('    printk("ZEPHYR_BOOT_STACK',
             '    printk("ZEPHYR_BOOT_OWNERSHIP entry_vecbase=%u\\n", s[2]);\n    printk("ZEPHYR_BOOT_STACK'),
            ('        s[2], s[1],', '        0x3ffe1320u, s[1],')]
    }
    # Slot 2 held the linked, constant stack lower bound; reuse it for VECBASE.
    # The paint loop still uses that same literal and the validity marker stays intact.
    for name, changes in edits.items():
        for before, after in changes:
            if files[name].count(before) != 1:
                raise ValueError('Startup vector observation anchor differs')
            files[name] = files[name].replace(before,after)
    return files


def observer_source(text, tail, stack_source=None, startup_source=None, tick_source=None, lifecycle_source=None):
    def once(before, after):
        nonlocal text
        if text.count(before) != 1:
            raise ValueError("Observation anchor differs: " + before)
        text = text.replace(before, after)
    once("#include <esp_private/esp_clk.h>", '#include <esp_private/esp_clk.h>\n#include "zephyr_message_trace.h"')
    once("    irq_unlock(key);\n}\n\n/* Called after native", "    irq_unlock(key);\n    tm_z_record((uintptr_t)heap, memory, 0, bytes);\n}\n\n/* Called after native")
    once("window=heap-init-through-main-idle-confirmation", "window=heap-init-through-third-message-report")
    once('    printk("ZEPHYR_RAM validation=%s', '    report("validation-end");\n    tm_z_dump();\n    printk("ZEPHYR_RAM validation=%s')
    if lifecycle_source is not None:
        if stack_source is not None:
            raise ValueError("Finite retired-thread validation uses its own native stack observations")
        once("static void validate(void)", lifecycle_source + "\n\nstatic __attribute__((noinline)) void validate(void)")
        once('    report("validation-end");', '    bench_z_validate_task_lifetimes();\n    report("validation-end");')
    text += "\n" + tail
    if stack_source is not None:
        once('#include "zephyr_message_trace.h"', '#include "zephyr_message_trace.h"\n'
             'static void tm_z_stack_report(const char *phase);')
        for phase in ("application-entry", "validation-end"):
            once('    report("'+phase+'");', '    report("'+phase+'");\n    tm_z_stack_report("'+phase+'");')
        once('        task_report();', '        task_report();\n        tm_z_stack_report("message-end");')
        text += "\n" + stack_source
    if startup_source is not None:
        once('#include "zephyr_message_trace.h"', '#include "zephyr_message_trace.h"\n'
             'static void bench_z_startup_report(void);')
        once('    main_thread = k_current_get();', '    bench_z_startup_report();\n    main_thread = k_current_get();')
        text += "\n" + startup_source
    if tick_source is not None:
        if stack_source is None or startup_source is None:
            raise ValueError("Tick snapshots require the existing stack/startup evidence")
        once('#include "zephyr_message_trace.h"', '#include "zephyr_message_trace.h"\n'
            'static unsigned tm_z_live_enabled;\nstatic void tm_z_live_report(void);')
        once('    if (++sleeps == 4) {', '    if (++sleeps == 1) tm_z_live_enabled = 1;\n'
            '    if (sleeps == 4) {\n        tm_z_live_enabled = 0;\n        tm_z_live_report();')
        text += "\n" + tick_source
    return text


def build(root, work, output, observer, stack_coverage=False, startup_coverage=False, tick_stacks=False, lifecycle_validation=False, startup_vectors=False):
    if startup_vectors and not startup_coverage:
        raise ValueError('Vector ownership readback requires startup coverage')
    if lifecycle_validation and stack_coverage:
        raise ValueError("Finite validation observes retired threads separately from the original workload")
    if tick_stacks and not startup_coverage:
        raise ValueError("Tick observation requires startup coverage")
    if startup_coverage and not stack_coverage:
        raise ValueError("Startup observation requires native stack ownership evidence")
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite build or evidence")
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
    reference = root / "downloads" / BASE
    app = work / "app"
    (app / "src").mkdir(parents=True)
    for name in ("main.c", "port.c", "test.c", "tm_override.h"):
        shutil.copyfile(reference / name, app / "src" / name)
    for name in ("zephyr_message_trace.h", "zephyr_message_tail.c"):
        shutil.copyfile(observer.parent / name, app / name)
    stack_source = None
    if stack_coverage:
        shutil.copyfile(observer.parent / "zephyr_message_stack.inc", app / "zephyr_message_stack.inc")
        stack_source = (app / "zephyr_message_stack.inc").read_text()
    startup_source = None
    if startup_coverage:
        for name, content in startup_observer_sources(observer.parent / 'zephyr_startup_stack',startup_vectors).items():
            (app / name).write_text(content)
        startup_source = (app / "startup-stack.inc").read_text()
    tick_source = None
    if tick_stacks:
        shutil.copyfile(observer.parent / "zephyr_tick_stacks.inc", app / "zephyr_tick_stacks.inc")
        tick_source = (app / "zephyr_tick_stacks.inc").read_text()
    lifecycle_source = None
    if lifecycle_validation:
        shutil.copyfile(observer.parent / "zephyr_task_lifecycle_validation.inc", app / "zephyr_task_lifecycle_validation.inc")
        lifecycle_source = (app / "zephyr_task_lifecycle_validation.inc").read_text()
    (app / "census.c").write_text(observer_source((observer / "census.c").read_text(),
        (app / "zephyr_message_tail.c").read_text(), stack_source, startup_source, tick_source, lifecycle_source))
    shutil.copyfile(observer / "Kconfig", app / "Kconfig")
    (app / "observer.conf").write_text((observer / "observer.conf").read_text()+"CONFIG_SYS_HEAP_LISTENER=y\n")
    if startup_coverage:
        with (app / "observer.conf").open("a") as stream:
            stream.write('CONFIG_KERNEL_ENTRY="bench_z_startup_entry"\n')
    original = root / "threadx-6.2.1_rel/utility/benchmarks/thread_metric"
    for name in ("tm_api.h", "tm_porting_layer.h", "tm_message_processing_test.c"):
        shutil.copyfile(original / name, app / "src" / name)
    (app / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(iotosbench_zephyr_tm)
target_include_directories(app PRIVATE src)
target_sources(app PRIVATE src/main.c src/port.c src/test.c census.c)
target_compile_definitions(app PRIVATE TM_TEST_message_processing=1)
zephyr_sources(${ZEPHYR_BASE}/lib/heap/heap_validate.c)
zephyr_link_libraries(-Wl,--wrap=main,--wrap=sys_heap_init,--wrap=z_impl_k_thread_join,--wrap=tm_thread_sleep,--wrap=heap_listener_notify_alloc,--wrap=heap_listener_notify_free)
''')
    if startup_coverage:
        with (app / "CMakeLists.txt").open("a") as stream:
            stream.write('target_sources(app PRIVATE startup-entry.S)\n')
    if tick_stacks:
        with (app / "CMakeLists.txt").open("a") as stream:
            stream.write('target_include_directories(app PRIVATE ${ZEPHYR_BASE}/arch/xtensa/include)\n')
            stream.write('zephyr_link_libraries(-Wl,--wrap=sys_clock_announce,--wrap=z_get_next_switch_handle)\n')
    edits_by_name = native_edits()
    if stack_coverage:
        edits_by_name = {**edits_by_name, "kernel/init.c":STACK_INIT_EDIT}
    for name, edits in edits_by_name.items():
        path = output / "original-native" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(zephyr / name, path)
        (zephyr / name).write_bytes(startup_init_source(path.read_bytes()) if startup_coverage and
            name == "kernel/init.c" else patched(path.read_bytes(), edits))
    for name in NATIVE + EXTRA + ((STACK_NATIVE,) if stack_coverage else ()) + (TICK_NATIVE if tick_stacks else ()):
        path = output / "native-source" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(zephyr / name, path)
    if startup_coverage:
        for name in STARTUP_NATIVE:
            path = output / "native-startup" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(zephyr / name, path)
        path = output / "native-startup/hal" / STARTUP_ROM
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(workspace / "modules/hal/espressif" / STARTUP_ROM, path)
    shutil.copyfile(reference / "config", output / "reference-config")
    shutil.copyfile(workspace / "tm-app-v2/prj.conf", app / "prj.conf")
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf"
    (work / "tmp").mkdir()
    env = dict(os.environ, ZEPHYR_BASE=str(zephyr), ZEPHYR_TOOLCHAIN_VARIANT="espressif",
        ESPRESSIF_TOOLCHAIN_PATH=str(gcc), CPATH=str(workspace / "modules/hal/espressif/components/xtensa/esp32/include"),
        PATH=str(workspace / "pyenv/bin")+":"+str(gcc / "bin")+":"+str(root / "bin")+":"+os.environ["PATH"],
        PYTHONDONTWRITEBYTECODE="1", XDG_CACHE_HOME=str(work / "cache"), TMPDIR=str(work / "tmp"))
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    def run(args, name):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    directory = work / "build"
    run([cmake, "-G", "Ninja", "-S", str(app), "-B", str(directory),
         "-DBOARD=esp32_devkitc_wroom/esp32/procpu", "-DZEPHYR_MODULES="+str(workspace / "modules/hal/espressif"),
         "-DCONF_FILE="+str(app / "prj.conf"), "-DEXTRA_CONF_FILE="+str(app / "observer.conf"),
         "-DKCONFIG_ROOT="+str(app / "Kconfig"), "-DCONFIG_SIZE_OPTIMIZATIONS=y",
         "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log")
    run([cmake, "--build", str(directory), "--parallel", "2"], "build.log")
    for name, dest in (("zephyr/zephyr.elf", "application.elf"), ("zephyr/zephyr.bin", "application.bin"),
                       ("zephyr/zephyr.map", "application.map"), ("zephyr/.config", "config"),
                       ("compile_commands.json", "compile_commands.json")):
        shutil.copyfile(directory / name, output / dest)
    a, b = config(output / "config"), config(reference / "config")
    allowed = ALLOWED | ({"CONFIG_KERNEL_ENTRY"} if startup_coverage else set())
    if {k:v for k,v in a.items() if k not in allowed} != {k:v for k,v in b.items() if k not in allowed}:
        raise ValueError("Configuration exceeds observation-only changes")
    shutil.copytree(app, output / "observer")
    shutil.copyfile(__file__, output / "build-script.py")
    for tool, args, name in (("gcc", ["--version"], "compiler.txt"),
                            ("objdump", ["-d", str(output / "application.elf")], "disassembly.txt"),
                            ("nm", ["-S", str(output / "application.elf")], "symbols.txt")):
        run([str(gcc / "bin" / ("xtensa-esp32-elf-"+tool)), *args], name)
    (output / "build.json").write_text(json.dumps({"status":"build_pass_not_measured", "os":"Zephyr",
        "reference":BASE, "clock_mhz":240, "tick_hz":100, "cores":1, "ranking_eligible":False,
        **({"message_native_stack_coverage":True} if stack_coverage else {}),
        **({"application_startup_stack_coverage":True} if startup_coverage else {}),
        **({"application_startup_vector_coverage":True} if startup_vectors else {}),
        **({"native_tick_stack_snapshots":True} if tick_stacks else {}),
        **({"task_lifecycle_validation":True} if lifecycle_validation else {}),
        "files":{p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file()}}, indent=2)+"\n")
    print("Zephyr original-message observer built; zero measurements", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path.home()/"esp32-pilot")
    for name in ("workspace", "output", "observer"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--stack-coverage", action="store_true")
    p.add_argument("--startup-coverage", action="store_true")
    p.add_argument("--tick-stacks", action="store_true")
    p.add_argument("--lifecycle-validation", action="store_true")
    p.add_argument('--startup-vectors', action='store_true')
    a = p.parse_args()
    build(a.root, a.workspace, a.output, a.observer, a.stack_coverage, a.startup_coverage, a.tick_stacks, a.lifecycle_validation, a.startup_vectors)
