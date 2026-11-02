#!/usr/bin/env python3
"""Build unchanged RIOT msg_pingpong on native Rhino with the verified GCC13 ABI route."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

NATIVE = (
    "kernel/rhino/k_buf_queue.c", "kernel/rhino/k_ringbuf.c", "kernel/rhino/k_pend.c",
    "kernel/rhino/k_task.c", "kernel/rhino/k_sched.c", "kernel/rhino/k_tick.c", "kernel/rhino/k_sys.c",
    "kernel/rhino/k_obj.c", "kernel/rhino/k_mm.c", "kernel/rhino/include/k_task.h",
    "kernel/rhino/include/k_buf_queue.h", "kernel/rhino/include/k_ringbuf.h",
    "kernel/rhino/include/k_sched.h", "kernel/rhino/include/k_obj.h", "kernel/rhino/include/k_internal.h",
    "platform/mcu/esp32/aos/hook_impl.c", "platform/arch/xtensa/lx6/xtensa_init.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h",
    "platform/mcu/esp32/espos/platform/rhino/espos_scheduler.c",
    "platform/mcu/esp32/bsp/include/driver/include/driver/timer.h",
    "platform/mcu/esp32/bsp/include/soc/esp32/include/soc/timer_group_struct.h",
    "platform/mcu/esp32/bsp/include/soc/esp32/include/soc/timer_group_reg.h")
LIBRARIES = ("platform/mcu/esp32/libc.a", "platform/mcu/esp32/lib/libnewlib.a",
             "platform/mcu/esp32/lib/libesp32.a", "platform/mcu/esp32/lib/libdriver.a",
             "platform/mcu/esp32/lib/libsoc.a")


def build(root, work, output, port):
    if work.exists() or output.exists():
        raise ValueError("Refusing to replace a source tree or evidence directory")
    shutil.copytree(Path("/dev/shm/iotos-rhino-gcc13-work-v1"), work,
                    ignore=shutil.ignore_patterns("out", ".git", "__pycache__"))
    output.mkdir(parents=True)
    reference = root / "downloads/riot-flags-alios-v1"
    app = work / "app/example/riot_msg"
    shutil.copytree(port / "alios", app)
    atomic = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/lib/gcc/xtensa-esp-elf/13.2.0/include/stdatomic.h"
    (app / "native-compiler-headers").mkdir()
    (app / "native-compiler-headers/stdatomic.h").symlink_to(atomic)
    for name in ("msg.h", "xtimer.h"):
        shutil.copyfile(port / "include" / name, app / "include" / name)
    for name in ("clk.h", "macros/units.h"):
        dest = app / "include" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / "riot-yield-pingpong/include" / name, dest)
    original = root / "downloads/riot-original-v1/msg_pingpong/source"
    shutil.copytree(original, output / "source")
    shutil.copyfile(original / "main.c", app / "original.c")
    shutil.copytree(root / "downloads/riot-msg-freertos-v1/original-semantics", output / "original-semantics")
    shutil.copyfile(port / "alios/examples-Config.in", work / "app/example/Config.in")
    for name in ("sdkconfig.h", "k_config.h"):
        shutil.copyfile(reference / name, work / "board/esp32bench" / name)
    shutil.copyfile(reference / "config", work / ".config")
    for name, dest in (("rhino-port-pinned.c", "port.c"), ("rhino-portasm-pinned.S", "portasm.S"),
                       ("rhino-vectors-pinned.S", "xtensa_vectors.S")):
        shutil.copyfile(reference / name, work / "platform/arch/xtensa/lx6" / dest)
    shutil.copyfile(root / "downloads/ram-hartstone-alios-v1/alios/ph4/original-k_mm.c", work / "kernel/rhino/k_mm.c")
    toolchain = Path("/dev/shm/iotos-rhino-gcc13-legacy-tools")
    env = dict(os.environ, PATH=str(root / "alios-build-tools/bin") + ":" + str(toolchain) + ":" + os.environ["PATH"],
               PYTHONDONTWRITEBYTECODE="1", ESP32_PILOT_ROOT=str(root))
    (work / "tmp").mkdir(exist_ok=True)
    env["TMPDIR"] = str(work / "tmp")
    commands = [["aos", "make", "riot_msg@esp32bench", "-c", "config", "TOOLCHAIN_PATH=" + str(toolchain) + "/"],
                ["aos", "make", "wifi=0", "VERBOSE=1", "TOOLCHAIN_PATH=" + str(toolchain) + "/"]]
    for args, name in zip(commands, ("configure.log", "build.log")):
        with (output / name).open("x") as stream:
            subprocess.run(args, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, check=True)
        if re.search(r"Traceback|Error [1-9]|\[ERROR\]|recipe.*failed|undefined reference", (output / name).read_text()):
            raise ValueError("Legacy build reported a failure: " + name)
        if name == "configure.log" and 'AOS_BUILD_APP="riot_msg"' not in (work / ".config").read_text():
            raise ValueError("Legacy configuration selected a different app")
    binary = work / "out/riot_msg@esp32bench/binary"
    for old, new in (("riot_msg@esp32bench.elf", "application.elf"), ("riot_msg@esp32bench.bin", "application.bin"),
                     ("riot_msg@esp32bench.map", "application.map"), ("link.opts", "link.opts")):
        shutil.copyfile(binary / old, output / new)
    for name, dest in (("platform/mcu/esp32/bsp/bootloader.bin", "bootloader.bin"),
                       ("platform/mcu/esp32/bsp/custom_partitions.bin", "partitions.bin"),
                       ("board/esp32bench/sdkconfig.h", "sdkconfig.h"), ("board/esp32bench/k_config.h", "k_config.h"),
                       (".config", "config")):
        shutil.copyfile(work / name, output / dest)
    shutil.copyfile(reference / "config", output / "reference-config")
    for name in ("aos.mk", "port.c", "Config.in", "examples-Config.in"):
        shutil.copyfile(app / name, output / name)
    shutil.copytree(app / "include", output / "include")
    for name in NATIVE:
        dest = output / "native-source" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work / name, dest)
    for name in ("rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S"):
        shutil.copyfile(reference / name, output / name)
    (output / "native-libraries").mkdir()
    for name in LIBRARIES:
        shutil.copyfile(work / name, output / "native-libraries" / Path(name).name)
    from prepare_esp32_rhino_abi import prepare
    prepare(root, work, output, root / "audit-workspace/firmware/bsp/esp32/alios_board/newlib_abi_probe.c",
            root / "audit-workspace/firmware/bsp/esp32/alios_board/xtensa-esp32-elf-gcc-legacy-newlib.sh")
    for command, args, name in (("gcc", ["--version"], "compiler.txt"),
            ("objdump", ["-d", str(output / "application.elf")], "disassembly.txt")):
        with (output / name).open("x") as stream:
            subprocess.run([str(toolchain / ("xtensa-esp32-elf-" + command)), *args], env=env,
                           stdout=stream, stderr=subprocess.STDOUT, check=True)
    include = Path(subprocess.check_output([str(toolchain / "xtensa-esp32-elf-gcc"), "-print-file-name=include"], env=env).decode().strip())
    shutil.copyfile(include / "stdatomic.h", output / "compiler-stdatomic.h")
    dependencies = work / "out/riot_msg@esp32bench/modules/app/example/riot_msg/original.d"
    shutil.copyfile(dependencies, output / "original-dependencies.d")
    shutil.copyfile(__file__, output / "build-script.py")
    report = {"status": "build_pass_not_measured", "board_resets": 0, "ranking_eligible": False,
        "os": "AliOS-Rhino", "commands": commands,
        "compiler": "GCC13 with original GCC5 Newlib headers and pinned legacy SDK libraries",
        "files": {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
                  for p in sorted(output.rglob("*")) if p.is_file()}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Built original RIOT msg_pingpong on native Rhino; zero board measurements", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    for name in ("workspace", "output", "port"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    build(args.root, args.workspace, args.output, args.port)
