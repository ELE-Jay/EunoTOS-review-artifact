#!/usr/bin/env python3
"""Build the unchanged RIOT message test on the existing native NuttX profile."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

NATIVE = (
    "arch/xtensa/src/esp32/esp32_oneshot.c", "arch/xtensa/src/esp32/esp32_oneshot.h",
    "arch/xtensa/src/esp32/esp32_tim.c", "arch/xtensa/src/esp32/esp32_tim.h",
    "arch/xtensa/src/esp32/esp32_irq.c", "arch/xtensa/src/esp32/esp32_timerisr.c",
    "arch/xtensa/src/esp32/esp32_clockconfig.c",
    "libs/libc/pthread/pthread_create.c", "libs/libc/pthread/pthread_attr_setstack.c",
    "sched/pthread/pthread_create.c", "sched/pthread/pthread_cancel.c",
    "sched/pthread/pthread_join.c", "sched/pthread/pthread_completejoin.c",
    "sched/task/task_cancelpt.c", "sched/sched/sched_foreach.c", "sched/sched/sched_gettcb.c",
    "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_releasestack.c",
    "arch/xtensa/src/common/xtensa_checkstack.c", "include/nuttx/sched.h",
    "fs/mqueue/mq_open.c", "fs/mqueue/mq_close.c", "fs/mqueue/mq_unlink.c",
    "sched/mqueue/mq_getattr.c", "sched/mqueue/mq_send.c", "sched/mqueue/mq_receive.c",
    "sched/mqueue/mq_sndinternal.c", "sched/mqueue/mq_rcvinternal.c",
    "sched/mqueue/mq_msgfree.c", "sched/mqueue/mq_msgqalloc.c", "sched/mqueue/mq_msgqfree.c",
    "sched/mqueue/mq_recover.c", "sched/mqueue/mqueue.h", "include/nuttx/mqueue.h")


def build(root):
    workspace = root / "riot-msg-nuttx-work-v1"
    output = root / "downloads/riot-msg-nuttx-v1"
    base = root / "riot-yield-nuttx-work-v1"
    if workspace.exists() or output.exists():
        raise ValueError("Refusing to replace an existing build or evidence directory")
    shutil.copytree(base, workspace, symlinks=True)
    for directory, dirs, files in os.walk(workspace, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink() and os.readlink(path).startswith(str(base) + "/"):
                target = str(workspace) + os.readlink(path)[len(str(base)):]
                path.unlink()
                path.symlink_to(target)
    board = workspace / "nuttx/arch/xtensa/src/board"
    board.unlink()
    board.symlink_to(workspace / "nuttx/boards/xtensa/esp32/common/src")
    app = workspace / "apps/examples/riot_msg"
    shutil.copytree(root / "riot-msg-pingpong/nuttx", app)
    output.mkdir(parents=True)
    (app / "include/macros").mkdir()
    for name in ("msg.h", "xtimer.h"):
        shutil.copyfile(root / "riot-msg-pingpong/include" / name, app / "include" / name)
    for name in ("clk.h", "macros/units.h"):
        shutil.copyfile(root / "riot-yield-pingpong/include" / name, app / "include" / name)
    original = root / "downloads/riot-original-v1/msg_pingpong/source"
    shutil.copytree(original, output / "source")
    shutil.copyfile(original / "main.c", app / "original.c")
    shutil.copytree(root / "downloads/riot-msg-freertos-v1/original-semantics", output / "original-semantics")
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env = dict(os.environ, PATH=str(gcc) + ":" + str(root / "python-nuttx/bin") + ":" + str(root / "bin") + ":" + os.environ["PATH"],
               PYTHONPATH=str(root / "python-nuttx/lib/python3.8/site-packages") + ":" + str(root / "esptool-4.8.1"))
    source = workspace / "nuttx"

    def run(args, name, extra=None):
        with (output / name).open("x") as stream:
            subprocess.run(args, cwd=source, env=dict(env, **(extra or {})), stdout=stream,
                           stderr=subprocess.STDOUT, check=True)

    run(["make", "distclean"], "distclean.log")
    reference = root / "downloads/riot-yield-nuttx-v1/config"
    shutil.copyfile(reference, source / ".config")
    shutil.copyfile(reference, output / "reference-config")
    shutil.copyfile(source / "boards/xtensa/esp32/esp32-devkitc/scripts/Make.defs", source / "Make.defs")
    run(["make", "apps_preconfig"], "configure.log")
    run(["setconfig", "EXAMPLES_RIOT_MSG=y", "EXAMPLES_RIOT_YIELD=n"], "select.log",
        {"APPSDIR": "../apps", "APPSBINDIR": "../apps", "BINDIR": str(source), "EXTERNALDIR": "dummy"})
    run(["make", "olddefconfig"], "olddefconfig.log")
    run(["tools/version.sh", "-v", "12.2.1", "-b", "snapshot-nuttx-12.2.1", ".version"], "version.log")
    run(["make", "context"], "context.log")
    run(["make", "clean"], "clean.log")
    run(["make", "--jobs=2", "V=1"], "build.log")
    for old, new in (("nuttx", "application.elf"), ("nuttx.bin", "application.bin"),
                     ("nuttx.map", "application.map"), (".config", "config"),
                     ("include/nuttx/version.h", "version-header.h")):
        shutil.copyfile(source / old, output / new)
    for old, new in (("bootloader-esp32.bin", "bootloader.bin"), ("partition-table-esp32.bin", "partitions.bin")):
        shutil.copyfile(workspace / old, output / new)
    for name in ("port.c", "Makefile", "Make.defs", "Kconfig"):
        shutil.copyfile(app / name, output / name)
    shutil.copytree(app / "include", output / "include")
    for name in NATIVE:
        destination = output / "native-source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination)
    run([str(gcc / "xtensa-esp32-elf-gcc"), "--version"], "compiler.txt")
    run([str(gcc / "xtensa-esp32-elf-objdump"), "-d", str(output / "application.elf")], "disassembly.txt")
    shutil.copyfile(Path(__file__), output / "build-script.py")
    from hashlib import sha256
    files = {str(p.relative_to(output)): sha256(p.read_bytes()).hexdigest()
             for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "build.json").write_text(json.dumps({"status": "build_pass_not_measured", "board_resets": 0,
        "ranking_eligible": False, "files": files}, indent=2) + "\n")
    print("Built unchanged RIOT msg_pingpong on native NuttX; no board result", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    build(parser.parse_args().root)
