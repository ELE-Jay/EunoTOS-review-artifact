#!/usr/bin/env python3
"""Read native Zephyr stack watermarks around the unchanged original PH4."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import build_esp32_zephyr_ram_lifetimes as engine

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/"firmware/bsp/esp32/resource_census/zephyr_lifetimes"
EXTENSION = ROOT/"firmware/bsp/esp32/resource_census/zephyr_stack_coverage/stack-coverage.inc"
EXTRA_NATIVE = "arch/xtensa/include/kernel_arch_func.h"
BASE_EDITS = engine.native_edits


def stack_native_edits():
    return {**BASE_EDITS(),"kernel/init.c":("\tarch_kernel_init();",
        "\tarch_kernel_init();\n\textern void bench_z_stack_begin(void);\n\tbench_z_stack_begin();")}


def extended_source(text,extension):
    changes = {"static int application_running, returned, finished;":
        "static int application_running, returned, finished;\nstatic void bench_z_stack_report(int terminal);",
        '    task_report();':'    task_report();\n    bench_z_stack_report(1);',
        '    printk("ZEPHYR_RAM END\\n");\n    return;':
        '    bench_z_stack_report(0);\n    printk("ZEPHYR_RAM END\\n");\n    return;'}
    for before,after in changes.items():
        if text.count(before)!=1:
            raise ValueError("Native lifecycle extension anchor differs")
        text = text.replace(before,after)
    return text+"\n"+extension


def build(root,work,output):
    native,edits = engine.NATIVE,engine.native_edits
    try:
        engine.NATIVE = native+(EXTRA_NATIVE,)
        engine.native_edits = stack_native_edits
        with tempfile.TemporaryDirectory(prefix="zephyr-stack-observer-",dir=root) as temporary:
            observer = Path(temporary)/"observer"
            shutil.copytree(BASE,observer)
            (observer/"census.c").write_text(extended_source((BASE/"census.c").read_text(),EXTENSION.read_text()))
            engine.build(root,work,output,observer)
    finally:
        engine.NATIVE,engine.native_edits = native,edits
    shutil.copyfile(EXTENSION,output/"stack-coverage.inc")
    shutil.copyfile(__file__,output/"stack-build-script.py")
    manifest = json.loads((output/"build.json").read_text())
    manifest["native_stack_coverage"] = True
    manifest["files"] = {p.relative_to(output).as_posix():engine.sha256(p.read_bytes()).hexdigest()
                         for p in output.rglob("*") if p.is_file() and p.name!="build.json"}
    (output/"build.json").write_text(json.dumps(manifest,indent=2)+"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    for name in ("workspace","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args = parser.parse_args()
    build(args.root,args.workspace,args.output)
