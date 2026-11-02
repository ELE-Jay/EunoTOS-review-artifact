#!/usr/bin/env python3
"""Extend native RIOT lifecycle evidence using its existing address-canary method."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import build_esp32_riot_ram_lifetimes as engine

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/"firmware/bsp/esp32/resource_census/riot_lifetimes"
EXTENSION = ROOT/"firmware/bsp/esp32/resource_census/riot_stack_coverage/stack-coverage.inc"
EXTRA = "LINKFLAGS += -Wl,--wrap=thread_isr_stack_init\n"


def extended_source(text,extension):
    changes = {"static kernel_pid_t main_pid;":"static kernel_pid_t main_pid;\nstatic void bench_r_irq_report(void);\nstatic void bench_r_idle_stack_report(void);",
        '    printf("RIOT_RAM final invalid=%u\\n",invalid);':'    bench_r_idle_stack_report();\n    bench_r_irq_report();\n    printf("RIOT_RAM final invalid=%u\\n",invalid);',
        '    puts("RIOT_RAM END");\n    return;':'    bench_r_irq_report();\n    puts("RIOT_RAM END");\n    return;'}
    for before,after in changes.items():
        if text.count(before) != 1:
            raise ValueError("Existing native lifetime extension anchor differs")
        text = text.replace(before,after)
    return text+"\n"+extension


def extended_makefile(text):
    before = "include $(HOME)/esp32-pilot/hartstone_riot/Makefile"
    if text.count(before) != 1:
        raise ValueError("Existing native build include differs")
    return text.replace(before,EXTRA+before)


def build(root,workspace,output):
    with tempfile.TemporaryDirectory(prefix="riot-stack-observer-",dir=root) as temporary:
        observer = Path(temporary)
        (observer/"census.c").write_text(extended_source((BASE/"census.c").read_text(),EXTENSION.read_text()))
        (observer/"Makefile").write_text(extended_makefile((BASE/"Makefile").read_text()))
        engine.build(root,workspace,output,observer)
    finish(root,output)


def finish(root,output):
    shutil.copyfile(EXTENSION,output/"stack-coverage.inc")
    shutil.copyfile(__file__,output/"stack-build-script.py")
    extra = output/"native-source/cpu/esp_common/thread_arch.c"
    shutil.copyfile(root/"RIOT-2024.10-devel/cpu/esp_common/thread_arch.c",extra)
    shutil.copyfile(root/"audit-workspace/artifacts/reports/esp32-riot-lifetimes-v7/official-native-library.json",output/"official-native-library.json")
    manifest = json.loads((output/"build.json").read_text())
    manifest["native_stack_coverage"] = True
    manifest["files"] = {p.relative_to(output).as_posix():engine.sha256(p.read_bytes()).hexdigest()
        for p in output.rglob("*") if p.is_file() and p.name != "build.json"}
    (output/"build.json").write_text(json.dumps(manifest,indent=2)+"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    for name in ("workspace","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args = parser.parse_args()
    build(args.root,args.workspace,args.output)
