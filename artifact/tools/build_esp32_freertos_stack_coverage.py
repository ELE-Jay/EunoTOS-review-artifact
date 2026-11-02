#!/usr/bin/env python3
"""Add ordinary-IRQ stack coverage to the existing unchanged-PH4 lifecycle build."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import build_esp32_freertos_ram_lifetimes as engine

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/"firmware/bsp/esp32/resource_census/freertos_lifetimes"
EXTENSION = ROOT/"firmware/bsp/esp32/resource_census/freertos_stack_coverage/stack-coverage.inc"
EXTRA = '\nidf_build_set_property(LINK_OPTIONS "-Wl,--wrap=xPortStartScheduler" APPEND)\n'


def extended_source(text, extension):
    if text.count('    puts("FREERTOS_RAM END");') != 2 or text.count("static unsigned terminal, complete;") != 1:
        raise ValueError("Original lifetime observer anchors differ")
    text = text.replace("static unsigned terminal, complete;",
                        "static unsigned terminal, complete;\nstatic void bench_irq_stack_report(void);")
    return text.replace('    puts("FREERTOS_RAM END");',
                        '    bench_irq_stack_report();\n    puts("FREERTOS_RAM END");')+"\n"+extension


def build(root, workspace, output):
    with tempfile.TemporaryDirectory(prefix="freertos-irq-observer-",dir=root) as temporary:
        observer = Path(temporary)/"observer"
        shutil.copytree(BASE,observer)
        (observer/"census.c").write_text(extended_source((BASE/"census.c").read_text(),EXTENSION.read_text()))
        (observer/"CMakeLists.txt").write_text((BASE/"CMakeLists.txt").read_text()+EXTRA)
        engine.build(root,workspace,output,observer)
    shutil.copyfile(EXTENSION,output/"stack-coverage.inc")
    shutil.copyfile(__file__,output/"stack-build-script.py")
    reference = root/"audit-workspace/artifacts/reports/esp32-freertos-lifetimes-v4"
    for name in ("official-native-source.json","official-tlsf-pin.json"):
        shutil.copyfile(reference/name,output/name)
    portasm = root/"esp-idf-v5.2.5/components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S"
    shutil.copyfile(portasm,output/"native-source/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S")
    manifest = json.loads((output/"build.json").read_text())
    manifest["ordinary_irq_stack_coverage"] = True
    manifest["files"] = {p.relative_to(output).as_posix():engine.digest(p) for p in output.rglob("*")
                         if p.is_file() and p.name != "build.json"}
    (output/"build.json").write_text(json.dumps(manifest,indent=2)+"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    for name in ("workspace","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args = parser.parse_args()
    build(args.root,args.workspace,args.output)
