#!/usr/bin/env python3
"""Pair unchanged native message observers with the verified vendor boot observer."""
import argparse
import json
from pathlib import Path
import shutil

from run_esp32_followup import sha
from audit_esp32_allocated_lifecycle import BOOT,boot_image
from build_esp32_riot_ram_lifetimes import NATIVE,SUPPORT,SDK_FILES,SUPPORT_SDK

ROOT=Path(__file__).resolve().parents[1]
SOURCE='artifacts/reports/esp32-riot-message-history-v3'
RHINO_BOOT='artifacts/reports/esp32-rhino-boot-handoff-v2'


def prepare(output,system='RIOT',boot_source=BOOT):
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or output.exists():
        raise ValueError('Prepare on leon in a fresh persistent folder')
    if system=='RIOT':
        from run_esp32_riot_message_history import build_proof
        source=ROOT/SOURCE
    else:
        from run_esp32_rhino_gcc13_history import build_proof
        source=ROOT/'artifacts/reports/esp32-rhino-gcc13-message-history-v1'
    proof=build_proof(source)
    if boot_source not in (BOOT,RHINO_BOOT) or system=='RIOT' and boot_source!=BOOT:
        raise ValueError('Use a declared source-bound paired boot profile')
    boot_image(ROOT,boot_source)
    output.mkdir(parents=True)
    for path in source.iterdir():
        if path.name=='build.json': continue
        if path.is_dir(): shutil.copytree(path,output/path.name)
        else: shutil.copyfile(path,output/path.name)
    shutil.copyfile(source/'bootloader.bin',output/'original-native-bootloader.bin')
    for name in ('bootloader.elf','bootloader.map'):
        if (output/name).exists():
            (output/name).rename(output/('original-native-'+name))
    for name in ('bootloader.bin','bootloader.elf','bootloader.map'):
        shutil.copyfile(ROOT/boot_source/name,output/name)
    names=[]
    if system=='RIOT':
        riot=Path('/home/reviewer/esp32-pilot/RIOT-2024.10-devel')
        names=list(dict.fromkeys((*NATIVE,*SUPPORT,'cpu/esp_common/thread_arch.c',
            'cpu/esp32/bootloader/stub.c')))
        for name in names:
            path=riot/name
            if path.stat().st_mtime_ns>(source/'application.elf').stat().st_mtime_ns:
                raise ValueError('Native source changed after the retained application build: '+name)
            destination=output/'native-source'/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,destination)
        for name in (*SDK_FILES,*SUPPORT_SDK):
            destination=output/'native-source/sdk'/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(riot/'build/pkg/esp32_sdk'/name,destination)
    shutil.copyfile(__file__,output/'prepare.py')
    record=json.loads((source/'build.json').read_text())
    record.update(paired_vendor_bootloader=True,application_rebuilt=False,
        native_application_source=source.name,native_application_manifest_sha256=sha(source/'build.json'),
        original_native_bootloader_sha256=sha(source/'bootloader.bin'),
        paired_bootloader_source=boot_source,
        scope='Five fresh normal cold-SPI original-message resets required with the unchanged '+system+' application and the same source-bound vendor boot observer used by the retained FreeRTOS/NuttX RAM measurements; no native-loader data substituted')
    record['files']={p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    result=build_proof(output)
    print(json.dumps({'audit':result['audit'],'application_rebuilt':False,
        'application_sha256':sha(output/'application.bin'),'paired_vendor_bootloader':True,
        'native_files':len(names),'board_resets':0,'ranking_eligible':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--system',choices=('RIOT','AliOS-Rhino'),default='RIOT')
    parser.add_argument('--boot-source',choices=(BOOT,RHINO_BOOT),default=BOOT)
    args=parser.parse_args();prepare(args.output,args.system,args.boot_source)
