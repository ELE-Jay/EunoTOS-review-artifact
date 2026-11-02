#!/usr/bin/env python3
"""Repackage the pinned native bootinfo capacity without changing kernel code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from tenonos_kvm_reproduce import sha,save
from audit_tenonos_memory_lifecycle import require

ORIGINAL_SHA='f46bee2557c4a3aa9bf81a2dfb72072d3bfdef58b27b124094b6210245da0585'
OLD=b'    mrd_size  = 64 if opt.names else 32\n'
NEW=b'    mrd_size  = 80 if opt.names else 48\n'
REFERENCE='artifacts/reports/tenonos-native-threads-rpi4-v2'
PROFILES=('initial-tlsf','accepted-buddy','accepted-tlsf')


def repair_script(raw):
    require(hashlib.sha256(raw).hexdigest()==ORIGINAL_SHA and raw.count(OLD)==1,'Different original bootinfo packager')
    return raw.replace(OLD,NEW)


def verify_blob_delta(before,after,physical_capacity):
    require(len(before)==len(after) and before[:72]==after[:72] and before[76:]==after[76:] and
        struct.unpack_from('<I',after,72)[0]==physical_capacity,'Repair changes more than native capacity')
    require(struct.unpack_from('<I',before,72)[0]!=physical_capacity,'No original capacity mismatch')


def layout(elf_path,image):
    from elftools.elf.elffile import ELFFile
    with elf_path.open('rb') as stream:
        elf=ELFFile(stream);table=elf.get_section_by_name('.symtab')
        main=table.get_symbol_by_name('iotos_original_main')[0];section=elf.get_section(main['st_shndx'])
        start=main['st_value']-section['sh_addr'];body=section.data()[start:start+main['st_size']]
        offset=image.find(body)
        require(len(body)>=32 and offset>=0 and image.find(body,offset+1)==-1,'No unique linked/image anchor')
        base=main['st_value']-offset;bi=table.get_symbol_by_name('bi_bootinfo_sec')[0]
        return bi['st_value']-base,bi['st_size']


def prepare(root,output,reference_campaign=REFERENCE,profiles=PROFILES):
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace') and not output.exists(),'Use leon and a new output')
    output.resolve().relative_to((root/'artifacts/reports').resolve());output.mkdir(parents=True)
    original=Path('/home/reviewer/esp32-pilot/tenonos-reproduction-v1/tenon-c11/support/scripts/mkbootinfo.py')
    raw=original.read_bytes();(output/'original-mkbootinfo.py').write_bytes(raw)
    (output/'fixed-mkbootinfo.py').write_bytes(repair_script(raw))
    env=dict(os.environ,LC_ALL='C');profiles_result=[]
    for name in profiles:
        source=root/reference_campaign/name/'build';folder=output/name;folder.mkdir()
        old=(source/'runtime-image').read_bytes();offset,size=layout(source/'linked-symbols.elf',old)
        config=(source/'.config').read_text()
        require('# CONFIG_UKPLAT_MEMRNAME is not set\n' in config and
                'CONFIG_UKPLAT_MEMREGION_MAX_COUNT=128\n' in config and size==80+128*48,'Different compiled bootinfo ABI')
        for mode in ('original','fixed'):
            argv=['python3',str(output/(mode+'-mkbootinfo.py')),str(source/'linked-symbols.elf'),str(folder/(mode+'.bootinfo')),
                  '-a','arm64']
            with (folder/(mode+'.stdout')).open('xb') as out,(folder/(mode+'.stderr')).open('xb') as err:
                subprocess.run(argv,env=env,check=True,stdout=out,stderr=err)
        before=(folder/'original.bootinfo').read_bytes();after=(folder/'fixed.bootinfo').read_bytes()
        require(before==old[offset:offset+size],'Regenerated original metadata differs from actual image')
        verify_blob_delta(before,after,128)
        repaired=old[:offset]+after+old[offset+size:];(folder/'runtime-image').write_bytes(repaired)
        changes=[i for i,(a,b) in enumerate(zip(old,repaired)) if a!=b]
        require(changes and all(offset+72<=i<offset+76 for i in changes),'Repackaging changed original code or other data')
        profiles_result.append({'profile':name,'reference':reference_campaign+'/'+name+'/build','original_image_sha256':sha(source/'runtime-image'),
            'repaired_image_sha256':sha(folder/'runtime-image'),'elf_sha256':sha(source/'linked-symbols.elf'),
            'config_sha256':sha(source/'.config'),'bootinfo_offset':offset,'bootinfo_bytes':size,
            'original_capacity':struct.unpack_from('<I',before,72)[0],'physical_and_repaired_capacity':128,
            'native_descriptor_stride':48,'changed_image_byte_offsets':changes})
    result={'audit':'pass','profiles':profiles_result,'source_packager_sha256':sha(output/'original-mkbootinfo.py'),
        'fixed_packager_sha256':sha(output/'fixed-mkbootinfo.py'),'new_builds':0,'model_calls':0,'native_retest_complete':False,
        'ranking_eligible':False,'whole_live_ram_peak_bytes':None,
        'scope':'Source-ABI repair and equivalent metadata-only images; original measured images remain unchanged. Native validation is separate.'}
    save(output/'repair.json',result);return result


def audit(root,output):
    result=json.loads((output/'repair.json').read_text())
    require((output/'fixed-mkbootinfo.py').read_bytes()==repair_script((output/'original-mkbootinfo.py').read_bytes()),
            'Different packager repair')
    require(sha(output/'original-mkbootinfo.py')==result['source_packager_sha256'] and
            sha(output/'fixed-mkbootinfo.py')==result['fixed_packager_sha256'],'Packager identity changed')
    for row in result['profiles']:
        p=output/row['profile'];source=root/row['reference']
        old=(source/'runtime-image').read_bytes();new=(p/'runtime-image').read_bytes();offset,size=layout(source/'linked-symbols.elf',old)
        require(sha(source/'runtime-image')==row['original_image_sha256'] and sha(p/'runtime-image')==row['repaired_image_sha256'] and
            sha(source/'linked-symbols.elf')==row['elf_sha256'] and sha(source/'.config')==row['config_sha256'],'Repaired input identity changed')
        require((offset,size)==(row['bootinfo_offset'],row['bootinfo_bytes']) and len(old)==len(new) and
            old[:offset]==new[:offset] and old[offset+size:]==new[offset+size:],'Repair changed non-bootinfo bytes')
        verify_blob_delta(old[offset:offset+size],new[offset:offset+size],row['physical_and_repaired_capacity'])
        require(old[offset:offset+size]==(p/'original.bootinfo').read_bytes() and
            new[offset:offset+size]==(p/'fixed.bootinfo').read_bytes(),'Generated metadata changed')
    return result


def compare(root,before,after):
    from audit_tenonos_boot_memory import audit as census_audit,bootinfo
    summaries=[]
    for folder in (before,after):
        actual=census_audit(root,folder)
        require(actual==json.loads((folder/'audit.json').read_text()),'Census replay differs')
        summaries.append(actual)
    rows=[]
    for name in PROFILES:
        old=before/name;new=after/name
        for filename in ('linked.elf','input.config'):
            require(sha(old/filename)==sha(new/filename),'Before/after ELF or config differs')
        stages=json.loads((old/'debug-result.json').read_text())['stages']
        for stage in stages:
            filename=stage['stage']+'.bootinfo';a=(old/filename).read_bytes();b=(new/filename).read_bytes()
            original=bootinfo(a,native_stride=48);repaired=bootinfo(b,native_stride=48)
            require(original['capacity']==192 and repaired['capacity']==128 and
                    original['physical_capacity']==repaired['physical_capacity']==128,
                    'Unexpected original/repaired native capacities')
            verify_blob_delta(a,b,128)
            rows.append({'profile':name,'stage':stage['stage'],'original_sha256':sha(old/filename),
                'repaired_sha256':sha(new/filename),'descriptor_count':len(repaired['regions']),
                'original_capacity':192,'repaired_capacity':128,'compiled_capacity':128})
    return {'audit':'pass','before_audit_sha256':sha(before/'audit.json'),
        'after_audit_sha256':sha(after/'audit.json'),'stages':rows,
        'reused_original_diagnostic_guests':summaries[0]['fresh_diagnostic_guests'],
        'repaired_diagnostic_guests':summaries[1]['fresh_diagnostic_guests'],
        'stage_pairs':len(rows),'only_capacity_field_differs':True,'new_builds':0,'model_calls':0,
        'whole_live_ram_peak_bytes':None,'ranking_eligible':False,
        'scope':'Metadata-only native ABI repair; observed descriptor counts remain below actual capacity. No observed overrun or new timing/energy result.'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare','audit','compare'))
    p.add_argument('--before',type=Path);p.add_argument('--after',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1]
    require(root==Path('/home/reviewer/esp32-pilot/audit-workspace'),'Run evidence-dependent work on leon')
    if a.action=='compare':
        require(a.before is not None and a.after is not None and not a.output.exists(),'Use two censuses and a new output')
        a.output.resolve().relative_to((root/'artifacts/reports').resolve())
        result=compare(root,a.before.resolve(),a.after.resolve());save(a.output,result)
    else:result=prepare(root,a.output.resolve()) if a.action=='prepare' else audit(root,a.output.resolve())
    print(json.dumps({k:v for k,v in result.items() if k not in ('profiles','stages')}))
