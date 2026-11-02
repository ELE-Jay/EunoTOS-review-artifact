#!/usr/bin/env python3
"""Publish source- and raw-bound normal-boot observer allocation capacities."""
import json

from run_esp32_followup import sha


def summary(root):
    from audit_esp32_rom_capacity import audit as f_audit
    from audit_esp32_active_rom_capacity import audit as zn_audit,RESULT as ZN
    from replay_esp32_rom_capacity import crosscheck as f_cross,PRIMARY as F,RESULT as FC
    from replay_esp32_active_rom_capacity import crosscheck as zn_cross,RESULT as ZNC
    from audit_esp32_resources import static_footprint
    if not (root/F).is_file() or not (root/ZN).is_file():return None
    rows=[];evidence={}
    for path,auditor,replayer,secondary,isolated_name in (
            (F,f_audit,f_cross,FC,'esp32-freertos-capacity-isolated-v1'),
            (ZN,zn_audit,zn_cross,ZNC,'esp32-active-rom-capacity-isolated-v1')):
        report=root/path;checked=json.loads(json.dumps(auditor(root)))
        if checked!=json.loads(report.read_text()) or not checked['complete_declared_lifecycle'] or checked['ranking_eligible']:
            raise ValueError('Normal-boot observer capacity evidence differs or is misqualified')
        separate=json.loads((root/secondary).read_text())
        if separate['rows']!=replayer(root,checked) or separate['primary_report_sha256']!=sha(report):
            raise ValueError('Independent capacity reconstruction differs')
        receipt_path=root/'artifacts/reports'/isolated_name/'receipt.json'
        receipt=json.loads(receipt_path.read_text())
        if not receipt['actual_isolated_copy_replay'] or not \
                receipt['original_evidence_network_devices_unapproved_subprocess_prohibited'] or \
                receipt['retained_independent_resets']!=checked['retained_independent_resets']:
            raise ValueError('Missing actual isolated capacity replay')
        evidence.update({path:sha(report),secondary:sha(root/secondary),
            str(receipt_path.relative_to(root)):sha(receipt_path)})
        cells=[checked] if path==F else checked['rows']
        for cell in cells:
            values=cell['whole_lifecycle_peak_allocated_occupancy_bytes']
            if len(values)!=5 or len(set(values))!=1:
                raise ValueError('A single displayed value requires five equal retained reset peaks')
            footprint=static_footprint(root/cell['source']/'application.elf')
            rows.append({'os':cell['os'],'static_sram_bytes':footprint['static_sram_bytes'],
                'peak_allocated_occupancy_bytes':values[0],'reset_values':values,
                'origin':'native-allocation-handoff' if path==F else cell['runs'][0]['peak_origin'],
                'source':cell['source'],'capture':cell['capture'],'elf_sha256':cell['elf_sha256'],
                'evidence':path,'observer_included':True,'ranking_eligible':False})
    if [r['os'] for r in rows]!=['FreeRTOS','Zephyr','NuttX']:
        raise ValueError('Wrong controlled observer cohort')
    return {'rows':rows,'retained_independent_resets':15,'new_benchmark_samples':0,'new_model_calls':0,
        'normal_boot_observer_lifecycle_complete':True,'ranking_eligible':False,'evidence':evidence,
        'scope':'Fixed observer images, normal POWERON_RESET/SPI through third original message report; source-bound ROM allocation ABI. Includes startup reservations, ROM/cache, image padding and mandatory metadata. Actual stack use is separate; not native/uninstrumented OS ranking or arbitrary-fault coverage.'}


def paper_text(value):
    if not value['normal_boot_observer_lifecycle_complete'] or value['ranking_eligible'] or \
            value['retained_independent_resets']!=15:
        raise ValueError('Invalid observer capacity publication scope')
    peaks=', '.join(format(r['peak_allocated_occupancy_bytes'],',') for r in value['rows'][:-1])
    peaks+=' and '+format(value['rows'][-1]['peak_allocated_occupancy_bytes'],',')
    return ('A subsequent normal-startup capacity analysis binds 9,040 physically read ROM bytes to '
        'the reset code, initializer tables and initial interrupt state. FreeRTOS\'s native witness '
        'dominates a conservative seven-arena early-boot envelope. For Zephyr and NuttX, the active '
        'ROM ABI includes initialized static data, the reserved PRO stack and CPU0 cache; disabled '
        'Bluetooth/APP domains, two peripheral-register mask constants and native retirement are '
        'checked separately. Source-bound allocation capacities are '+peaks+'\\,B, respectively, '
        'identical across the five retained resets per image (Table~\\ref{tab:ram}). Independent '
        'byte-level unions and raw entry/vector/loader markers agree; actual isolated input-copy '
        'replay passes offline. This closes allocated capacity for the fixed observer images under '
        'the normal successful cold-SPI ABI, not arbitrary-fault memory safety, exact live-stack '
        'use or uninstrumented OS RAM. No new benchmark repetitions or energy samples are added.')
