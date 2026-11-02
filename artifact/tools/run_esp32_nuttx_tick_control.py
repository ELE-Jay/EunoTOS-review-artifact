#!/usr/bin/env python3
"""Four-reset, same-binary tick on/off diagnostic; no score or peak claim."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess

from run_esp32_followup import Board, sha
from run_esp32_message_observer_pairs import write_json
from run_esp32_nuttx_message_lifetimes import MAC, IMAGES, build_proof, read_run
from audit_esp32_zephyr_thread import read_raw_capture

ORDER = (0, 1, 1, 0)


def plan(source):
    return {"enabled_order":list(ORDER), "independent_resets":4,
        "build_manifest_sha256":sha(source/'build.json'), "same_binary":True,
        "primary":"original first 30-second message count; two alternating-order pairs",
        "scope":"diagnostic runtime toggle and wrapper cycles; not native performance or whole RAM"}


def read(folder, enabled, proof):
    result=read_run(folder,1,{**proof,'native_tick_stack_snapshots':bool(enabled)})
    result.pop('native_tick_probe_cost',None)
    lines=[r['line'] for r in read_raw_capture(folder,1)]
    controls=[s for s in lines if s.startswith('TM_N_TICK_CONTROL ')]
    if controls!=[f'TM_N_TICK_CONTROL enabled={enabled} clock_hz=240000000']:
        raise ValueError('Runtime control/clock differs')
    costs=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r'TM_N_TICK_COST calls=(\d+) cycles=(\d+) maximum=(\d+)',s))]
    if len(costs)!=1 or sum(s.startswith('TM_N_TICK_COST ') for s in lines)!=1:
        raise ValueError('Cycle witness missing or malformed')
    calls,cycles,maximum=costs[0]
    if not 8000<=calls<=11000 or not 0<maximum<=cycles<=calls*maximum or maximum>=2**32:
        raise ValueError('Cycle arithmetic/window differs')
    if not enabled and [s for s in lines if s.startswith('TM_N_LIVE ')]!=[
            'TM_N_LIVE samples=0 records=0 maximum=0 context=216 idle='+str(proof['tick_idle_tcb'])]:
        raise ValueError('Disabled control still contains sampling')
    if enabled and result['native_tick_stack_snapshots']['samples']!=calls:
        raise ValueError('Tick samples and timed calls disagree')
    return {"enabled":enabled,"original_counts":result['original_message']['original_window_totals'],
        "calls":calls,"cycles":cycles,"maximum":maximum,
        "native_heap_peak_bytes":result['native_heap_peak_bytes'],"observer":result}


def collect(root,source,output,port):
    proof=build_proof(source)
    if not proof.get('native_tick_same_image_control'):
        raise ValueError('Diagnostic requires a runtime-control image')
    device=subprocess.check_output(['udevadm','info','-q','property','-n',port]).decode()
    if not {'ID_VENDOR_ID=1a86','ID_MODEL_ID=7523','ID_USB_DRIVER=ch341'}<=set(device.splitlines()):
        raise ValueError('Wrong serial bridge')
    with (root/'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        write_json(output/'plan.json',plan(source))
        write_json(output/'build-proof.json',proof)
        (output/'device.log').write_text(device)
        shutil.copyfile(__file__,output/'runner.py')
        shutil.copyfile(Path(__file__).with_name('run_esp32_followup.py'),output/'board-helper.py')
        shutil.copyfile(root/'capture_esp32_uart.py',output/'capture_esp32_uart.py')
        (output/'build').mkdir()
        for name in IMAGES:shutil.copyfile(source/name,output/'build'/name)
        campaign={'mode':'nuttx-tick-same-image-control','status':'incomplete','board_mac':MAC,
            'completed_resets':0,'started_utc':datetime.now(timezone.utc).isoformat(),
            'original_flash_restored':False,'old_cohort_modified':False,'energy_measured':False,
            'external_independent_replication':False}
        board=Board(root,output,MAC,port)
        try:
            board.backup()
            try:
                for index,enabled in enumerate(ORDER,1):
                    folder=output/'runs'/str(index);folder.mkdir(parents=True)
                    pairs=board.flash(folder,output/'build')
                    board.capture(folder,1,115,stop='NUTTX_MESSAGE_RAM END',send=f'iotosbench --tick={enabled}')
                    board.verify(pairs,folder/'verify-after.log')
                    result=read(folder,enabled,proof)
                    write_json(folder/'result.json',result)
                    campaign['completed_resets']+=1
                    write_json(output/'progress.json',{'completed_resets':campaign['completed_resets'],'enabled':enabled})
                    print('CONTROL',index,enabled,result['original_counts'],result['cycles'],flush=True)
                campaign['status']='collection_complete_audit_pending'
            finally:
                board.restore();campaign['original_flash_restored']=True
        finally:
            campaign['completed_utc']=datetime.now(timezone.utc).isoformat()
            campaign['files']={p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}
            write_json(output/'campaign.json',campaign)


def audit(output,source):
    from audit_esp32_followup import envelope,verified
    data=envelope(output);proof=build_proof(source)
    if data['mode']!='nuttx-tick-same-image-control' or data['board_mac']!=MAC or data['completed_resets']!=4 or \
            json.loads((output/'plan.json').read_text())!=plan(source) or not proof.get('native_tick_same_image_control') or \
            json.loads((output/'build-proof.json').read_text())!=proof:
        raise ValueError('Incomplete or altered same-binary experiment')
    for name in IMAGES:
        if sha(output/'build'/name)!=sha(source/name):raise ValueError('Runtime arms do not share one image')
    runs=[]
    for index,enabled in enumerate(ORDER,1):
        folder=output/'runs'/str(index)
        verified(folder,output/'build',MAC)
        value=read(folder,enabled,proof)
        if json.loads(json.dumps(value))!=json.loads((folder/'result.json').read_text()):
            raise ValueError('Saved result differs from raw replay')
        runs.append({k:value[k] for k in ('enabled','original_counts','calls','cycles','maximum','native_heap_peak_bytes')})
    return {'audit':'pass','same_binary':True,'independent_resets':4,'runs':runs,
        'on_off_first_count_ratios':[runs[b]['original_counts'][0]/runs[a]['original_counts'][0] for a,b in ((0,1),(3,2))],
        'original_flash_restored':True,'ranking_eligible':False,'whole_live_ram_peak_bytes':None}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('collect','audit'))
    p.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--port',default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    a=p.parse_args()
    if a.mode=='collect':
        def interrupted(signum,frame):
            signal.alarm(0)
            raise InterruptedError('Interrupted diagnostic; restoring original Flash')
        signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGALRM,interrupted);signal.alarm(1200)
        try:collect(a.root,a.source,a.output,a.port)
        finally:signal.alarm(0)
    else:
        result=audit(a.output,a.source);write_json(a.output/'audit.json',result);print(json.dumps(result,indent=2))
