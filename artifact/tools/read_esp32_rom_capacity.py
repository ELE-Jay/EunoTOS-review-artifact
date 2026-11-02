#!/usr/bin/env python3
"""Read immutable boot ROM windows; never program Flash or eFuses."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import shutil

from run_esp32_followup import Board, sha

ROOT=Path(__file__).resolve().parents[1]
MAC='34:98:7a:a2:85:28'
WINDOWS={'reset.bin':(0x40000400,0x350),'initializers.bin':(0x4000d4f8,0x2000)}
BACKUP='private-backups/esp32-zephyr-ownership-observer-pairs-b1-v2/original-flash.bin'


def readonly(board,operation,output=None,backup=None):
    if operation=='verify-original':
        return board.base+['verify_flash','0',str(backup)]
    if operation in WINDOWS and output is not None:
        address,size=WINDOWS[operation]
        return board.base+['dump_mem',hex(address),hex(size),str(output)]
    raise ValueError('Only bounded ROM reads and existing Flash verification are admitted')


def save(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2);f.write('\n')


def collect(folder,port):
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or folder.exists():
        raise ValueError('Use a new persistent diagnostic directory on leon')
    folder.resolve().relative_to(ROOT/'artifacts/reports')
    if shutil.disk_usage(ROOT).free<32*1024**2:
        raise ValueError('Insufficient persistent diagnostic space')
    with (ROOT.parent/'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        folder.mkdir();board=Board(ROOT.parent,folder,MAC,port)
        backup=ROOT.parent/BACKUP
        if backup.stat().st_size!=0x400000:raise ValueError('Missing complete retained Flash reference')
        commands=[readonly(board,'verify-original',backup=backup)]+[
            readonly(board,name,folder/name) for name in WINDOWS]+[readonly(board,'verify-original',backup=backup)]
        save(folder/'plan.json',{'mac':MAC,'windows':WINDOWS,'commands':commands,
            'original_flash_sha256':sha(backup),'benchmark_samples':0,'flash_or_efuse_write_allowed':False})
        shutil.copyfile(__file__,folder/'collector.py')
        shutil.copyfile(Path(__file__).with_name('run_esp32_followup.py'),folder/'board-helper.py')
        state={'status':'incomplete','started_utc':datetime.now(timezone.utc).isoformat(),
            'firmware_verified_before':False,'firmware_verified_after':False,
            'flash_written':False,'efuses_written':False,'new_benchmark_samples':0,'new_model_calls':0}
        try:
            board.identify(folder/'identity-before.log')
            text=board.command(commands[0],folder/'verify-before.log')
            if 'verify OK (digest matched)' not in text:raise ValueError('Original firmware not witnessed')
            state['firmware_verified_before']=True
            for name,command in zip(WINDOWS,commands[1:-1]):
                board.command(command,folder/(name+'.log'),180)
                if (folder/name).stat().st_size!=WINDOWS[name][1]:raise ValueError('Partial ROM window')
            state['status']='read_complete'
        except BaseException as error:
            state['error']=repr(error);raise
        finally:
            try:
                text=board.command(commands[-1],folder/'verify-after.log')
                state['firmware_verified_after']='verify OK (digest matched)' in text and sha(backup)==json.loads(
                    (folder/'plan.json').read_text())['original_flash_sha256']
                captures=folder/'captures';captures.mkdir()
                board.capture(captures,1,8,monotonic_clock=True)
            finally:
                state['ended_utc']=datetime.now(timezone.utc).isoformat()
                state['files']={str(p.relative_to(folder)):sha(p) for p in folder.rglob('*') if p.is_file()}
                save(folder/'campaign.json',state)
        if not state['firmware_verified_after']:raise ValueError('Inspect retained firmware verification')
        return {k:v for k,v in state.items() if k!='files'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--port',default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    args=parser.parse_args();print(json.dumps(collect(args.folder.resolve(),args.port),indent=2))
