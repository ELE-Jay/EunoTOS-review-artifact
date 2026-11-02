#!/usr/bin/env python3
"""Collect fixed task-feasibility references, never generative-system results."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import subprocess

from build_esp32_evolution_candidate import audit_candidate
from run_esp32_followup import Board
from audit_esp32_tm_basic import audit as original_audit
from audit_esp32_tm_reboots import require_self_check

ROOT = Path(__file__).resolve().parents[1]
CELLS = (("C1", "message_processing", "message-task", "C1-message"),
         ("C2", "message_processing", "message-task", "C2-message"),
         ("C2", "synchronization_processing", "semaphore-task", "C2-semaphore"))
MAC = "34:98:7a:a2:85:28"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+"\n")


def capture_result(path, case):
    result = original_audit(path, "Zephyr", case)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    require_self_check(rows, "queue" if case == "message_processing" else "semaphore")
    resets = [r for r in rows if r["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
        raise ValueError("One independent physical reset is required")
    return result


def collect(prepared, output, root, port):
    for _,_,bundle,built in CELLS:
        audit_candidate(prepared/bundle, prepared/built)
    device = subprocess.check_output(["udevadm","info","-q","property","-n",port]).decode()
    if any(s not in device.splitlines() for s in ("ID_VENDOR_ID=1a86","ID_MODEL_ID=7523","ID_USB_DRIVER=ch341")) or \
            "ID_TYPE=audio" in device or "ID_MODEL=USB_MIDI" in device:
        raise ValueError("Not the usable retained bridge")
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        (output/"device.log").write_text(device)
        for name in ("run_esp32_task_references.py","build_esp32_evolution_candidate.py",
                     "run_esp32_followup.py","capture_esp32_uart.py","audit_esp32_tm_basic.py",
                     "audit_esp32_tm_reboots.py","import_iotos_subjects.py"):
            shutil.copyfile(Path(__file__).parent/name,output/name)
        campaign={"schema":"esp32-task-feasible-reference-v1", "mode":"fixed_reference",
            "status":"incomplete", "board_mac":MAC, "started_utc":datetime.now(timezone.utc).isoformat(),
            "original_flash_restored":False, "old_cohort_modified":False, "energy_measured":False,
            "external_independent_replication":False, "generated_origin_verified":False,
            "generated_task_runs":0, "requested_cells":[[t,c] for t,c,_,_ in CELLS]}
        board=Board(root,output,MAC,port)
        try:
            board.backup()
            try:
                for task,case,bundle_name,build_name in CELLS:
                    cell=output/task/case
                    cell.mkdir(parents=True)
                    shutil.copytree(prepared/bundle_name,cell/"task")
                    build=cell/"build"
                    build.mkdir()
                    for source in (prepared/build_name).iterdir():
                        if source.name=="app":
                            shutil.copytree(source,build/"app")
                        elif source.is_file():
                            shutil.copyfile(source,build/source.name)
                    save(cell/"build-audit.json",audit_candidate(cell/"task",build))
                    captures=cell/"captures"
                    captures.mkdir()
                    pairs=board.flash(captures,build)
                    for i in (1,2,3):
                        board.capture(captures,i,95,capture_script=Path(__file__).parent/"capture_esp32_uart.py")
                        save(captures/("result%d.json"%i),capture_result(captures/("reset%d.jsonl"%i),case))
                        board.verify(pairs,captures/("verify-run%d.log"%i))
                        print("REFERENCE",task,case,i,"complete",flush=True)
                    board.verify(pairs,captures/"verify-after.log")
                campaign["status"]="collection_complete_audit_pending"
            finally:
                board.restore()
                campaign["original_flash_restored"]=True
        except Exception as exc:
            campaign["error"]=str(exc)
            raise
        finally:
            campaign["completed_utc"]=datetime.now(timezone.utc).isoformat()
            campaign["files"]={p.relative_to(output).as_posix():sha(p) for p in output.rglob("*")
                               if p.is_file() and p.name!="campaign.json"}
            save(output/"campaign.json",campaign)


def audit(directory, root=ROOT):
    from audit_esp32_followup import envelope, verified
    from audit_esp32_zephyr_thread import read_raw_capture
    from import_iotos_subjects import config_text
    campaign=envelope(directory)
    if campaign["board_mac"]!=MAC or campaign["mode"]!="fixed_reference" or \
            campaign["generated_origin_verified"] or campaign["generated_task_runs"]!=0 or \
            campaign["requested_cells"]!=[[t,c] for t,c,_,_ in CELLS]:
        raise ValueError("Reference campaign scope changed")
    cells,records,times=[],[],[]
    def ref(p):
        return {"path":p.relative_to(root).as_posix(),"sha256":sha(p)}
    for task,case,_,_ in CELLS:
        folder=directory/task/case
        build, captures=folder/"build",folder/"captures"
        proof=audit_candidate(folder/"task",build)
        if proof!=json.loads((folder/"build-audit.json").read_text()):
            raise ValueError("Build replay differs")
        config,_=config_text((build/"config").read_text())
        required={"CONFIG_SCHED_SCALABLE":"y"} if task=="C1" else {"CONFIG_SCHED_MULTIQ":"y","CONFIG_WAITQ_SCALABLE":"y"}
        if any(config.get(k)!=v for k,v in required.items()):
            raise ValueError("Reference did not implement its declared task")
        verified(captures,build,MAC)
        values=[]
        for i in (1,2,3):
            rows=read_raw_capture(captures,i)
            run=capture_result(captures/("reset%d.jsonl"%i),case)
            if run!=json.loads((captures/("result%d.json"%i)).read_text()):
                raise ValueError("Original result replay differs")
            verified(captures,build,MAC,logs=("verify-run%d.log"%i,))
            times.append(tuple(datetime.fromisoformat(rows[n]["utc"]) for n in (0,-1)))
            values.append(run["original_window_totals"][0])
        cell={"task_id":task,"os":"Zephyr","case":case,"values":values,
            "median":statistics.median(values),"unit":"count/30s","independent_resets":3,
            "image_bytes":(build/"application.bin").stat().st_size,"required_config":required,
            "generation_evidence":False,"ranking_eligible":False}
        cells.append(cell)
        records.append({**cell,"id":directory.name+"/"+task+"/"+case,
            "origin":"fixed_feasible_reference","metric":"original_count_30s","board_mac":MAC,
            "resolved_config":config,"config_sha256":sha(build/"config"),"artifact":ref(build/"application.bin"),
            "audit":ref(folder/"build-audit.json"),"source_proof":ref(folder/"task/job.json"),
            "raw_captures":[ref(captures/("reset%d.jsonl"%i)) for i in (1,2,3)],
            "manifest":ref(directory/"campaign.json"),
            "acquired_utc":[campaign["started_utc"],campaign["completed_utc"]]})
    times.sort()
    if any(start>=end for start,end in times) or any(a[1]>=b[0] for a,b in zip(times,times[1:])):
        raise ValueError("Physical reference captures overlap")
    return {"schema":campaign["schema"],"audit":"pass","cells":cells,"reference_records":records,
        "independent_resets":9,"generated_task_runs":0,"generation_evidence":False,
        "original_flash_restored":True,"energy_measured":False,"whole_ram_peak_measured":False,
        "boundary":"Fixed feasible references only; no generative-system result, optimizer, RSI or cross-OS rank."}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("collect","audit"))
    parser.add_argument("--prepared",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args=parser.parse_args()
    if args.command=="collect":
        if args.prepared is None:
            parser.error("collect requires --prepared")
        collect(args.prepared.resolve(),args.output.resolve(),args.root.resolve(),args.port)
    else:
        result=audit(args.output.resolve())
        save(args.output/"audit.json",result)
        print(json.dumps({"audit":result["audit"],"independent_resets":9,"generated_task_runs":0},indent=2))
