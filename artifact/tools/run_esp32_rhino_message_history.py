#!/usr/bin/env python3
"""Collect/replay GCC5 original-message diagnostics, never a whole-RAM score."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil

from run_esp32_followup import Board, sha

ROOT=Path(__file__).resolve().parents[1]
MAC="34:98:7a:a2:85:28"
IMAGES=("application.elf","application.bin","bootloader.bin","partitions.bin")


def fields(line):
    return {k:int(v) if re.fullmatch(r"-?\d+",v) else v for k,v in
            (s.split("=",1) for s in line.split()[1:] if "=" in s)}


def build_proof(source):
    from build_esp32_rhino_message_history import FILES, WRAPS, observer_source
    from build_esp32_rhino_ram_lifetimes import patched
    from audit_esp32_alios_tm import check_compilation
    from audit_esp32_resources import audit_elf_image, static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    reference=ROOT/"artifacts/reports/ram-census-v2/alios"
    manifest=json.loads((source/"build.json").read_text())
    if manifest["status"]!="build_pass_not_measured" or not manifest["diagnostic_only"] or manifest["ranking_eligible"]:
        raise ValueError("Incorrect diagnostic declaration")
    for name,digest in manifest["files"].items():
        path=(source/name).resolve()
        if not path.is_relative_to(source.resolve()) or sha(path)!=digest:
            raise ValueError("Build artifact changed: "+name)
    for name in FILES+("sdkconfig.h","k_config.h","config","bootloader.bin","partitions.bin"):
        if (source/name).read_bytes()!=(reference/name).read_bytes():
            raise ValueError("Original legacy profile changed: "+name)
    observer=ROOT/"firmware/bsp/esp32/resource_census"
    gated=manifest.get("bootstrap_readiness_gate",False)
    extension=(observer/"rhino_message_boot_ready.inc").read_text() if gated else None
    if (source/"census.c").read_text()!=observer_source((observer/"rhino_message_history.c").read_text(),extension) or \
            (source/"rhino_lifetimes_core.c").read_bytes()!=(observer/"rhino_lifetimes/census.c").read_bytes() or \
            gated and (source/"boot-ready.inc").read_text()!=extension:
        raise ValueError("Observer source changed")
    for name,pinned in (("port.c","rhino-port-pinned.c"),("portasm.S","rhino-portasm-pinned.S"),
                        ("xtensa_vectors.S","rhino-vectors-pinned.S")):
        if (source/"native-source/platform/arch/xtensa/lx6"/name).read_bytes()!=(reference/pinned).read_bytes():
            raise ValueError("Native legacy port changed")
    if (source/"native-source/kernel/rhino/k_mm.c").read_bytes()!=patched((source/"original-k_mm.c").read_bytes()):
        raise ValueError("Native allocator observation points changed")
    if "5.2.0" not in (source/"compiler.txt").read_text() or any(
            "-Wl,--wrap="+name not in (source/"aos.mk").read_text() for name in WRAPS):
        raise ValueError("Compiler or wrapper selection changed")
    check_compilation(source,"message_processing")
    audit_elf_image(source/"application.elf",source/"application.bin")
    machine=calls(source,[("k_mm_init","bench_h_heap_ready"),("k_mm_alloc","bench_h_observe"),
        ("tm_message_processing_thread_report","__wrap_tm_thread_sleep"),
        ("__wrap_tm_main","tm_main"),("__wrap_krhino_mm_alloc","krhino_mm_alloc")],require_iram=False)
    return {"audit":"pass",**static_footprint(source/"application.elf"),"machine_calls":machine,
        "baseline_static_sram_bytes":static_footprint(reference/"application.elf")["static_sram_bytes"],
        "build_manifest_sha256":sha(source/"build.json"),"diagnostic_only":True,"ranking_eligible":False,
        **({"bootstrap_readiness_gate":True} if gated else {})}


def observations(lines):
    prefix="RHINO_MESSAGE_RAM "
    rows=[fields(s) for s in lines if s.startswith(prefix)]
    ends=[r for r in rows if "END" not in r and "events" in r]
    # BEGIN/END are record types rather than key=value fields.
    if len(ends)!=1:
        raise ValueError("Incomplete diagnostic termination")
    final=ends[0]
    events=[r for r in rows if "event" in r]
    tasks=[r for r in rows if "name" in r]
    blocks=[r for r in rows if "block" in r]
    boundaries=[r for r in rows if "boundary" in r]
    regions=[r for r in rows if "start" in r]
    if final["invalid"] or final["original_reports"]!=3 or not 0<len(events)<512 or \
            [e["event"] for e in events]!=list(range(len(events))) or final["events"]!=len(events) or \
            final["tasks"]!=len(tasks) or final["blocks"]!=len(blocks) or \
            [r["boundary"] for r in boundaries]!=list(range(4)):
        raise ValueError("Invalid, overflowed or reordered history")
    if any(e["kind"] not in range(4) or e["occupied"]>e["legacy"] or e["legacy"]-e["occupied"]>8192 for e in events) or \
            any(a["observation"]>b["observation"] for a,b in zip(events,events[1:])) or \
            final["legacy"]!=final["occupied"]+final["fixed_free"] or \
            final["peak"]!=max(e["occupied"] for e in events) or final["legacy_peak"]!=max(e["legacy"] for e in events) or \
            (final["occupied"],final["legacy"])!=(events[-1]["occupied"],events[-1]["legacy"]):
        raise ValueError("Native and buffered occupancy disagree")
    live={b["pointer"]:b["usable"] for b in blocks}
    if len(live)!=len(blocks) or any(v<=0 for v in live.values()) or len(regions)!=2 or any(
            not any(r["start"]<=p-16<p+n<=r["start"]+r["bytes"] for r in regions) for p,n in live.items()):
        raise ValueError("Duplicate/invalid native live block")
    if final["active"]!=sum(t["present"] for t in tasks):
        raise ValueError("Task list and lifetime hooks disagree")
    for t in tasks:
        if t["present"] and (t["deleted"] or t["stack_freed"] or t["tcb_freed"]):
            raise ValueError("Live task retired")
        if t["present"] and t["dynamic"]==2 and (live.get(t["stack"])!=t["stack_usable"] or
                live.get(t["tcb"])!=t["tcb_usable"] or t["stack_usable"]<t["reserved"]):
            raise ValueError("Dynamic task lacks native live allocations")
        if t["hwm_measured"] and not 0<=t["spare"]<=t["reserved"]:
            raise ValueError("Task watermark outside reservation")
    tm=[t for t in tasks if t["name"]=="tm"]
    if len(tm)!=2 or any(t["reserved"]!=4096 or not t["present"] or t["dynamic"]==2 for t in tm):
        raise ValueError("Original static TM task layout changed")
    readiness=[r for r in rows if "readiness" in r]
    if readiness:
        if len(readiness)!=1 or readiness[0]["readiness"]!="bootstrap-retired" or not 0<=readiness[0]["waits"]<=100:
            raise ValueError("Bootstrap readiness failed")
        task=tasks[readiness[0]["task_id"]]
        if task["reserved"]!=8704 or not all(task[k] for k in ("deleted","stack_freed","tcb_freed")) or task["present"]:
            raise ValueError("Readiness task still live")
    return {"audit":"pass","events":len(events),"heap_final_bytes":final["occupied"],
        "legacy_heap_final_bytes":final["legacy"],"heap_peak_bytes":final["peak"],
        "legacy_heap_peak_bytes":final["legacy_peak"],"fixed_pool_free_bytes":final["fixed_free"],
        "boundaries":boundaries,"tasks":tasks,"live_blocks":blocks,"heap_regions":regions,
        "legacy_outside_live_large_blocks_bytes":final["legacy"]-sum(n+16 for n in live.values()),
        "whole_live_ram_peak_bytes":None,
        "bootstrap_readiness":readiness[0] if readiness else None,
        "ranking_eligible":False}


def read_run(folder,index):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_alios_tm import check_conditions
    from audit_esp32_tm_basic import audit
    rows=read_raw_capture(folder,index)
    check_conditions(rows)
    lines=[r["line"] for r in rows]
    expected="RHINO_MESSAGE_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100 legacy_fixed_pool_reserved=1"
    if lines.count(expected)!=1 or sum(s.startswith("RHINO_MESSAGE_RAM END ") for s in lines)!=1:
        raise ValueError("Runtime profile/termination missing")
    normalized=[s.replace("RHINO_MESSAGE_RAM BEGIN ","RHINO_MESSAGE_RAM ").replace(
        "RHINO_MESSAGE_RAM END ","RHINO_MESSAGE_RAM ") for s in lines]
    result=observations(normalized)
    result["original_message"]=audit(folder/("reset%d.jsonl"%index),"AliOS-Rhino","message_processing")
    return result


def collect(root,source,output,port,resets,*,build_check=None,run_check=None,runner=None):
    build_check=build_check or build_proof;run_check=run_check or read_run
    proof=build_check(source)
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        build=output/"build"
        build.mkdir()
        for name in IMAGES:
            shutil.copyfile(source/name,build/name)
        for path,name in ((Path(__file__),"runner.py"),(Path(__file__).with_name("run_esp32_followup.py"),"board-helper.py"),
            (Path(__file__).with_name("capture_esp32_guarded_uart.py"),"capture_esp32_guarded_uart.py"),
            (root/"capture_esp32_uart.py","capture_esp32_uart.py")):
            shutil.copyfile(path,output/name)
        if runner is not None:
            shutil.copyfile(output/'runner.py',output/'shared-collector.py')
            shutil.copyfile(runner,output/'runner.py')
        (output/"build-proof.json").write_text(json.dumps(proof,indent=2)+"\n")
        (output/"plan.json").write_text(json.dumps({"resets":resets,"seconds":110,"board_mac":MAC,
            "build_manifest_sha256":sha(source/"build.json"),"diagnostic_only":True,"old_results_replaced":False},indent=2)+"\n")
        board=Board(root,output,MAC,port)
        campaign={"kind":"rhino-message-history","status":"incomplete","board_mac":MAC,"independent_resets":0,
            "started_utc":datetime.now(timezone.utc).isoformat(),"original_flash_restored":False,
            "old_cohort_modified":False,"energy_measured":False,"external_independent_replication":False,
            "ranking_eligible":False,"diagnostic_only":True}
        try:
            board.backup()
            try:
                captures=output/"captures"
                captures.mkdir()
                pairs=board.flash(captures,build)
                for index in range(1,resets+1):
                    board.capture(captures,index,110,stop="RHINO_MESSAGE_RAM END",capture_script=output/"capture_esp32_guarded_uart.py")
                    board.verify(pairs,captures/("verify-run%d.log"%index))
                    result=run_check(captures,index)
                    campaign["independent_resets"]=index
                    print("Rhino original message",index,"legacy heap",result["legacy_heap_final_bytes"],
                          "native occupied",result["heap_final_bytes"],"events",result["events"],flush=True)
                board.verify(pairs,captures/"verify-after.log")
                campaign["status"]="collection_complete_audit_pending"
            finally:
                board.restore()
                campaign["original_flash_restored"]=True
        finally:
            campaign["completed_utc"]=datetime.now(timezone.utc).isoformat()
            campaign["files"]={p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file()}
            (output/"campaign.json").write_text(json.dumps(campaign,indent=2)+"\n")


def replay(source,output,*,build_check=None,run_check=None):
    from audit_esp32_followup import envelope, verified, independent_captures
    campaign=envelope(output)
    build_check=build_check or build_proof;run_check=run_check or read_run
    proof=build_check(source)
    plan=json.loads((output/"plan.json").read_text())
    if campaign["kind"]!="rhino-message-history" or campaign["board_mac"]!=MAC or \
            plan["build_manifest_sha256"]!=sha(source/"build.json") or plan["resets"]!=campaign["independent_resets"] or \
            proof!=json.loads((output/"build-proof.json").read_text()):
        raise ValueError("Campaign profile differs")
    if any(sha(source/n)!=sha(output/"build"/n) for n in IMAGES):
        raise ValueError("Collected image differs")
    verified(output/"captures",output/"build",MAC)
    independent_captures(output/"captures",range(1,plan["resets"]+1))
    runs=[run_check(output/"captures",i) for i in range(1,plan["resets"]+1)]
    return {"audit":"pass","diagnostic_only":True,"independent_resets":len(runs),"runs":runs,
        "legacy_heap_final_bytes":[r["legacy_heap_final_bytes"] for r in runs],
        "ranking_eligible":False,"whole_live_ram_peak_bytes":None,"original_flash_restored":True}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("build-audit","collect","audit"))
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    parser.add_argument("--resets",type=int,choices=(1,5),default=5)
    args=parser.parse_args()
    if args.mode=="collect":
        collect(args.root,args.source,args.output,args.port,args.resets)
    else:
        result=build_proof(args.source) if args.mode=="build-audit" else replay(args.source,args.output)
        if args.mode=="audit":
            (args.output/"audit.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result,indent=2))
