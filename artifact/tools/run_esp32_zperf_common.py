#!/usr/bin/env python3
"""Validate the source-bound 16 KiB zperf candidate against the original iPerf CSV receiver."""
import argparse
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal

from run_esp32_followup import Board, sha

REPORTS = Path(__file__).resolve().parents[1]/"artifacts/reports"
BUILD = "esp32-network-common-zephyr-v2"
MAC = "34:98:7a:a2:85:28"
PLAN = {"seconds":60,"payload_bytes":16384,"case":"tcp_tx","independent_resets":1,
        "peer":"original iPerf 2.0.5 CSV receiver", "purpose":"runtime and byte-accounting pilot",
        "clock_mhz":240,"cores":1,"tick_hz":100,"heap_reservation_bytes":65536}


def save(path, value):
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+"\n")


def proof(reports=REPORTS):
    from audit_esp32_zperf_original import native_image
    from run_esp32_network_controlled import configuration
    p=reports/BUILD
    meta=json.loads((p/"candidate.json").read_text())
    for name,digest in meta["files"].items():
        if sha(p/name)!=digest:
            raise ValueError("Frozen candidate changed: "+name)
    configuration("Zephyr",p)
    cfg=set((p/"config").read_text().splitlines())
    if not {"CONFIG_HEAP_MEM_POOL_SIZE=65536","CONFIG_NET_ZPERF_MAX_PACKET_SIZE=16384"}<=cfg:
        raise ValueError("Wrong heap/payload profile")
    originals=json.loads((reports/"zperf-original-v3/official-source.json").read_text())
    for row in originals:
        if sha(p/row["path"])!=row["sha256"]:
            raise ValueError("Original source differs")
    native_image(p)
    expected=json.loads((p/"dependencies/provenance.json").read_text())["iperf_binary_sha256"]
    if sha(p/"iperf-host")!=expected:
        raise ValueError("Original host peer differs")
    return {"build":BUILD,"candidate_manifest_canonical_sha256":hashlib.sha256(
                json.dumps(meta,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "images":{"application.elf":sha(p/"zephyr.elf"),"application.bin":sha(p/"zephyr.bin")},
            "peer_sha256":expected,"config_sha256":sha(p/"config"),"original_source_files":len(originals)}


def collect(root, output, restore_uuid, port):
    import run_esp32_iperf_original as native
    import run_esp32_zperf_original as zperf
    from run_esp32_native_network_b1 import peer_link
    evidence=proof()
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        build=output/"build"
        build.mkdir()
        for name,saved in (("zephyr.elf","application.elf"),("zephyr.bin","application.bin")):
            shutil.copyfile(REPORTS/BUILD/name,build/saved)
        shutil.copyfile(REPORTS/BUILD/"iperf-host",output/"iperf-host")
        (output/"iperf-host").chmod(0o755)
        for path,name in ((Path(__file__),"runner.py"),(Path(zperf.__file__),"zperf-capture.py"),
                          (Path(native.__file__),"native-peer.py")):
            shutil.copyfile(path,output/name)
        save(output/"proof.json",evidence)
        save(output/"plan.json",PLAN)
        board=Board(root,output,MAC,port)
        report={"mode":"zperf-common-pilot","board_mac":MAC,"status":"incomplete",
                "started_utc":datetime.now(timezone.utc).isoformat(),"original_flash_restored":False,
                "old_cohort_modified":False,"energy_measured":False,"external_independent_replication":False}
        board.backup()
        try:
            with peer_link(output,native.run,"Zephyr",restore_uuid) as connection:
                for module in (native,zperf):
                    module.CONNECTION=connection
                    module.SSID,module.PASSWORD="ESP32-bench-55dc","benchmark-only-55dc"
                    module.SERIAL_PORT=port
                zperf.OUTPUT=output
                run=output/"run1"
                run.mkdir()
                installed=board.flash(run,build)
                zperf.trial(run/"tcp_tx","tcp_tx",60,controlled_peer=True,payload=16384,host_csv=True)
                board.verify(installed,run/"verify-after.log")
                report["status"]="collection_complete_audit_pending"
        except BaseException as error:
            report["error"]=repr(error)
            raise
        finally:
            try:
                board.restore()
                report["original_flash_restored"]=True
            finally:
                report["completed_utc"]=datetime.now(timezone.utc).isoformat()
                report["files"]={p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file()}
                save(output/"campaign.json",report)


def tcp_csv(text):
    rows=[]
    for row in csv.reader(io.StringIO(text)):
        if len(row)!=9 or not re.fullmatch(r"\d{14}",row[0]):
            continue
        if row[1:4]!=["192.168.4.2","5001","192.168.4.1"]:
            raise ValueError("CSV peer direction differs")
        a,b=map(float,row[6].split("-"))
        size,rate=int(row[7]),int(row[8])
        tolerance=.051 if a==0 else .101
        if a<0 or b<=a or size<=0 or rate<=0 or not a-tolerance < b-size*8/rate < a+tolerance:
            raise ValueError("CSV byte/rate/time arithmetic differs")
        rows.append({"start_s":a,"end_s":b,"bytes":size,"bits_per_second":rate})
    final=[r for r in rows if r["start_s"]==0 and r["end_s"]>=55]
    if len(final)!=1 or not 55<=final[0]["end_s"]<=65:
        raise ValueError("Original complete receiver aggregate missing")
    return final[0]


def audit(output,reports=REPORTS):
    from audit_esp32_followup import envelope,verified
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_iperf_original import ANSI
    c=envelope(output)
    expected=proof(reports)
    if c["mode"]!="zperf-common-pilot" or c["board_mac"]!=MAC or json.loads((output/"plan.json").read_text())!=PLAN:
        raise ValueError("Wrong pilot protocol/board")
    if json.loads((output/"proof.json").read_text())!=expected or sha(output/"iperf-host")!=expected["peer_sha256"]:
        raise ValueError("Captured source/peer identity differs")
    if any(sha(output/"build"/n)!=h for n,h in expected["images"].items()):
        raise ValueError("Captured image differs")
    verified(output/"run1",output/"build",MAC)
    rows=read_raw_capture(output/"run1/tcp_tx","",prefix="uart",allow_legacy=True)
    text="\n".join(ANSI.sub("",r["line"]) for r in rows)
    if sum(r["line"].startswith("rst:0x") for r in rows)!=1 or text.count("Upload completed!")!=1 or \
            not re.search(r"Packet size:\s*16384 bytes",text) or re.search(r"fatal|panic|assert|TCP upload failed|allocation failed",text,re.I):
        raise ValueError("Original boot/payload/completion or error checks failed")
    counts=re.findall(r"Num packets:\s*(\d+)",text)
    errors=re.findall(r"Num errors:\s*(\d+) \(retry or fail\)",text)
    if len(counts)!=1 or errors!=["0"]:
        raise ValueError("Original send totals/errors differ")
    received=tcp_csv((output/"run1/tcp_tx/host.log").read_text())
    # Original iPerf 2.0.5 Listener::Run reads sizeof(client_hdr) before
    # starting its reporter; the pinned header contains six 32-bit fields.
    provenance=json.loads((reports/BUILD/"dependencies/provenance.json").read_text())
    archive=reports/BUILD/"dependencies/iperf-2.0.5.tar.gz"
    if sha(archive)!=provenance["iperf_archive_sha256"]:
        raise ValueError("Original receiver header/source provenance differs")
    header_bytes=24
    if int(counts[0])*16384!=received["bytes"]+header_bytes:
        raise ValueError("Original completed sends do not equal complete receiver bytes")
    actions=json.loads((output/"run1/tcp_tx/actions.json").read_text())
    commands=[r["host_command"] for r in actions if "host_command" in r]
    tail=["-B","192.168.4.2","-i","3","-f","m","-s","-l","16384","-y","C"]
    if len(commands)!=1 or commands[0][1:]!=tail or sum(r.get("capture_complete") is True for r in actions)!=1:
        raise ValueError("Original receiver command or capture boundary differs")
    after=json.loads((output/"host-after.json").read_text())
    if not after["management_wifi_restored"] or any(r["returncode"] for r in after["actions"]):
        raise ValueError("Wi-Fi restoration/cleanup incomplete")
    return {"audit":"pass","board_mac":MAC,"independent_resets":1,"payload_bytes":16384,
            "completed_blocks":int(counts[0]),"receiver":received,
            "receiver_unreported_client_header_bytes":header_bytes,"original_flash_restored":True,
            "management_wifi_restored":True,"ranking_eligible":False,"energy_measured":False,
            "scope":"single runtime/byte-accounting pilot; native zperf application; further send-policy alignment and repetitions required"}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("collect","audit"))
    parser.add_argument("--system",choices=("Zephyr",),default="Zephyr")
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--restore-uuid")
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args=parser.parse_args()
    def stop(signum,frame):
        raise InterruptedError("Pilot interrupted; restoring board/network")
    signal.signal(signal.SIGTERM,stop)
    if args.mode=="collect":
        collect(args.root,args.output,args.restore_uuid,args.port)
    else:
        result=audit(args.output)
        save(args.output/"audit.json",result)
        print(json.dumps(result,indent=2))
