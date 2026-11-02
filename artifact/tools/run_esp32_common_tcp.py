#!/usr/bin/env python3
"""Run the unchanged zperf synchronous TCP core with one CSV receiver protocol."""
import argparse
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import importlib
from pathlib import Path
import re
import shlex
import shutil
import signal
import statistics
import sys

from run_esp32_followup import Board,sha
from run_esp32_zperf_common import MAC,tcp_csv,proof as zephyr_proof
from build_esp32_common_tcp_ports import original_core,ORIGINAL_SHA

REPORTS=Path(__file__).resolve().parents[1]/"artifacts/reports"
SOURCES={"Zephyr":"esp32-network-common-zephyr-v2", "FreeRTOS":"esp32-common-tcp-freertos-v2",
         "NuttX":"esp32-common-tcp-nuttx-v1"}
SCHEDULE=[{"round":r+1,"system":s} for r in range(5)
          for s in list(SOURCES)[r%3:]+list(SOURCES)[:r%3]]
PLAN={"schedule":SCHEDULE,"payload_bytes":16384,"seconds":60,"tick_hz":100,"clock_mhz":240,"cores":1,
      "core":"Zephyr v3.7.0 sendall/tcp_upload/zperf_tcp_upload, byte-identical original functions",
      "receiver":"original iPerf 2.0.5, -C compatibility, -y C CSV, -l 16384",
      "primary":"complete receiver decimal bit/s; exact receiver bytes must equal completed blocks * 16384",
      "window":"original sender tick deadline; complete receiver EOF aggregate, actual rounded interval retained",
      "admission":"zero original errors; full bytes, boot, original output, complete peer and restoration evidence",
      "scope":"same public application core and parameters; native scheduling/socket/RF stacks and reserved memory remain profile-specific"}


def save(path,value):
    pending=path.with_suffix(path.suffix+".tmp")
    pending.write_text(json.dumps(value,indent=2,allow_nan=False)+"\n")
    pending.replace(path)


def proofs(reports=REPORTS):
    from run_esp32_network_controlled import configuration
    from audit_esp32_resources import audit_elf_image
    result={"Zephyr":zephyr_proof(reports)}
    for system in ("FreeRTOS","NuttX"):
        p=reports/SOURCES[system]
        meta=json.loads((p/"build.json").read_text())
        if not meta["built"] or meta["system"]!=system or meta["original_full_source_sha256"]!=ORIGINAL_SHA:
            raise ValueError("Wrong native build or original program identity")
        for name,digest in meta["files"].items():
            if sha(p/name)!=digest:
                raise ValueError("Frozen native build changed: "+name)
        if sha(p/"upstream-full.c")!=ORIGINAL_SHA or (p/"application-source/upstream_tcp.inc").read_text()!=original_core():
            raise ValueError("Original synchronous upload core changed")
        configuration(system,p)
        adapter=p/("application-source/zperf_common_port.c" if system=="FreeRTOS" else "application-source/port.c")
        text=adapter.read_text().replace("#define NET_WARN(...) printf(__VA_ARGS__)",
             "#define NET_WARN(format, value) printf(format, (unsigned int)(value))")
        template=Path(__file__).resolve().parents[1]/"firmware/bsp/esp32/zperf_common/port.c"
        if text!=template.read_text():
            raise ValueError("Native clock/yield/socket adaptation differs")
        if system=="FreeRTOS":
            units=[r for r in json.loads((p/"compile_commands.json").read_text()) if r["file"].endswith("/zperf_common_port.c")]
            commands=[shlex.split(r["command"]) for r in units]
        else:
            commands=[shlex.split(l) for l in (p/"build.log").read_text().splitlines()
                      if l.startswith("xtensa-esp32-elf-gcc -c ") and " port.c " in l and ".zperf_common.o" in l]
        if len(commands)!=1 or "-O2" not in commands[0] or "-Os" in commands[0]:
            raise ValueError("Missing actual original-core -O2 compilation")
        audit_elf_image(p/"application.elf",p/"application.bin")
        result[system]={"build":SOURCES[system],"build_manifest_canonical_sha256":hashlib.sha256(
                json.dumps(meta,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                "images":{n:sha(p/n) for n in ("application.elf","application.bin","bootloader.bin","partitions.bin")},
                "config_sha256":sha(p/"config"),"core_sha256":sha(p/"application-source/upstream_tcp.inc"),
                "adapter_sha256":sha(adapter)}
    return result


def reusable_prefix(parent,suite,protocol):
    from audit_esp32_followup import envelope,verified
    c=envelope(parent,allow_incomplete=True)
    expected=suite.proofs()
    if c["status"]!="incomplete" or c["mode"]!="common-original-zperf-"+protocol or c["board_mac"]!=MAC or \
            json.loads((parent/"plan.json").read_text())!=suite.PLAN or \
            json.loads((parent/"proofs.json").read_text())!=expected:
        raise ValueError("Resume requires the same restored, frozen common protocol")
    if any(sha(parent/"builds"/s/n)!=h for s in suite.SOURCES for n,h in expected[s]["images"].items()):
        raise ValueError("Resume parent image differs from frozen build")
    host=json.loads((parent/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(a["returncode"] for a in host["actions"]):
        raise ValueError("Parent network recovery incomplete")
    records=[]
    actual={p.parent.relative_to(parent/"runs").as_posix() for p in (parent/"runs").rglob("identity.log")}
    for item in suite.SCHEDULE:
        relative="round%d/%s"%(item["round"],item["system"])
        if relative not in actual:
            break
        folder=parent/"runs"/relative
        verified(folder,parent/"builds"/item["system"],MAC)
        value=suite.read_capture(folder,item["system"])
        if (folder/"result.json").exists() and json.loads((folder/"result.json").read_text())!=value:
            raise ValueError("Parent stored result differs from raw replay")
        records.append((relative,value))
    if not 0<len(records)<len(suite.SCHEDULE) or actual!={r for r,_ in records}:
        raise ValueError("Resume source is not a complete contiguous raw-capture prefix")
    return records


def collect(root,output,restore_uuid,port,protocol="tcp",resume_parent=None):
    import run_esp32_iperf_original as native
    import run_esp32_zperf_original as zperf
    from run_esp32_native_network_b1 import peer_link
    if protocol not in ("tcp","udp"):
        raise ValueError("Unsupported common original protocol")
    suite=importlib.import_module("run_esp32_common_udp") if protocol=="udp" else sys.modules[__name__]
    frozen=suite.proofs()
    reused=reusable_prefix(resume_parent,suite,protocol) if resume_parent else []
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        save(output/"plan.json",suite.PLAN)
        save(output/"proofs.json",frozen)
        for system in suite.SOURCES:
            p=output/"builds"/system
            p.mkdir(parents=True)
            if system=="Zephyr":
                for n,saved in (("zephyr.elf","application.elf"),("zephyr.bin","application.bin")):
                    shutil.copyfile(REPORTS/suite.SOURCES[system]/n,p/saved)
            else:
                for n in frozen[system]["images"]:
                    shutil.copyfile(REPORTS/suite.SOURCES[system]/n,p/n)
        shutil.copyfile(REPORTS/suite.SOURCES["Zephyr"]/"iperf-host",output/"iperf-host")
        (output/"iperf-host").chmod(0o755)
        for p,name in ((Path(suite.__file__),"runner.py"),(Path(native.__file__),"native-capture.py"),
                       (Path(zperf.__file__),"zephyr-capture.py"),(Path(Board.command.__code__.co_filename),"board-helper.py")):
            shutil.copyfile(p,output/name)
        if protocol=="udp":
            shutil.copyfile(Path(__file__),output/"common-collector.py")
            shutil.copyfile(Path(__file__).with_name("audit_esp32_common_udp.py"),output/"packet-replay.py")
        if reused:
            save(output/"reuse-parent.json",{"parent":resume_parent.name,"campaign_sha256":sha(resume_parent/"campaign.json"),
                "captures":[r for r,_ in reused],"reason":"raw-complete prefix retained after host-side interruption"})
            for relative,value in reused:
                shutil.copytree(resume_parent/"runs"/relative,output/"runs"/relative)
                save(output/"runs"/relative/"result.json",value)
        board=Board(root,output,MAC,port)
        report={"mode":"common-original-zperf-"+protocol,"board_mac":MAC,"status":"incomplete",
                "completed_resets":len(reused),"started_utc":datetime.now(timezone.utc).isoformat(),
                "old_cohort_modified":False,"energy_measured":False,"original_flash_restored":False,
                "external_independent_replication":False}
        board.backup()
        try:
            with peer_link(output,native.run,"Common",restore_uuid) as connection:
                for module in (native,zperf):
                    module.CONNECTION=connection
                    module.SSID,module.PASSWORD="ESP32-bench-55dc","benchmark-only-55dc"
                    module.SERIAL_PORT=port
                zperf.OUTPUT=output
                for item in suite.SCHEDULE[len(reused):]:
                    r,system=item["round"],item["system"]
                    folder=output/"runs"/("round%d"%r)/system
                    folder.mkdir(parents=True)
                    installed=board.flash(folder,output/"builds"/system)
                    if protocol=="udp" and system=="Zephyr":
                        zperf.trial(folder/"udp_tx","udp_tx",60,controlled_peer=True,payload=1024,host_csv=True,host_compat=True)
                    elif protocol=="udp":
                        native.trial(folder/"udp_tx","udp_tx",60,"idf" if system=="FreeRTOS" else "nuttx",
                            str(output/"iperf-host"),controlled_peer=True,board_command="zperf_udp_common",
                            completion_token="ORIGINAL_ZPERF_UDP END",host_csv=True,host_compat=True,receiver_payload=1024)
                    elif system=="Zephyr":
                        zperf.trial(folder/"tcp_tx","tcp_tx",60,controlled_peer=True,payload=16384,host_csv=True,host_compat=True)
                    else:
                        native.trial(folder/"tcp_tx","tcp_tx",60,"idf" if system=="FreeRTOS" else "nuttx",
                            str(output/"iperf-host"),16384,controlled_peer=True,board_command="zperf_common",
                            completion_token="ORIGINAL_ZPERF END",host_csv=True,host_compat=True)
                    board.verify(installed,folder/"verify-after.log")
                    record=suite.read_capture(folder,system)
                    save(folder/"result.json",record)
                    report["completed_resets"]+=1
                    save(output/"progress.json",{**item,"completed_resets":report["completed_resets"],"result":record})
                    print("COMMON_"+protocol.upper(),r,system,record["receiver"]["bits_per_second"],flush=True)
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


def read_capture(folder,system):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_iperf_original import ANSI
    path=folder/"tcp_tx"
    rows=read_raw_capture(path,"",prefix="uart",allow_legacy=True)
    text="\n".join(ANSI.sub("",r["line"]) for r in rows)
    if sum(r["line"].startswith("rst:0x") for r in rows)!=1 or re.search(r"panic|fatal|ASSERT|Brownout|Guru Meditation|TCP upload failed",text):
        raise ValueError("Independent boot/error witness differs")
    if system=="Zephyr":
        if text.count("Upload completed!")!=1 or not re.search(r"Packet size:\s*16384 bytes",text):
            raise ValueError("Original Zephyr upload completion/payload differs")
        counts=re.findall(r"Num packets:\s*(\d+)",text)
        errors=re.findall(r"Num errors:\s*(\d+) \(retry or fail\)",text)
        if len(counts)!=1 or errors!=["0"]:
            raise ValueError("Original Zephyr totals/errors differ")
        blocks=int(counts[0])
        sender_us=None
    else:
        if text.count("ORIGINAL_ZPERF BEGIN target="+system+" packet=16384 seconds=60 tick_hz=100")!=1:
            raise ValueError("Native target/start parameters differ")
        found=re.findall(r"ORIGINAL_ZPERF END status=(-?\d+) blocks=(\d+) errors=(\d+) packet=(\d+) time_us=(\d+)",text)
        if len(found)!=1:
            raise ValueError("Native original-core completion differs")
        status,blocks,errors,size,sender_us=map(int,found[0])
        if status or errors or size!=16384 or not 59000000<=sender_us<=65000000:
            raise ValueError("Original upload error/payload/physical duration differs")
    received=tcp_csv((path/"host.log").read_text())
    if blocks<=0 or received["bytes"]!=blocks*16384:
        raise ValueError("Original complete blocks do not equal exact receiver bytes")
    actions=json.loads((path/"actions.json").read_text())
    hosts=[r["host_command"] for r in actions if "host_command" in r]
    expected=["-B","192.168.4.2","-i","3","-f","m","-s","-l","16384","-y","C","-C"]
    commands=[r["board_command"] for r in actions if "board_command" in r]
    requested="zperf tcp upload 192.168.4.2 5001 60 16384" if system=="Zephyr" else "zperf_common"
    if len(hosts)!=1 or hosts[0][1:]!=expected or commands.count(requested)!=1 or \
            sum(r.get("capture_complete") is True for r in actions)!=1:
        raise ValueError("Common peer/board command or completion differs")
    links=[r["output"] for r in actions if r.get("arguments",[])[:2]==["iw","dev"]]
    if len(links)!=2 or any("34:98:7a:a2:85:29" not in r or "freq: 2412" not in r for r in links):
        raise ValueError("AP identity/channel differs")
    return {"blocks":blocks,"sender_time_us":sender_us,"receiver":received,
            "start_utc":rows[0]["utc"],"end_utc":rows[-1]["utc"],"raw_sha256":sha(path/"uart.raw")}


def audit(output,protocol="tcp"):
    from audit_esp32_followup import envelope,verified
    c=envelope(output)
    suite=importlib.import_module("run_esp32_common_udp") if protocol=="udp" else sys.modules[__name__]
    expected=suite.proofs()
    if c["mode"]!="common-original-zperf-"+protocol or c["board_mac"]!=MAC or c["completed_resets"]!=15 or \
            json.loads((output/"plan.json").read_text())!=suite.PLAN or json.loads((output/"proofs.json").read_text())!=expected:
        raise ValueError("Incomplete common protocol/build identities")
    if sha(output/"iperf-host")!=expected["Zephyr"]["peer_sha256"]:
        raise ValueError("Original peer differs")
    if (output/"reuse-parent.json").exists():
        reused=json.loads((output/"reuse-parent.json").read_text())
        if Path(reused["parent"]).name!=reused["parent"]:
            raise ValueError("Resume parent escapes report directory")
        parent=output.parent/reused["parent"]
        if sha(parent/"campaign.json")!=reused["campaign_sha256"]:
            raise ValueError("Sealed interrupted campaign changed")
        prefix=reusable_prefix(parent,suite,protocol)
        if [r for r,_ in prefix]!=reused["captures"] or any(
                json.loads((output/"runs"/r/"result.json").read_text())!=value for r,value in prefix):
            raise ValueError("Reused prefix differs from original raw replay")
    for system in suite.SOURCES:
        if any(sha(output/"builds"/system/n)!=h for n,h in expected[system]["images"].items()):
            raise ValueError("Installed common image differs")
    records,previous={},None
    for item in suite.SCHEDULE:
        folder=output/"runs"/("round%d"%item["round"])/item["system"]
        verified(folder,output/"builds"/item["system"],MAC)
        value=suite.read_capture(folder,item["system"])
        if value!=json.loads((folder/"result.json").read_text()):
            raise ValueError("Recorded common statistics differ")
        start,end=(datetime.fromisoformat(value[k]) for k in ("start_utc","end_utc"))
        if start>=end or previous is not None and previous>=start:
            raise ValueError("Reset order differs from frozen rotation")
        previous=end
        records.setdefault(item["system"],[]).append(value)
    host=json.loads((output/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Management Wi-Fi/cleanup not restored")
    cells=[]
    for system,runs in records.items():
        values=[r["receiver"]["bits_per_second"]/1000000 for r in runs]
        cells.append({"system":system,"runs":runs,"values_mbit_s":values,"median_mbit_s":statistics.median(values),
                      "range_mbit_s":[min(values),max(values)],"independent_resets":5})
        if protocol=="udp":
            cells[-1].update(original_lost_packets=[r["receiver"]["lost"] for r in runs],
                original_datagrams=[r["receiver"]["datagrams"] for r in runs],
                original_loss_percent=[r["receiver"]["loss_percent"] for r in runs])
    return {"audit":"pass","board_mac":MAC,"independent_resets":15,"cells":cells,
            "original_flash_restored":True,"management_wifi_restored":True,"energy_measured":False,
            "shared_public_core":True,"ranking_scope":"declared three native network-stack profiles only",
            "whole_live_ram_peak_bytes":None,
            **({"pacing_scope":suite.PLAN["pacing_scope"]} if protocol=="udp" else {})}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("proof","collect","audit"))
    p.add_argument("--system",choices=("Common",),default="Common")
    p.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    p.add_argument("--output",type=Path)
    p.add_argument("--restore-uuid")
    p.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args=p.parse_args()
    def stop(signum,frame):
        raise InterruptedError("Common TCP interrupted; restoring board/network")
    signal.signal(signal.SIGTERM,stop)
    if args.mode=="collect": collect(args.root,args.output,args.restore_uuid,args.port)
    else:
        result=proofs() if args.mode=="proof" else audit(args.output)
        if args.mode=="audit": save(args.output/"audit.json",result)
        print(json.dumps(result,indent=2))
