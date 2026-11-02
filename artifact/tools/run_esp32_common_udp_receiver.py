#!/usr/bin/env python3
"""Collect the original UDP receiver with one original fixed-byte host sender."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import statistics
import struct

from build_esp32_common_tcp_ports import REPORTS, ROOT, RECEIVER_SHA, HOST_SOURCES, original_receiver_parts
from run_esp32_followup import Board, sha
from run_esp32_common_tcp import save
from run_esp32_native_network_b1 import MAC, DEVICE, peer_link, QUEUE_PROFILE, queue_config

SOURCES={"FreeRTOS":"esp32-common-udp-receiver-freertos-v3",
         "Zephyr":"esp32-common-udp-receiver-zephyr-v5", "NuttX":"esp32-common-udp-receiver-nuttx-v3"}
SCHEDULE=[{"round":r+1,"system":s} for r in range(5)
          for s in list(SOURCES)[r%3:]+list(SOURCES)[:r%3]]
PLAN={"schedule":SCHEDULE,"packet_bytes":1024,"requested_bytes":75000000,
      "host_send_buffer_bytes":212992,
      "expected_sender_datagrams":73243,"expected_sender_bytes":75000832,
      "rate_bits_s":10000000,"tick_hz":100,"clock_mhz":240,"cores":1,
      "direction":"host original iPerf 2.0.5 -> board original Zephyr 3.7 UDP receiver/session core",
      "boundary":"original first data packet starts the session and is not counted; FIN is not data; repeated FIN resends the same statistics",
      "finish_id":"original threaded iPerf CloseReport reads the asynchronous reporter count; bind replies to the observed FIN ID, not the number of outgoing data packets",
      "timing":"actual sender count, duration and packet timeline verified; target rate alone does not imply equal packet timing",
      "jitter_scope":"original clock is 100 Hz; retain raw jitter as diagnostic, not a fine-resolution latency rank",
      "receive_clock_sanity":"native original duration must agree with UART STARTED-to-END elapsed within 0.25 seconds; gross-drift gate, not a calibrated timing-error bound",
      "scope":"three declared native network-stack profiles; not isolated kernel performance",
      "admission":"independent boot; source/config/image bindings; exact complete outgoing IDs and bytes; original final statistics agree with UART; successful host exit; zero pcap kernel drops; full Flash and management network restored"}
CONTROLLED_PLAN={**PLAN,"host_source_queue_profile":QUEUE_PROFILE,"host_source_path_snapshots":True}


def proofs(reports=REPORTS):
    from audit_esp32_resources import audit_elf_image
    from run_esp32_network_controlled import configuration
    result={}
    peer=reports/"esp32-network-common-zephyr-v2"
    peer_sha=json.loads((peer/"dependencies/provenance.json").read_text())["iperf_binary_sha256"]
    if sha(peer/"iperf-host")!=peer_sha:
        raise ValueError("Original iPerf host peer differs")
    for system,name in SOURCES.items():
        folder=reports/name
        meta=json.loads((folder/"build.json").read_text())
        if not meta["built"] or meta["system"]!=system or meta["protocol"]!="udp-receiver" or meta["original_full_source_sha256"]!=RECEIVER_SHA:
            raise ValueError("Wrong original receiver build")
        for relative,digest in meta["files"].items():
            path=folder/relative
            if not path.resolve().is_relative_to(folder.resolve()) or sha(path)!=digest:
                raise ValueError("Frozen receiver build changed: "+relative)
        configuration(system,folder)
        cfg=(folder/"config").read_text().splitlines()
        if any(line in cfg for line in ("CONFIG_FREERTOS_USE_TICKLESS_IDLE=y","CONFIG_ESP32_TICKLESS=y")) or \
                system=="Zephyr" and "# CONFIG_TICKLESS_KERNEL is not set" not in cfg:
            raise ValueError("Common receiver requires the declared periodic timer profile")
        for relative,digest in HOST_SOURCES.items():
            if sha(folder/"host-source"/relative)!=digest:
                raise ValueError("Original host sender/reporter logic differs")
        app=folder/"application-source"/("src" if system=="Zephyr" else "")
        for relative,text in original_receiver_parts().items():
            if (app/relative).read_text()!=text:
                raise ValueError("Original receiver/session core differs")
        adapter=app/("zperf_udp_receiver_port.c" if system=="FreeRTOS" else "port.c")
        if adapter.read_text()!=(ROOT/"firmware/bsp/esp32/zperf_udp_receiver/port.c").read_text():
            raise ValueError("Common receiver socket loop/clock binding differs")
        if system=="NuttX":
            commands=[shlex.split(line) for line in (folder/"build.log").read_text().splitlines()
                      if line.startswith("xtensa-esp32-elf-gcc -c ") and " port.c " in line and ".zperf_udp_receiver.o" in line]
        else:
            commands=[shlex.split(row["command"]) for row in json.loads((folder/"compile_commands.json").read_text())
                      if row["file"].endswith("/"+adapter.name)]
        if len(commands)!=1 or "-O2" not in commands[0] or any(flag in commands[0] for flag in ("-Os","-O0","-O1","-O3","-Og")):
            raise ValueError("Missing actual common receiver -O2 compilation")
        if system=="Zephyr":
            if "CONFIG_MINIMAL_LIBC=y" not in (folder/"config").read_text().splitlines() or \
                    (app/"zephyr_stdio.h").read_bytes()!=(ROOT/"firmware/bsp/esp32/zperf_udp_receiver/zephyr_stdio.h").read_bytes() or \
                    "-include" not in commands[0] or not any(p.endswith("/src/zephyr_stdio.h") for p in commands[0]):
                raise ValueError("Zephyr minimal-libc stdout adaptation differs")
        audit_elf_image(folder/"application.elf",folder/"application.bin",ram_only_header=system=="Zephyr")
        images={n:sha(folder/n) for n in ("application.elf","application.bin","bootloader.bin","partitions.bin") if (folder/n).exists()}
        result[system]={"build":name,"build_json_sha256":sha(folder/"build.json"),"images":images,
            "config_sha256":sha(folder/"config"),"adapter_sha256":sha(adapter),
            "peer_sha256":peer_sha,
            "original_parts":{n:sha(app/n) for n in original_receiver_parts()}}
    if len({r["adapter_sha256"] for r in result.values()})!=1 or len({tuple(r["original_parts"].values()) for r in result.values()})!=1:
        raise ValueError("Receiver application sources differ between OSes")
    return result


def packet_exchange(path, expected=73243):
    """Check outgoing offered load and native receiver's returned original counters.

    Host pcap cannot reconstruct packets dropped inside the board driver/stack.
    It witnesses the offered sequence and final reply, not the board receive sequence.
    """
    data=Path(path).read_bytes()
    if len(data)<24 or data[:4]!=b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I",data,20)[0]!=1:
        raise ValueError("Expected little-endian Ethernet pcap")
    position=24
    outgoing=[]
    fins=[]
    replies=[]
    flows=set()
    while position<len(data):
        if position+16>len(data): raise ValueError("Truncated pcap header")
        sec,usec,captured,actual=struct.unpack_from("<4I",data,position)
        position+=16
        if usec>=1000000 or not 54<=captured<=min(96,actual) or position+captured>len(data):
            raise ValueError("Invalid pcap bounds/time")
        frame=data[position:position+captured]
        position+=captured
        if frame[12:14]!=b"\x08\x00" or frame[14]!=0x45 or frame[23]!=17 or struct.unpack_from("!H",frame,20)[0]&0x3fff:
            raise ValueError("Non-native UDP IPv4 or fragmented traffic")
        if actual!=14+struct.unpack_from("!H",frame,16)[0]: raise ValueError("IPv4 captured length differs")
        sport,dport,length,_=struct.unpack_from("!4H",frame,34)
        if length!=actual-34: raise ValueError("UDP length differs")
        ident,sent_sec,sent_us=struct.unpack_from("!iII",frame,42)
        if sent_us>=1000000: raise ValueError("Invalid original UDP timestamp")
        stamp=sec*1000000+usec
        if frame[26:30]==bytes((192,168,4,2)) and frame[30:34]==bytes((192,168,4,1)) and dport==5001:
            if length!=1032: raise ValueError("Original fixed-size host datagram differs")
            flows.add((sport,dport))
            (outgoing if ident>=0 else fins).append((ident,stamp))
        elif frame[26:30]==bytes((192,168,4,1)) and frame[30:34]==bytes((192,168,4,2)) and sport==5001:
            if length!=60 or captured<94 or ident>=0:
                raise ValueError("Original UDP reply ABI or FIN identity differs")
            f=struct.unpack_from("!10I",frame,54)
            if f[0]!=0x80000000 or f[4]>=1000000 or f[8]!=0:
                raise ValueError("Original UDP statistics flags/time differs")
            replies.append({"ports":(dport,sport),"stamp":stamp,"finish_id":ident,"bytes":(f[1]<<32)+f[2],
                "receiver_us":f[3]*1000000+f[4],"lost":f[5],"outorder":f[6],"datagrams":f[7],"jitter_us":f[9]})
        else: raise ValueError("Unexpected UDP endpoint")
    if len(flows)!=1 or [ident for ident,_ in outgoing]!=list(range(expected)) or not fins or len({i for i,_ in fins})!=1 or not replies:
        raise ValueError("Incomplete/duplicate/reordered outgoing fixed-byte sequence or finish exchange")
    if any(b[1]<a[1] for a,b in zip(outgoing,outgoing[1:])) or fins[0][1]<outgoing[-1][1]:
        raise ValueError("Outgoing packet time/order differs")
    stats={k:v for k,v in replies[0].items() if k not in ("ports","stamp","finish_id")}
    if any(r["ports"] not in flows or r["stamp"]<fins[0][1] or r["finish_id"]!=fins[0][0] or
            {k:v for k,v in r.items() if k not in ("ports","stamp","finish_id")}!=stats for r in replies):
        raise ValueError("Returned original statistics contradict each other")
    if not stats["datagrams"] or stats["bytes"]!=stats["datagrams"]*1024 or not stats["receiver_us"]:
        raise ValueError("Original byte/count/duration statistics differ")
    span=outgoing[-1][1]-outgoing[0][1]
    if not 55000000<=span<=75000000: raise ValueError("Actual sender duration outside the frozen complete-load range")
    return {"sender_datagrams":expected,"sender_bytes":expected*1024,"sender_span_us":span,
            "sender_bits_s":expected*1024*8000000/span,"finish_attempts":len(fins),"stat_replies":len(replies),
            "original_finish_id":fins[0][0],
            "receiver":stats,"receiver_bits_s":stats["bytes"]*8000000/stats["receiver_us"],
            "scope":"host offered sequence and native returned counters; not a packet-by-packet board receive trace"}


def read_capture(folder,system,*,host_buffer=None):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_iperf_original import ANSI
    from run_esp32_iperf_original import fixed_udp_arguments
    path=folder/"udp_rx"
    rows=read_raw_capture(path,"",prefix="uart",allow_legacy=True)
    text="\n".join(ANSI.sub("",r["line"]) for r in rows)
    if sum(r["line"].startswith("rst:0x") for r in rows)!=1 or re.search(r"panic|fatal|ASSERT|Brownout|Guru Meditation|ORIGINAL_ZPERF_RX ERROR",text,re.I):
        raise ValueError("Independent boot or receiver fault witness differs")
    if text.count("ORIGINAL_ZPERF_RX READY target="+system+" port=5001 buffer=1500 tick_hz=100")!=1 or \
            text.count("ORIGINAL_ZPERF_RX STARTED")!=1 or text.count("ORIGINAL_ZPERF_RX CLOSED status=0")!=1:
        raise ValueError("Original receiver readiness/session/closure differs")
    values=re.findall(r"ORIGINAL_ZPERF_RX END datagrams=(\d+) lost=(\d+) outorder=(\d+) bytes=(\d+) receiver_us=(\d+) jitter_us=(\d+)",text)
    if len(values)!=1: raise ValueError("One complete native receiver result required")
    native=dict(zip(("datagrams","lost","outorder","bytes","receiver_us","jitter_us"),map(int,values[0])))
    started=[r["elapsed_s"] for r in rows if ANSI.sub("",r["line"]).strip()=="ORIGINAL_ZPERF_RX STARTED"]
    ended=[r["elapsed_s"] for r in rows if "ORIGINAL_ZPERF_RX END datagrams=" in r["line"]]
    if len(started)!=1 or len(ended)!=1 or abs(ended[0]-started[0]-native["receiver_us"]/1000000)>.25:
        raise ValueError("Native original receive clock disagrees with external UART elapsed time")
    wire=packet_exchange(path/"network.pcap",PLAN["expected_sender_datagrams"])
    if native!=wire["receiver"] or not re.search(r"\b0 packets dropped by kernel\b",(path/"pcap.log").read_text()):
        raise ValueError("UART and original returned statistics disagree or host pcap dropped packets")
    if native["receiver_us"]%10000: raise ValueError("Native result is not in the original 100-Hz timebase")
    actions=json.loads((path/"actions.json").read_text())
    hosts=[r["host_command"] for r in actions if "host_command" in r]
    if len(hosts)!=1 or hosts[0][1:]!=fixed_udp_arguments("iperf",75000000,host_buffer)[1:]+["-y","C","-C"] or \
            [r["host_returncode"] for r in actions if "host_returncode" in r]!=[0] or \
            sum(r.get("capture_complete") is True for r in actions)!=1:
        raise ValueError("Original sender arguments/exit/capture completion differ")
    if host_buffer is not None:
        states=[r for r in actions if "original_sender_socket_state" in r]
        if not states or not any(r["original_sender_socket_state"]["returncode"]==0 and
                re.search(r"\bpid="+str(r["host_pid"])+r"\b",r["original_sender_socket_state"]["output"]) and
                re.search(r"\btb"+str(2*host_buffer)+r"\b",r["original_sender_socket_state"]["output"]) for r in states):
            raise ValueError("Original sender socket buffer lacks an observed runtime witness")
    host=(path/"host.log").read_text()
    if re.search(r"WARNING|failed|did not receive|error",host,re.I): raise ValueError("Original sender reports an error")
    links=[r["output"] for r in actions if r.get("arguments",[])[:2]==["iw","dev"]]
    if len(links)!=2 or any("34:98:7a:a2:85:29" not in r or "freq: 2412" not in r for r in links):
        raise ValueError("Controlled AP/channel differs")
    return {**wire,"start_utc":rows[0]["utc"],"end_utc":rows[-1]["utc"],
            "raw_sha256":sha(path/"uart.raw"),"pcap_sha256":sha(path/"network.pcap")}


def resume_prefix(parent,frozen):
    from audit_esp32_followup import envelope,verified
    record=envelope(parent,allow_incomplete=True)
    if parent.name!="esp32-common-original-udp-receiver-b1-v2" or record["status"]!="incomplete" or \
            record["mode"]!="common-original-zperf-udp-receiver" or record["board_mac"]!=MAC or record["completed_resets"]!=1 or \
            record["error"]!="RuntimeError('original board aggregate did not complete')" or \
            json.loads((parent/"plan.json").read_text())!={k:v for k,v in PLAN.items() if k!="receive_clock_sanity"}:
        raise ValueError("Resume requires the sealed pre-workload Zephyr stdout fault and original protocol")
    old=json.loads((parent/"proofs.json").read_text())
    for system in ("FreeRTOS","NuttX"):
        if old[system]!=frozen[system]: raise ValueError("Completed/native receiver build changed before resume")
    failed=parent/"runs/round1/Zephyr"
    from replay_esp32_followup import raw_rows
    lines="\n".join(r["line"] for r in raw_rows(failed/"udp_rx/uart.jsonl"))
    if "ZEPHYR FATAL ERROR 0" not in lines or "PC 0x4000be94 VADDR (nil)" not in lines or \
            "ORIGINAL_ZPERF_RX STARTED" in lines or (failed/"result.json").exists() or \
            old["Zephyr"]["build"]!="esp32-common-udp-receiver-zephyr-v3":
        raise ValueError("The retained Zephyr failure is not the diagnosed pre-workload libc boundary")
    host=json.loads((parent/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Interrupted parent did not restore management networking")
    relative="round1/FreeRTOS"
    folder=parent/"runs"/relative
    for name,digest in frozen["FreeRTOS"]["images"].items():
        if sha(parent/"builds/FreeRTOS"/name)!=digest: raise ValueError("Completed prefix image differs")
    verified(folder,parent/"builds/FreeRTOS",MAC)
    result=read_capture(folder,"FreeRTOS")
    if result!=json.loads((folder/"result.json").read_text()): raise ValueError("Completed prefix raw/result differs")
    return [(relative,result)]


def collect(root,output,restore_uuid,port,resume_parent=None,diagnostic_system=None,source_queue_profile=None):
    import run_esp32_iperf_original as native
    frozen=proofs()
    if diagnostic_system is not None and (diagnostic_system not in SOURCES or resume_parent is not None):
        raise ValueError("Source-path diagnosis requires one native OS and no resumed benchmark prefix")
    plan=PLAN if diagnostic_system is None else {**PLAN,"schedule":[{"round":1,"system":diagnostic_system}],
        "diagnostic_only":True,"host_source_path_snapshots":True}
    if source_queue_profile is not None:
        if source_queue_profile!=QUEUE_PROFILE or resume_parent:
            raise ValueError("Controlled source queue needs a fresh frozen-profile collection")
        plan={**plan,"host_source_queue_profile":QUEUE_PROFILE,"host_source_path_snapshots":True}
    reused=resume_prefix(resume_parent,frozen) if resume_parent else []
    os.environ["LC_ALL"]="C"
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        save(output/"plan.json",plan)
        save(output/"proofs.json",frozen)
        if reused:
            save(output/"reuse-parent.json",{"parent":resume_parent.name,"campaign_sha256":sha(resume_parent/"campaign.json"),
                "captures":[r for r,_ in reused],"reason":"retain the complete identical FreeRTOS reset; Zephyr failed before original session start, fixed only its minimal-libc stdout binding"})
            for relative,value in reused:
                shutil.copytree(resume_parent/"runs"/relative,output/"runs"/relative)
                save(output/"runs"/relative/"result.json",value)
        for system in SOURCES:
            target=output/"builds"/system
            target.mkdir(parents=True)
            for name in frozen[system]["images"]: shutil.copyfile(REPORTS/SOURCES[system]/name,target/name)
        shutil.copyfile(REPORTS/"esp32-network-common-zephyr-v2/iperf-host",output/"iperf-host")
        (output/"iperf-host").chmod(0o755)
        for source,name in ((Path(__file__),"runner.py"),(Path(native.__file__),"native-capture.py"),
                            (Path(Board.backup.__code__.co_filename),"board-helper.py"),
                            (Path(peer_link.__code__.co_filename),"network-guard.py")):
            shutil.copyfile(source,output/name)
        board=Board(root,output,MAC,port)
        report={"mode":"common-original-zperf-udp-receiver"+ ("-diagnostic" if diagnostic_system else ""),"board_mac":MAC,"status":"incomplete",
                "completed_resets":len(reused),"started_utc":datetime.now(timezone.utc).isoformat(),
                "reused_complete_resets":len(reused),
                "old_cohort_modified":False,"energy_measured":False,"original_flash_restored":False,
                "external_independent_replication":False}
        board.backup()
        try:
            with peer_link(output,native.run,"Common",restore_uuid,source_queue_profile=source_queue_profile) as connection:
                native.CONNECTION=connection
                native.SERIAL_PORT=port
                native.SSID,native.PASSWORD="ESP32-bench-55dc","benchmark-only-55dc"
                for item in plan["schedule"][len(reused):]:
                    system=item["system"]
                    folder=output/"runs"/("round%d"%item["round"])/system
                    folder.mkdir(parents=True)
                    installed=board.flash(folder,output/"builds"/system)
                    native.trial(folder/"udp_rx","udp_rx",60,
                        {"FreeRTOS":"idf","Zephyr":"zephyr","NuttX":"nuttx"}[system],str(output/"iperf-host"),
                        controlled_peer=True,board_command="zperf_udp_receiver",
                        completion_token="ORIGINAL_ZPERF_RX CLOSED status=0",host_csv=True,host_compat=True,
                        fixed_udp_bytes=PLAN["requested_bytes"],fixed_udp_send_buffer=PLAN["host_send_buffer_bytes"],
                        host_udp_path_diagnostics=diagnostic_system is not None or source_queue_profile is not None,
                        source_queue_state=output/"wifi-restore-state.json" if source_queue_profile else None)
                    board.verify(installed,folder/"verify-after.log")
                    value=read_capture(folder,system,host_buffer=PLAN["host_send_buffer_bytes"])
                    if source_queue_profile:
                        controlled_queue_capture(folder)
                    save(folder/"result.json",value)
                    report["completed_resets"]+=1
                    save(output/"progress.json",{**item,"completed_resets":report["completed_resets"],"result":value})
                    print("COMMON_UDP_RX",item["round"],system,value["receiver_bits_s"],flush=True)
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


def audit(output):
    from audit_esp32_followup import envelope, verified
    record=envelope(output)
    frozen=proofs()
    plan=json.loads((output/"plan.json").read_text())
    controlled=plan==CONTROLLED_PLAN
    if record["mode"]!="common-original-zperf-udp-receiver" or record["board_mac"]!=MAC or record["completed_resets"]!=15 or \
            plan not in (PLAN,CONTROLLED_PLAN) or json.loads((output/"proofs.json").read_text())!=frozen:
        raise ValueError("Frozen receiver protocol/build/count differs")
    if controlled:
        if record.get("reused_complete_resets")!=0 or (output/"reuse-parent.json").exists():
            raise ValueError("The controlled host queue cohort requires all fifteen fresh resets")
        controlled_queue_restoration(output)
    if any(sha(output/"iperf-host")!=r["peer_sha256"] for r in frozen.values()):
        raise ValueError("Collected original host peer differs")
    if (output/"reuse-parent.json").exists():
        reused=json.loads((output/"reuse-parent.json").read_text())
        if Path(reused["parent"]).name!=reused["parent"]: raise ValueError("Resume parent path escapes reports")
        parent=output.parent/reused["parent"]
        if sha(parent/"campaign.json")!=reused["campaign_sha256"]: raise ValueError("Resume parent changed")
        entries=resume_prefix(parent,frozen)
        if [r for r,_ in entries]!=reused["captures"] or any(
                json.loads((output/"runs"/r/"result.json").read_text())!=v for r,v in entries):
            raise ValueError("Reused result differs from original prefix")
    host=json.loads((output/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Management network restoration incomplete")
    records={}
    previous=None
    for item in SCHEDULE:
        system=item["system"]
        for name,digest in frozen[system]["images"].items():
            if sha(output/"builds"/system/name)!=digest: raise ValueError("Installed receiver image differs")
        folder=output/"runs"/("round%d"%item["round"])/system
        verified(folder,output/"builds"/system,MAC)
        value=read_capture(folder,system,host_buffer=PLAN["host_send_buffer_bytes"])
        if controlled: controlled_queue_capture(folder)
        if value!=json.loads((folder/"result.json").read_text()): raise ValueError("Saved result differs from raw capture")
        start,end=(datetime.fromisoformat(value[k]) for k in ("start_utc","end_utc"))
        if start>=end or previous is not None and start<=previous: raise ValueError("Independent reset chronology differs")
        previous=end
        records.setdefault(system,[]).append(value)
    cells=[]
    for system,runs in records.items():
        values=[r["receiver_bits_s"]/1000000 for r in runs]
        cells.append({"system":system,"runs":runs,"independent_resets":5,"values_mbit_s":values,
                      "median_mbit_s":statistics.median(values),"range_mbit_s":[min(values),max(values)]})
    return {"audit":"pass","board_mac":MAC,"independent_resets":15,"cells":cells,
            "original_flash_restored":True,"management_wifi_restored":True,"shared_public_core":True,
            "reused_complete_resets":record.get("reused_complete_resets",0),
            **({"source_queue_profile":QUEUE_PROFILE,"source_queue_restored":True} if controlled else {}),
            "whole_live_ram_peak_bytes":None,"energy_measured":False,
            "scope":PLAN["scope"],"timebase_limit":PLAN["jitter_scope"],"receiver_boundary":PLAN["boundary"]}


def interrupted_diagnostic(output):
    """Retain and replay the real first attempt without admitting it to the new group."""
    from audit_esp32_followup import envelope, verified
    from elftools.elf.elffile import ELFFile
    record=envelope(output,allow_incomplete=True)
    if output.name!="esp32-common-original-udp-receiver-b1-v1" or record["status"]!="incomplete" or \
            record["error"]!="ValueError('Original UDP reply ABI or FIN identity differs')" or record["completed_resets"]!=0:
        raise ValueError("Not the retained first receiver-auditor mismatch")
    frozen=json.loads((output/"proofs.json").read_text())
    expected={"FreeRTOS":"esp32-common-udp-receiver-freertos-v2",
              "Zephyr":"esp32-common-udp-receiver-zephyr-v2","NuttX":"esp32-common-udp-receiver-nuttx-v1"}
    for system,name in expected.items():
        source=REPORTS/name
        if frozen[system]["build"]!=name or frozen[system]["build_json_sha256"]!=sha(source/"build.json"):
            raise ValueError("Retained receiver build identity changed")
        meta=json.loads((source/"build.json").read_text())
        app=source/"application-source"/("src" if system=="Zephyr" else "")
        if meta["original_full_source_sha256"]!=RECEIVER_SHA or any(
                (app/n).read_text()!=text for n,text in original_receiver_parts().items()):
            raise ValueError("Retained original receiver/session source differs")
        if any(sha(source/n)!=digest for n,digest in meta["files"].items()) or \
                any(sha(output/"builds"/system/n)!=digest for n,digest in frozen[system]["images"].items()):
            raise ValueError("Retained receiver build/source/image changed")
    folder=output/"runs/round1/FreeRTOS"
    verified(folder,output/"builds/FreeRTOS",MAC)
    value=read_capture(folder,"FreeRTOS")
    peer=REPORTS/"esp32-network-common-zephyr-v2"
    expected_peer=json.loads((peer/"dependencies/provenance.json").read_text())["iperf_binary_sha256"]
    if sha(output/"iperf-host")!=expected_peer: raise ValueError("Retained original host peer differs")
    with (output/"iperf-host").open("rb") as stream:
        elf=ELFFile(stream)
        if "pthread_create" not in {s.name for s in elf.get_section_by_name(".dynsym").iter_symbols()}:
            raise ValueError("Original threaded host reporter not linked")
    host=json.loads((output/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Interrupted experiment did not restore management networking")
    return {"audit":"diagnostic_capture_replayed","board_mac":MAC,"physical_resets":1,"qualified_resets":0,
            "result":value,"old_campaign_unchanged":True,"original_flash_restored":True,
            "management_wifi_restored":True,"whole_live_ram_peak_bytes":None,
            "reason":"auditor incorrectly required FIN ID magnitude to equal offered data count; original threaded CloseReport uses the asynchronous reporter counter",
            "subsequent_group_boundary":"new wrapper follows the original static receive-buffer lifetime to avoid a 1500-byte packet array on the 2048-byte Zephyr shell stack; this earlier image is diagnostic, not pooled",
            "campaign_sha256":sha(output/"campaign.json"),"peer_sha256":expected_peer}


def qdisc_drop_snapshot(text, *, leaf_kind="fq_codel"):
    result={}
    for block in re.split(r"(?m)(?=^qdisc )",text):
        if not block.strip(): continue
        header=re.match(r"qdisc (\S+) \S+ (root|parent (\S+))",block)
        counter=re.search(r"\bSent \d+ bytes \d+ pkt \(dropped (\d+),",block)
        if header is None or counter is None:
            raise ValueError("Native qdisc drop snapshot missing header/counter")
        key="root" if header[2]=="root" else header[3]
        if leaf_kind=="pfifo" and key.startswith("1:"): key=key[1:]
        if key in result: raise ValueError("Repeated qdisc identity")
        result[key]={"kind":header[1],"dropped":int(counter[1])}
    if set(result)!={"root",":1",":2",":3",":4"} or result["root"]["kind"]!="mq" or \
            any(result[k]["kind"]!=leaf_kind for k in result if k!="root"):
        raise ValueError("Unexpected multi-queue/leaf profile")
    return result


def controlled_queue_capture(folder):
    actions=json.loads((folder/"udp_rx/actions.json").read_text())
    changes=[(i,a["host_udp_queue"]) for i,a in enumerate(actions) if "host_udp_queue" in a]
    if len(changes)!=1 or changes[0][1]["profile"]!=QUEUE_PROFILE or changes[0][1]["restored"]:
        raise ValueError("Controlled source queue selection missing")
    change=changes[0][1]
    queue_config(change["before"]["output"])
    if set(queue_config(change["after"]["output"]).values())!={"pfifo"} or \
            any(a["returncode"] for a in [change["before"],*change["actions"],change["after"]]):
        raise ValueError("Controlled source queue not installed")
    snapshots={}
    indices={}
    for phase in ("before_sender","after_sender"):
        rows=[(i,a) for i,a in enumerate(actions) if a.get("host_udp_path")==phase and a["arguments"][:1]==["tc"]]
        if len(rows)!=1 or rows[0][1]["returncode"] or rows[0][1]["arguments"]!=["tc","-s","qdisc","show","dev",DEVICE]:
            raise ValueError("Controlled source queue endpoint missing")
        indices[phase]=rows[0][0]
        snapshots[phase]=qdisc_drop_snapshot(rows[0][1]["output"],leaf_kind="pfifo")
    begin=[i for i,a in enumerate(actions) if "host_command" in a]
    end=[i for i,a in enumerate(actions) if "host_returncode" in a]
    if len(begin)!=1 or len(end)!=1 or not changes[0][0]<indices["before_sender"]<begin[0]<end[0]<indices["after_sender"]:
        raise ValueError("Source queue observations do not bracket the original sender")
    drops={k:snapshots["after_sender"][k]["dropped"]-snapshots["before_sender"][k]["dropped"]
           for k in snapshots["before_sender"]}
    if any(drops.values()):
        raise ValueError("Controlled source queue dropped packets or reset counters")
    return {"profile":QUEUE_PROFILE,"source_queue_drop_delta":drops}


def controlled_queue_restoration(output):
    state=json.loads((output/"wifi-restore-state.json").read_text())
    result=json.loads((output/"source-queue-restoration.json").read_text())
    host=json.loads((output/"host-after.json").read_text())
    if state.get("source_queue_profile")!=QUEUE_PROFILE or state.get("source_queue_restore_pending") is not False or \
            not host.get("source_queue_restored") or not host["management_wifi_restored"] or \
            any(a["returncode"] for a in host["actions"]) or result.get("restored") is not True or \
            result.get("profile")!=QUEUE_PROFILE or \
            set(queue_config(state["source_queue_original"]["output"]).values())!={"fq_codel"} or \
            set(queue_config(result["after"]["output"]).values())!={"fq_codel"} or \
            any(a["returncode"] for a in [result["before"],*result["actions"],result["after"]]):
        raise ValueError("Controlled source queue restoration not witnessed")


def source_queue_control(output):
    from audit_esp32_followup import envelope,verified
    from replay_esp32_followup import common_udp_receiver_capture,replay_source_queue
    record=envelope(output)
    expected={**PLAN,"schedule":[{"round":1,"system":"Zephyr"}],"diagnostic_only":True,
              "host_source_path_snapshots":True,"host_source_queue_profile":QUEUE_PROFILE}
    if record["mode"]!="common-original-zperf-udp-receiver-diagnostic" or record["board_mac"]!=MAC or \
            record["completed_resets"]!=1 or record.get("reused_complete_resets")!=0 or \
            json.loads((output/"plan.json").read_text())!=expected or json.loads((output/"proofs.json").read_text())!=proofs():
        raise ValueError("Not the frozen full-load Zephyr source queue control")
    previous=output.parent/"esp32-common-udp-source-path-b1-v1"
    before=source_path_diagnostic(previous)
    if json.loads((previous/"proofs.json").read_text())!=json.loads((output/"proofs.json").read_text()) or \
            sha(previous/"iperf-host")!=sha(output/"iperf-host") or \
            json.loads((previous/"plan.json").read_text())!={k:v for k,v in expected.items() if k!="host_source_queue_profile"}:
        raise ValueError("Source queue control changed the workload or firmware")
    folder=output/"runs/round1/Zephyr"
    frozen=json.loads((output/"proofs.json").read_text())["Zephyr"]
    if any(sha(output/"builds/Zephyr"/name)!=value for name,value in frozen["images"].items()):
        raise ValueError("Control image differs from the frozen build")
    verified(folder,output/"builds/Zephyr",MAC)
    value=read_capture(folder,"Zephyr",host_buffer=PLAN["host_send_buffer_bytes"])
    if value!=json.loads((folder/"result.json").read_text()):
        raise ValueError("Source queue control saved result differs")
    replay=common_udp_receiver_capture(folder/"udp_rx")
    if any(value[k]!=v for k,v in replay.items()):
        raise ValueError("Independent packet replay disagrees")
    condition=controlled_queue_capture(folder)
    controlled_queue_restoration(output)
    replay_source_queue(output)
    replay_source_queue(output,folder)
    return {"audit":"diagnostic_source_queue_control","ranking_eligible":False,"qualified_resets":0,
            "physical_resets":1,"campaign_sha256":sha(output/"campaign.json"),"result":value,
            "before_campaign_sha256":before["campaign_sha256"],
            "before_missing_outgoing_ids":before["missing_outgoing_ids"],
            "before_queue_drop_delta":before["source_queue_drop_delta"],**condition,
            "original_flash_restored":True,"management_wifi_restored":True,"source_queue_restored":True,
            "scope":"one full-load source queue intervention, same frozen firmware and original workload; five independent resets per OS still required"}


def source_path_diagnostic(output):
    from audit_esp32_followup import envelope,verified
    from replay_esp32_followup import raw_rows
    record=envelope(output,allow_incomplete=True)
    if output.name!="esp32-common-udp-source-path-b1-v1" or \
            record["board_mac"]!=MAC or \
            record["mode"]!="common-original-zperf-udp-receiver-diagnostic" or \
            record["status"]!="incomplete" or record["completed_resets"]!=0 or \
            record["error"]!="ValueError('Incomplete/duplicate/reordered outgoing fixed-byte sequence or finish exchange')":
        raise ValueError("Not the retained host source-path diagnostic")
    if sha(output/"plan.json")!="1a55f89f42e6d2ae063aecddecd172847b6be0f075cf967ac71cc4f9b64269fd":
        raise ValueError("Diagnostic changed the original offered-load parameters")
    run=output/"runs/round1/Zephyr"
    verified(run,output/"builds/Zephyr",MAC,logs=("identity.log","flash.log","verify-before.log","verify-after.log"))
    path=run/"udp_rx"
    actions=json.loads((path/"actions.json").read_text())
    snapshots={}
    for phase in ("before_sender","after_sender"):
        rows=[r for r in actions if r.get("host_udp_path")==phase and r["arguments"][:1]==["tc"]]
        if len(rows)!=1 or rows[0]["returncode"] or rows[0]["arguments"]!=["tc","-s","qdisc","show","dev","wlxa41a3ad16459"]:
            raise ValueError("Diagnostic lacks source queue endpoints")
        snapshots[phase]=qdisc_drop_snapshot(rows[0]["output"])
    changes={k:snapshots["after_sender"][k]["dropped"]-snapshots["before_sender"][k]["dropped"] for k in snapshots["before_sender"]}
    if any(n<0 for n in changes.values()) or changes["root"]!=sum(n for k,n in changes.items() if k!="root"):
        raise ValueError("Source queue counters reset or aggregate/leaf counts differ")
    data=(path/"network.pcap").read_bytes()
    if data[:4]!=b"\xd4\xc3\xb2\xa1" or len(data)<24 or struct.unpack_from("<I",data,20)[0]!=1:
        raise ValueError("Source diagnostic pcap format differs")
    cursor=24; ids=[]
    while cursor<len(data):
        if cursor+16>len(data): raise ValueError("Source diagnostic pcap header truncated")
        sec,us,n,wire=struct.unpack_from("<4I",data,cursor); cursor+=16
        if us>=1000000 or not 54<=n<=min(96,wire) or cursor+n>len(data):
            raise ValueError("Source diagnostic pcap bounds differ")
        frame=data[cursor:cursor+n]; cursor+=n
        if frame[12:14]!=b"\x08\x00" or frame[14]!=0x45 or frame[23]!=17:
            raise ValueError("Source diagnostic IPv4/UDP frame differs")
        if frame[26:30]==bytes((192,168,4,2)):
            if frame[30:34]!=bytes((192,168,4,1)) or struct.unpack_from("!H",frame,36)[0]!=5001 or wire!=1066:
                raise ValueError("Source diagnostic sender direction/size differs")
            ident=struct.unpack_from("!i",frame,42)[0]
            if ident>=0: ids.append(ident)
    if ids!=sorted(set(ids)) or not ids or ids[0]!=0 or ids[-1]!=73242 or \
            not re.search(r"\b0 packets dropped by kernel\b",(path/"pcap.log").read_text()):
        raise ValueError("Source diagnostic capture contains duplicates/reordering or kernel capture drops")
    native=[r["line"] for r in raw_rows(path/"uart.jsonl") if r["line"].startswith("ORIGINAL_ZPERF_RX END ")]
    if len(native)!=1: raise ValueError("Source diagnostic original receiver aggregate missing")
    host=json.loads((output/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Source diagnostic management recovery failed")
    missing=sorted(set(range(73243))-set(ids))
    return {"audit":"diagnostic_host_queue_loss","ranking_eligible":False,"qualified_resets":0,
        "campaign_sha256":sha(output/"campaign.json"),"pcap_sha256":sha(path/"network.pcap"),
        "outgoing_data_packets":len(ids),"missing_outgoing_ids":missing,"source_queue_snapshots":snapshots,
        "source_queue_drop_delta":changes,"queue_and_missing_counts_match":changes["root"]==len(missing),
        "original_receiver_line":native[0],"original_flash_restored":True,"management_wifi_restored":True,
        "scope":"host queue drop counters and missing host-interface frames; not per-packet kernel attribution or an OS loss score",
        "interpretation":"matching counts support a controlled non-dropping source-queue comparison; receiver results are not corrected by subtraction"}


def clock_diagnostic(output,*,periodic=False):
    from audit_esp32_followup import envelope,verified
    from replay_esp32_followup import raw_rows
    record=envelope(output,allow_incomplete=True)
    expected_name="esp32-common-original-udp-receiver-b1-v4" if periodic else "esp32-common-original-udp-receiver-b1-v3"
    if output.name!=expected_name or record["status"]!="incomplete" or \
            record["completed_resets"]!=1 or record["error"]!="ValueError('Incomplete/duplicate/reordered outgoing fixed-byte sequence or finish exchange')":
        raise ValueError("Not the preserved tickless-clock/injection mismatch")
    frozen=json.loads((output/"proofs.json").read_text())
    for system in ("FreeRTOS","Zephyr","NuttX"):
        source=REPORTS/frozen[system]["build"]
        meta=json.loads((source/"build.json").read_text())
        if sha(source/"build.json")!=frozen[system]["build_json_sha256"] or \
                any(sha(source/n)!=v for n,v in meta["files"].items()):
            raise ValueError("Preserved clock-diagnostic source changed")
    folder=output/"runs/round1/Zephyr"
    verified(folder,output/"builds/Zephyr",MAC,logs=("identity.log","flash.log","verify-before.log","verify-after.log"))
    rows=raw_rows(folder/"udp_rx/uart.jsonl")
    starts=[r for r in rows if r["line"].strip()=="ORIGINAL_ZPERF_RX STARTED"]
    ends=[r for r in rows if r["line"].startswith("ORIGINAL_ZPERF_RX END ")]
    if len(starts)!=1 or len(ends)!=1: raise ValueError("Clock diagnostic lacks original session endpoints")
    native={k:int(v) for k,v in (s.split("=",1) for s in ends[0]["line"].split()[2:])}
    wire=(folder/"udp_rx/network.pcap").read_bytes()
    position=24
    ids=[]
    replies=[]
    while position<len(wire):
        sec,usec,n,actual=struct.unpack_from("<4I",wire,position)
        position+=16
        frame=wire[position:position+n]
        position+=n
        if frame[26:30]==bytes((192,168,4,2)):
            ident=struct.unpack_from("!i",frame,42)[0]
            if ident>=0: ids.append(ident)
        else:
            f=struct.unpack_from("!10I",frame,54)
            replies.append(dict(bytes=(f[1]<<32)+f[2],receiver_us=f[3]*1000000+f[4],
                lost=f[5],outorder=f[6],datagrams=f[7],jitter_us=f[9]))
    if position!=len(wire) or not replies or any(r!=native for r in replies) or \
            len(set(ids))!=len(ids) or ids!=sorted(ids) or ids[0]!=0 or ids[-1]!=73242:
        raise ValueError("Clock diagnostic sequence/returned original counters disagree")
    wall=ends[0]["elapsed_s"]-starts[0]["elapsed_s"]
    native_seconds=native["receiver_us"]/1000000
    deficit=wall-native_seconds
    wraps=2*(2**32)/240000000
    source=REPORTS/frozen["Zephyr"]["build"]
    config=(source/"config").read_text()
    expected_timer="# CONFIG_TICKLESS_KERNEL is not set" if periodic else "CONFIG_TICKLESS_KERNEL=y"
    if expected_timer not in config.splitlines() or (abs(deficit)>.25 if periodic else abs(deficit-wraps)>.02):
        raise ValueError("Preserved diagnostic does not match the observed tickless-clock discrepancy")
    result={"audit":"diagnostic_injection_and_clock_mismatch","ranking_eligible":False,
            "campaign_sha256":sha(output/"campaign.json"),"board_mac":MAC,
            "actual_offered_data_packets":len(ids),"requested_expected_data_packets":73243,
            "missing_outgoing_ids":sorted(set(range(73243))-set(ids)),"native_original_result":native,
            "external_uart_elapsed_seconds":wall,"native_elapsed_seconds":native_seconds,
            "difference_seconds":deficit,"two_32bit_cycle_wraps_at_240mhz_seconds":wraps,
            "interpretation":"consistent with two lost CCOUNT wraps; requires the periodic-timer control, not a proven general driver root cause",
            "original_flash_restored":True,"management_wifi_restored":json.loads((output/"host-after.json").read_text())["management_wifi_restored"],
            "scope":"failed common-load/timing admission retained; not an OS throughput rank"}
    if periodic:
        from import_iotos_subjects import config_text
        before_path=output.parent/"esp32-common-original-udp-receiver-b1-v3"
        before=clock_diagnostic(before_path)
        before_proofs=json.loads((before_path/"proofs.json").read_text())
        previous=REPORTS/before_proofs["Zephyr"]["build"]
        old,old_duplicates=config_text((previous/"config").read_text())
        new,new_duplicates=config_text(config)
        changes={k:[old.get(k,"n"),new.get(k,"n")] for k in sorted(old.keys()|new.keys()) if old.get(k,"n")!=new.get(k,"n")}
        names=("port.c","zephyr_stdio.h",*original_receiver_parts())
        if old_duplicates or new_duplicates or changes!={"CONFIG_TICKLESS_KERNEL":["y","n"]} or \
                any((previous/"application-source/src"/n).read_bytes()!=(source/"application-source/src"/n).read_bytes() for n in names) or \
                (previous/"compiler.txt").read_bytes()!=(source/"compiler.txt").read_bytes():
            raise ValueError("Periodic control changed more than the declared timer configuration")
        result.update(audit="diagnostic_periodic_clock_control",config_changes=changes,
            before_campaign_sha256=before["campaign_sha256"],before_native_elapsed_seconds=before["native_elapsed_seconds"],
            before_external_uart_elapsed_seconds=before["external_uart_elapsed_seconds"],
            interpretation="one periodic-timer control restores elapsed-time agreement; host offered-sequence admission still fails, and five-reset validation remains pending")
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("proof","collect","collect-diagnostic","audit","diagnose","diagnose-clock","diagnose-periodic","diagnose-source-path","diagnose-source-control"))
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--system",choices=("CommonRX",),default="CommonRX")
    parser.add_argument("--restore-uuid")
    parser.add_argument("--resume-parent",type=Path)
    parser.add_argument("--diagnostic-system",choices=tuple(SOURCES))
    parser.add_argument("--source-queue-profile",choices=(QUEUE_PROFILE,))
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args=parser.parse_args()
    def stop(signum,frame): raise InterruptedError("Common UDP receiver interrupted; restoring board/network")
    signal.signal(signal.SIGTERM,stop)
    if args.mode in ("collect","collect-diagnostic"):
        if (args.mode=="collect-diagnostic") != (args.diagnostic_system is not None):
            parser.error("A source-path diagnosis requires collect-diagnostic and --diagnostic-system together")
        collect(args.root,args.output,args.restore_uuid,args.port,args.resume_parent,args.diagnostic_system,args.source_queue_profile)
    else:
        value=source_queue_control(args.output) if args.mode=="diagnose-source-control" else source_path_diagnostic(args.output) if args.mode=="diagnose-source-path" else proofs() if args.mode=="proof" else interrupted_diagnostic(args.output) if args.mode=="diagnose" else \
            clock_diagnostic(args.output,periodic=args.mode=="diagnose-periodic") if args.mode in ("diagnose-clock","diagnose-periodic") else audit(args.output)
        if args.mode in ("audit","diagnose","diagnose-clock","diagnose-periodic","diagnose-source-path","diagnose-source-control"): save(args.output/"audit.json",value)
        print(json.dumps(value,indent=2))
