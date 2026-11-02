#!/usr/bin/env python3
"""Standalone byte/count replay. Does not certify adapter semantic equivalence."""
import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw_rows(path):
    raw = path.with_suffix(".raw").read_bytes()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    absolute_keys = {"host_boot_id", "capture_started_monotonic_ns", "clock_read_before_ns", "clock_read_after_ns"}
    absolute = any(absolute_keys & set(r) for r in rows)
    offset, previous, previous_utc = 0, -1, None
    for row in rows:
        size = row["raw_bytes"]
        require(type(size) is int and size > 0, "Invalid raw chunk length")
        chunk = raw[offset:offset + size]
        require(hashlib.sha256(chunk).hexdigest() == row["raw_sha256"] and
                chunk.decode("utf-8", "replace").rstrip("\r\n") == row["line"], "Raw UART bytes differ")
        elapsed, utc = row["elapsed_s"], datetime.fromisoformat(row["utc"])
        require(math.isfinite(elapsed) and elapsed >= previous and utc.tzinfo is not None and
                (absolute or previous_utc is None or utc >= previous_utc), "Capture chronology differs")
        offset, previous, previous_utc = offset + size, elapsed, utc
    require(rows and offset == len(raw), "Raw UART coverage incomplete")
    if absolute:
        require(all(absolute_keys | {"clock_read_before_s", "clock_read_after_s"} <= set(r) for r in rows),
                "Monotonic clock fields incomplete")
        boot, started = rows[0]["host_boot_id"], rows[0]["capture_started_monotonic_ns"]
        require(isinstance(boot, str) and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot) and
                type(started) is int and started > 0, "Monotonic clock epoch invalid")
        previous_ns = started
        for r in rows:
            lo, hi = r["clock_read_before_ns"], r["clock_read_after_ns"]
            require(r["host_boot_id"] == boot and r["capture_started_monotonic_ns"] == started and
                type(lo) is int and type(hi) is int and previous_ns <= lo <= hi and
                abs(r["elapsed_s"] - (lo - started) / 1e9) <= 1e-6 and
                abs(r["clock_read_before_s"] - (lo - started) / 1e9) <= 1e-6 and
                abs(r["clock_read_after_s"] - (hi - started) / 1e9) <= 1e-6, "Monotonic clock chronology differs")
            previous_ns = hi
    elif any("clock_read_before_s" in r or "clock_read_after_s" in r for r in rows):
        intervals = []
        last = -1
        for r in rows:
            require("clock_read_before_s" in r and "clock_read_after_s" in r, "Clock bracket missing")
            low, high = r["clock_read_before_s"], r["clock_read_after_s"]
            require(math.isfinite(low) and math.isfinite(high) and 0 <= low and last <= low <= r["elapsed_s"] <= high,
                    "Clock bracket ordering differs")
            wall = datetime.fromisoformat(r["utc"]).timestamp()
            intervals.append((wall - high, wall - low))
            last = high
        require(max(low for low, _ in intervals) <= min(high for _, high in intervals) + 0.1,
                "Clock offset falls outside measured brackets")
    return rows


def campaign(folder, *, allow_energy=False, allow_incomplete=False):
    data = json.loads((folder / "campaign.json").read_text())
    statuses=("collection_complete_audit_pending","incomplete") if allow_incomplete else ("collection_complete_audit_pending",)
    require(data["status"] in statuses and data["original_flash_restored"] and
            data["energy_measured"] is allow_energy and
            not any(data[k] for k in ("old_cohort_modified", "external_independent_replication")),
            "Incomplete or misqualified campaign")
    expected = set(data["files"])
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*")
              if p.is_file() and p not in (folder / "campaign.json", folder / "audit.json")}
    require(expected == actual, "Campaign file coverage differs")
    for name, value in data["files"].items():
        path = (folder / name).resolve()
        require(path.is_relative_to(folder.resolve()) and digest(path) == value, "Changed campaign file: " + name)
    restore = (folder / "restore-verify.log").read_text()
    require("Verifying 0x400000 (4194304) bytes @ 0x00000000" in restore and
            "verify OK (digest matched)" in restore, "Full Flash restoration not verified")
    for name in ("identity-before.log", "identity-restore.log", "restore-verify.log"):
        require(set(re.findall(r"^MAC: ([0-9a-f:]+)$", (folder / name).read_text(), re.M)) == {data["board_mac"]},
                "Board identity differs")
    return data


def replay_source_queue(folder, run=None):
    """Replay queue conditions from saved host outputs, without the controller."""
    def configuration(raw,kind,root):
        rows=json.loads(re.sub(r'("options"\s*:\s*)\{limit (\d+)p\}',r'\1{"limit":\2}',raw))
        expected_options=({"limit":10240} if kind=="pfifo" else
            {"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":True})
        require(len(rows)==5 and len([r for r in rows if r.get("root") and r["kind"]=="mq" and r["handle"]==root])==1,
                "Replayed source queue root differs")
        children=[r for r in rows if "parent" in r]
        prefix="1" if root=="1:" else ""
        require(len(children)==4 and {r["parent"] for r in children}=={prefix+":"+str(n) for n in range(1,5)} and
                all(r["kind"]==kind and r["options"]==expected_options for r in children),"Replayed source queue leaves differ")
    if run is None:
        state=json.loads((folder/"wifi-restore-state.json").read_text())
        restored=json.loads((folder/"source-queue-restoration.json").read_text())
        require(state["source_queue_profile"]=="mq-four-pfifo-10240-v1" and
                state["source_queue_restore_pending"] is False and restored["restored"] is True,
                "Replayed source queue recovery incomplete")
        configuration(state["source_queue_original"]["output"],"fq_codel","0:")
        configuration(restored["after"]["output"],"fq_codel","0:")
        require(not any(a["returncode"] for a in [restored["before"],*restored["actions"],restored["after"]]),
                "Replayed source queue restore command failed")
        return
    actions=json.loads((run/"udp_rx/actions.json").read_text())
    setup=[(i,a["host_udp_queue"]) for i,a in enumerate(actions) if "host_udp_queue" in a]
    require(len(setup)==1 and setup[0][1]["profile"]=="mq-four-pfifo-10240-v1" and not setup[0][1]["restored"],
            "Replayed source queue setup absent")
    configuration(setup[0][1]["after"]["output"],"pfifo","1:")
    require(not any(a["returncode"] for a in [setup[0][1]["before"],*setup[0][1]["actions"],setup[0][1]["after"]]),
            "Replayed source queue setup failed")
    counters=[]; positions=[]
    for phase in ("before_sender","after_sender"):
        entries=[(i,a) for i,a in enumerate(actions) if a.get("host_udp_path")==phase and a["arguments"][:1]==["tc"]]
        require(len(entries)==1 and entries[0][1]["returncode"]==0,"Replayed source queue counter endpoint absent")
        value={}
        for block in re.split(r"(?m)(?=^qdisc )",entries[0][1]["output"]):
            if not block.strip(): continue
            header=block.splitlines()[0].split()
            key="root" if "root" in header else header[header.index("parent")+1]
            drops=re.search(r"\(dropped (\d+),",block)
            require(key not in value and drops and header[1]==("mq" if key=="root" else "pfifo"),
                    "Replayed source queue identity/counter differs")
            value[key]=int(drops[1])
        require(set(value)=={"root","1:1","1:2","1:3","1:4"},"Replayed source queue count coverage differs")
        counters.append(value); positions.append(entries[0][0])
    begin=[i for i,a in enumerate(actions) if "host_command" in a]
    end=[i for i,a in enumerate(actions) if "host_returncode" in a]
    require(len(begin)==len(end)==1 and setup[0][0]<positions[0]<begin[0]<end[0]<positions[1] and
            counters[0]==counters[1],"Replayed queue counters changed or do not bracket the sender")


def original_tcp_csv(text):
    """Independent integer-byte replay of original iPerf receiver output."""
    final = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) != 9 or not re.fullmatch(r"\d{14}",row[0]):
            continue
        require(row[1:4] == ["192.168.4.2","5001","192.168.4.1"], "TCP receiver direction differs")
        begin,end = (float(t) for t in row[6].split("-"))
        size,rate = int(row[7]),int(row[8])
        rounding = .051 if begin == 0 else .101
        require(0 <= begin < end and size > 0 and rate > 0 and
                abs(end-begin-size*8/rate) < rounding, "TCP integer-byte/rate/interval arithmetic differs")
        if begin == 0 and end >= 55:
            final.append({"start_s":begin,"end_s":end,"bytes":size,"bits_per_second":rate})
    require(len(final) == 1 and final[0]["end_s"] <= 65, "TCP complete receiver aggregate missing")
    return final[0]


def original_udp_capture(directory,sent):
    """Independent wire/CSV replay of the original 2.0.5 listener and FIN rules."""
    rows=[r for r in csv.reader(io.StringIO((directory/"host.log").read_text()))
          if len(r)==14 and re.fullmatch(r"\d{14}",r[0]) and
          float(r[6].split("-")[0])==0 and float(r[6].split("-")[1])>=55]
    require(len(rows)==1,"UDP complete original receiver aggregate missing")
    row=rows[0]
    buf=io.StringIO()
    csv.writer(buf).writerow(row[:9])
    received={**original_tcp_csv(buf.getvalue()),"jitter_ms":float(row[9]),"lost":int(row[10]),
              "datagrams":int(row[11]),"loss_percent":float(row[12]),"outorder":int(row[13])}
    require(0<=received["lost"]<=received["datagrams"] and received["datagrams"]>0 and
            received["jitter_ms"]>=0 and received["outorder"]>=0 and
            abs(received["loss_percent"]-100*received["lost"]/received["datagrams"])<=.0005001,
            "UDP original loss denominator/percentage differs")
    paths=[p for p in (directory/"udp.pcap",directory/"network.pcap") if p.is_file()]
    require(len(paths)==1 and re.search(r"\b0 packets dropped by kernel\b",(directory/"pcap.log").read_text()),
            "UDP capture is missing, ambiguous or dropped packets")
    data=paths[0].read_bytes()
    require(len(data)>=24 and data[:4]==b"\xd4\xc3\xb2\xa1" and
            struct.unpack_from("<I",data,20)[0]==1,"Unsupported UDP pcap format")
    pos,last_time,ports=24,{},None
    before,after,fins,stats=[],0,0,[]
    while pos<len(data):
        require(pos+16<=len(data),"Truncated UDP pcap record")
        sec,usec,size,wire_size=struct.unpack_from("<4I",data,pos)
        pos+=16
        require(usec<1000000 and 78<=size<=min(wire_size,96) and pos+size<=len(data),
                "Invalid UDP packet length/time")
        frame=data[pos:pos+size]
        pos+=size
        require(frame[12:14]==b"\x08\x00" and frame[14]>>4==4 and frame[23]==17,
                "Non-IPv4/UDP packet in original capture")
        ip_length=(frame[14]&15)*4
        start=14+ip_length
        require(ip_length>=20 and not struct.unpack_from("!H",frame,20)[0]&0x3fff and
                wire_size==14+struct.unpack_from("!H",frame,16)[0] and len(frame)>=start+44,
                "Fragmented or incomplete original UDP packet")
        src,dst=frame[26:30],frame[30:34]
        sport,dport,length,_=struct.unpack_from("!4H",frame,start)
        require(length==wire_size-start==1032,"UDP datagram is not 1024 bytes")
        sending=(src,dst)==(bytes((192,168,4,1)),bytes((192,168,4,2))) and dport==5001
        returning=(src,dst)==(bytes((192,168,4,2)),bytes((192,168,4,1))) and sport==5001
        require(sending!=returning,"UDP endpoint direction differs")
        flow=(src,dst,sport,dport)
        stamp=sec*1000000+usec
        require(stamp>=last_time.get(flow,0),"UDP same-flow capture chronology reversed")
        last_time[flow]=stamp
        payload=frame[start+8:]
        ident,ssec,susec=struct.unpack_from("!iII",payload)
        require(susec<1000000 and (ssec*1000000+susec)%10000==0,"UDP sender is not 100-Hz timestamped")
        pair=(sport,dport) if sending else (dport,sport)
        ports=pair if ports is None else ports
        require(pair==ports,"UDP session ports changed")
        if sending:
            f,threads,port,_,rate,packet=struct.unpack_from("!6I",payload,12)
            require((f,threads,packet)==(0,1,1024) and int.from_bytes(payload[24:28],"little")==16384,
                    "Original UDP flags/ABI/buffer size differ")
            if ident<0:
                require(ident==-sent and (port,rate)==(0,0),"UDP FIN sequence/request differs")
                fins+=1
            else:
                require(0<=ident<sent and (port,rate)==(5001,10000),"UDP offered sequence/request differs")
                if fins: after+=1
                else: before.append(ident)
        else:
            require(ident==-sent and len(payload)>=52,"UDP returned server report missing")
            values=struct.unpack_from("!10I",payload,12)
            require(values[0]==0x80000000 and values[4]<1000000 and values[9]<1000000,
                    "UDP returned server header differs")
            stats.append(dict(bytes=values[1]*2**32+values[2],duration_us=values[3]*1000000+values[4],
                              lost=values[5],outorder=values[6],datagrams=values[7],
                              jitter_us=values[8]*1000000+values[9]))
    require(before and fins and stats and all(s==stats[0] for s in stats),"UDP finish exchange incomplete/contradictory")
    # Listener consumes the first packet. The server reports the equal-size FIN.
    sequence=before[1:]+[sent]
    maximum,missing,reordered=0,0,0
    for ident in sequence:
        if ident:
            if ident>maximum+1: missing+=ident-maximum-1
            elif ident<maximum+1: reordered+=1
            maximum=max(maximum,ident)
    if missing>reordered: missing-=reordered
    expected={"bytes":len(sequence)*1024,"lost":missing,"outorder":reordered,"datagrams":maximum}
    s=stats[0]
    require(55000000<=s["duration_us"]<=65000000 and all(s[k]==v==received[k] for k,v in expected.items()) and
            abs(received["end_s"]*1000000-s["duration_us"])<=51000 and
            abs(received["bits_per_second"]-s["bytes"]*8000000/s["duration_us"])<=1.1 and
            abs(received["jitter_ms"]*1000-s["jitter_us"])<=1.001,
            "UDP wire, CSV or original loss/FIN arithmetic differs")
    return {"receiver":s,"csv":received,"observed_data_frames":len(before)+after,
            "frames_before_fin":len(before),"late_data_frames":after,"finish_attempts":fins,
            "first_data_id":before[0],"last_data_id":before[-1]}


def common_udp_receiver_capture(directory, expected_packets=73243):
    """Independent host-offered stream, original receiver reply and CSV check.

    This observes the host interface, not a hidden board receive-packet trace.
    In particular, the original receiver's lost/count ratio is not loss/offered.
    """
    require(re.search(r"\b0 packets dropped by kernel\b",(directory/"pcap.log").read_text()),
            "Common UDP host capture dropped packets")
    data=(directory/"network.pcap").read_bytes()
    require(len(data)>=24 and data[:4]==b"\xd4\xc3\xb2\xa1" and
            struct.unpack_from("<I",data,20)[0]==1,"Common UDP pcap header differs")
    cursor=24
    sent,finish,answers=[],[],[]
    ports=None
    times={}
    while cursor<len(data):
        require(cursor+16<=len(data),"Common UDP pcap record header truncated")
        sec,us,n,wire=struct.unpack_from("<4I",data,cursor)
        cursor+=16
        require(us<1000000 and 54<=n<=min(wire,96) and cursor+n<=len(data),"Common UDP captured size/time differs")
        frame=data[cursor:cursor+n]
        cursor+=n
        require(frame[12:14]==b"\x08\x00" and frame[14]==0x45 and frame[23]==17 and
                not struct.unpack_from("!H",frame,20)[0]&0x3fff and
                struct.unpack_from("!H",frame,16)[0]+14==wire,"Common UDP IPv4 frame differs")
        sport,dport,udp_bytes,_=struct.unpack_from("!4H",frame,34)
        require(udp_bytes==wire-34,"Common UDP length field differs")
        ident,seconds,micros=struct.unpack_from("!iII",frame,42)
        require(micros<1000000,"Common UDP sender time field differs")
        src,dst=frame[26:30],frame[30:34]
        outbound=(src,dst)==(b"\xc0\xa8\x04\x02",b"\xc0\xa8\x04\x01")
        inbound=(src,dst)==(b"\xc0\xa8\x04\x01",b"\xc0\xa8\x04\x02")
        require(outbound!=inbound,"Common UDP host/board direction differs")
        stamp=sec*1000000+us
        require(stamp>=times.get(outbound,0),"Common UDP direction time reversed")
        times[outbound]=stamp
        pair=(sport,dport) if outbound else (dport,sport)
        ports=pair if ports is None else ports
        require(pair==ports and ports[1]==5001,"Common UDP session port changed")
        if outbound:
            require(udp_bytes==1032,"Common UDP host payload is not 1024 bytes")
            (sent if ident>=0 else finish).append((ident,stamp))
        else:
            require(udp_bytes==60 and n==94 and ident<0,"Common UDP original statistic reply ABI differs")
            fields=struct.unpack_from("!10I",frame,54)
            require(fields[0]==0x80000000 and fields[4]<1000000 and fields[8]==0,
                    "Common UDP original statistic flags/time differs")
            answers.append((ident,stamp,dict(bytes=fields[1]*2**32+fields[2],
                receiver_us=fields[3]*1000000+fields[4],lost=fields[5],outorder=fields[6],
                datagrams=fields[7],jitter_us=fields[9])))
    require(len(sent)==expected_packets and [p[0] for p in sent]==list(range(expected_packets)) and
            finish and len({p[0] for p in finish})==1 and answers,"Common UDP offered sequence/FIN incomplete")
    require(finish[0][1]>=sent[-1][1] and all(p[0]==finish[0][0] and p[1]>=finish[0][1] and
            p[2]==answers[0][2] for p in answers),"Common UDP FIN/statistic binding differs")
    stats=answers[0][2]
    require(stats["bytes"]==stats["datagrams"]*1024 and stats["datagrams"]>0 and
            stats["receiver_us"]>0 and stats["receiver_us"]%10000==0,"Common UDP original count/byte/tick arithmetic differs")
    span=sent[-1][1]-sent[0][1]
    require(55000000<=span<=75000000,"Common UDP complete offered duration differs")
    csv_rows=list(csv.reader(io.StringIO((directory/"host.log").read_text())))
    finals=[r for r in csv_rows if len(r) in (9,14) and re.fullmatch(r"\d{14}",r[0]) and
            r[6].startswith("0.0-") and float(r[6].split("-")[1])>=55]
    sender=[r for r in finals if len(r)==9]
    receiver=[r for r in finals if len(r)==14]
    require(len(sender)==len(receiver)==1,"Common UDP original sender/receiver CSV aggregate missing")
    sender,receiver=sender[0],receiver[0]
    require(sender[1:5]==["192.168.4.2",str(ports[0]),"192.168.4.1","5001"] and
            receiver[1:5]==["192.168.4.1","5001","192.168.4.2",str(ports[0])],"Common UDP original CSV directions differ")
    require(int(sender[7])==expected_packets*1024 and int(sender[8])>0 and
            abs(float(sender[6].split("-")[1])-int(sender[7])*8/int(sender[8]))<=.051,
            "Common UDP sender CSV byte/rate/time differs")
    require([int(receiver[i]) for i in (7,10,11,13)]==[stats[k] for k in ("bytes","lost","datagrams","outorder")] and
            abs(float(receiver[6].split("-")[1])*1000000-stats["receiver_us"])<=51000 and
            abs(int(receiver[8])-stats["bytes"]*8000000/stats["receiver_us"])<=1.1 and
            abs(float(receiver[9])*1000-stats["jitter_us"])<=1.001 and
            abs(float(receiver[12])-100*stats["lost"]/stats["datagrams"])<=.0005001,
            "Common UDP receiver CSV and returned original counters differ")
    return {"sender_datagrams":len(sent),"sender_bytes":len(sent)*1024,"sender_span_us":span,
            "sender_bits_s":len(sent)*1024*8000000/span,"finish_attempts":len(finish),"stat_replies":len(answers),
            "original_finish_id":finish[0][0],"receiver":stats,
            "receiver_bits_s":stats["bytes"]*8000000/stats["receiver_us"]}


def native_allocation_addresses(lines):
    """Rebuild the live block set without the production allocator replay."""
    def records(prefix, skip):
        return [{k:int(v) for k,v in (s.split("=",1) for s in line.split()[skip:])}
                for line in lines if line.startswith(prefix)]
    events = records("TM_N_RAM event=",1)
    identities = records("TM_N_ID at=",1)
    regions = records("RAM_EVENTS region ",2)
    layout = records("TM_N_RAM layout ",2)
    require(len(layout) == 1 and layout[0]["control_bytes"] == 368 and layout[0]["node_bytes"] == 8,
            "Native allocation layout missing")
    require(regions and identities and len({e["at"] for e in identities}) == len(identities),
            "Address transitions missing or duplicated")
    pending = {e["at"]:e for e in identities}
    live,used,peak,guards = {},0,0,0
    for i,event in enumerate(events):
        k = event["kind"]
        require(event["event"] == i and k in range(7) and (i == 0) == (k == 0),
                "Native address event order differs")
        if k == 0:
            require(event["delta"] == 368,"Native heap control prefix differs")
        elif k == 6:
            require(event["delta"] == 16,"Native region sentinels differ")
            guards += 16
        else:
            entry = pending.pop(i,None)
            require(entry is not None and entry["heap"] == layout[0]["heap"],"Native address event coverage differs")
            old,nold,new,nnew = [entry[f] for f in ("old","old_bytes","new","new_bytes")]
            require((old == 0) == (nold == 0) and (new == 0) == (nnew == 0) and
                (k == 1) == (old == 0) and (k == 2) == (new == 0) and nnew-nold == event["delta"],
                "Native allocation transition shape or bytes differ")
            if old:
                require(live.pop(old,None) == nold,"Native old address was not live at that size")
            require(k != 3 or old == new and nnew <= nold,"Native shrink changes identity or grows")
            require(k != 4 or nnew >= nold,"Native growth shrinks")
            require(k != 5 or new > old,"Native alignment does not advance address")
            if new:
                require(new not in live and nnew >= 8 and nnew % 8 == 0 and any(
                    r["start"] < new-8 < new-8+nnew <= r["end"]-8 for r in regions),
                    "Native allocation region or live address collision")
                live[new] = nnew
            spans = sorted((p-8,p-8+n) for p,n in live.items())
            require(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])),"Native live blocks overlap")
        used += event["delta"]
        peak = max(peak,used)
        require(used == 368+guards+sum(live.values()) and [used,peak] == [event["occupied"],event["peak"]],
                "Native live set differs from original occupied/peak history")
    require(not pending and events,"Extra native identity transitions")
    walked = records("TM_N_ID live ",2)
    final = {b["pointer"]:b["bytes"] for b in walked}
    require(len(final) == len(walked) and live == final and records("TM_N_ID trace ",2) == [
        {"transitions":len(identities),"live":len(final),"overflow":0}],"Native final block walk differs")
    return {"events":len(events),"transitions":len(identities),"live":live,"native_heap_peak_bytes":peak}


def nuttx_startup_observation(lines,stack=None):
    selected=[(i,s) for i,s in enumerate(lines) if s.startswith("NUTTX_BOOT_STACK ")]
    require(len(selected)==1,"Native startup line missing/repeated")
    at,line=selected[0]
    fields=[p.split("=",1) for p in line.split()[1:]]
    require(len(fields)==12 and all(len(p)==2 and p[1].isdigit() for p in fields),"Native startup fields differ")
    item={k:int(v) for k,v in fields}
    require(set(item)=={"entry_sp","before_switch","after_switch","idle","reserved","painted","verified",
        "recolor_sp","spare","touched","recolors","frame"},"Native startup field inventory differs")
    low,n=item["idle"],item["reserved"]
    entry,before,after,sp=(item[k] for k in ("entry_sp","before_switch","after_switch","recolor_sp"))
    require((stack is None or [low,n]==list(stack)) and 0x3ffb0000<=low<low+n<=0x40000000 and
        n==item["painted"]==item["verified"]==3072 and after==low+n and
        0x3ffe0000<=before<entry<0x40000000 and entry-before==item["frame"]==32 and
        not any(p%16 for p in (entry,before,after,sp)) and low+64<sp<after and
        0<=item["spare"]<n and item["spare"]%4==item["touched"]%4==0 and
        item["spare"]+item["touched"]==n and item["recolors"]==1 and
        at+1<len(lines) and lines[at+1].startswith("TM_N_ID "),"Native startup switch/paint/arithmetic differs")
    return {"application_entry_sp":entry,"before_native_switch_sp":before,"after_native_switch_sp":after,
        "inherited_native_frame_bytes":32,"idle_stack_address":low,"idle_reserved_bytes":n,
        "initial_painted_and_verified_bytes":item["painted"],"before_native_recolor_sp":sp,
        "spare_pattern_bytes":item["spare"],"touched_watermark_bytes":item["touched"],"resolution_bytes":4,
        "observed_before_native_idle_recolor":True,"already_in_static_sram":True,
        "scope":"native idle startup before recolor; observer-inclusive historical writes, not ROM/bootloader or simultaneous-live bytes",
        "full_live_ram_peak_bytes":None}


def rhino_message_snapshot(lines):
    """Independent raw-record arithmetic for the legacy message diagnostic."""
    event_re=(r"RHINO_MESSAGE_RAM event=(\d+) kind=(\d+) pointer=(\d+) requested=(\d+) "
              r"occupied=(\d+) legacy=(\d+) observation=(\d+) task=(\d+)")
    events=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(event_re,s))]
    end_re=(r"RHINO_MESSAGE_RAM END events=(\d+) tasks=(\d+) active=(\d+) blocks=(\d+) "
            r"occupied=(\d+) legacy=(\d+) fixed_free=(\d+) peak=(\d+) legacy_peak=(\d+) invalid=(\d+) original_reports=(\d+)")
    endings=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(end_re,s))]
    require(len(endings)==1 and 0<len(events)<512,"Rhino diagnostic missing/overflowed")
    e=endings[0]
    require(e[0]==len(events) and e[-2:]==(0,3) and e[5]==e[4]+e[6] and
            [r[0] for r in events]==list(range(len(events))) and
            all(r[1] in range(4) and 0<=r[5]-r[4]<=8192 for r in events) and
            all(a[6]<=b[6] for a,b in zip(events,events[1:])) and
            (e[4],e[5])==events[-1][4:6] and
            (e[7],e[8])==(max(r[4] for r in events),max(r[5] for r in events)),
            "Rhino buffered history and native occupancy disagree")
    boundaries=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"RHINO_MESSAGE_RAM boundary=(\d+) occupied=(\d+) legacy=(\d+) observations=(\d+)",s))]
    require([r[0] for r in boundaries]==list(range(4)) and all(r[1]<=e[7] and r[2]<=e[8] for r in boundaries),
            "Rhino original message observation boundaries differ")
    tasks=[]
    for s in lines:
        if not s.startswith("RHINO_MESSAGE_RAM task="):
            continue
        row=dict(t.split("=",1) for t in s.split()[1:])
        tasks.append({k:v if k=="name" else int(v) for k,v in row.items()})
    blocks=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"RHINO_MESSAGE_RAM block=(\d+) pointer=(\d+) usable=(\d+)",s))]
    require(len(tasks)==e[1] and sum(t["present"] for t in tasks)==e[2] and len(blocks)==e[3] and
            [b[0] for b in blocks]==list(range(len(blocks))) and len({b[1] for b in blocks})==len(blocks),
            "Rhino task/block inventory differs")
    tm=[t for t in tasks if t["name"]=="tm"]
    require(len(tm)==2 and all(t["present"] and t["dynamic"]==1 and t["reserved"]==4096 for t in tm),
            "Original static message tasks differ")
    boot=[t for t in tasks if t["name"]=="main" and t["reserved"]==8704]
    require(len(boot)==1,"Rhino bootstrap identity missing")
    boot=boot[0]
    frees={p:[r[0] for r in events if r[1]==2 and r[2]==p] for p in (boot["stack"],boot["tcb"])}
    if boot["present"]:
        require(boot["state"]==1 and not any(boot[k] for k in ("deleted","stack_freed","tcb_freed")) and
                not any(frees.values()) and (boot["stack"],8704) in [(p,n) for _,p,n in blocks] and
                (boot["tcb"],136) in [(p,n) for _,p,n in blocks],"Retained bootstrap ownership differs")
        state="retained-ready"
    else:
        reclaimer=[t["tcb"] for t in tasks if t["name"]=="dyn_mem_proc_task"]
        require(len(reclaimer)==1 and all(boot[k] for k in ("deleted","stack_freed","tcb_freed")) and
                all(len(v)==1 for v in frees.values()) and all(r[7]==reclaimer[0] for r in events
                    if r[1]==2 and r[2] in frees),"Bootstrap native reclamation differs")
        state="deleted-and-freed"
    ready=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"RHINO_MESSAGE_RAM readiness=bootstrap-retired waits=(\d+) before=(\d+) after=(\d+) task_id=(\d+) prio_observed=(\d+) prio=(\d+)",s))]
    if ready:
        require(len(ready)==1 and ready[0][0]<=100 and ready[0][3]==boot["task"] and state=="deleted-and-freed",
                "Rhino bootstrap readiness failed")
    positions=[(i,int(m[1])) for i,s in enumerate(lines) if (m:=re.fullmatch(
        r"\*\*\*\* Thread-Metric Message Processing Test \*\*\*\* Relative Time: (\d+)",s))]
    require([s for _,s in positions]==[30,60,90],"Original three message reports incomplete")
    totals=[]
    for i,_ in positions:
        m=re.fullmatch(r"Time Period Total:\s+(\d+)",lines[i+1])
        require(m is not None and int(m[1])>0,"Original message count missing/failed")
        totals.append(int(m[1]))
    return {"events":len(events),"heap_final_bytes":e[4],"legacy_heap_final_bytes":e[5],
        "heap_peak_bytes":e[7],"legacy_heap_peak_bytes":e[8],"fixed_pool_free_bytes":e[6],
        "original_window_totals":totals,"bootstrap_state":state,"bootstrap_free_events":{str(k):v for k,v in frees.items()},
        "bootstrap_readiness_present":bool(ready)}


def replay(folder, prepared=None):
    data = campaign(folder)
    intervals, cells = [], []
    mode = data.get("mode", data.get("kind"))
    if mode == "rhino-message-history":
        require(prepared is not None and data["independent_resets"]==5 and data["board_mac"]=="34:98:7a:a2:85:28" and
                data["diagnostic_only"] and not data["ranking_eligible"],"Rhino diagnostic cohort differs")
        plan=json.loads((folder/"plan.json").read_text())
        build=json.loads((prepared/"build.json").read_text())
        require(plan["resets"]==5 and plan["build_manifest_sha256"]==digest(prepared/"build.json"),"Rhino diagnostic build binding differs")
        for name in ("application.elf","application.bin","bootloader.bin","partitions.bin"):
            require(digest(folder/"build"/name)==digest(prepared/name),"Rhino diagnostic image differs")
        runs=[]
        for index in range(1,6):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count(
                "Thread-Metric conditions cpu_hz=240000000 cores=1 tick_hz=100 scheduler=priority-fifo")==1 and
                lines.count("Thread-Metric queue self-check PASS")==1 and not any(
                re.search(r"panic|abort|Exception|ASSERT|FATAL|invalid=[1-9]|readiness=FAIL",s,re.I) for s in lines),
                "Rhino reset/profile/correctness differs")
            result=rhino_message_snapshot(lines)
            require(result["bootstrap_readiness_present"]==build.get("bootstrap_readiness_gate",False),"Readiness version differs")
            runs.append(result)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"AliOS-Rhino","runs":runs,"ranking_eligible":False})
    elif mode == "nuttx-message-lifetimes":
        require(prepared is not None and data["independent_resets"] == 5 and data["board_mac"] == "34:98:7a:a2:85:28",
                "Address lifecycle replay requires matching prepared build and five B1 resets")
        build = json.loads((prepared/"build.json").read_text())
        startup=build.get("application_startup_stack_coverage",False)
        tick=build.get('native_tick_stack_snapshots',False)
        require(type(startup) is bool,"Native startup mode differs")
        plan = json.loads((folder/"plan.json").read_text())
        require(build.get("allocation_identities") is True and plan["build_manifest_sha256"] == digest(prepared/"build.json"),
                "Allocation address observer build identity differs")
        if plan.get('reused_first_reset'):
            previous=folder/'reused-first-source'
            old=json.loads((previous/'campaign.json').read_text())
            require(digest(previous/'campaign.json')==plan['reused_first_campaign_sha256'] and
                old['status']=='incomplete' and old['original_flash_restored'] and old['board_mac']==data['board_mac'],
                'Reused original first-reset/restoration identity differs')
            for name,value in old['files'].items():
                p=(previous/name).resolve()
                require(p.is_relative_to(previous.resolve()) and digest(p)==value,'Reused sealed bytes differ')
            for name in ('reset1.raw','reset1.jsonl','capture1.log','verify-run1.log'):
                require((previous/'captures'/name).read_bytes()==(folder/'captures'/name).read_bytes(),
                    'Reused reset bytes were modified')
        for name in ("application.elf","application.bin","bootloader.bin","partitions.bin"):
            require(digest(folder/"build"/name) == digest(prepared/name),"Address trace image differs")
        validation = [r["line"] for r in raw_rows(folder/"validation/reset1.jsonl")]
        native_allocation_addresses(validation)
        passed = re.findall(r"RAM_EVENTS validation=PASS base=(\d+) final=(\d+)","\n".join(validation))
        require(len(passed) == 1 and passed[0][0] == passed[0][1] and
                validation[-1] == "NUTTX_MESSAGE_RAM VALIDATION END","Separate allocator validation missing")
        startup_stack=None
        if startup:
            require(digest(prepared/"symbols.txt")==build["files"]["symbols.txt"],"Native startup symbol evidence changed")
            entries=[(int(m[1],16),int(m[2],16)) for s in (prepared/"symbols.txt").read_text().splitlines()
                if (m:=re.fullmatch(r"([0-9a-f]+) ([0-9a-f]+) \w g_idlestack",s))]
            require(len(entries)==1,"Native idle symbol missing/repeated")
            startup_stack=entries[0]
            nuttx_startup_observation(validation,startup_stack)
        results = []
        for i in range(1,6):
            rows = raw_rows(folder/"captures"/("reset%d.jsonl"%i))
            lines = [r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines) == 1 and
                lines.count("NUTTX_MESSAGE_RAM END invalid=0 original_reports=3") == 1 and
                lines.count("Thread-Metric queue self-check PASS") == 1 and not re.search(
                    r"panic|fatal|assert|Exception|error:","\n".join(lines),re.I),"Original message reset or correctness differs")
            value = native_allocation_addresses(lines)
            headings = [(n,int(m[1]),r["elapsed_s"]) for n,r in enumerate(rows) if (m:=re.search(
                r"Thread-Metric Message Processing Test .* Relative Time: (\d+)$",r["line"]))]
            totals = [(n,int(m[1])) for n,s in enumerate(lines) if (m:=re.fullmatch(r"Time Period Total:\s*(\d+)",s.strip()))]
            require([h[1] for h in headings] == [30,60,90] and len(totals) == 3 and
                all(h[0] < t[0] < (headings[j+1][0] if j < 2 else len(lines)) and t[1] > 0
                    for j,(h,t) in enumerate(zip(headings,totals))) and
                all(29.5 < b[2]-a[2] < 30.5 for a,b in zip(headings,headings[1:])),"Original message count/window differs")
            value["original_counts"] = [v for _,v in totals]
            if startup:
                value["application_startup_stack"]=nuttx_startup_observation(lines,startup_stack)
            if tick:
                from replay_esp32_nuttx_tick_stacks import observations as tick_observations
                symbols={m[4]:(int(m[1],16),int(m[2],16)) for s in (prepared/'symbols.txt').read_text().splitlines()
                    if (m:=re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) (\w) (\S+)',s))}
                value['native_tick_stack_snapshots']=tick_observations(lines,symbols)
                if build.get('native_tick_same_image_control'):
                    from replay_esp32_nuttx_tick_stacks import probe_cost
                    value['native_tick_probe_cost']=probe_cost(lines,value['native_tick_stack_snapshots']['samples'])
            results.append(value)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells = [{"system":"NuttX","runs":results}]
    elif mode=="common-original-zperf-udp-receiver":
        require(data["board_mac"]=="34:98:7a:a2:85:28" and data["completed_resets"]==15,
                "Common UDP receiver board/reset count differs")
        order=["FreeRTOS","Zephyr","NuttX"]
        schedule=[{"round":r+1,"system":s} for r in range(5) for s in order[r%3:]+order[:r%3]]
        plan=json.loads((folder/"plan.json").read_text())
        require(plan["schedule"]==schedule and [plan[k] for k in
            ("packet_bytes","requested_bytes","expected_sender_datagrams","expected_sender_bytes","rate_bits_s","tick_hz","clock_mhz","cores")]==
            [1024,75000000,73243,75000832,10000000,100,240,1],"Common UDP receiver frozen parameters differ")
        require(plan["host_send_buffer_bytes"]==212992,"Common UDP original host-buffer request differs")
        controlled_queue=plan.get("host_source_queue_profile")
        if controlled_queue:
            require(controlled_queue=="mq-four-pfifo-10240-v1" and plan["host_source_path_snapshots"] is True and
                    data.get("reused_complete_resets")==0 and not (folder/"reuse-parent.json").exists(),
                    "Controlled source queue requires a fresh full cohort")
            replay_source_queue(folder)
        if (folder/"reuse-parent.json").exists():
            reuse=json.loads((folder/"reuse-parent.json").read_text())
            require(Path(reuse["parent"]).name==reuse["parent"] and reuse["captures"]==["round1/FreeRTOS"],
                    "Common UDP reused prefix identity differs")
            parent=folder.parent/reuse["parent"]
            original=campaign(parent,allow_incomplete=True)
            require(original["status"]=="incomplete" and original["mode"]==mode and original["completed_resets"]==1 and
                    original["board_mac"]==data["board_mac"] and digest(parent/"campaign.json")==reuse["campaign_sha256"] and
                    json.loads((parent/"plan.json").read_text())=={k:v for k,v in plan.items() if k!="receive_clock_sanity"},
                    "Common UDP reused parent differs")
            for path in (parent/"runs/round1/FreeRTOS").rglob("*"):
                if path.is_file():
                    require(digest(path)==digest(folder/"runs/round1/FreeRTOS"/path.relative_to(parent/"runs/round1/FreeRTOS")),
                            "Common UDP reused prefix raw bytes changed")
        sources=json.loads((folder/"proofs.json").read_text())
        require(set(sources)==set(order),"Common UDP receiver proof group differs")
        for system in order:
            require(digest(folder/"iperf-host")==sources[system]["peer_sha256"],"Common UDP original host peer changed")
            for name,sha in sources[system]["images"].items():
                require(digest(folder/"builds"/system/name)==sha,"Common UDP receiver installed image changed")
            if prepared is not None:
                source=prepared/sources[system]["build"]
                require(digest(source/"build.json")==sources[system]["build_json_sha256"],"Common UDP prepared build changed")
                manifest=json.loads((source/"build.json").read_text())
                for name,sha in manifest["files"].items():
                    path=(source/name).resolve()
                    require(path.is_relative_to(source.resolve()) and digest(path)==sha,"Common UDP prepared source file changed")
        results={s:[] for s in order}
        ansi=re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
        for item in schedule:
            system=item["system"]
            run=folder/"runs"/("round%d"%item["round"])/system
            path=run/"udp_rx"
            build=folder/"builds"/system
            installed=[(0x1000,"application.bin")] if not (build/"bootloader.bin").exists() else [
                (0x1000,"bootloader.bin"),(0x8000,"partitions.bin"),(0x10000,"application.bin")]
            for name in ("identity.log","flash.log","verify-before.log","verify-after.log"):
                log=(run/name).read_text()
                require(set(re.findall(r"^MAC: ([0-9a-f:]+)$",log,re.M))=={data["board_mac"]} and
                        not re.search(r"fatal error|digest mismatch|Traceback",log,re.I),"Common UDP per-reset Flash identity differs")
                if name.startswith("verify-"):
                    matches=re.findall(r"^Verifying 0x[0-9a-f]+ \((\d+)\) bytes @ 0x([0-9a-f]+).*\n"
                        r"-- verify OK \(digest matched\)$",log,re.M)
                    require([(int(n),int(a,16)) for n,a in matches]==[
                        (((build/n).stat().st_size+3)&~3,a) for a,n in installed],"Common UDP per-reset image coverage differs")
            rows=raw_rows(path/"uart.jsonl")
            text="\n".join(ansi.sub("",r["line"]) for r in rows)
            require(sum(r["line"].startswith("rst:0x") for r in rows)==1 and not re.search(
                r"panic|fatal|assert|Brownout|Guru Meditation|ORIGINAL_ZPERF_RX ERROR",text,re.I),"Common UDP receiver boot/fault differs")
            require(text.count("ORIGINAL_ZPERF_RX READY target="+system+" port=5001 buffer=1500 tick_hz=100")==1 and
                    text.count("ORIGINAL_ZPERF_RX STARTED")==1 and text.count("ORIGINAL_ZPERF_RX CLOSED status=0")==1,
                    "Common UDP original receiver readiness/closure differs")
            values=re.findall(r"ORIGINAL_ZPERF_RX END datagrams=(\d+) lost=(\d+) outorder=(\d+) bytes=(\d+) receiver_us=(\d+) jitter_us=(\d+)",text)
            require(len(values)==1,"Common UDP receiver final counters missing")
            counters=dict(zip(("datagrams","lost","outorder","bytes","receiver_us","jitter_us"),map(int,values[0])))
            begins=[r["elapsed_s"] for r in rows if ansi.sub("",r["line"]).strip()=="ORIGINAL_ZPERF_RX STARTED"]
            finishes=[r["elapsed_s"] for r in rows if "ORIGINAL_ZPERF_RX END datagrams=" in r["line"]]
            require(len(begins)==len(finishes)==1 and abs(finishes[0]-begins[0]-counters["receiver_us"]/1000000)<=.25,
                    "Common UDP native and external elapsed time disagree")
            observed=common_udp_receiver_capture(path)
            require(counters==observed["receiver"],"Common UDP UART and independent wire replay disagree")
            saved=json.loads((run/"result.json").read_text())
            require(all(saved[k]==v for k,v in observed.items()) and saved["raw_sha256"]==digest(path/"uart.raw") and
                    saved["pcap_sha256"]==digest(path/"network.pcap"),"Common UDP stored result differs from independent replay")
            actions=json.loads((path/"actions.json").read_text())
            if controlled_queue: replay_source_queue(folder,run)
            commands=[a["host_command"] for a in actions if "host_command" in a]
            require(len(commands)==1 and commands[0][1:]==["-B","192.168.4.2","-i","3","-f","m","-c","192.168.4.1",
                    "-u","-b","10000000","-l","1024","-n","75000000","-w","212992","-y","C","-C"] and
                    [a["host_returncode"] for a in actions if "host_returncode" in a]==[0] and
                    sum(a.get("capture_complete") is True for a in actions)==1,"Common UDP original sender execution differs")
            states=[a for a in actions if "original_sender_socket_state" in a]
            require(any(a["original_sender_socket_state"]["returncode"]==0 and
                    re.search(r"\bpid="+str(a["host_pid"])+r"\b",a["original_sender_socket_state"]["output"]) and
                    re.search(r"\btb425984\b",a["original_sender_socket_state"]["output"]) for a in states),
                    "Common UDP actual host send-buffer witness missing")
            results[system].append(observed["receiver_bits_s"]/1000000)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        host=json.loads((folder/"host-after.json").read_text())
        require(host["management_wifi_restored"] and not any(a["returncode"] for a in host["actions"]),"Common UDP management recovery differs")
        if controlled_queue: require(host.get("source_queue_restored") is True,"Source queue recovery missing")
        require(all(a[1]<b[0] for a,b in zip(intervals,intervals[1:])),"Common UDP OS rotation chronology differs")
        cells=[{"system":s,"values_mbit_s":v,"median_mbit_s":statistics.median(v),
                "range_mbit_s":[min(v),max(v)],"independent_resets":5} for s,v in results.items()]
    elif mode in ("common-original-zperf-tcp","common-original-zperf-udp"):
        udp=mode.endswith("udp")
        size=1024 if udp else 16384
        require(data["board_mac"] == "34:98:7a:a2:85:28" and data["completed_resets"] == 15,
                "Common TCP board/reset scope differs")
        order = ["Zephyr","FreeRTOS","NuttX"]
        schedule = [{"round":r+1,"system":s} for r in range(5)
                    for s in order[r%3:]+order[:r%3]]
        plan = json.loads((folder/"plan.json").read_text())
        require(plan["schedule"] == schedule and
                [plan[k] for k in ("payload_bytes","seconds","tick_hz","clock_mhz","cores")] ==
                [size,60,100,240,1] and (not udp or plan["rate_kbps_argument"]==10000),
                "Common network frozen protocol differs")
        if (folder/"reuse-parent.json").exists():
            reuse=json.loads((folder/"reuse-parent.json").read_text())
            require(Path(reuse["parent"]).name==reuse["parent"],"Reused network parent escapes reports")
            parent=folder.parent/reuse["parent"]
            original=campaign(parent,allow_incomplete=True)
            require(original["status"]=="incomplete" and original["mode"]==mode and
                    original["board_mac"]==data["board_mac"] and digest(parent/"campaign.json")==reuse["campaign_sha256"] and
                    json.loads((parent/"plan.json").read_text())==plan and 0<len(reuse["captures"])<15 and
                    reuse["captures"]==["round%d/%s"%(s["round"],s["system"]) for s in schedule[:len(reuse["captures"])]],
                    "Reused network prefix is not bound to the sealed original protocol")
            for relative in reuse["captures"]:
                for p in (parent/"runs"/relative).rglob("*"):
                    if p.is_file():
                        require(digest(p)==digest(folder/"runs"/relative/p.relative_to(parent/"runs"/relative)),
                                "Reused raw capture differs from source")
        results = {s:[] for s in order}
        ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
        for item in schedule:
            system = item["system"]
            path = folder/"runs"/("round%d"%item["round"])/system/("udp_tx" if udp else "tcp_tx")
            rows = raw_rows(path/"uart.jsonl")
            text = "\n".join(ansi.sub("",r["line"]) for r in rows)
            require(sum(r["line"].startswith("rst:0x") for r in rows) == 1 and not re.search(
                r"panic|fatal|assert|Brownout|Guru Meditation|TCP upload failed|Upload failed|LAST PACKET NOT RECEIVED",text,re.I),
                "Common TCP physical boot/error witness differs")
            if udp:
                if system=="Zephyr":
                    counts=re.findall(r"Num packets:\s*(\d+)\s*\((\d+)\)",text)
                    require(len(counts)==1 and text.count("Upload completed!")==1 and
                            re.search(r"Packet size:\s*1024 bytes",text) and re.search(r"Rate:\s*10000 kbps",text),
                            "Original UDP completion/request differs")
                    server,sent=map(int,counts[0])
                    sender_us,native=None,None
                    client={}
                    for label,key,units in (("Rate","rate",{"Mbps":1000000,"Kbps":1000}),
                            ("Duration","duration",{"m":60000000,"s":1000000,"ms":1000,"us":1})):
                        displays=re.findall(r"\b"+label+r":\s*[^()\n]+\(([^()\n]+)\)",text)
                        require(len(displays)==1,"Original UDP printed client report missing")
                        display=displays[0].strip()
                        part=re.fullmatch(r"(\d+(?:\.\d+)?)\s+(\w+)",display)
                        require(part and part[2] in units,"Original UDP printed unit differs")
                        number,unit=part.groups()
                        decimals=len(number.split(".")[1]) if "." in number else 0
                        client[key]=dict(original=display,value=float(number)*units[unit],resolution=units[unit]/10**decimals)
                    rate,duration=client["rate"],client["duration"]
                    require(rate["value"]>0 and duration["value"]>0 and max(rate["value"],
                        sent*1024*8*1000000/(duration["value"]+duration["resolution"]))<min(
                        rate["value"]+rate["resolution"],sent*1024*8*1000000/duration["value"]),
                        "Original UDP printed sender count/rate/duration disagree")
                else:
                    values=re.findall(r"ORIGINAL_ZPERF_UDP END status=(-?\d+) sent=(\d+) datagrams=(\d+) lost=(\d+) outorder=(\d+) bytes=(\d+) receiver_us=(\d+) jitter_us=(\d+) sender_us=(\d+)",text)
                    require(len(values)==1,"Native UDP completion missing")
                    status,sent,server,lost,outorder,nbytes,duration,jitter,sender_us=map(int,values[0])
                    require(status==0 and 59000000<=sender_us<=65000000 and text.count(
                        "ORIGINAL_ZPERF_UDP BEGIN target="+system+" packet=1024 seconds=60 tick_hz=100 rate_kbps=10000")==1,
                        "Native UDP status/duration/request differs")
                    native=dict(bytes=nbytes,duration_us=duration,lost=lost,outorder=outorder,datagrams=server,jitter_us=jitter)
                wire=original_udp_capture(path,sent)
                receiver=wire["csv"]
                require(wire["receiver"]["datagrams"]==server and (native is None or native==wire["receiver"]),
                        "Board-decoded UDP statistics differ from wire")
                if system=="Zephyr":
                    for label,key in (("Num packets lost:","lost"),("Num packets out order:","outorder")):
                        require(re.findall(re.escape(label)+r"\s*(\d+)",text)==[str(wire["receiver"][key])],
                                "Original returned UDP count differs")
                recorded=json.loads((path.parent/"result.json").read_text())
                require(recorded["sent_packets"]==sent and recorded["wire"]==wire and recorded["receiver"]==receiver and
                        recorded["raw_sha256"]==digest(path/"uart.raw"),"Stored UDP result differs from independent replay")
                if native is not None:
                    require(recorded["client"]==dict(sender_time_us=sender_us,sent_packets=sent),"Native UDP client differs")
                else:
                    require(recorded["client"]==client,"Printed original UDP client differs from stored interpretation")
            elif system == "Zephyr":
                counts = re.findall(r"Num packets:\s*(\d+)",text)
                require(len(counts) == 1 and re.findall(r"Num errors:\s*(\d+) \(retry or fail\)",text) == ["0"]
                    and text.count("Upload completed!") == 1 and re.search(r"Packet size:\s*16384 bytes",text),
                    "Original Zephyr completion/count differs")
                blocks,sender_us = int(counts[0]),None
            else:
                matches = re.findall(r"ORIGINAL_ZPERF END status=(-?\d+) blocks=(\d+) errors=(\d+) packet=(\d+) time_us=(\d+)",text)
                require(len(matches) == 1, "Native original-core completion missing")
                status,blocks,errors,size,sender_us = map(int,matches[0])
                require(status == errors == 0 and size == 16384 and 59000000 <= sender_us <= 65000000,
                        "Original upload status, payload or tick duration differs")
            if not udp:
                receiver = original_tcp_csv((path/"host.log").read_text())
                require(blocks > 0 and receiver["bytes"] == blocks*16384,
                        "Original completed sends and complete receiver bytes differ")
                recorded = json.loads((path.parent/"result.json").read_text())
                require(recorded["blocks"] == blocks and recorded["sender_time_us"] == sender_us and
                        recorded["receiver"] == receiver and recorded["raw_sha256"] == digest(path/"uart.raw"),
                        "Stored TCP result differs from independent replay")
            actions = json.loads((path/"actions.json").read_text())
            commands = [a["host_command"] for a in actions if "host_command" in a]
            require(len(commands) == 1 and commands[0][1:] ==
                ["-B","192.168.4.2","-i","3","-f","m","-s"]+
                (["-u"] if udp else [])+["-l",str(size),"-y","C","-C"],
                "Original compatibility-mode CSV receiver command differs")
            results[system].append(receiver["bits_per_second"]/1000000)
            interval = tuple(datetime.fromisoformat(r["utc"]) for r in (rows[0],rows[-1]))
            require(interval[0] < interval[1] and (not intervals or intervals[-1][1] < interval[0]),
                    "Common TCP rotated reset chronology differs")
            intervals.append(interval)
        host = json.loads((folder/"host-after.json").read_text())
        require(host["management_wifi_restored"] and not any(a["returncode"] for a in host["actions"]),
                "Common TCP network recovery incomplete")
        cells = [{"system":s,"values_mbit_s":v,"median_mbit_s":statistics.median(v),
                  "range_mbit_s":[min(v),max(v)],"independent_resets":5} for s,v in results.items()]
    elif mode == "fixed_reference":
        requested = [["C1", "message_processing"], ["C2", "message_processing"],
                     ["C2", "synchronization_processing"]]
        require(data["requested_cells"] == requested and data["generated_task_runs"] == 0 and
                data["generated_origin_verified"] is False, "Fixed reference scope differs")
        for task, case in requested:
            values = []
            title = "Message Processing" if case == "message_processing" else "Synchronization Processing"
            obj = "queue" if case == "message_processing" else "semaphore"
            for index in (1, 2, 3):
                path = folder / task / case / "captures" / ("reset%d.jsonl" % index)
                rows = raw_rows(path)
                lines = [row["line"] for row in rows]
                resets = [row for row in rows if row["line"].startswith("rst:0x")]
                require(len(resets) == 1 and resets[0]["elapsed_s"] <= 2 and
                        lines.count("Thread-Metric Zephyr ESP32 boot") == 1 and
                        lines.count("Thread-Metric " + obj + " self-check PASS") == 1,
                        "Fixed reference reset or original object self-check missing")
                require(not any(re.search(r"ERROR:|panic|abort|task_wdt|Guru Meditation|Exception|reboot!|ASSERT|FATAL|Brownout",
                                          line, re.I) for line in lines), "Fixed reference runtime error present")
                headings = [(i, int(m[1]), row["elapsed_s"]) for i, row in enumerate(rows)
                            if (m := re.search(r"Thread-Metric " + title + r" Test .* Relative Time: (\d+)$", row["line"]))]
                totals = [(i, int(m[1])) for i, line in enumerate(lines)
                          if (m := re.fullmatch(r"Time Period Total:\s*(\d+)", line.strip()))]
                require([h[1] for h in headings] == [30, 60, 90] and len(totals) == 3 and
                        25 < headings[0][2] < 40 and
                        all(29.5 < b[2] - a[2] < 30.5 for a, b in zip(headings, headings[1:])),
                        "Fixed reference original windows differ")
                require(all(h[0] < t[0] < (headings[i+1][0] if i < 2 else len(rows)) and t[1] > 0
                            for i, (h, t) in enumerate(zip(headings, totals))) and
                        [t[1] for t in totals] == json.loads(path.with_name("result%d.json" % index).read_text())["original_window_totals"],
                        "Fixed reference original count/window association differs")
                values.append(totals[0][1])
                intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
            cells.append({"task_id": task, "case": case, "values": values, "median": statistics.median(values)})
    elif mode == "interrupts":
        require(prepared is not None, "IRQ replay needs prepared images")
        build = json.loads((prepared / "build.json").read_text())
        require(build == json.loads((folder / "build.json").read_text()), "Prepared build differs")
        headings = {"interrupt_processing": "Interrupt Processing",
                    "interrupt_preemption_processing": "Interrupt Preemption Processing"}
        for case, title in headings.items():
            values = {}
            for variant in ("legacy", "corrected", "replica"):
                item = next(i for i in build["builds"] if (i["variant"], i["case"]) == (variant, case))
                source = prepared / item["directory"]
                require(source.resolve().is_relative_to(prepared.resolve()), "Image path escapes package")
                require(all(digest(source / n) == h for n, h in item["images"].items()), "Image digest differs")
                values[variant] = []
                for index in (1, 2, 3):
                    path = folder / variant / case / ("run%d" % index) / "reset1.jsonl"
                    rows = raw_rows(path)
                    lines = [r["line"] for r in rows]
                    require(sum("rst:0x" in s for s in lines) == 1 and
                            lines.count("Thread-Metric AliOS-Rhino ESP32 boot") == 1, "Expected one physical reset/boot")
                    require(not any(re.search(r"ERROR:|panic|abort|task_wdt|Guru Meditation|Exception|reboot!|ASSERT|FATAL",
                                              s, re.I) for s in lines), "Test error present")
                    heading = re.compile(r"Thread-Metric " + title + r" Test .* Relative Time: (\d+)$")
                    periods = [(i, int(m[1]), r["elapsed_s"]) for i, r in enumerate(rows)
                               if (m := heading.search(r["line"]))]
                    totals = [(i, int(m[1])) for i, s in enumerate(lines)
                              if (m := re.search(r"Time Period Total:\s*(\d+)$", s))]
                    require([p[1] for p in periods] == [30, 60, 90] and len(totals) == 3 and
                            25 < periods[0][2] < 40 and
                            all(29.5 < b[2] - a[2] < 30.5 for a, b in zip(periods, periods[1:])), "Original windows differ")
                    require(all(p[0] < t[0] < (periods[i+1][0] if i < 2 else len(rows)) and t[1] > 0
                                for i, (p, t) in enumerate(zip(periods, totals))), "Original total pairing differs")
                    require([t[1] for t in totals] == json.loads(path.with_name("result.json").read_text())["original_window_totals"],
                            "Recorded original totals differ")
                    values[variant].append(totals[0][1])
                    intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
            medians = {v: statistics.median(ns) for v, ns in values.items()}
            cells.append({"case": case, "original_counts_30s": values, "medians": medians,
                          "relative_change_percent": (medians["corrected"] / medians["legacy"] - 1) * 100})
    elif mode in ("message-cohort", "kernel-cohort"):
        case = data.get("case", "message_processing")
        titles = {"cooperative_scheduling": "Cooperative Scheduling",
                  "basic_processing": "Basic Single Thread Processing", "memory_allocation": "Memory Allocation",
                  "preemptive_scheduling": "Preemptive Scheduling", "message_processing": "Message Processing",
                  "synchronization_processing": "Synchronization Processing", "interrupt_processing": "Interrupt Processing",
                  "interrupt_preemption_processing": "Interrupt Preemption Processing"}
        require(case in titles, "Unknown original kernel workload")
        systems = data.get("systems", ["FreeRTOS", "Zephyr", "NuttX"])
        require(len(set(systems)) == len(systems) >= 2 and
                set(systems) <= {"FreeRTOS", "Zephyr", "NuttX"}, "Invalid native subset")
        for system in systems:
            values = []
            for index in (1, 2, 3):
                rows = raw_rows(folder / system / ("run%d" % index) / "reset1.jsonl")
                lines = [r["line"] for r in rows]
                require(sum("rst:0x" in s for s in lines) == 1 and
                        lines.count("Thread-Metric " + system + " ESP32 boot") == 1,
                        "Independent reset or original workload boot missing")
                if case in ("message_processing", "synchronization_processing"):
                    obj = "queue" if case == "message_processing" else "semaphore"
                    require(lines.count("Thread-Metric " + obj + " self-check PASS") == 1,
                            "Original object self-check missing")
                if case == "memory_allocation" and system == "FreeRTOS":
                    require(lines.count("Thread-Metric memory self-check PASS") == 1 and
                            lines.count("Thread-Metric memory pool family=ESP_IDF_MULTI_HEAP arena_bytes=4096 lock=PORTMUX") == 1,
                            "Private general-heap self-check/family missing")
                if case.startswith("interrupt_"):
                    require(lines.count("Thread-Metric interrupt source=CPU_FROM_CPU2 peripheral=26 level=1 context=ISR") == 1,
                            "Matched hardware interrupt marker missing")
                require(not any(re.search(r"ERROR:|panic|abort|Guru Meditation|Exception|reboot!|ASSERT|FATAL", s, re.I)
                                for s in lines), "Original workload error present")
                headings = [(i, int(m[1]), r["elapsed_s"]) for i, r in enumerate(rows)
                            if (m := re.search(r"Thread-Metric " + titles[case] + r" Test .* Relative Time: (\d+)$", r["line"]))]
                totals = [(i, int(m[1])) for i, s in enumerate(lines)
                          if (m := re.fullmatch(r"Time Period Total:\s*(\d+)", s.strip()))]
                require([r[1] for r in headings] == [30, 60, 90] and len(totals) == 3 and
                        25 < headings[0][2] < 40 and all(29.5 < b[2] - a[2] < 30.5 for a, b in zip(headings, headings[1:])),
                        "Original kernel windows differ")
                require(all(h[0] < t[0] < (headings[i + 1][0] if i < 2 else len(rows)) and t[1] > 0
                            for i, (h, t) in enumerate(zip(headings, totals))), "Original count/window association differs")
                if case == "cooperative_scheduling":
                    previous = 0
                    for heading, total in zip(headings, totals):
                        workers = [re.fullmatch(r"tm_cooperative_thread_([0-4])_counter:\s*(\d+)", s)
                                   for s in lines[heading[0] + 1:total[0]]]
                        workers = [(int(m[1]), int(m[2])) for m in workers if m]
                        require([i for i, _ in workers] == list(range(5)), "Missing original worker counters")
                        current = sum(v for _, v in workers) % (2 ** 32)
                        average = current // 5
                        require(all((average - 1) % (2 ** 32) <= v <= (average + 1) % (2 ** 32)
                                    for _, v in workers) and (current - previous) % (2 ** 32) == total[1],
                                "Original worker balance or unsigned total differs")
                        previous = current
                values.append(totals[0][1])
                intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
            cells.append({"os": system, "values": values, "median": statistics.median(values)})
    elif mode == "message-observer-pairs":
        plan = json.loads((folder/"plan.json").read_text())
        profile = plan.get("profile","native-v1")
        require(profile in ("native-v1","nuttx-addresses-v1","nuttx-message-startup-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1","nuttx-compact-loader-v1","zephyr-message-stack-v1","zephyr-message-startup-v1","zephyr-message-tick-stacks-v1","zephyr-message-ownership-v1","freertos-message-stack-v1","freertos-message-startup-v1","freertos-message-tick-stacks-v1","freertos-message-boot-handoff-v1","freertos-message-steps-v1","freertos-message-boundaries-v1","freertos-message-combined-stacks-v1","freertos-message-native-sp-v1"),"Unknown paired observer profile")
        boot_profile = profile in ("freertos-message-boot-handoff-v1", "freertos-message-steps-v1", "freertos-message-boundaries-v1", "freertos-message-combined-stacks-v1", "freertos-message-native-sp-v1")
        monotonic_profile = boot_profile or profile in ("zephyr-message-ownership-v1","nuttx-compact-loader-v1")
        systems = (["NuttX"] if profile in ("nuttx-addresses-v1","nuttx-message-startup-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1","nuttx-compact-loader-v1") else ["Zephyr"] if profile in
                   ("zephyr-message-stack-v1","zephyr-message-startup-v1","zephyr-message-tick-stacks-v1","zephyr-message-ownership-v1") else ["FreeRTOS"] if profile in ("freertos-message-stack-v1","freertos-message-startup-v1","freertos-message-tick-stacks-v1","freertos-message-boot-handoff-v1","freertos-message-steps-v1","freertos-message-boundaries-v1","freertos-message-combined-stacks-v1","freertos-message-native-sp-v1") else
                   ["FreeRTOS", "Zephyr", "NuttX"])
        expected, values = [], {}
        monotonic_boot = None
        if monotonic_profile:
            require(plan.get("chronology") == "host-boot-scoped-monotonic-ns-v1", "Paired monotonic protocol missing")
        for round_ in range(5):
            for position in range(len(systems)):
                system = systems[(round_+position) % len(systems)]
                variants = ["baseline", "observer"]
                if (round_+systems.index(system)) % 2:
                    variants.reverse()
                for variant in variants:
                    expected.append({"round":round_+1,"os":system,"variant":variant})
        require(data["board_mac"] == "34:98:7a:a2:85:28" and data["completed_resets"] == len(expected) and
                plan["schedule"] == expected and plan["pairs_per_os"] == 5 and
                plan["case"] == "message_processing", "Paired plan differs")
        if profile == "nuttx-compact-loader-v1":
            proof=json.loads((folder/"proofs.json").read_text())["NuttX"]
            require(plan["source_proof_sha256"]==digest(folder/"proofs.json") and
                proof["observer"].get("compact_observer") is True and
                proof["observer"].get("application_startup_stack_coverage") is True,
                "Compact loader paired source identity differs")
            names={"nuttx":"application.elf","nuttx.bin":"application.bin",
                   "partition-table-esp32.bin":"partitions.bin"}
            for variant in ("baseline","observer"):
                actual={p.name:digest(p) for p in (folder/"builds/NuttX"/variant).iterdir()}
                require(actual==proof["installed_images"][variant],"Compact loader installed image differs")
                original=({saved:proof["baseline"]["images"][name] for name,saved in names.items()}
                    if variant=="baseline" else {n:v for n,v in proof["observer_images"].items() if n!="bootloader.bin"})
                require(all(actual[n]==v for n,v in original.items()),"Compact loader application was changed")
            a,b=[proof["installed_images"][v] for v in ("baseline","observer")]
            require(a["bootloader.bin"]==b["bootloader.bin"] and a["partitions.bin"]==b["partitions.bin"],
                "Compact loader control is not matched")
        for item in expected:
            system, variant, number = item["os"], item["variant"], item["round"]
            path = folder/"runs"/("round%d" % number)/system/variant/"reset1.jsonl"
            rows = raw_rows(path)
            lines = [r["line"] for r in rows]
            if profile == "nuttx-compact-loader-v1":
                from replay_esp32_bootloader_ram import boot_rows
                stages=boot_rows(lines)
                positions=[i for i,s in enumerate(lines) if s.startswith("BOOT_RAM phase=")]
                native=[i for i,s in enumerate(lines) if s=="Thread-Metric NuttX ESP32 boot"]
                require(len(native)==1 and max(positions)<native[0] and stages==
                    json.loads(path.with_name("result.json").read_text())["boot_stages"],
                    "Compact loader runtime observation differs")
            if profile in ("nuttx-addresses-v1","nuttx-message-startup-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1","nuttx-compact-loader-v1") and variant == "observer":
                native_allocation_addresses(lines)
                if profile in ("nuttx-message-startup-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1","nuttx-compact-loader-v1"):
                    proof=json.loads((folder/"proofs.json").read_text())["NuttX"]["observer"]
                    require(proof.get("application_startup_stack_coverage") is True and
                        plan["source_proof_sha256"]==digest(folder/"proofs.json"),"Native startup paired identity differs")
                    nuttx_startup_observation(lines,proof["reservations"]["g_idlestack"])
                if profile in ('nuttx-message-tick-stacks-v1','nuttx-message-tick-control-v1'):
                    from replay_esp32_nuttx_tick_stacks import observations as tick_observations
                    require(proof.get('native_tick_stack_snapshots') is True,'Native timer image differs')
                    tick_observations(lines,{'g_idletcb':(proof['tick_idle_tcb'],164),
                        'g_idlestack':proof['reservations']['g_idlestack']})
                    if profile=='nuttx-message-tick-control-v1':
                        from replay_esp32_nuttx_tick_stacks import probe_cost
                        probe_cost(lines,tick_observations(lines,{'g_idletcb':(proof['tick_idle_tcb'],164),
                            'g_idlestack':proof['reservations']['g_idlestack']})['samples'])
            if profile in ("zephyr-message-stack-v1","zephyr-message-startup-v1","zephyr-message-tick-stacks-v1","zephyr-message-ownership-v1") and variant == "observer":
                from replay_esp32_message_stack import watermarks, heap_history, startup_watermark
                proof=json.loads((folder/"proofs.json").read_text())["Zephyr"]["observer"]
                require(proof.get("message_native_stack_coverage") is True and
                    plan["source_proof_sha256"]==digest(folder/"proofs.json"),"Native stack observer identity differs")
                symbols={k:tuple(v) for k,v in proof["reservations"].items()}
                watermarks(lines,symbols,["application-entry","message-end"])
                heap_history(lines,symbols)
                require(lines[-1]=="TM_Z_RAM END invalid=0 original_reports=3","Native stack observer endpoint missing")
                if profile in ("zephyr-message-startup-v1","zephyr-message-tick-stacks-v1","zephyr-message-ownership-v1"):
                    require(proof.get("application_startup_stack_coverage") is True,"Startup paired image differs")
                    startup_watermark(lines,{**symbols,"_stack_sentry":(0x3ffe1320,0),"__stack":(0x3ffe3f20,0)})
                if profile == "zephyr-message-ownership-v1":
                    owners=[(i,m) for i,s in enumerate(lines) if (m:=re.fullmatch(
                        r'ZEPHYR_BOOT_OWNERSHIP entry_vecbase=(\d+)',s))]
                    following=[i for i,s in enumerate(lines) if s.startswith('ZEPHYR_BOOT_STACK ')]
                    require(proof.get('application_startup_vector_coverage') is True and
                        len(owners)==len(following)==1 and owners[0][0]+1==following[0] and
                        int(owners[0][1][1]) in (0x40000000,0x40080000),
                        'Native entry-vector ownership witness differs')
                if profile == "zephyr-message-tick-stacks-v1":
                    from replay_esp32_message_stack import tick_snapshots
                    require(proof.get('native_tick_stack_snapshots') is True,'Tick paired image differs')
                    tick_snapshots(lines,symbols)
            if profile in ("freertos-message-stack-v1","freertos-message-startup-v1","freertos-message-tick-stacks-v1","freertos-message-boot-handoff-v1","freertos-message-steps-v1","freertos-message-boundaries-v1","freertos-message-combined-stacks-v1","freertos-message-native-sp-v1") and variant == "observer":
                proof=json.loads((folder/"proofs.json").read_text())["FreeRTOS"]["observer"]
                require(proof.get("message_ordinary_irq_stack_coverage") is True and
                    plan["source_proof_sha256"]==digest(folder/"proofs.json"),"FreeRTOS IRQ observer identity differs")
                matches=[(i,m) for i,s in enumerate(lines) if (m:=re.fullmatch(
                    r"FREERTOS_STACK irq_address=(\d+) reserved=(\d+) painted=(\d+) boot_sp=(\d+) scheduler=1 nesting=0 spare=(\d+) touched=(\d+)",s))]
                require(len(matches)==1 and matches[0][0]==len(lines)-2 and
                    lines[-1].startswith("TM_RAM END "),"FreeRTOS IRQ observation boundary missing")
                a,n,paint,sp,spare,touched=map(int,matches[0][1].groups())
                irq=proof["interrupt_stack"]
                require((a,n,paint)==(irq["address"],irq["reserved_bytes"],irq["reserved_bytes"]) and
                    not a<=sp<a+n and 0<spare<n and touched==n-spare,"FreeRTOS IRQ paint/context/watermark differs")
                if profile in ("freertos-message-startup-v1","freertos-message-tick-stacks-v1","freertos-message-boot-handoff-v1","freertos-message-steps-v1","freertos-message-boundaries-v1","freertos-message-combined-stacks-v1","freertos-message-native-sp-v1"):
                    from replay_esp32_freertos_message import startup_watermark
                    require(proof.get("application_startup_stack_coverage") is True,"Application startup observation missing")
                    tasks=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                        r"FREERTOS_RAM live tcb=(\d+) stack=(\d+) span=(\d+) tcb_bytes=(\d+) kind=(\d+) role=(\d+) stack_heap=(\d+) tcb_heap=(\d+) stack_block=(\d+) tcb_block=(\d+) spare=(\d+)",s))]
                    startup_watermark(lines,tasks)
                if boot_profile:
                    from replay_esp32_bootloader_ram import handoff_row
                    from replay_esp32_freertos_message import history, peak_contexts
                    require(proof.get("allocation_peak_context") is True,"Allocation-context observer missing")
                    handoff = handoff_row(lines, proof["boot_readback_state_address"])
                    native = history(lines)
                    startup = startup_watermark(lines, native["live_tasks"])
                    require(handoff["app_sp"] == startup["application_entry_sp"] and handoff ==
                        json.loads(path.with_name("result.json").read_text())["observer"]["boot_handoff"],
                        "Paired boot handoff differs from application entry or stored result")
                    peak_contexts(lines, irq["address"], irq["reserved_bytes"])
                if profile == "freertos-message-steps-v1":
                    from replay_esp32_message_steps import decode
                    require(proof.get("continuous_instruction_stack_trace") is True, "Continuous observer image differs")
                    require(decode(lines) == json.loads(path.with_name("result.json").read_text())["observer"]["continuous_stack"],
                            "Paired continuous contexts differ from retained result")
                if profile in ("freertos-message-boundaries-v1", "freertos-message-combined-stacks-v1"):
                    from replay_esp32_message_boundaries import decode
                    require(proof.get("compiler_boundary_stack_trace") is True, "Boundary observer image differs")
                    require(decode(lines) == json.loads(path.with_name("result.json").read_text())["observer"]["boundary_stack"],
                            "Paired boundary contexts differ from retained result")
                if profile in ("freertos-message-combined-stacks-v1", "freertos-message-native-sp-v1"):
                    from replay_esp32_native_sp import decode as native_decode, return_addresses
                    require(proof.get("native_assembly_sp_trace") is True, "Native assembly observer image differs")
                    returns = return_addresses(folder / "builds/FreeRTOS/observer/application.elf")
                    require(native_decode(lines, returns) == json.loads(path.with_name("result.json").read_text())["observer"]["native_sp"],
                            "Paired native assembly contexts differ from retained result")
                if profile == "freertos-message-tick-stacks-v1":
                    from replay_esp32_freertos_message import history, tick_snapshots
                    require(proof.get("native_tick_stack_snapshots") is True,"Native tick observation missing")
                    native=history(lines)
                    tick_snapshots(lines,native["live_tasks"],irq["address"],irq["reserved_bytes"])
            resets = [r for r in rows if r["line"].startswith("rst:0x")]
            require(len(resets) == 1 and resets[0]["elapsed_s"] <= 2 and
                    lines.count("Thread-Metric " + system + " ESP32 boot") == 1 and
                    lines.count("Thread-Metric queue self-check PASS") == 1,
                    "Paired reset, OS or object check differs")
            require(not any(re.search(r"ERROR:|panic|abort|task_wdt|Guru Meditation|Exception|reboot!|ASSERT|FATAL|Brownout", s, re.I)
                            for s in lines), "Paired runtime error present")
            headings = [(i,int(m[1]),r["elapsed_s"]) for i,r in enumerate(rows)
                        if (m := re.search(r"Thread-Metric Message Processing Test .* Relative Time: (\d+)$", r["line"]))]
            totals = [(i,int(m[1])) for i,s in enumerate(lines)
                      if (m := re.fullmatch(r"Time Period Total:\s*(\d+)", s.strip()))]
            require([h[1] for h in headings] == [30,60,90] and len(totals) == 3 and
                    25 < headings[0][2] < 40 and
                    all(29.5 < b[2]-a[2] < 30.5 for a,b in zip(headings,headings[1:])),
                    "Paired original report windows differ")
            require(all(h[0] < t[0] < (headings[i+1][0] if i < 2 else len(rows)) and t[1] > 0
                        for i,(h,t) in enumerate(zip(headings,totals))), "Paired count/window association differs")
            counts = [t[1] for t in totals]
            require(counts == json.loads(path.with_name("result.json").read_text())["original_message"]["original_window_totals"],
                    "Paired recorded totals differ")
            values[system,number,variant] = counts
            if monotonic_profile:
                require(all("host_boot_id" in r and "clock_read_before_ns" in r and "clock_read_after_ns" in r for r in rows),
                        "Paired absolute clock evidence missing")
                boot = rows[0]["host_boot_id"]
                require(monotonic_boot is None or boot == monotonic_boot, "Paired host boot changed")
                monotonic_boot = boot
                start, end = rows[0]["clock_read_before_ns"], rows[-1]["clock_read_after_ns"]
                stored = json.loads(path.with_name("result.json").read_text())["monotonic_interval"]
                require(stored == {"host_boot_id": boot, "start_ns": start, "end_ns": end}, "Stored monotonic interval differs")
            else:
                start, end = datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])
            require(start < end and (not intervals or intervals[-1][1] < start), "Paired order differs from schedule")
            intervals.append((start,end))
        for system in systems:
            pairs = [{"round":r,"baseline_counts":values[system,r,"baseline"],
                      "observer_counts":values[system,r,"observer"],
                      "first_window_ratio":values[system,r,"observer"][0]/values[system,r,"baseline"][0]}
                     for r in range(1,6)]
            ratios = [p["first_window_ratio"] for p in pairs]
            cells.append({"os":system,"pairs":pairs,"median_ratio":statistics.median(ratios),
                          "ratio_range":[min(ratios),max(ratios)]})
    elif mode == "native-suite":
        titles = {"basic_processing": "Basic Single Thread Processing",
                  "cooperative_scheduling": "Cooperative Scheduling",
                  "preemptive_scheduling": "Preemptive Scheduling",
                  "synchronization_processing": "Synchronization Processing",
                  "memory_allocation": "Memory Allocation",
                  "interrupt_processing": "Interrupt Processing",
                  "interrupt_preemption_processing": "Interrupt Preemption Processing"}
        require(data["requested_cases"] and set(data["requested_cases"]) <= set(titles),
                "Unknown native original replay cases")
        for case in data["requested_cases"]:
            for system in ("RIOT", "AliOS-Rhino"):
                values = []
                for index in (1, 2, 3):
                    folder_case = folder / system / case / "captures"
                    rows = raw_rows(folder_case / ("reset%d.jsonl" % index))
                    lines = [r["line"] for r in rows]
                    require(sum(s.startswith("rst:0x") for s in lines) == 1 and
                            lines.count("Thread-Metric " + system + " ESP32 boot") == 1,
                            "Native physical reset/boot witness differs")
                    if case.startswith("interrupt_"):
                        require(lines.count("Thread-Metric interrupt source=CPU_FROM_CPU2 peripheral=26 level=1 context=ISR") == 1,
                                "Native IRQ context witness differs")
                    checks = {"synchronization_processing": "semaphore", "memory_allocation": "memory"}
                    if case in checks:
                        require(lines.count("Thread-Metric " + checks[case] + " self-check PASS") == 1,
                                "Native original object self-check missing")
                    require(not any(re.search(r"ERROR:|panic|abort|task_wdt|Guru Meditation|Exception|reboot!|ASSERT|FATAL", s, re.I)
                                    for s in lines), "Native original IRQ error present")
                    headings = [(i, int(m[1]), row["elapsed_s"]) for i, row in enumerate(rows) if (m := re.search(
                        r"Thread-Metric " + titles[case] + r" Test .* Relative Time: (\d+)$", row["line"]))]
                    totals = [(i, int(m[1])) for i, line in enumerate(lines) if
                              (m := re.fullmatch(r"Time Period Total:\s*(\d+)", line.strip()))]
                    require([h[1] for h in headings] == [30, 60, 90] and len(totals) == 3 and
                            25 < headings[0][2] < 40 and all(29.5 < b[2] - a[2] < 30.5 for a, b in zip(headings, headings[1:])),
                            "Native IRQ report windows differ")
                    require(all(h[0] < t[0] < (headings[i + 1][0] if i < 2 else len(rows)) and t[1] > 0
                                for i, (h, t) in enumerate(zip(headings, totals))), "Native IRQ total/window association differs")
                    require([t[1] for t in totals] == json.loads((folder_case / ("result%d.json" % index)).read_text())["original_window_totals"],
                            "Recorded IRQ counts differ")
                    if case == "cooperative_scheduling":
                        previous = 0
                        for heading, total in zip(headings, totals):
                            workers = [re.fullmatch(r"tm_cooperative_thread_([0-4])_counter:\s*(\d+)", s)
                                       for s in lines[heading[0] + 1:total[0]]]
                            workers = [(int(m[1]), int(m[2])) for m in workers if m]
                            require([i for i, _ in workers] == list(range(5)), "Native cooperative counters missing")
                            current = sum(v for _, v in workers) % (2 ** 32)
                            average = current // 5
                            require(all((average - 1) % (2 ** 32) <= v <= (average + 1) % (2 ** 32)
                                        for _, v in workers) and (current - previous) % (2 ** 32) == total[1],
                                    "Native original worker balance/unsigned total differs")
                            previous = current
                    values.append(totals[0][1])
                    intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
                cells.append({"os": system, "case": case, "values": values, "median": statistics.median(values)})
    elif mode == "message":
        values, system = [], None
        for index in (1, 2, 3):
            rows = raw_rows(folder / "captures" / ("reset%d.jsonl" % index))
            lines = [r["line"] for r in rows]
            names = [m[1] for line in lines if (m := re.fullmatch(r"Thread-Metric (RIOT|AliOS-Rhino) ESP32 boot", line))]
            require(len(names) == 1 and (system is None or names[0] == system) and
                    sum(line.startswith("rst:0x") for line in lines) == 1 and
                    lines.count("Thread-Metric queue self-check PASS") == 1, "Native reset/queue check differs")
            system = names[0]
            require(not any(re.search(r"ERROR:|panic|abort|Guru Meditation|Exception|reboot!|ASSERT|FATAL", line, re.I)
                            for line in lines), "Native original error present")
            headings = [(i, int(m[1]), row["elapsed_s"]) for i, row in enumerate(rows) if (m := re.search(
                r"Thread-Metric Message Processing Test .* Relative Time: (\d+)$", row["line"]))]
            totals = [(i, int(m[1])) for i, line in enumerate(lines) if (m := re.fullmatch(r"Time Period Total:\s*(\d+)", line.strip()))]
            require([h[1] for h in headings] == [30, 60, 90] and len(totals) == 3 and 25 < headings[0][2] < 40 and
                    all(29.5 < b[2] - a[2] < 30.5 for a, b in zip(headings, headings[1:])),
                    "Native original windows differ")
            require(all(h[0] < t[0] < (headings[i + 1][0] if i < 2 else len(rows)) and t[1] > 0
                        for i, (h, t) in enumerate(zip(headings, totals))), "Native total/window association differs")
            values.append(totals[0][1])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os": system, "values": values, "median": statistics.median(values)})
    elif mode == "candidates":
        requested = data.get("requested_candidates") or sorted(
            p.name for p in folder.iterdir() if p.is_dir() and
            re.fullmatch(r"riot-(yield|flags|msg)-(freertos|zephyr|nuttx|alios)-v\d+", p.name))
        for name in requested:
            path = folder / name
            result = json.loads((path / "result.json").read_text())
            if result["status"] != "pass":
                continue
            values = []
            kind = name.split("-")[1].upper()
            for index in (1, 2, 3):
                rows = raw_rows(path / "captures" / ("reset%d.jsonl" % index))
                lines = [r["line"] for r in rows]
                require(sum("rst:0x" in s for s in lines) == 1 and
                        lines[-1] == "RIOT " + kind + " PORT END", "Original program not completed once")
                outputs = [json.loads(s) for s in lines if re.fullmatch(r'\{\s*"result"\s*:.*\}', s)]
                require(len(outputs) == 1 and outputs[0]["result"] > 0 and
                        outputs[0]["result"] == result["captures"][index-1]["original_count"], "Original count differs")
                values.append(outputs[0]["result"])
                intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
            cells.append({"original": name, "values": values, "median": statistics.median(values)})
    elif mode == "riot-msg-alios":
        values=[]; nominal_ticks=[]; buffered_peaks=[]
        for index in (1,2,3):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[re.sub(r"\x1b\[[0-9;]*m","",r["line"]).strip() for r in rows]
            begin=[i for i,s in enumerate(lines) if s.startswith("RIOT MSG PORT BEGIN AliOS-Rhino ")]
            results=[(i,json.loads(s)) for i,s in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }',s)]
            final="RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 buffered_peak=0 free_bytes=8 min_free_bytes=8 waiters=1 alarm_count=1 isr=1"
            timers=[(i,re.fullmatch(r"RIOT MSG NATIVE TIMER counter_us=(\d+) alarm_count=1 irq_released=1",s))
                    for i,s in enumerate(lines) if s.startswith("RIOT MSG NATIVE TIMER")]
            retires=[(i,re.fullmatch(r"RIOT MSG PORT RETIRE tasks_before=(\d+) tasks_after=(\d+) queues_before=(\d+) queues_after=(\d+)",s))
                     for i,s in enumerate(lines) if s.startswith("RIOT MSG PORT RETIRE")]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and len(begin)==len(results)==len(timers)==len(retires)==1 and
                    lines.count("main starting")==1 and lines.count("Welcome to AliOS Things")==1 and lines.count(final)==1 and
                    lines[-1]=="RIOT MSG PORT END" and not any(re.search(r"PORT FAIL|panic|assert|FAILED|Brownout|Exception",s,re.I) for s in lines),
                    "Rhino original message reset or native direct-copy completion differs")
            i,result=results[0]; j,timer=timers[0]; k,retire=retires[0]
            require(timer is not None and retire is not None and retire[1]==retire[2] and retire[3]==retire[4] and int(retire[1])>=2 and
                    begin[0]<lines.index("main starting")<i<lines.index(final)<j<k<len(lines)-1 and
                    1000000<=int(timer[1])<=0xffffffff and set(result)=={"result","ticks"} and 0<result["result"]<=0xffffffff and
                    result["ticks"]==240000000//result["result"] and
                    rows[i]["elapsed_s"]-rows[lines.index("main starting")]["elapsed_s"]>=0.95,
                    "Rhino original one-second formula or native resource retirement differs")
            values.append(result["result"]); nominal_ticks.append(result["ticks"]); buffered_peaks.append(0)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"AliOS-Rhino","original":"msg_pingpong","values":values,"original_nominal_ticks":nominal_ticks,
            "native_buffered_peaks":buffered_peaks,"ranking_eligible":False,"not_isolated_api_latency":True})
    elif mode == "riot-msg-nuttx":
        values=[]; nominal_ticks=[]
        for index in (1,2,3):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[re.sub(r"\x1b\[[0-9;]*m","",r["line"]).strip() for r in rows]
            begin=[i for i,s in enumerate(lines) if s.startswith("RIOT MSG PORT BEGIN NuttX ")]
            results=[(i,json.loads(s)) for i,s in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }',s)]
            retired=[(i,re.fullmatch(r"RIOT MSG PORT RETIRE before=(\d+) after=(\d+)",s))
                     for i,s in enumerate(lines) if s.startswith("RIOT MSG PORT RETIRE")]
            final="RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 alarm_count=1 isr=1"
            require(sum(s.startswith("rst:0x") for s in lines)==1 and len(begin)==len(results)==len(retired)==1 and
                    lines.count("main starting")==1 and lines.count(final)==1 and lines[-1]=="RIOT MSG PORT END" and
                    not any(re.search(r"PORT FAIL|panic|assert|FAILED|Brownout|Exception",s,re.I) for s in lines),
                    "NuttX original message reset/completion differs")
            i,result=results[0]; j,retire=retired[0]
            require(retire is not None and retire[1]==retire[2] and int(retire[1])>=2 and
                    begin[0]<lines.index("main starting")<i<lines.index(final)<j<len(lines)-1 and
                    set(result)=={"result","ticks"} and 0<result["result"]<=0xffffffff and
                    result["ticks"]==240000000//result["result"] and
                    rows[i]["elapsed_s"]-rows[lines.index("main starting")]["elapsed_s"]>=0.95,
                    "NuttX original one-second formula or native post-window retirement differs")
            values.append(result["result"]); nominal_ticks.append(result["ticks"])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"NuttX","original":"msg_pingpong","values":values,"original_nominal_ticks":nominal_ticks,
            "ranking_eligible":False,"not_isolated_api_latency":True})
    elif mode == "riot-native-message":
        values=[]; nominal_ticks=[]
        for index in (1,2,3):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count("START")==1 and
                    lines.count("Single core mode")==1 and lines.count("main starting")==1 and
                    lines.count("main(): This is RIOT! (Version: 2024.10-devel)")==1 and
                    not any(re.search(r"Exception|panic|assert|FAILED",s,re.I) for s in lines),
                    "Native original message reset/boot/completion differs")
            result=json.loads(lines[-1])
            require(set(result)=={"result","ticks"} and all(type(v) is int and v>0 for v in result.values()) and
                    result["ticks"]==240000000//result["result"] and
                    rows[-1]["elapsed_s"]-rows[lines.index("main starting")]["elapsed_s"]>=0.95,
                    "Native original one-second count/nominal tick arithmetic differs")
            values.append(result["result"]); nominal_ticks.append(result["ticks"])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"RIOT","original":"msg_pingpong","values":values,"original_nominal_ticks":nominal_ticks,
            "ranking_eligible":False,"not_isolated_api_latency":True})
    elif mode == "rhino-ram":
        check_rows=raw_rows(folder/"validation/reset1.jsonl")
        checks=[dict(t.split("=",1) for t in r["line"].split()[1:]) for r in check_rows
                if r["line"].startswith("RHINO_RAM validation=")]
        require(len(checks)==1 and checks[0]["validation"]=="PASS" and checks[0]["invalid"]=="0" and
                checks[0]["base"]==checks[0]["final"] and
                int(checks[0]["base"])<int(checks[0]["required_overlap_peak"])<=int(checks[0]["observed_peak"]),
                "Native Rhino moving-realloc overlap oracle missing")
        require(sum(r["line"]=="RHINO_RAM validation_idle_output=PASS" for r in check_rows)==1,
                "Rhino native idle terminal output did not pass validation")
        peaks,totals,counts,threads_out,timers_out,samples_out=[],[],[],[],[],[]
        stack_coverages=[]
        stack_expected=json.loads((folder/"build/build.json").read_text()).get("native_stack_coverage",False)
        for index in (1,2,3):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count("RHINO_RAM END")==1 and
                    not any(re.search(r"invalid=[1-9]|invalid-command|status=FAIL|panic|fatal|assert|Exception",s,re.I) for s in lines),
                    "Rhino physical reset/completion/error differs")
            parsed=lambda prefix,start:[{k:int(v) if v.isdecimal() else v for k,v in
                (t.split("=",1) for t in s.split()[start:])} for s in lines if s.startswith(prefix)]
            samples=parsed("RHINO_RAM phase=",1)
            regions=parsed("RHINO_RAM region ",2)
            threads=parsed("RHINO_RAM thread ",2)
            timers=parsed("RHINO_RAM timer ",2)
            final=parsed("RHINO_RAM final ",2)
            loss=[int(m[1]) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=\d+",s))]
            trials=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH TRIAL source=SEI_DERIVED_C clock_hz=240000000 tick_hz=100 duration_s=10 raw_speed_kwips=\d+ experiment=4 step=(\d+) task_count=(\d+)",s))]
            require(len(loss)==1 and trials==[(s,5+s) for s in range(loss[0]+1)] and
                    [s["phase"] for s in samples]==["application-entry","before-controller-suspend","controller-suspended"] and
                    len(regions)==2 and len(final)==1 and final[0]["invalid"]==0,
                    "Original Rhino PH4 or native phase coverage differs")
            capacity=sum(r["bytes"] for r in regions)
            require(all(not s["invalid"] and 0<s["occupied"]<=s["peak"]<=capacity and
                        s["occupied"]==capacity-s["large_free"]-s["fixed_free"]==s["native_used"]+24 and
                        s["peak"]==s["native_peak"]+24 and 0<=s["fixed_free"]<=8192 and s["fixed_free"]%32==0
                        for s in samples) and
                    all(a[k]<=b[k] for a,b in zip(samples,samples[1:]) for k in ("peak","observations")),
                    "Native region walk/fixed-pool/statistics arithmetic differs")
            f=final[0]; workers=[t for t in threads if t["role"]==0]
            require(len(workers)==loss[0]+5 and len(threads)==f["created"] and len(timers)==f["timers"]==len(workers)+1 and
                    sum(t["present"] for t in threads)==f["native_active"] and
                    len({t["tcb"] for t in threads if t["present"]})==f["native_active"] and
                    [t["id"] for t in threads]==list(range(len(threads))),"Native registry count differs")
            for t in threads:
                require(t["stack"]<=t["cp"] and t["cp"]+96<=t["stack"]+t["reserved"] and
                        0<=t["spare"]<=t["reserved"]-4 and t["spare"]%4==0,"Native stack/CP bounds differ")
                if t["present"]:
                    require(not any(t[k] for k in ("deleted","stack_freed","tcb_freed")) and t["status"]!=7 and
                            t["hwm_measured"]==int(t["tcb"]!=f["idle"]) and
                            (t["dynamic"]!=2 or t["stack_usable"]>=t["reserved"] and t["tcb_usable"]>=136),
                            "Native active resource lifetime differs")
                else:
                    require(t["deleted"]==1 and t["status"]==7 and
                            (t["dynamic"]!=2 or t["stack_freed"]==t["tcb_freed"]==1),
                            "Native retirement lacks physical free evidence")
            for t in workers:
                require(t["present"]==t["hwm_measured"]==t["dynamic"]==1 and t["status"]==2 and
                        t["reserved"]==4096 and t["stack_usable"]>=4096 and t["blocked"]==t["gate"] and t["value"]==0 and
                        t["waiter_next"]==t["waiter_prev"]==t["tcb"]+36 and t["node_next"]==t["node_prev"]==t["gate"],
                        "Original worker not retained on its own native gate")
                matching=[x for x in timers if not x["deleted"] and x["output"]==t["gate"]+88]
                require(len(matching)==1 and matching[0]["argument"]==t["gate"]+44 and matching[0]["usable"]>0 and not matching[0]["freed"],
                        "Original worker native timer ownership differs")
            require([t["gate"] for t in workers]==list(range(workers[0]["gate"],workers[0]["gate"]+264*len(workers),264)) and
                    sum(t["deleted"] for t in timers)==1 and timers[0]["deleted"]==timers[0]["freed"]==1,
                    "Worker slots or temporary timer retirement differs")
            retained=sum(t["stack_usable"]+16 for t in workers)+sum(t["usable"] for t in timers if not t["deleted"])
            require(retained==samples[-1]["occupied"]-samples[0]["occupied"] and
                    samples[0]["fixed_free"]-samples[-1]["fixed_free"]==32*len(workers),
                    "Native retained stack/timer byte balance differs")
            require(len([t for t in threads if t["role"]==1 and t["tcb"]==f["controller"] and t["status"]==3 and t["present"]])==1 and
                    len([t for t in threads if t["role"]==2 and t["tcb"]==f["idle"] and t["present"]])==1,
                    "Native controller suspension/idle witness missing")
            if stack_expected:
                starts=parsed("RHINO_STACK begin ",2)
                retired=parsed("RHINO_STACK retired ",2)
                idles=parsed("RHINO_STACK idle ",2)
                irqs=parsed("RHINO_STACK irq ",2)
                ends=parsed("RHINO_STACK final ",2)
                require(all(len(x)==1 for x in (starts,idles,irqs,ends)),"Native extended stack records incomplete")
                start,idle,irq,end=starts[0],idles[0],irqs[0],ends[0]
                admitted=json.loads((folder/"stack-build-proof.json").read_text())
                require(start=={"stopped":1,"running":0,"nesting":0,"irq_start":admitted["interrupt_stack"]["start"],
                            "irq_bytes":1536,"pattern":0xa5a5a5a5,"initialized_words":384} and end["invalid"]==0,
                        "Ordinary IRQ watermark did not start before the scheduler")
                deleted={t["id"]:t for t in threads if t["deleted"]}
                require(len(retired)==len(deleted)==end["retired"]>0 and {r["id"] for r in retired}==set(deleted),
                        "Pre-delete native stack generation coverage differs")
                for r in retired:
                    t=deleted[r["id"]]
                    require(r["tcb"]==t["tcb"] and r["reserved"]==t["reserved"] and
                            r["before_native_delete"]==r["stack_freed"]==r["tcb_freed"]==t["stack_freed"]==t["tcb_freed"]==1 and
                            0<r["spare"]<=r["reserved"]-4 and r["spare"]%4==0,"Pre-delete watermark/free evidence differs")
                matches=[t for t in threads if t["id"]==idle["id"] and t["role"]==2 and t["present"]]
                require(len(matches)==1 and idle["tcb"]==matches[0]["tcb"]==f["idle"] and idle["current"]==1 and
                        idle["reserved"]==1024 and 0<idle["spare"]<=1020 and idle["spare"]%4==0,
                        "Current native idle watermark absent")
                require(irq["reserved"]==1536 and irq["nesting"]==0 and 0<irq["spare"]<1536 and irq["spare"]%4==0 and
                        irq["touched_watermark"]==1536-irq["spare"] and lines[-1]=="RHINO_RAM END",
                        "Native IRQ touched watermark formula/completion differs")
                for r in (*retired,idle):r["reserved_minus_spare_bytes"]=r["reserved"]-r["spare"]
                stack_coverages.append({"deleted_stacks":retired,"current_idle_stack":idle,"ordinary_irq_stack":irq,
                    "pre_scheduler_irq_initialization":start,"all_deleted_generations_covered":True,
                    "whole_live_ram_peak_bytes":None,"ranking_eligible":False})
            peaks.append(samples[-1]["peak"]); counts.append(len(workers))
            totals.append([f[k] for k in ("created","native_active","timers")])
            threads_out.append(threads); timers_out.append(timers); samples_out.append(samples)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"AliOS-Rhino","native_heap_peaks":peaks,"task_lifetimes":totals,"workers_retained_blocked":counts,
            "thread_records":threads_out,"timer_records":timers_out,"heap_samples":samples_out,"ranking_eligible":False})
        if stack_expected:
            require(len(stack_coverages)==3,"Incomplete extended native stack replay")
            cells[-1]["stack_coverage"]=stack_coverages
    elif mode == "riot-ram":
        stack_expected = json.loads((folder/"build/build.json").read_text()).get("native_stack_coverage",False)
        stack_coverages = []
        def riot_stacks(lines,validation=False):
            proof = json.loads((folder/"stack-build-proof.json").read_text())
            parse = lambda prefix:[{k:int(v) for k,v in (t.split("=",1) for t in s.split()[1:])}
                                   for s in lines if s.startswith(prefix)]
            irq = parse("RIOT_STACK irq_address=")
            idle = parse("RIOT_STACK idle_pid=")
            require(len(irq)==1 and len(idle)==(not validation) and
                    sum(s.startswith("RIOT_STACK ") for s in lines)==len(irq)+len(idle),"Native RIOT stack inventory differs")
            r = irq[0]; start = proof["interrupt_stack"]["address"]; size = proof["interrupt_stack"]["reserved_bytes"]
            require(size==2048 and r["irq_address"]==start and r["reserved"]==r["zero_verified"]==r["painted"]==size and
                    not start<=r["boot_sp"]<start+size and r["nesting"]==0 and 0<r["spare"]<size and
                    r["touched"]==size-r["spare"],"Native RIOT IRQ initialization/range/watermark differs")
            at = next(i for i,s in enumerate(lines) if s.startswith("RIOT_STACK irq_address="))
            require(lines[at+1:]==(["RIOT_RAM END"] if validation else ["RIOT_RAM final invalid=0","RIOT_RAM END"]),
                    "Native RIOT IRQ completion differs")
            if idle:
                r = idle[0]
                threads = [{k:int(v) for k,v in (t.split("=",1) for t in s.split()[2:])}
                           for s in lines if s.startswith("RIOT_RAM thread ")]
                match = [s for s in threads if s["role"]==2]
                require(len(match)==1,"Native RIOT current idle missing")
                t = match[0]; aligned = (t["stack"]+3)&~3
                require((r["idle_pid"],r["tcb"],r["stack"],r["reserved"])==(t["pid"],t["tcb"],t["stack"],t["reserved"]) and
                    [r["stack"],r["reserved"]]==proof["static_reservations"]["idle_stack"] and r["start"]==aligned and
                    r["scan_bytes"]==t["tcb"]-aligned and 0<r["spare"]<r["scan_bytes"] and
                    r["touched_in_span"]==r["scan_bytes"]-r["spare"] and r["main_exited"]==1 and not r["nesting"] and
                    lines[at-1].startswith("RIOT_STACK idle_pid=") and
                    any(s.startswith("RIOT_RAM phase=main-exited ") for s in lines[:at-1]),
                    "Native RIOT idle span/lifecycle/watermark differs")
            return {"ordinary_irq_stack":irq[0],"current_idle_stack":idle[0] if idle else None}
        validation_rows=raw_rows(folder/"validation/reset1.jsonl")
        checks=[dict(t.split("=",1) for t in r["line"].split()[1:]) for r in validation_rows
                if r["line"].startswith("RIOT_RAM validation=")]
        require(len(checks)==1 and checks[0]["validation"]=="PASS" and checks[0]["invalid"]=="0" and
                checks[0]["base"]==checks[0]["final"] and
                int(checks[0]["base"])<int(checks[0]["required_overlap_peak"])<=int(checks[0]["observed_peak"]),
                "Native RIOT moving-realloc overlap validation missing")
        if stack_expected:
            riot_stacks([r["line"] for r in validation_rows],True)
        peaks,totals,workers,retained=[],[],[],[]
        for index in (1,2,3):
            rows=raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines=[r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count("RIOT_RAM END")==1 and
                    lines.count("RIOT_RAM final invalid=0")==1 and lines.count("RIOT_RAM returned=0")==1 and
                    not any(re.search(r"panic|fatal|assert|invalid-command|Exception|status=FAIL",s,re.I) for s in lines),
                    "RIOT native lifecycle reset/completion/error differs")
            parsed=lambda prefix,start:[{k:int(v) if v.isdecimal() else v for k,v in
                (t.split("=",1) for t in s.split()[start:])} for s in lines if s.startswith(prefix)]
            samples=parsed("RIOT_RAM phase=",1)
            heaps=parsed("RIOT_RAM heap ",2)
            tasks=parsed("RIOT_RAM tasks ",2)
            threads=parsed("RIOT_RAM thread ",2)
            final=[int(m[1]) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=\d+",s))]
            trials=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH TRIAL source=SEI_DERIVED_C clock_hz=240000000 tick_hz=0 duration_s=10 raw_speed_kwips=\d+ experiment=4 step=(\d+) task_count=(\d+)",s))]
            require(len(final)==1 and trials==[(s,5+s) for s in range(final[0]+1)] and
                    [s["phase"] for s in samples]==["application-entry","series-return","main-exited"] and
                    len(heaps)==12 and all(not s["invalid"] and 0<s["occupied"]<=s["peak"] and s["unlocks"]>0 for s in samples) and
                    all(a[k]<=b[k] for a,b in zip(samples,samples[1:]) for k in ("peak","observations","unlocks","sbrks")),
                    "Original persistent-worker PH4 or allocator phases differ")
            count=final[0]+5
            expected=dict(created=count+3,stopped=1,active=count+2,workers=count,native_active=count+2,invalid=0)
            require(tasks==[expected] and len(threads)==count+3 and
                    len({s["pid"] for s in threads})==len(threads) and len({s["tcb"] for s in threads})==len(threads),
                    "Native worker/main/idle task inventory differs")
            gates=[]
            for s in threads:
                aligned=(s["stack"]+3)&~3
                require(s["tcb"]==((s["stack"]+s["reserved"]-48)&~3) and
                        s["effective_flags"]==(s["original_flags"]|8) and 0<=s["spare"]<=s["tcb"]-aligned,
                        "Embedded TCB/stack fill bounds differ")
                if s["role"]==0:
                    require(s["reserved"]==4096 and s["usable"]>=4096 and s["present"]==s["hwm_measured"]==1 and
                            s["status"]==3 and s["original_flags"]==5 and s["waiter"]==s["tcb"]+12 and
                            not any(s[k] for k in ("value","gate_state","next")) and
                            any(h["start"]<=s["stack"]-4<s["stack"]+s["usable"]<=h["start"]+h["committed"] for h in heaps[-4:]),
                            "Worker not retained blocked on original native gate")
                    gates.append(s["gate"])
                elif s["role"]==3:
                    require(s["pid"]==1 and s["reserved"]==3632 and s["present"]==s["hwm_measured"]==1 and
                            s["status"]==2 and s["original_flags"]==12 and
                            any(h["start"]<=s["stack"]<s["stack"]+s["reserved"]<=h["start"]+h["committed"] for h in heaps[:4]),
                            "Native pre-main heap-backed timer task missing")
                else:
                    require(s["role"] in (1,2) and s["present"]==(s["role"]==2) and
                            s["status"]==(11 if s["role"]==2 else 0) and s["hwm_measured"]==(s["role"]==1),
                            "Main exit or original idle retention missing")
            require(len(gates)==count and sorted(gates)==list(range(min(gates),min(gates)+12*count,12)),
                    "Native retained gates missing/duplicated")
            require(sorted(s["role"] for s in threads)==[0]*count+[1,2,3],"Native role inventory differs")
            if stack_expected:
                stack_coverages.append(riot_stacks(lines))
            peaks.append(samples[-1]["peak"])
            workers.append(count)
            totals.append([tasks[0][k] for k in ("created","stopped","active","workers","native_active")])
            retained.append([[s[k] for k in ("pid","stack","reserved","usable","role","present","status","hwm_measured","spare","gate")]
                             for s in threads])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"RIOT","native_heap_peaks":peaks,"task_lifetimes":totals,"workers_retained_blocked":workers,
                      "retained_records":retained,"ranking_eligible":False})
        if stack_expected:
            require(len(stack_coverages)==3,"Incomplete RIOT native stack replay")
            cells[-1]["stack_coverage"]=stack_coverages
    elif mode == "zephyr-ram":
        stack_expected = json.loads((folder/"build/build.json").read_text()).get("native_stack_coverage",False)
        stack_coverages = []
        def zephyr_stacks(lines,validation=False):
            proof = json.loads((folder/"stack-build-proof.json").read_text())
            parse = lambda prefix:[{k:int(v) for k,v in (t.split("=",1) for t in s.split()[1:])}
                                   for s in lines if s.startswith(prefix)]
            irq,idle = parse("ZEPHYR_STACK irq_address="),parse("ZEPHYR_STACK idle_tcb=")
            require(len(irq)==1 and len(idle)==(not validation) and
                    sum(s.startswith("ZEPHYR_STACK ") for s in lines)==len(irq)+len(idle),"Native Zephyr stack inventory differs")
            r = irq[0]; start,size = proof["static_reservations"]["z_interrupt_stacks"]
            require(size==2048 and r["irq_address"]==start and r["reserved"]==r["initial_verified"]==size and
                    not start<=r["boot_sp"]<start+size and r["nesting"]==0 and 0<r["spare"]<size and
                    r["touched"]==size-r["spare"],"Native Zephyr initial fill/context/IRQ watermark differs")
            at = next(i for i,s in enumerate(lines) if s.startswith("ZEPHYR_STACK irq_address="))
            require(lines[at+1:]==(["ZEPHYR_RAM END"] if validation else ["ZEPHYR_RAM final invalid=0","ZEPHYR_RAM END"]),
                    "Native Zephyr stack terminal boundary differs")
            if idle:
                r = idle[0]
                threads = [{k:int(v) for k,v in (t.split("=",1) for t in s.split()[2:])}
                           for s in lines if s.startswith("ZEPHYR_RAM stack ")]
                match = [s for s in threads if s["role"]==2]
                require(len(match)==1,"Native Zephyr current idle missing")
                t = match[0]
                require([r["stack"],r["reserved"]]==proof["static_reservations"]["z_idle_stacks"] and
                    r["idle_tcb"]==proof["static_reservations"]["z_idle_threads"][0] and
                    tuple(r[k] for k in ("idle_tcb","stack","start","reserved","span"))==tuple(t[k] for k in ("tcb","stack","start","reserved","span")) and
                    0<r["spare"]<r["span"] and r["touched"]==r["span"]-r["spare"] and
                    r["main_exited"]==1 and r["nesting"]==0 and lines[at-1].startswith("ZEPHYR_STACK idle_tcb=") and
                    any(s.startswith("ZEPHYR_RAM phase=main-exited ") for s in lines[:at-1]),
                    "Native Zephyr idle lifecycle/bounds/watermark differs")
            return {"ordinary_irq_stack":irq[0],"current_idle_stack":idle[0] if idle else None}
        validation_rows = raw_rows(folder/"validation/reset1.jsonl")
        checks = [dict(t.split("=",1) for t in r["line"].split()[1:]) for r in validation_rows
                  if r["line"].startswith("ZEPHYR_RAM validation=")]
        require(len(checks)==1 and checks[0]["validation"]=="PASS" and checks[0]["invalid"]=="0" and
                checks[0]["base"]==checks[0]["final"] and
                int(checks[0]["base"])<int(checks[0]["required_overlap_peak"])<=int(checks[0]["observed_peak"]),
                "Native Zephyr heap validation missing")
        if stack_expected:
            zephyr_stacks([r["line"] for r in validation_rows],True)
        peaks, totals, worker_lifetimes, slot_generations = [],[],[],[]
        for index in (1,2,3):
            rows = raw_rows(folder/"captures"/("reset%d.jsonl"%index))
            lines = [r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count("ZEPHYR_RAM END")==1 and
                    lines.count("ZEPHYR_RAM final invalid=0")==1 and lines.count("ZEPHYR_RAM returned=0")==1 and
                    not any(re.search(r"panic|fatal|assert|invalid-command|Exception|error:",s,re.I) for s in lines),
                    "Zephyr lifecycle reset/completion/error differs")
            parsed = lambda prefix,start:[{k:int(v) if v.isdecimal() else v for k,v in
                (t.split("=",1) for t in s.split()[start:])} for s in lines if s.startswith(prefix)]
            samples = parsed("ZEPHYR_RAM phase=",1)
            heaps = parsed("ZEPHYR_RAM heap ",2)
            roles = parsed("ZEPHYR_RAM role=",1)
            stacks = parsed("ZEPHYR_RAM stack ",2)
            require([s["phase"] for s in samples]==["application-entry","series-return","main-exited"] and
                    [s["phase"] for s in heaps]==["application-entry","series-return","main-exited"] and
                    all(not s["invalid"] and s["heaps"]==1 and s["created"]==s["retired"]+s["active"] for s in samples) and
                    all(h["valid"]==1 and h["reserved"]==4096 and 0<=h["allocated"]<=h["peak"]<=h["reserved"] for h in heaps),
                    "Native Zephyr statistics or lifecycle phases differ")
            final = [int(m[1]) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=\d+",s))]
            trials = [tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                r"HARTSTONE PH TRIAL source=SEI_DERIVED_C clock_hz=240000000 tick_hz=100000 duration_s=10 raw_speed_kwips=\d+ experiment=4 step=(\d+) task_count=(\d+)",s))]
            require(len(final)==1 and trials==[(s,5+s) for s in range(final[0]+1)],"Original Zephyr PH4 coverage differs")
            workers = sum(c for _,c in trials)
            require([s["role"] for s in roles]==["worker","main","system"] and
                    roles[0]==dict(role="worker",created=workers,dead=workers,retired=workers,active=0) and
                    roles[1]==dict(role="main",created=1,dead=1,retired=1,active=0) and
                    roles[2]==dict(role="system",created=1,dead=0,retired=0,active=1) and
                    all(sum(s[k] for s in roles)==samples[-1][k] for k in ("created","dead","retired","active")) and
                    samples[-1]["joined"]==workers and samples[-2]["retired"]==workers,
                    "Native Zephyr main/worker retirement differs")
            worker_slots = [s for s in stacks if s["role"]==0]
            require(len(worker_slots)==final[0]+5 and len(stacks)==len(worker_slots)+2 and
                    len({s["tcb"] for s in stacks})==len(stacks) and
                    sum(s["generations"] for s in worker_slots)==workers and
                    all(s["dead"]==s["joined"]==s["retired"]==s["hwm_measured"]==1 and
                        0<=s["spare"]<=s["span"]<=s["reserved"] for s in worker_slots),
                    "Static worker slot reuse/join/high-water evidence incomplete")
            peaks.append(heaps[-1]["peak"])
            if stack_expected:
                stack_coverages.append(zephyr_stacks(lines))
            worker_lifetimes.append(workers)
            slot_generations.append([s["generations"] for s in worker_slots])
            totals.append([samples[-1][k] for k in ("created","dead","joined","retired","active")])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"Zephyr","native_heap_peaks":peaks,"task_lifetimes":totals,
                      "worker_lifetimes":worker_lifetimes,"slot_generations":slot_generations,"ranking_eligible":False})
        if stack_expected:
            require(len(stack_coverages)==3,"Incomplete Zephyr native stack replay")
            cells[-1]["stack_coverage"]=stack_coverages
    elif mode == "freertos-ram":
        values, task_totals, role_totals = [], [], []
        irq_extension = json.loads((folder/"build/build.json").read_text()).get("ordinary_irq_stack_coverage",False)
        irq_values = []
        def irq_record(lines):
            matches = [dict(token.split("=",1) for token in s.split()[1:])
                       for s in lines if s.startswith("FREERTOS_STACK ")]
            require(len(matches) == 1,"One ordinary-IRQ watermark required")
            v = {k:int(n) for k,n in matches[0].items()}
            native = json.loads((folder/"stack-build-proof.json").read_text())["interrupt_stack"]
            require(set(v) == {"irq_address","reserved","painted","boot_sp","scheduler","nesting","spare","touched"} and
                    v["irq_address"] == native["address"] and v["reserved"] == v["painted"] == native["reserved_bytes"] and
                    not v["irq_address"] <= v["boot_sp"] < v["irq_address"]+v["reserved"] and
                    v["scheduler"] == 1 and v["nesting"] == 0 and 0 < v["spare"] < v["reserved"] and
                    v["touched"] == v["reserved"]-v["spare"] and lines[-2:] == [next(s for s in lines if s.startswith("FREERTOS_STACK ")),"FREERTOS_RAM END"],
                    "Ordinary-IRQ range/paint/early context/watermark differs")
            return v
        validation_rows = raw_rows(folder / "validation/reset1.jsonl")
        text = [r["line"] for r in validation_rows]
        if irq_extension:
            irq_record(text)
        checks = [tuple(map(int,m.groups())) for s in text if (m := re.fullmatch(
            r"FREERTOS_RAM validation=PASS base=(\d+) final=(\d+) required_overlap_peak=(\d+) observed_peak=(\d+)", s))]
        require(len(checks) == 1 and checks[0][0] == checks[0][1] < checks[0][2] <= checks[0][3] and
                text.count("FREERTOS_RAM END") == 1 and not any(s.startswith("HARTSTONE PH ") for s in text),
                "Native heap separate-reset validation missing")
        for index in (1, 2, 3):
            rows = raw_rows(folder / "captures" / ("reset%d.jsonl" % index))
            lines = [r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines) == 1 and lines.count("FREERTOS_RAM END") == 1 and
                    not any(re.search(r"panic|abort|Guru Meditation|Exception|ASSERT|FATAL|invalid-command", s, re.I) for s in lines),
                    "Native lifecycle reset/completion/error differs")
            samples = []
            for s in lines:
                if not s.startswith("FREERTOS_RAM phase="):
                    continue
                fields = dict(token.split("=", 1) for token in s.split()[1:])
                samples.append({k: v if k == "phase" else int(v) for k,v in fields.items()})
            require([r["phase"] for r in samples] == ["application-entry", "application-return", "series-end", "controller-delayed"] and
                    all(not r["invalid"] and 0 < r["occupied"] <= r["peak"] for r in samples) and
                    all(a[k] <= b[k] for a,b in zip(samples,samples[1:]) for k in ("peak","alloc","free","resize","align")),
                    "Native allocator phase/ledger differs")
            summaries = [dict(token.split("=",1) for token in s.split()[2:]) for s in lines if s.startswith("FREERTOS_RAM tasks ")]
            require(len(summaries) == 1, "Native task summary missing")
            totals = {k:int(v) for k,v in summaries[0].items()}
            final = [int(m[1]) for s in lines if (m := re.fullmatch(r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=\d+",s))]
            trials = [tuple(map(int,m.groups())) for s in lines if (m := re.fullmatch(
                r"HARTSTONE PH TRIAL source=SEI_DERIVED_C clock_hz=240000000 tick_hz=1000 duration_s=10 raw_speed_kwips=\d+ experiment=4 step=(\d+) task_count=(\d+)",s))]
            require(len(final) == 1 and trials == [(s,5+s) for s in range(final[0]+1)], "Original PH4 trial coverage differs")
            roles = {}
            for s in lines:
                if s.startswith("FREERTOS_RAM role="):
                    fields = dict(token.split("=",1) for token in s.split()[1:])
                    name = fields.pop("role")
                    require(name not in roles, "Duplicate task role")
                    roles[name] = {k:int(v) for k,v in fields.items()}
            workers = sum(c for _,c in trials)
            require(set(roles) == {"worker","controller","main","system"} and
                    list(roles["worker"].values()) == [workers,workers,workers,0] and
                    list(roles["controller"].values()) == [1,0,0,1] and list(roles["main"].values()) == [1,1,1,0] and
                    not totals["invalid"] and totals["requested"] == totals["cleanup"] == totals["retired"] and
                    totals["created"] == totals["retired"] + totals["active"] and
                    all(sum(r[k] for r in roles.values()) == totals[k] for k in ("created","requested","retired","active")),
                    "Native task allocation retirement differs")
            pools = [dict(token.split("=",1) for token in s.split()[2:]) for s in lines if s.startswith("FREERTOS_RAM pool ")]
            require(len(pools) == samples[-1]["register"] and sum(int(p["occupied"]) for p in pools) == samples[-1]["occupied"] and
                    all(0 < int(p["metadata"]) <= int(p["occupied"]) <= int(p["bytes"]) and int(p["checks"]) > 0 for p in pools),
                    "Native pool ledger does not reconcile")
            live = [s for s in lines if s.startswith("FREERTOS_RAM live ")]
            require(len(live) == totals["active"], "Native retained task inventory incomplete")
            if irq_extension:
                irq_values.append(irq_record(lines))
            values.append(samples[-1]["peak"])
            task_totals.append([totals[k] for k in ("created","requested","cleanup","retired","active")])
            role_totals.append(roles)
            intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os":"FreeRTOS", "values":values, "task_lifetimes":task_totals, "roles":role_totals,
                      "ranking_eligible":False, **({"ordinary_irq_stack":irq_values} if irq_extension else {})})
    elif mode == "ram" and data.get("kind") == "ram":
        values, lifetimes, block_peaks, cleanup_records, owner_records = [], [], [], [], []
        cleanup = data.get("task_cleanup_extension", False)
        owners = data.get("retained_owners_extension",False)
        validation = [r["line"] for r in raw_rows(folder / "validation/reset1.jsonl")]
        passed = [m for s in validation if (m := re.fullmatch(r"RAM_EVENTS validation=PASS base=(\d+) final=(\d+)", s))]
        require(len(passed) == 1 and passed[0][1] == passed[0][2] and validation[-1] == "RAM_EVENTS END",
                "Same-image allocator oracle validation missing")
        for index in (1, 2, 3):
            rows = raw_rows(folder / "captures" / ("reset%d.jsonl" % index))
            lines = [r["line"] for r in rows]
            require(sum(s.startswith("rst:0x") for s in lines) == 1 and lines[-1] == ("RAM_OWNERS END" if owners else "RAM_CLEANUP END" if cleanup else "RAM_EVENTS END") and not any(
                re.search(r"invalid=[1-9]|status=FAIL|panic|abort|ASSERT|Exception", s, re.I) for s in lines),
                "Native RAM reset/terminal/invariants differ")
            samples = [m for s in lines if (m := re.fullmatch(
                r"RAM_EVENTS phase=(\S+) occupied=(\d+) peak=(\d+) invalid=(\d+) oracle=(\d+) .*", s))]
            phases = ["parent-before-launch", "application-entry", "series-return", "parent-after-cleanup"] if cleanup else ["application-entry", "series-return"]
            if cleanup and any(s.startswith("RAM_CLEANUP maintenance=") for s in lines):
                phases += ["parent-after-native-reclaim"]
            require([m[1] for m in samples] == phases and all(
                int(m[2]) <= int(m[3]) and int(m[4]) == 0 and int(m[5]) > 0 for m in samples) and
                all(int(a[3]) <= int(b[3]) for a,b in zip(samples,samples[1:])), "Native heap endpoint/peak arithmetic differs")
            stacks = [list(map(int, m.groups())) for s in lines if (m := re.fullmatch(
                r"RAM_EVENTS stacks created=(\d+) retired=(\d+) active=(\d+) peak_active=(\d+) retired_max_high_water=(\d+)", s))]
            terminal = [m for s in lines if (m := re.fullmatch(r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=\d+", s))]
            require(len(stacks) == 1 and len(terminal) == 1, "RAM original first-loss/stack ledger missing")
            workers = 5 + int(terminal[0][1])
            expected = sum(range(5, workers + 1))
            require(stacks[0][:3] == [expected + 3, expected, 3] and stacks[0][3] == workers + 3,
                    "Original worker stack lifetime arithmetic differs")
            summary = [list(map(int, m.groups())) for s in lines if (m := re.fullmatch(
                r"STACK_LIFE summary created=(\d+) retired=(\d+) active=(\d+) block_live=(\d+) block_peak=(\d+) use_calls=(\d+) use_success=(\d+) invalid=(\d+)", s))]
            if summary:
                blocks = [list(map(int, m.groups())) for s in lines if (m := re.fullmatch(
                    r"STACK_LIFE live allocation=(\d+) usable=(\d+) block=(\d+)", s))]
                require(len(summary) == 1 and summary[0][:3] == stacks[0][:3] and len(blocks) == 3 and
                    sum(b[2] for b in blocks) == summary[0][3] <= summary[0][4] <= int(samples[-1][3]) and
                    summary[0][5:] == [0, 0, 0], "Native stack block allocation arithmetic differs")
                block_peaks.append(summary[0][4])
            if cleanup:
                before = [list(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                    r"RAM_CLEANUP baseline parent=(\d+) occupied=(\d+) active=(\d+) blocks=(\d+) created=(\d+) retired=(\d+)",s))]
                after = [list(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                    r"RAM_CLEANUP final controller=(\d+) parent=(\d+) wait_result=(\d+) status=(\d+) released=(\d+) absent=(\d+) occupied=(\d+) peak=(\d+) active=(\d+) blocks=(\d+) created=(\d+) retired=(\d+) invalid=(\d+)",s))]
                require(len(before)==len(after)==1, "Cleanup endpoints missing")
                b,a = before[0],after[0]
                require(a[0]==a[2] and a[0]!=a[1] and a[1]==b[0] and a[3:6]==[0,1,1] and a[-1]==0 and
                    a[8:10]==b[2:4] and a[10:12]==[expected+b[4]+1,expected+b[5]+1] and
                    [b[1],a[6],a[7]]==[int(samples[0][2]),int(samples[-1][2]),int(samples[-1][3])],
                    "Native post-exit lifetime arithmetic differs")
                cleanup_records.append({"created":a[10],"retired":a[11],"active":a[8],
                    "allocated_delta_bytes":a[6]-b[1],"controller_pid":a[0]})
                if phases[-1] == "parent-after-native-reclaim":
                    deferred = [list(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                        r"RAM_CLEANUP deferred count=(\d+) bytes=(\d+)",s))]
                    require(len(deferred)==1 and lines.count("RAM_CLEANUP reclaim pending=0")==1 and
                        int(samples[-2][2])-int(samples[-1][2])==deferred[0][1],
                        "Deferred native allocation balance differs")
                    cleanup_records[-1]["deferred_blocks_reclaimed"] = deferred[0][0]
                    cleanup_records[-1]["deferred_bytes_reclaimed"] = deferred[0][1]
                if owners:
                    hashes = [list(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                        r"RAM_OWNERS pidhash before_slots=(\d+) before_block=(\d+) after_slots=(\d+) after_block=(\d+) allocation=(\d+)",s))]
                    totals = [list(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
                        r"RAM_OWNERS summary created=(\d+) delete_requested=(\d+) pending=(\d+) pending_bytes=(\d+) hash_delta=(\d+) invalid=(\d+)",s))]
                    blocks = [int(m[1]) for s in lines if (m:=re.fullmatch(
                        r"RAM_OWNERS timer allocation=\d+ block=(\d+) state=\d+ link=\d+ prev=\d+ next=\d+",s))]
                    require(len(hashes)==len(totals)==1,"Retained native owner summary missing")
                    h,t = hashes[0],totals[0]
                    require(t[:3]==[expected,expected,workers] and len(blocks)==workers and
                        sum(blocks)==t[3] and h[3]-h[1]==t[4] and t[3]+t[4]==a[6]-b[1] and t[5]==0,
                        "Retained native object byte/count arithmetic differs")
                    owner_records.append({"hash_capacity_delta_bytes":t[4],"pending_timer_count":t[2],
                        "pending_timer_block_bytes":t[3],"allocated_delta_bytes":a[6]-b[1]})
            values.append(int(samples[-1][3]))
            lifetimes.append(stacks[0][:3])
            intervals.append((datetime.fromisoformat(rows[0]["utc"]), datetime.fromisoformat(rows[-1]["utc"])))
        cells.append({"os": "NuttX", "metric": "native allocated heap peak", "unit": "B", "values": values,
            "stack_lifetimes": lifetimes, "allocated_stack_block_peaks": block_peaks,
            "full_live_ram_measured": False, **({"post_exit_cleanup":cleanup_records} if cleanup else {}),
            **({"retained_native_ownership":owner_records} if owners else {})})
    else:
        raise ValueError("Unsupported original arithmetic replay family")
    require(cells, "No completed test cells found")
    intervals.sort()
    require(all(a[1] < b[0] for a, b in zip(intervals, intervals[1:])), "Physical captures overlap")
    return {"replay": "pass", "scope": "separate stdlib byte/count implementation; not external physical reproduction or semantic audit",
            **({"chronology": "host-boot-scoped-monotonic-ns-v1", "host_boot_id": monotonic_boot}
               if mode == "message-observer-pairs" and monotonic_profile else {}),
            "board_mac": data["board_mac"], "independent_resets": len(intervals), "cells": cells,
            "energy_measured": False, "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--prepared", type=Path)
    args = parser.parse_args()
    print(json.dumps(replay(args.directory, args.prepared), indent=2))
