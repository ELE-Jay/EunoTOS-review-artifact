#!/usr/bin/env python3
"""Separate stdlib replay of the FreeRTOS message/IRQ observation, without board access."""
import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re

from replay_esp32_followup import campaign, digest, raw_rows, require


def history(lines, phases=None):
    pools=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"FREERTOS_RAM pool start=(\d+) bytes=(\d+) occupied=(\d+) metadata=(\d+) native_bias=(\d+) checks=(\d+)",s))]
    events=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"TM_RAM event=(\d+) kind=(\d+) pool=(\d+) pointer=(\d+) delta=(-?\d+)",s))]
    require(pools and 0<len(events)<1024 and len({p[0] for p in pools})==len(pools),"Native pool/event inventory differs")
    allocations,usage,owners,pairs,requests,cleanups,retired={},{},{},{},set(),set(),set()
    generations, stack_tasks = {}, {}
    counts,peak,maximum=Counter(),0,0
    pending=None
    for index,(sequence,kind,pool,pointer,delta) in enumerate(events):
        require(sequence==index and 0<=kind<=8,"Missing/unknown native event")
        counts[kind]+=1
        if kind==0:
            require(pool==len(usage) and pool<len(pools) and (pointer,delta)==(pools[pool][0],pools[pool][3]),
                    "Native region registration differs")
            usage[pool]=delta
        elif kind<=4:
            require(pool in usage,"Transition before pool registration")
            if kind in (1,4):
                require(pointer not in allocations and delta>4,"Duplicate/invalid native allocation")
                allocations[pointer]=(pool,delta)
                generations[pointer]=generations.get(pointer,0)+1
            elif kind==2:
                identity=(pointer,generations.get(pointer))
                if identity in owners:
                    task=identity if owners[identity][0]==5 else stack_tasks[identity]
                    require(task in cleanups,"Task storage released before native cleanup")
                require(allocations.pop(pointer,None)==(pool,-delta),"Release without matching live native block")
            else:
                require(pointer in allocations and allocations[pointer][0]==pool and allocations[pointer][1]+delta>4,
                        "Native resize lacks its original block")
                allocations[pointer]=(pool,allocations[pointer][1]+delta)
            usage[pool]+=delta
            for p,(h,n) in allocations.items():
                start,size=pools[h][:2]
                require(start<=p-4<p-4+n<=start+size,"Native block outside pool")
            for h in usage:
                spans=sorted((p-4,p-4+n) for p,(owner,n) in allocations.items() if owner==h)
                require(all(a[1]<=b[0] for a,b in zip(spans,spans[1:])),"Live native block intervals overlap")
        elif kind in (5,6):
            identity=(pointer,generations.get(pointer))
            require(identity not in owners and pointer in allocations and 0<=pool<=3 and
                    0<delta<=allocations[pointer][1]-4,"Task storage ownership differs")
            owners[identity]=(kind,pool,delta)
            if kind==5:
                require(pending is None,"Task creation lacks its matching stack")
                pending=identity
            else:
                require(pending is not None and owners[pending][1]==pool,"Stack role differs from its task")
                pairs[pending]=identity
                stack_tasks[identity]=pending
                pending=None
        elif kind==7:
            identity=(pointer,generations.get(pointer))
            require(identity in pairs and identity not in requests and owners[identity][1]==pool and delta==0,
                    "Task deletion has no matching creation")
            requests.add(identity)
        else:
            identity=(pointer,generations.get(pointer))
            require(identity in requests and identity not in cleanups and owners[identity][1]==pool and delta==0,
                    "Native cleanup has no matching request")
            cleanups.add(identity)
        for tcb,stack in pairs.items():
            tcb_live=tcb[0] in allocations and generations[tcb[0]]==tcb[1]
            stack_live=stack[0] in allocations and generations[stack[0]]==stack[1]
            if not tcb_live or not stack_live:
                require(tcb in cleanups,"Task storage released before native cleanup")
            if not tcb_live and not stack_live:
                retired.add(tcb)
        maximum=max(maximum,len(pairs)-len(retired))
        require(all(n==pools[h][3]+sum(v for owner,v in allocations.values() if owner==h)
                    for h,n in usage.items()),"Native live-set byte accounting differs")
        peak=max(peak,sum(usage.values()))
    require(pending is None and len(usage)==len(pools) and all(usage[i]==p[2] for i,p in enumerate(pools)),
            "Native final live set differs from pool walk")
    samples=[(m[1],*map(int,m.groups()[1:])) for s in lines if (m:=re.fullmatch(
        r"FREERTOS_RAM phase=(\S+) occupied=(\d+) peak=(\d+) invalid=(\d+) register=(\d+) alloc=(\d+) free=(\d+) resize=(\d+) align=(\d+)",s))]
    allowed = (phases,) if phases is not None else (["application-entry","message-end"],
        ["application-entry","application-return","message-end"])
    require([s[0] for s in samples] in allowed and all(s[3]==0 for s in samples),
            "Original observation boundaries or heap checks differ")
    require(samples[-1][1:3]==(sum(usage.values()),peak) and samples[-1][4:]==tuple(counts[k] for k in range(5)),
            "Native peak or per-kind event counters differ")
    live=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"FREERTOS_RAM live tcb=(\d+) stack=(\d+) span=(\d+) tcb_bytes=(\d+) kind=(\d+) role=(\d+) stack_heap=(\d+) tcb_heap=(\d+) stack_block=(\d+) tcb_block=(\d+) spare=(\d+)",s))]
    require(len(live)==len(pairs)-len(retired) and {r[0] for r in live}=={t[0] for t in set(pairs)-retired},
            "Retained task inventory differs")
    for tcb,stack,span,tcb_size,kind,role,sh,th,sb,tb,spare in live:
        tcb_id,stack_id=(tcb,generations[tcb]),(stack,generations[stack])
        require(pairs[tcb_id]==stack_id and owners[tcb_id]==(5,role,tcb_size) and owners[stack_id]==(6,role,span) and
                kind in (0,1,2) and sh==th==1 and allocations[tcb][1]==tb and allocations[stack][1]==sb and
                0<=spare<=span,"Native task block/watermark ownership differs")
    summaries=[tuple(map(int,m.groups())) for s in lines if (m:=re.fullmatch(
        r"FREERTOS_RAM tasks created=(\d+) requested=(\d+) cleanup=(\d+) retired=(\d+) active=(\d+) peak_active=(\d+) retired_max_used=(\d+) invalid=(\d+)",s))]
    require(len(summaries)==1 and summaries[0][:6]==(len(pairs),len(requests),len(cleanups),len(retired),len(live),maximum)
            and summaries[0][-1]==0,"Native task lifetime counts differ")
    return {"events":len(events),"heap_peak_bytes":peak,"heap_final_bytes":sum(usage.values()),
        "active_tasks":len(live),"live_tasks":[list(r) for r in live]}


def irq_watermark(lines,address,size):
    matches=[(i,tuple(map(int,m.groups()))) for i,s in enumerate(lines) if (m:=re.fullmatch(
        r"FREERTOS_STACK irq_address=(\d+) reserved=(\d+) painted=(\d+) boot_sp=(\d+) scheduler=1 nesting=0 spare=(\d+) touched=(\d+)",s))]
    require(len(matches)==1 and matches[0][0]==len(lines)-2,"IRQ terminal boundary missing")
    a,n,paint,sp,spare,touched=matches[0][1]
    require((a,n,paint)==(address,size,size) and sp%16==0 and not a<=sp<a+n and 0<spare<n and
            touched==n-spare,"IRQ paint/context/native watermark differs")
    return {"address":a,"reserved_bytes":n,"painted_bytes":paint,"boot_stack_pointer":sp,
        "spare_pattern_bytes":spare,"touched_watermark_bytes":touched,"already_in_static_sram":True,
        "exact_simultaneous_live_bytes":False,"nmi_debug_rom_covered":False}


def startup_watermark(lines,live_tasks=None):
    selected=[(i,s) for i,s in enumerate(lines) if s.startswith("FREERTOS_BOOT_STACK ")]
    require(len(selected)==1,"Startup observation missing or repeated")
    at,line=selected[0]
    fields=[part.split("=",1) for part in line.split()[1:]]
    require(len(fields)==10 and all(len(p)==2 and p[1].isdigit() for p in fields),"Startup field shape differs")
    item={k:int(v) for k,v in fields}
    require(set(item)=={"low","entry_sp","paint_end","painted","verified","handoff_sp","spare","touched","guard","handoffs"},
            "Startup field inventory differs")
    low,entry,end,other=(item[k] for k in ("low","entry_sp","paint_end","handoff_sp"))
    require(low==0x3ffe0440 and low+64<entry<=0x3ffe3f20 and entry%16==other%16==0 and
        item["guard"]==64 and end+64==entry and item["painted"]==item["verified"]==end-low and
        0<=item["spare"]<=end-low and item["spare"]%4==item["touched"]%4==0 and
        low+item["spare"]+item["touched"]==end and not low<=other<0x40000000 and item["handoffs"]==1 and
        at+1<len(lines) and lines[at+1].startswith("FREERTOS_STACK irq_address="),"Startup paint/phase/arithmetic differs")
    if live_tasks is not None:
        owner=[t for t in live_tasks if t[5]==2 and t[1]<=other<t[1]+t[2]]
        require(len(owner)==1,"Startup handoff lacks native main-stack ownership")
    return {"application_entry_sp":entry,"painted_start":low,"painted_end":end,
        "initial_painted_and_verified_bytes":item["painted"],"handoff_main_task_sp":other,
        "spare_pattern_bytes":item["spare"],"touched_watermark_bytes":item["touched"],"unpainted_guard_bytes":64,
        "resolution_bytes":4,"observed_before_native_heap_registration":True,
        "scope":"application entry to startup-heap handoff; no bootloader/ROM-before-entry, untouched frames or simultaneous-live peak",
        "full_live_ram_peak_bytes":None}


def tick_snapshots(lines, live, irq_address, irq_size):
    """Independent field-based reconstruction of saved-SP and heap epochs."""
    fields=[]
    for line in lines:
        if not line.startswith("FREERTOS_LIVE "): continue
        pairs=[part.split("=",1) for part in line.split()[1:]]
        require(all(len(p)==2 and p[1].isdigit() for p in pairs) and
                len({p[0] for p in pairs})==len(pairs),"Invalid snapshot fields")
        fields.append({k:int(v) for k,v in pairs})
    summary=[r for r in fields if "samples" in r]
    require(len(summary)==1 and set(summary[0])=={"samples","records","skipped","maximum","capacity","frame"},
            "Snapshot summary missing/duplicated")
    s=summary[0]
    require(8000<=s["samples"]<=11000 and 0<s["records"]<=s["capacity"]==128 and s["frame"]==192,
            "Snapshot count/window differs")
    boundaries={row[0]:(row[1],row[1]+row[2]-1) for row in live}
    require(len(boundaries)==len(live) and 0<len(live)<=8,"Live task set ambiguous")
    epochs=[0]
    creation={}
    for line in lines:
        if not line.startswith("TM_RAM event="): continue
        e=dict(part.split("=",1) for part in line.split()[1:])
        kind=int(e["kind"])
        require(int(e["event"])==len(epochs)-1 and kind not in (7,8),"Retained-task epoch differs")
        epochs.append(epochs[-1]+(int(e["delta"]) if kind<5 else 0))
        if kind==5: creation[int(e["pointer"])]=len(epochs)-1
    records=[r for r in fields if "current" in r]
    members=[r for r in fields if "task" in r]
    require(len(fields)==1+len(records)+len(members) and len(records)==s["records"],"Unknown snapshot type")
    rebuilt=[]
    last_sum=last_sample=0
    last_tick=-1
    for index,r in enumerate(records):
        require(set(r)=={"record","tick","sample","current","irq_sp","heap","events","tasks",
                "task_sum","irq_depth","interrupted_sp","ps"} and r["record"]==index and
                last_tick<r["tick"] and last_sample<r["sample"]<=s["samples"],"Snapshot progression differs")
        current=[p for p in members if p["record"]==index]
        require(len(current)==r["tasks"]==len(live) and [p["task"] for p in current]==list(range(len(live))) and
                {p["tcb"] for p in current}==set(boundaries) and r["current"] in boundaries,"Snapshot tasks differ")
        require(0<r["events"]<len(epochs) and epochs[r["events"]]==r["heap"] and r["ps"]&15 and
                r["irq_sp"]%16==0 and irq_address<=r["irq_sp"]<irq_address+irq_size and
                r["irq_depth"]==irq_address+irq_size-r["irq_sp"],"Snapshot native heap/IRQ differs")
        values=[]
        for p in current:
            require(set(p)=={"record","task","tcb","sp"},"Unexpected saved-SP fields")
            low,top=boundaries[p["tcb"]]
            require(p["tcb"] in creation and creation[p["tcb"]]<=r["events"] and
                    low<=p["sp"]<top and p["sp"]%16==top%16==0,"Snapshot native stack outside ownership")
            if p["tcb"]==r["current"]:
                require(r["interrupted_sp"]==p["sp"]+192<=top,"Unsolicited frame reservation differs")
            values.append({"tcb":p["tcb"],"stack_low":low,"stack_aligned_top":top,"saved_sp":p["sp"],
                "reserved_span_bytes":top-p["sp"]})
        total=sum(p["reserved_span_bytes"] for p in values)
        require(total==r["task_sum"] and total+r["irq_depth"]>last_sum,"Simultaneous record-high sum differs")
        last_sum,last_sample,last_tick=total+r["irq_depth"],r["sample"],r["tick"]
        rebuilt.append({"tick":r["tick"],"sample":r["sample"],"heap_occupied_bytes":r["heap"],
            "heap_event_count":r["events"],"current_tcb":r["current"],"interrupted_task_sp":r["interrupted_sp"],
            "irq_sp":r["irq_sp"],"irq_reserved_span_bytes":r["irq_depth"],"tasks":values,
            "simultaneous_stack_reserved_span_bytes":last_sum})
    require(last_sum==s["maximum"] and all(0<=r["record"]<s["records"] for r in members),"Snapshot maximum differs")
    return {"samples":s["samples"],"record_high_snapshots":rebuilt,"non_irq_calls_skipped":s["skipped"],
        "maximum_sampled_stack_reserved_span_bytes":last_sum,"new_ram_bytes_to_add":0,
        "exact_peak_established":False,"whole_live_ram_peak_bytes":None,
        "scope":"100-Hz native tick snapshots of existing stack reservations, observer included; not exact live or whole-RAM peak"}


def peak_contexts(lines, irq_address, irq_size):
    """Independent field/prefix replay; no primary RAM-oracle imports."""
    fields = []
    events = []
    for line in lines:
        if not line.startswith(("FREERTOS_PEAK ", "TM_RAM event=")):
            continue
        pairs = [part.split("=", 1) for part in line.split()[1:]]
        require(all(len(p) == 2 and p[1].lstrip("-").isdigit() for p in pairs)
                and len({p[0] for p in pairs}) == len(pairs), "Invalid peak/prefix fields")
        value = {k: int(v) for k, v in pairs}
        (events if line.startswith("TM_RAM ") else fields).append(value)
    headers = [r for r in fields if "heap" in r]
    members = [r for r in fields if "task" in r]
    require(len(fields) == len(headers) + len(members) and headers
            and {r["phase"] for r in headers} >= {0, 2}
            and len({r["phase"] for r in headers}) == len(headers), "Peak phase inventory differs")
    prefixes, owners, pending, total = [(0, {})], {}, None, 0
    for index, event in enumerate(events):
        require(set(event) == {"event", "kind", "pool", "pointer", "delta"}
                and event["event"] == index and 0 <= event["kind"] <= 8, "Peak event order differs")
        kind, address, delta = (event[k] for k in ("kind", "pointer", "delta"))
        if kind <= 4:
            total += delta
            if kind == 2:
                owners = {tcb: pair for tcb, pair in owners.items() if address not in (tcb, pair[0])}
        elif kind == 5:
            require(pending is None, "Peak TCB/stack ownership is incomplete")
            pending = address
        elif kind == 6:
            require(pending is not None, "Peak stack lacks a native TCB")
            owners[pending] = (address, delta)
            pending = None
        prefixes.append((total, owners.copy()))
    output = []
    for r in sorted(headers, key=lambda v: v["phase"]):
        require(set(r) == {"phase", "heap", "events", "sp", "current", "ps", "nesting", "tasks"}
                and r["phase"] in range(3) and 0 < r["events"] < len(prefixes)
                and r["ps"] & 15 and r["nesting"] in (0, 1), "Peak header fields differ")
        used, owners = prefixes[r["events"]]
        group = [v for v in members if v["phase"] == r["phase"]]
        require(used == r["heap"] and len(group) == r["tasks"] == len(owners)
                and [v["task"] for v in group] == list(range(len(group)))
                and {v["tcb"] for v in group} == set(owners), "Peak heap epoch/task set differs")
        if r["phase"] == 0:
            require(r["current"] == r["nesting"] == 0 and 0x3ffe0440 <= r["sp"] <= 0x3ffe3f20,
                    "Peak startup stack differs")
            context = "application startup stack"
        elif r["nesting"]:
            require(r["current"] in owners and irq_address <= r["sp"] < irq_address + irq_size,
                    "Peak interrupt stack differs")
            context = "native IRQ stack"
        else:
            require(r["current"] in owners, "Peak current task lacks ownership")
            low, span = owners[r["current"]]
            require(low <= r["sp"] < low + span, "Peak running SP outside native stack")
            context = "native task stack"
        stacks = []
        for member in group:
            require(set(member) == {"phase", "task", "tcb", "saved"}, "Peak task field inventory differs")
            low, span = owners[member["tcb"]]
            top = low + span - 1
            require(low <= member["saved"] < top and member["saved"] % 16 == top % 16 == 0,
                    "Peak saved SP outside native stack")
            effective = r["sp"] if member["tcb"] == r["current"] and not r["nesting"] else member["saved"]
            stacks.append({"tcb": member["tcb"], "stack": low, "span": span, "saved_sp": member["saved"],
                           "observed_sp": effective, "reserved_span_below_top_bytes": top - effective})
        output.append({"phase": r["phase"], "native_heap_occupied_bytes": used,
                       "allocation_event_cursor": r["events"], "observed_sp": r["sp"],
                       "current_tcb": r["current"], "ps": r["ps"], "interrupt_nesting": r["nesting"],
                       "current_context": context, "task_contexts": stacks})
    require(max(r["native_heap_occupied_bytes"] for r in output) == max(v[0] for v in prefixes)
            and all(v["phase"] in {r["phase"] for r in headers} for v in members),
            "Peak witness is missing/has orphan tasks")
    return output


def replay(folder,prepared):
    data=campaign(folder)
    plan=json.loads((folder/"plan.json").read_text())
    manifest=json.loads((prepared/"build.json").read_text())
    require(data["mode"]=="tm-message-lifetimes" and data["board_mac"]=="34:98:7a:a2:85:28" and
        data["independent_resets"]==plan["resets"]==5 and plan["seconds"]==100 and not plan["reused_first_reset"] and
        not plan["old_results_replaced"] and manifest.get("message_ordinary_irq_stack_coverage") is True and
        plan["build_manifest_sha256"]==digest(prepared/"build.json"),"Frozen new-IRQ message cohort differs")
    for name,value in manifest["files"].items():
        path=(prepared/name).resolve()
        require(path.is_relative_to(prepared.resolve()) and digest(path)==value,"Prepared source/image changed")
    images=("application.elf","application.bin","bootloader.bin","partitions.bin")
    require(all(digest(folder/"build"/n)==digest(prepared/n) for n in images),"Collected image differs")
    symbols={m[4]:(int(m[1],16),int(m[2],16)) for s in (prepared/"symbols.txt").read_text().splitlines()
             if (m:=re.fullmatch(r"([0-9a-f]+) ([0-9a-f]+) (\w) (\S+)",s))}
    address,size=symbols["port_IntStack"]
    require(size==1536,"Original IRQ reservation differs")
    capacity = manifest.get("trace_capacity", 1024)
    require(capacity == 1024 or capacity == 128 and manifest.get("compact_observer") is True,
            "Unreviewed native event-buffer capacity")
    def checked_rows(directory,index):
        rows=raw_rows(directory/("reset%d.jsonl"%index))
        lines=[r["line"] for r in rows]
        require(sum(s.startswith("rst:0x") for s in lines)==1 and lines.count(
            f"TM_RAM BEGIN clock_mhz=240 cores=1 tick_hz=100 capacity={capacity}")==1 and not re.search(
            r"panic|abort|Guru Meditation|Exception|ASSERT|FATAL|invalid-command|watchdog", "\n".join(lines),re.I),
            "Original boot/profile/runtime status differs")
        log=(directory/("verify-run%d.log"%index)).read_text()
        require(set(re.findall(r"^MAC: ([0-9a-f:]+)$",log,re.M))=={data["board_mac"]} and
                log.count("verify OK (digest matched)")==3,"Per-reset installed-image verification missing")
        return rows,lines
    validation,lines=checked_rows(folder/"validation",1)
    check=re.findall(r"FREERTOS_RAM validation=PASS base=(\d+) final=(\d+) required_overlap_peak=(\d+) observed_peak=(\d+)","\n".join(lines))
    require(len(check)==1 and int(check[0][0])==int(check[0][1])<int(check[0][2])<=int(check[0][3]) and
            lines[-1]=="FREERTOS_RAM END","Separate allocator self-check failed")
    validated_irq=irq_watermark(lines,address,size)
    startup=manifest.get("application_startup_stack_coverage",False)
    validated_startup=startup_watermark(lines) if startup else None
    validated_peak = peak_contexts(lines, address, size) if manifest.get("allocation_peak_context") else None
    previous=datetime.fromisoformat(validation[-1]["utc"])
    runs=[]
    for index in range(1,6):
        rows,lines=checked_rows(folder/"captures",index)
        start,end=(datetime.fromisoformat(rows[i]["utc"]) for i in (0,-1))
        require(previous<start<end,"Five independent reset captures overlap")
        previous=end
        result=history(lines)
        headings=[(i,int(m[1]),r["elapsed_s"]) for i,r in enumerate(rows) if (m:=re.search(
            r"Thread-Metric Message Processing Test .* Relative Time: (\d+)$",r["line"]))]
        totals=[(i,int(m[1])) for i,s in enumerate(lines) if (m:=re.fullmatch(r"Time Period Total:\s*(\d+)",s))]
        require([h[1] for h in headings]==[30,60,90] and len(totals)==3 and all(
            h[0]<t[0]<(headings[j+1][0] if j<2 else len(lines)) and t[1]>0 for j,(h,t) in enumerate(zip(headings,totals))) and
            all(29.5<b[2]-a[2]<30.5 for a,b in zip(headings,headings[1:])) and
            lines.count("Thread-Metric queue self-check PASS")==1 and
            lines[-1]=="TM_RAM END events=%d invalid=0 original_reports=3"%result["events"],"Original message reports incomplete")
        runs.append({**result,"original_counts":[t[1] for t in totals],"ordinary_irq_stack":irq_watermark(lines,address,size),
            **({"native_tick_stack_snapshots":tick_snapshots(lines,result["live_tasks"],address,size)}
               if manifest.get("native_tick_stack_snapshots") else {}),
            **({"application_startup_stack":startup_watermark(lines,result["live_tasks"])} if startup else {})})
        if manifest.get("allocation_peak_context"):
            runs[-1]["allocation_peak_contexts"] = peak_contexts(lines, address, size)
    return {"replay":"pass","board_mac":data["board_mac"],"independent_resets":5,"runs":runs,
        "validation_irq":validated_irq,"original_flash_restored":True,"full_live_ram_peak_bytes":None,
        **({"validation_application_startup_stack":validated_startup} if startup else {}),
        **({"validation_allocation_peak_contexts":validated_peak} if validated_peak is not None else {}),
        "scope":"separate stdlib raw-byte/allocation/task/IRQ replay; not simultaneous live-RAM or external reproduction"}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path)
    p.add_argument("prepared",type=Path)
    p.add_argument("--output",type=Path)
    args=p.parse_args()
    result=replay(args.directory,args.prepared)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps({"replay":"pass","independent_resets":5,"output":str(args.output)}))
    else:
        print(json.dumps(result,indent=2))
