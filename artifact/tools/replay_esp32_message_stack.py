#!/usr/bin/env python3
"""Separate stdlib byte, allocator and native-watermark replay; no board access."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from replay_esp32_followup import campaign, digest, raw_rows, require


def records(lines, prefix):
    result = []
    for line in lines:
        if not line.startswith(prefix):
            continue
        pairs = [part.split("=", 1) for part in line[len(prefix):].split()]
        require(all(len(p) == 2 for p in pairs) and len({p[0] for p in pairs}) == len(pairs),
                "Duplicate/malformed observed fields")
        result.append({k:int(v) if re.fullmatch(r"\d+",v) else v for k,v in pairs})
    return result


def watermarks(lines, symbols, phases):
    irq = records(lines,"TM_Z_STACK ")
    tasks = records(lines,"TM_Z_STACK_TASK ")
    require([r["phase"] for r in irq] == phases, "IRQ observation phases differ")
    main, idle = (symbols[n][0] for n in ("z_main_thread","z_idle_threads"))
    pool, slots = symbols["stacks"][0], symbols["threads"][0]
    bounds = {main:symbols["z_main_stack"], idle:symbols["z_idle_stacks"],
              slots:(pool,4096), slots+5*96:(pool+5*4096,4096)}
    previous, before = {}, None
    for row in irq:
        start, size = symbols["z_interrupt_stacks"]
        phase = row["phase"]
        current = slots+5*96 if phase == "message-end" else main
        require(set(row) == {"phase","irq","reserved","initial","boot_sp","spare","touched","current","nesting"} and
            (row["irq"],row["reserved"],row["initial"],row["current"],row["nesting"]) == (start,size,size,current,0) and
            row["boot_sp"] % 16 == 0 and not start <= row["boot_sp"] < start+size and
            0 <= row["spare"] <= size and row["touched"] == size-row["spare"], "Native IRQ context/arithmetic differs")
        if before:
            require(row["boot_sp"] == before["boot_sp"] and row["touched"] >= before["touched"],
                    "IRQ touch watermark or startup observation regressed")
        before = row
        group = [r for r in tasks if r["phase"] == phase]
        expected = set(bounds) if phase == "message-end" else {main,idle}
        require(len(group) == len(expected) and {r["tcb"] for r in group} == expected,
                "Retained task inventory differs")
        for r in group:
            require(set(r) == {"phase","tcb","start","span","spare","touched","current"} and
                (r["start"],r["span"]) == bounds[r["tcb"]] and r["current"] == int(r["tcb"] == current) and
                0 <= r["spare"] <= r["span"] and r["touched"] == r["span"]-r["spare"] and
                r["touched"] >= previous.get(r["tcb"],0), "Native task watermark/bounds/current differ")
            previous[r["tcb"]] = r["touched"]
    require(len(tasks) == sum(4 if p == "message-end" else 2 for p in phases), "Extra native stack observations")
    return {"irq":irq,"tasks":tasks}


def heap_history(lines, symbols):
    events = records([s for s in lines if s.startswith("TM_Z_RAM event=")],"TM_Z_RAM ")
    trace = records(lines,"TM_Z_RAM trace ")
    require(trace == [{"events":len(events),"overflow":0}] and 0 < len(events) < 128, "Dropped/extra heap events")
    live, maximum, pending, pool = {}, 0, None, None
    for index, row in enumerate(events):
        require(set(row) == {"event","heap","pointer","kind","bytes","allocated","peak"} and
                row["event"] == index, "Heap event shape/order differs")
        kind, pointer, size = (row[n] for n in ("kind","pointer","bytes"))
        if index == 0:
            require(kind == 0 and (pointer,size) == symbols["kheap__system_heap"] and
                    row["allocated"] == row["peak"] == 0, "Native heap initialization differs")
            pool = row["heap"]
            continue
        start, capacity = symbols["kheap__system_heap"]
        require(row["heap"] == pool and size > 0 and start <= pointer < pointer+size <= start+capacity,
                "Heap transition outside native pool")
        if pending:
            require((kind,pointer,size) == (2,*pending), "Native in-place realloc pair differs")
            pending = None
        elif kind == 1:
            if pointer in live:
                pending = (pointer,live[pointer])
            live[pointer] = size
        else:
            require(kind == 2 and live.pop(pointer,None) == size, "Unmatched native release")
        spans = sorted((p,p+n) for p,n in live.items())
        require(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])), "Native live blocks overlap")
        total = sum(live.values())
        maximum = max(maximum,total)
        require((row["allocated"],row["peak"]) == (total,maximum), "Original heap accounting differs")
    require(pending is None, "Truncated native realloc pair")
    final = records(lines,"ZEPHYR_RAM heap ")[-1]
    require((final["allocated"],final["peak"],final["valid"]) == (sum(live.values()),maximum,1),
            "Native statistics do not match replay")
    return {"events":len(events),"native_heap_peak_bytes":maximum,"native_heap_final_bytes":sum(live.values())}


def tick_snapshots(lines, symbols):
    headers=records([s for s in lines if s.startswith('TM_Z_LIVE samples=')],'TM_Z_LIVE ')
    snapshots=records([s for s in lines if s.startswith('TM_Z_LIVE record=') and ' task=' not in s],'TM_Z_LIVE ')
    tasks=records([s for s in lines if s.startswith('TM_Z_LIVE record=') and ' task=' in s],'TM_Z_LIVE ')
    require(len(headers)==1 and sum(s.startswith('TM_Z_LIVE ') for s in lines)==1+len(snapshots)+len(tasks),
        'Incomplete native IRQ-return observations')
    h=headers[0]
    require(set(h)=={'samples','ticks','records','maximum','pending','bsa_bytes'} and
        h['pending']==0 and h['bsa_bytes']==68 and 8000<=h['samples']<=11000 and
        h['ticks']==h['samples'] and 0<len(snapshots)==h['records']<=128,'Periodic sampling window differs')
    bounds={symbols['z_main_thread'][0]:symbols['z_main_stack'],symbols['z_idle_threads'][0]:symbols['z_idle_stacks']}
    bounds.update({symbols['threads'][0]+i*96:(symbols['stacks'][0]+i*4096,4096) for i in (0,5)})
    events=records([s for s in lines if s.startswith('TM_Z_RAM event=')],'TM_Z_RAM ')
    start,size=symbols['z_interrupt_stacks']
    out=[]
    for i,s in enumerate(snapshots):
        require(set(s)=={'record','sample','tick','current','irq_sp','heap','events','total'} and
            s['record']==i and 0<s['sample']<=h['samples'] and s['tick']==s['sample'] and
            s['current'] in bounds and start<=s['irq_sp']<start+size and s['irq_sp']%16==0 and
            0<s['events']<=len(events) and events[s['events']-1]['allocated']==s['heap'],
            'Native IRQ pointer/heap prefix differs')
        require(not out or s['sample']>out[-1]['sample'],'Native sample order differs')
        group=[t for t in tasks if t['record']==i]
        require(len(group)==4 and [t['task'] for t in group]==list(range(4)) and
            {t['tcb'] for t in group}==set(bounds),'Missing/repeated native task')
        detail=[]
        total=start+size-s['irq_sp']
        for t in group:
            low,n=bounds[t['tcb']]
            require(set(t)=={'record','task','tcb','handle','bsa'} and
                low<=t['handle'] and t['handle']+4<=t['bsa'] and t['bsa']+68<=low+n and
                t['handle']%4==t['bsa']%4==0,'Native restore handle/base frame differs')
            depth=low+n-t['handle'];total+=depth
            detail.append({'tcb':t['tcb'],'stack_low':low,'stack_top':low+n,'handle':t['handle'],
                'bsa':t['bsa'],'restored_sp':t['bsa']+68,'reserved_span_bytes':depth})
        require(total==s['total'] and (not out or total>out[-1]['simultaneous_stack_reserved_span_bytes']),
            'Simultaneous reservation arithmetic differs')
        out.append({'sample':s['sample'],'tick':s['tick'],'current_tcb':s['current'],'irq_sp':s['irq_sp'],
            'irq_reserved_span_bytes':start+size-s['irq_sp'],'heap_occupied_bytes':s['heap'],
            'heap_event_count':s['events'],'tasks':detail,'simultaneous_stack_reserved_span_bytes':total})
    require(out[-1]['simultaneous_stack_reserved_span_bytes']==h['maximum'] and
        all(t['record'] in range(len(out)) for t in tasks),'Native maximum binding differs')
    return {'samples':h['samples'],'record_high_snapshots':out,
        'maximum_sampled_stack_reserved_span_bytes':h['maximum'],'new_ram_bytes_to_add':0,
        'exact_peak_established':False,'whole_live_ram_peak_bytes':None,
        'scope':'100-Hz native IRQ-return context reservations, observer included; not exact live or whole-RAM peak'}


def startup_watermark(lines, symbols):
    rows = records(lines, "ZEPHYR_BOOT_STACK ")
    require(len(rows) == 1, "Missing/duplicate inherited startup observation")
    r = rows[0]
    require(set(r) == {"low","entry_sp","paint_end","painted","verified","main_sp","spare","touched","guard","switches"},
        "Inherited startup field inventory differs")
    low, entry, end, capacity = (r[k] for k in ("low","entry_sp","paint_end","painted"))
    main, size = symbols["z_main_stack"]
    position = next(i for i, s in enumerate(lines) if s.startswith("ZEPHYR_BOOT_STACK "))
    require(low == symbols["_stack_sentry"][0] == 0x3ffe1320 and
        low + 64 < entry <= symbols["__stack"][0] == 0x3ffe3f20 and entry % 16 == 0 and
        end == entry - 64 and capacity == r["verified"] == end - low and capacity > 0 and
        r["guard"] == 64 and 0 <= r["spare"] <= capacity and
        r["spare"] + r["touched"] == capacity and r["spare"] % 4 == r["touched"] % 4 == 0 and
        main <= r["main_sp"] < main + size and r["main_sp"] % 16 == 0 and r["switches"] == 1 and
        position + 1 < len(lines) and lines[position + 1].startswith("ZEPHYR_RAM BEGIN "),
        "Inherited startup window, arithmetic, main context or phase differs")
    return {"application_entry_sp":entry,"painted_start":low,"painted_end":end,
        "initial_painted_and_verified_bytes":capacity,"first_main_task_sp":r["main_sp"],
        "spare_pattern_bytes":r["spare"],"touched_watermark_bytes":r["touched"],
        "unpainted_guard_bytes":64,"resolution_bytes":4,"observed_before_post_kernel_initialization":True,
        "scope":"inherited ROM-stack window from application entry to first native main context; no before-entry ROM, untouched frames or simultaneous-live peak",
        "full_live_ram_peak_bytes":None}


def replay(folder, prepared):
    envelope = campaign(folder)
    require(envelope["mode"] == "zephyr-message-lifetimes" and envelope["independent_resets"] == 5 and
            envelope["board_mac"] == "34:98:7a:a2:85:28", "Wrong/incomplete physical cohort")
    plan = json.loads((folder/"plan.json").read_text())
    manifest = json.loads((prepared/"build.json").read_text())
    require(manifest.get("message_native_stack_coverage") is True and plan["resets"] == 5 and
            plan["seconds"] == 100 and not plan["old_results_replaced"] and
            plan["build_manifest_sha256"] == digest(prepared/"build.json"), "Frozen build/protocol differs")
    for name, value in manifest["files"].items():
        path = (prepared/name).resolve()
        require(path.is_relative_to(prepared.resolve()) and digest(path) == value, "Changed prepared source/image")
    for name in ("application.elf","application.bin"):
        require(digest(folder/"build"/name) == digest(prepared/name), "Collected firmware differs")
    symbols = {m[4]:(int(m[1],16),int(m[2],16)) for s in (prepared/"symbols.txt").read_text().splitlines()
               if (m:=re.fullmatch(r"([0-9a-f]+) ([0-9a-f]+) (\w) (\S+)",s))}
    if manifest.get("application_startup_stack_coverage"):
        # Absolute linker symbols have no size in GNU nm output.
        symbols.update({m[3]:(int(m[1],16),0) for s in (prepared/"symbols.txt").read_text().splitlines()
            if (m:=re.fullmatch(r"([0-9a-f]+) ([Aa]) (\S+)",s))})
    def read(directory,index,validation=False):
        rows = raw_rows(directory/("reset%d.jsonl"%index))
        lines = [r["line"] for r in rows]
        require(sum(s.startswith("rst:0x") for s in lines) == 1 and not re.search(
                r"panic|fatal|assert|Exception|error:|invalid=[1-9]", "\n".join(lines),re.I), "Boot/error check failed")
        require(lines.count("ZEPHYR_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100 window=heap-init-through-third-message-report") == 1,
                "Runtime condition witness differs")
        proof = (directory/("verify-run%d.log"%index)).read_text()
        size = (prepared/"application.bin").stat().st_size
        require(set(re.findall(r"^MAC: ([0-9a-f:]+)$",proof,re.M)) == {envelope["board_mac"]} and
                "(%d) bytes @ 0x00001000"%size in proof and "verify OK (digest matched)" in proof,
                "Per-reset installed image verification missing")
        value = {**heap_history(lines,symbols), **watermarks(lines,symbols,
            ["validation-end"] if validation else ["application-entry","message-end"])}
        if manifest.get("application_startup_stack_coverage"):
            value["application_startup_stack"] = startup_watermark(lines, symbols)
        if validation:
            passes = records([s for s in lines if s.startswith("ZEPHYR_RAM validation=")],"ZEPHYR_RAM ")
            require(len(passes) == 1 and passes[0]["validation"] == "PASS" and passes[0]["invalid"] == 0 and
                passes[0]["base"] == passes[0]["final"] == value["native_heap_final_bytes"] and
                passes[0]["base"] < passes[0]["required_overlap_peak"] <= passes[0]["observed_peak"] == value["native_heap_peak_bytes"] and
                lines[-1] == "ZEPHYR_RAM END", "Separate allocator validation failed")
        else:
            if manifest.get('native_tick_stack_snapshots'):
                value['native_tick_stack_snapshots']=tick_snapshots(lines,symbols)
            counts = [(i,int(m[1])) for i,s in enumerate(lines) if (m:=re.fullmatch(r"Time Period Total:\s*(\d+)",s))]
            heads = [(i,int(m[1]),r["elapsed_s"]) for i,r in enumerate(rows) if (m:=re.fullmatch(
                r"\*+ Thread-Metric Message Processing Test \*+ Relative Time: (\d+)",r["line"]))]
            require([h[1] for h in heads] == [30,60,90] and len(counts) == 3 and all(
                h[0] < c[0] < (heads[j+1][0] if j < 2 else len(lines)) and c[1] > 0
                for j,(h,c) in enumerate(zip(heads,counts))) and all(29.5 < b[2]-a[2] < 30.5 for a,b in zip(heads,heads[1:])) and
                lines.count("Thread-Metric queue self-check PASS") == 1 and
                lines[-1] == "TM_Z_RAM END invalid=0 original_reports=3", "Original message test incomplete")
            value["original_counts"] = [c[1] for c in counts]
        return value, (datetime.fromisoformat(rows[0]["utc"]),datetime.fromisoformat(rows[-1]["utc"]))
    validation, previous = read(folder/"validation",1,True)
    runs = []
    for i in range(1,6):
        value, interval = read(folder/"captures",i)
        require(previous[1] < interval[0] < interval[1], "Independent reset chronology overlaps")
        previous = interval
        runs.append(value)
    return {"replay":"pass","board_mac":envelope["board_mac"],"independent_resets":5,
        "validation":validation,"runs":runs,"original_flash_restored":True,"whole_live_ram_peak_bytes":None,
        "scope":"separate stdlib byte/count/native historical touch replay; not simultaneous live-RAM or external reproduction"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    parser.add_argument("prepared",type=Path)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    value = replay(args.directory,args.prepared)
    if args.output:
        args.output.write_text(json.dumps(value,indent=2)+"\n")
        print(json.dumps({"replay":value["replay"],"independent_resets":value["independent_resets"],"output":str(args.output)}))
    else:
        print(json.dumps(value,indent=2))
