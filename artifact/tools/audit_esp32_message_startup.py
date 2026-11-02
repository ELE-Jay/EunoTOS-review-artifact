#!/usr/bin/env python3
"""Bind existing message traces to compiled startup and physical-memory scopes."""
import argparse
import importlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_hartstone_ram_riot import symbol_bytes
from audit_esp32_message_ram_cohort import audit as message_cohort
from audit_esp32_ram_scope import message_startup_scope
from audit_esp32_resources import physical_intervals,union_bytes
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha
from run_esp32_tm_ram_lifetimes import EVENT,POOL

ROOT=Path(__file__).resolve().parents[1]
REPORTS=ROOT/"artifacts/reports"


def structure(elf,name):
    layouts=set()
    for cu in elf.get_dwarf_info().iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag not in ("DW_TAG_typedef","DW_TAG_structure_type") or \
                    die.attributes.get("DW_AT_name") is None or die.attributes["DW_AT_name"].value!=name.encode():
                continue
            while die.tag in ("DW_TAG_typedef","DW_TAG_const_type","DW_TAG_volatile_type"):
                die=die.get_DIE_from_attribute("DW_AT_type")
            if "DW_AT_byte_size" not in die.attributes:
                continue
            members=[]
            for member in die.iter_children():
                if member.tag!="DW_TAG_member": continue
                t=member.get_DIE_from_attribute("DW_AT_type")
                while "DW_AT_byte_size" not in t.attributes:
                    t=t.get_DIE_from_attribute("DW_AT_type")
                offset=member.attributes["DW_AT_data_member_location"].value
                name_attr=member.attributes.get("DW_AT_name")
                members.append((name_attr.value.decode() if name_attr else "@"+str(offset),
                    offset,t.attributes["DW_AT_byte_size"].value))
            layouts.add((die.attributes["DW_AT_byte_size"].value,tuple(members)))
    if len(layouts)!=1:
        raise ValueError("Missing or inconsistent compiled structure ABI: "+name)
    size,members=layouts.pop()
    return size,{name:(offset,width) for name,offset,width in members}


def available(regions,reservations):
    """Apply native address exclusions and adjacent type/startup coalescing."""
    result=[]
    for region in regions:
        spans=[(region["start"],region["start"]+region["size"])]
        for lo,hi in reservations:
            if lo>hi: raise ValueError("Reversed native reservation")
            if lo==hi: continue
            spans=[part for a,b in spans for part in ((a,min(b,lo)),(max(a,hi),b)) if part[0]<part[1]]
        for lo,hi in spans:
            row={"start":lo,"size":hi-lo,"type":region["type"],"startup_stack":region["startup_stack"]}
            if result and result[-1]["start"]+result[-1]["size"]==lo and all(
                    result[-1][k]==row[k] for k in ("type","startup_stack")):
                result[-1]["size"]+=row["size"]
            else:
                result.append(row)
    spans=sorted((r["start"],r["start"]+r["size"]) for r in result)
    if any(a[1]>b[0] for a,b in zip(spans,spans[1:])):
        raise ValueError("Native available regions overlap")
    return result


def entry_frame(elf,symbols,name,expected):
    symbol=symbols.get_symbol_by_name(name)[0]
    raw=symbol_bytes(elf,symbols,name,symbol["st_size"])
    encoded=(expected//8<<12)|0x136
    if raw[:3]!=encoded.to_bytes(3,"little"):
        raise ValueError("Compiled inherited-stack entry frame differs: "+name)
    return {"symbol":name,"address":symbol["st_value"],"reserved_frame_bytes":expected,
            "initial_instruction_hex":raw[:3].hex(),"inherited_sp_measured":False}


def freertos(cell, *, entry_symbol="call_start_cpu0"):
    source=ROOT/cell["build"]
    capture=ROOT/cell["evidence"]
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        size,fields=structure(elf,"soc_memory_region_t")
        if (size,fields)!=(20,{"start":(0,4),"size":(4,4),"type":(8,4),
                "iram_address":(12,4),"startup_stack":(16,1)}):
            raise ValueError("Unexpected native memory descriptor ABI")
        count=int.from_bytes(symbol_bytes(elf,symbols,"soc_memory_region_count",4),"little")
        raw=symbol_bytes(elf,symbols,"soc_memory_regions",count*size)
        regions=[{k:int.from_bytes(raw[p+off:p+off+n],"little") for k,(off,n) in fields.items()}
                 for p in range(0,len(raw),size)]
        if count!=44 or any(r["startup_stack"] not in (0,1) or r["size"]<=0 for r in regions):
            raise ValueError("Compiled native memory-provider table differs")
        if structure(elf,"soc_reserved_region_t")!=(8,{"start":(0,4),"end":(4,4)}):
            raise ValueError("Unexpected native reservation ABI")
        reserved=[]
        for s in symbols.iter_symbols():
            if s.name.startswith("reserved_region_"):
                value=symbol_bytes(elf,symbols,s.name,8)
                reserved.append({"name":s.name,"start":int.from_bytes(value[:4],"little"),
                    "end":int.from_bytes(value[4:],"little")})
        a=symbols.get_symbol_by_name("soc_reserved_memory_region_start")[0]["st_value"]
        b=symbols.get_symbol_by_name("soc_reserved_memory_region_end")[0]["st_value"]
        if len(reserved)!=8 or b-a!=8*len(reserved) or sorted(
                s["st_value"] for s in symbols.iter_symbols() if s.name.startswith("reserved_region_"))!=list(range(a,b,8)):
            raise ValueError("Incomplete linked native reservation table")
        pools=available(regions,[(r["start"],r["end"]) for r in reserved])
        entry=entry_frame(elf,symbols,"call_start_cpu0",64)
        if elf["e_entry"]!=symbols.get_symbol_by_name(entry_symbol)[0]["st_value"]:
            raise ValueError("FreeRTOS installed boot entry differs")
        irq=symbols.get_symbol_by_name("port_IntStack")[0]
        if irq["st_size"]!=1536:
            raise ValueError("Ordinary interrupt stack capacity differs")
        irq_record={"start":irq["st_value"],"reserved_bytes":irq["st_size"],"already_in_static_sram":True}
    expected={(r["start"],r["size"]) for r in pools}
    late=[r for r in pools if r["startup_stack"]]
    if len(expected)!=6 or len(late)!=1:
        raise ValueError("Native startup handoff/heap count differs")
    traces=[]
    for i in range(1,6):
        lines=[r["line"] for r in read_raw_capture(capture/"captures",i)]
        actual=[tuple(map(int,m.groups())) for s in lines if (m:=POOL.fullmatch(s))]
        events=[tuple(map(int,m.groups())) for s in lines if (m:=EVENT.fullmatch(s))]
        if {(r[0],r[1]) for r in actual}!=expected:
            raise ValueError("Observed pools do not cover compiled providers minus reservations")
        index=next(j for j,r in enumerate(actual) if r[0]==late[0]["start"])
        registration=[e for e in events if e[1]==0 and e[2]==index]
        if len(registration)!=1 or registration[0][0]<=max(e[0] for e in events if e[1]==5 and e[2]==2):
            raise ValueError("Deferred startup region registered before original main-task creation")
        traces.append({"reset":i,"deferred_registration_event":registration[0][0],"observed_pool_count":len(actual),
                       "raw_sha256":sha(capture/"captures"/("reset%d.raw"%i))})
    reserved_by_name={r["name"]:r for r in reserved}
    outside=[reserved_by_name[n] for n in ("reserved_region_cpu0_cache","reserved_region_rom_data","reserved_region_rom_pro_data")]
    physical=[v for r in pools for v in physical_intervals(r["start"],r["size"])]
    if union_bytes(physical)!=sum(r["size"] for r in pools):
        raise ValueError("Aliased allocator regions counted twice")
    handoff_edges = ([("main_task","__wrap_heap_caps_enable_nonos_stack_heaps"),
        ("__wrap_heap_caps_enable_nonos_stack_heaps","bench_startup_heap_handoff"),
        ("bench_startup_heap_handoff","heap_caps_enable_nonos_stack_heaps")]
        if json.loads((source/"build.json").read_text()).get("startup_heap_handoff") else
        [("main_task","heap_caps_enable_nonos_stack_heaps")])
    return {"os":"FreeRTOS","build":cell["build"],"evidence":cell["evidence"],"entry":entry,
        "descriptor_abi_bytes":size,"native_descriptor_count":count,"native_reservations":reserved,
        "native_available_pools":pools,"heap_capacity_bytes_not_occupied_peak":sum(r["size"] for r in pools),
        "startup_stack_handoff_region":late[0],"ordinary_irq_stack":irq_record,
        "outside_software_occupancy":outside,"five_reset_handoff_replay":traces,
        "machine_calls":calls(source,handoff_edges+[
            ("heap_caps_enable_nonos_stack_heaps","register_heap"),("register_heap","multi_heap_register"),
            ("multi_heap_register_impl","bench_heap_register")]),
        "remaining":["actual inherited/startup stack use before its region becomes heap",
                     "simultaneous live-stack use and ROM/cache runtime ownership"],
        "elf_sha256":cell["elf_sha256"],"campaign_sha256":cell["campaign_sha256"]}


def zephyr(cell):
    source=ROOT/cell["build"]
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        entries=[entry_frame(elf,symbols,n,f) for n,f in (("__start",32),("__esp_platform_start",48),("z_cstart",48))]
        if elf["e_entry"]!=entries[0]["address"]:
            raise ValueError("Zephyr loader entry differs")
        size,fields=structure(elf,"init_entry")
        if size!=8 or fields.get("init_fn")!=(0,4):
            raise ValueError("Unexpected compiled Zephyr init table ABI")
        init=symbols.get_symbol_by_name("__init_statics_init_pre")[0]
        begin,end=[symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("__init_PRE_KERNEL_1_start","__init_PRE_KERNEL_2_start")]
        value=symbol_bytes(elf,symbols,init.name,size)
        fn=symbols.get_symbol_by_name("statics_init")[0]["st_value"]
        if not begin<=init["st_value"]<end or int.from_bytes(value[:4],"little")!=fn:
            raise ValueError("Native static heap initialization not bound to PRE_KERNEL_1 table")
        stacks=[]
        for name,capacity in (("z_interrupt_stacks",2048),("z_main_stack",4096),("z_idle_stacks",1024)):
            symbol=symbols.get_symbol_by_name(name)[0]
            if symbol["st_size"]!=capacity:
                raise ValueError("Static stack reservation differs")
            stacks.append({"name":name,"start":symbol["st_value"],"reserved_bytes":capacity,"already_in_static_sram":True})
        heap=symbols.get_symbol_by_name("kheap__system_heap")[0]
    return {"os":"Zephyr","build":cell["build"],"evidence":cell["evidence"],"entries":entries,
        "heap_initialization":{"level":"PRE_KERNEL_1","entry_address":init["st_value"],"function_address":fn},
        "kernel_heap":{"start":heap["st_value"],"reserved_bytes":heap["st_size"],"already_in_static_sram":True},
        "static_stacks":stacks,"elf_sha256":cell["elf_sha256"],"campaign_sha256":cell["campaign_sha256"],
        "machine_calls":calls(source,[("__start","bootloader_init"),("__start","__esp_platform_start"),
            ("__esp_platform_start","z_cstart"),("statics_init","k_heap_init"),
            ("k_heap_init","__wrap_sys_heap_init")],require_iram=False),
        "remaining":["loader and inherited startup stack before the native heap/threads are ready",
                     "simultaneous live-stack use and unmanaged ROM/cache ownership"],
        "generic_irq_stack_comment_is_not_a_measured_boot_stack":True}


def audit():
    cohort=message_cohort()
    cells={c["os"]:c for c in cohort["cells"]}
    return {"audit":"pass","board_mac":cohort["board_mac"],"clock_mhz":240,"cores":1,"tick_hz":100,
        "workload":cohort["workload"],"cells":[freertos(cells["FreeRTOS"]),zephyr(cells["Zephyr"]),
            {"os":"NuttX",**message_startup_scope()}],"reused_workload_resets":15,
        "new_board_resets":0,"new_metric_created":False,"old_data_modified":False,
        "scope":"compiled provider/startup boundary and retained raw-trace audit, not new peak-RAM measurement",
        "whole_ram_status":"正在测，未加入评分","whole_live_ram_peak_bytes":None}


def current_windows():
    """Reconcile new startup windows without replacing the historical boundary audit."""
    from run_esp32_message_observer_pairs import audit as pair_audit
    from replay_esp32_followup import replay
    specs=(
        ("FreeRTOS","run_esp32_tm_ram_lifetimes","esp32-freertos-message-startup-v1",
            "application entry through native startup-heap handoff"),
        ("Zephyr","run_esp32_zephyr_message_lifetimes","esp32-zephyr-message-startup-v2",
            "application entry through first native main context before POST_KERNEL"),
        ("NuttX","run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-startup-v5",
            "unused idle stack through native recoloring; inherited entry SP tracked separately"))
    cells=[]
    for system,module,build_name,scope in specs:
        slug=system.lower()
        capture=REPORTS/f"esp32-{slug}-message-startup-b1-v1"
        source=REPORTS/build_name
        pairs=REPORTS/f"esp32-{slug}-startup-observer-pairs-b1-v1"
        result=json.loads(json.dumps(importlib.import_module(module).audit(capture,source)))
        paired=pair_audit(pairs)
        if result!=json.loads((capture/"audit.json").read_text()) or paired!=json.loads((pairs/"audit.json").read_text()):
            raise ValueError("Current startup saved evidence differs: "+system)
        if system=="FreeRTOS":
            separate=importlib.import_module("replay_esp32_freertos_message").replay(capture,source)["runs"]
        elif system=="Zephyr":
            separate=importlib.import_module("replay_esp32_message_stack").replay(capture,source)["runs"]
        else:
            separate=replay(capture,prepared=source)["cells"][0]["runs"]
        windows=[r["application_startup_stack"] for r in result["runs"]]
        if result["independent_resets"]!=5 or len(windows)!=5 or any(
                a!=b["application_startup_stack"] for a,b in zip(windows,separate,strict=True)):
            raise ValueError("Current startup independent byte replay differs: "+system)
        pair=paired["cells"][0]
        if paired["independent_resets"]!=10 or replay(pairs)["cells"]!=[
                {k:pair[k] for k in ("os","pairs","median_ratio","ratio_range")}]:
            raise ValueError("Current startup observer-pair replay differs: "+system)
        cells.append({"os":system,"build":source.relative_to(ROOT).as_posix(),
            "capture":capture.relative_to(ROOT).as_posix(),"scope":scope,
            "workload_resets":5,"paired_resets":10,"startup_windows":windows,
            "static_sram_bytes":result["build"]["static_sram_bytes"],
            "heap_and_task_ownership_audited":True,"original_flash_restored":True,
            "startup_watermark_added_to_allocated_heap_bytes":0,
            "cross_os_startup_ranking_eligible":False,
            "campaign_sha256":sha(capture/"campaign.json"),"pair_campaign_sha256":sha(pairs/"campaign.json"),
            "observer_count_ratio_median":pair["median_ratio"],"observer_count_ratio_range":pair["ratio_range"]})
    return {"audit":"pass","board_mac":"34:98:7a:a2:85:28","cells":cells,
        "new_board_resets":0,"new_metric_created":False,"old_data_modified":False,
        "scope":"current original-message startup-window evidence and version-specific observer controls; not a new RAM score",
        "remaining":["unmarked inherited-stack guards and unwritten reserved frames",
            "before-entry ROM/bootloader and unmanaged ROM/cache runtime ownership",
            "simultaneous live-stack depth and instrumented versus uninstrumented RAM accounting"],
        "whole_ram_status":"正在测，未加入评分","whole_live_ram_peak_bytes":None}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path)
    p.add_argument("--current-windows",action="store_true")
    args=p.parse_args()
    value=current_windows() if args.current_windows else audit()
    if args.output: args.output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps(value,ensure_ascii=False,indent=2))
