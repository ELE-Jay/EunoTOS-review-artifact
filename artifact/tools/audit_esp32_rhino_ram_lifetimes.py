#!/usr/bin/env python3
"""Audit original Rhino PH4, native heap events and retained resource owners."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile

from build_esp32_rhino_ram_lifetimes import NATIVE,ORIGINAL,WRAPS,ADDITIONS,patched
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_alios_tm import check_native_port
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope,independent_captures,verified
from audit_esp32_hartstone_series import audit as series
from audit_esp32_resources import audit_elf_image,static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_zephyr_thread import read_raw_capture
from audit_esp32_zephyr_ram_lifetimes import fields
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
OBSERVER=ROOT/"firmware/bsp/esp32/resource_census/rhino_lifetimes/census.c"
REFERENCE=ROOT/"artifacts/reports/hartstone-alios-native-v4/ph4"
LAYOUT=[136,44,16,8,40,32,8192,36,52,0,0,96,2,3,7,2,1,4]


def native_file(folder,name):
    return folder/"original-k_mm.c" if name=="kernel/rhino/k_mm.c" else folder/"native-source"/name


def provenance(folder):
    known=set()
    for p in (ROOT/"artifacts/reports").rglob("official-native-source.json"):
        for row in json.loads(p.read_text()):
            if {"path","url","sha256"}<=row.keys():
                known.add((row["path"],row["url"],row["sha256"]))
    result=[]
    for name in NATIVE:
        url=UPSTREAM+name; digest=sha(native_file(folder,name))
        if (name,url,digest) not in known:
            with urlopen(url,timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest()!=digest:
                    raise ValueError("Native source differs from pinned official revision: "+name)
        result.append({"path":name,"url":url,"sha256":digest})
    (folder/"official-native-source.json").write_text(json.dumps(result,indent=2)+"\n")


def symbol_values(elf,name,count):
    symbols=elf.get_section_by_name(".symtab").get_symbol_by_name(name)
    if not symbols or len(symbols)!=1 or symbols[0]["st_size"]!=4*count:
        raise ValueError("Actual ELF descriptor differs: "+name)
    s=symbols[0]; section=elf.get_section(s["st_shndx"]); offset=s["st_value"]-section["sh_addr"]
    return list(struct.unpack("<"+str(count)+"I",section.data()[offset:offset+4*count]))


def workload_layout(elf):
    found=[]
    for cu in elf.get_dwarf_info().iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag=="DW_TAG_typedef" and die.attributes.get("DW_AT_name") and die.attributes["DW_AT_name"].value==b"ph_task_t":
                body=die.get_DIE_from_attribute("DW_AT_type")
                members={c.attributes["DW_AT_name"].value.decode():c.attributes["DW_AT_data_member_location"].value
                         for c in body.iter_children() if c.tag=="DW_TAG_member"}
                found.append({"bytes":body.attributes["DW_AT_byte_size"].value,"members":members})
    if len(found)!=1 or set(found[0]["members"])!={"hz","work","met","missed","skipped","late","failures","native","gate","released","timer","stack"}:
        raise ValueError("Original task layout is not witnessed by its actual compiled DWARF")
    return found[0]


def prepare_branch(folder,tool):
    with (folder/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        s=elf.get_section_by_name(".symtab").get_symbol_by_name("application_start")[0]
        end=s["st_value"]+s["st_size"]
    targets=[int(m[1],16) for m in re.finditer(r"\bj\s+([0-9a-f]+) <application_start\+0x[0-9a-f]+>",
                                            (folder/"disassembly.txt").read_text()) if s["st_value"]<=int(m[1],16)<end]
    anchor=max(targets)
    command=[str(tool),"-d","--start-address="+hex(anchor),"--stop-address="+hex(end),str(folder/"application.elf")]
    with (folder/"suspend-branch.txt").open("x") as log:
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    (folder/"suspend-branch.json").write_text(json.dumps({"anchor":anchor,"end":end,"command":command,
        "elf_sha256":sha(folder/"application.elf"),"disassembly_sha256":sha(folder/"suspend-branch.txt")},indent=2)+"\n")


def suspension_branch(folder):
    proof=json.loads((folder/"suspend-branch.json").read_text())
    text=(folder/"suspend-branch.txt").read_text()
    if proof["elf_sha256"]!=sha(folder/"application.elf") or proof["disassembly_sha256"]!=sha(folder/"suspend-branch.txt"):
        raise ValueError("Supplemental original controller branch identity differs")
    with (folder/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        s=elf.get_section_by_name(".symtab").get_symbol_by_name("application_start")[0]
        section=elf.get_section(s["st_shndx"]); data=section.data(); base=section["sh_addr"]
        anchor=proof["anchor"]; end=s["st_value"]+s["st_size"]
        if proof["end"]!=end or not s["st_value"]<=anchor<end:
            raise ValueError("Controller branch escapes actual function")
        branches=re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+j\s+"+format(anchor,"x")+r" <application_start\+0x[0-9a-f]+>$",
                            (folder/"disassembly.txt").read_text(),re.M)
        if not branches: raise ValueError("Supplemental block has no real original control-flow predecessor")
        for pc,encoding in branches:
            pc,value=int(pc,16),int(encoding,16)
            offset=value>>6
            if offset & (1<<17): offset-=1<<18
            if not s["st_value"]<=pc<end or value & 0x3f!=6 or pc+4+offset!=anchor or \
                    data[pc-base:pc-base+3]!=value.to_bytes(3,"little"):
                raise ValueError("Original jump encoding/target differs")
        position=anchor
        instructions=re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{4}(?:[0-9a-f]{2})?)\s+(.+)$",text,re.M)
        if not instructions: raise ValueError("Supplemental native block is empty")
        for pc,encoding,_ in instructions:
            raw=bytes.fromhex(encoding)[::-1]
            if int(pc,16)!=position or data[position-base:position-base+len(raw)]!=raw:
                raise ValueError("Supplemental decode instruction coverage/ELF bytes differ")
            position+=len(raw)
        if position!=end or instructions[-1][2].strip()!="retw.n":
            raise ValueError("Original final native block is incomplete")
    return text


def build(folder,verify_upstream=False):
    manifest=json.loads((folder/"build.json").read_text())
    if manifest["status"]!="build_pass_not_measured" or manifest["board_resets"] or manifest["ranking_eligible"] or manifest["whole_live_ram_peak_bytes"] is not None:
        raise ValueError("Build-only artifact incorrectly qualified")
    if any(not (folder/n).resolve().is_relative_to(folder.resolve()) or sha(folder/n)!=v for n,v in manifest["files"].items()):
        raise ValueError("Source/image manifest differs")
    expected_observer=OBSERVER.read_bytes()
    additions=ADDITIONS
    if manifest.get("native_stack_coverage"):
        from build_esp32_rhino_stack_coverage import extended_source, EXTRA
        extension=OBSERVER.with_name("stack-coverage.inc")
        if manifest["base_observer_sha256"]!=sha(OBSERVER) or (folder/"stack-coverage.inc").read_bytes()!=extension.read_bytes() or \
                (folder/"stack-build-script.py").read_bytes()!=(ROOT/"tools/build_esp32_rhino_stack_coverage.py").read_bytes():
            raise ValueError("Native stack extension recipe differs")
        expected_observer=extended_source(OBSERVER.read_text(),extension.read_text()).encode()
        additions+=EXTRA
    if (folder/"census.c").read_bytes()!=expected_observer or (folder/"build-script.py").read_bytes()!=(ROOT/"tools/build_esp32_rhino_ram_lifetimes.py").read_bytes():
        raise ValueError("Unreviewed observer or recipe")
    for name in (*ORIGINAL,"sdkconfig.h","k_config.h","config"):
        if (folder/name).read_bytes()!=(REFERENCE/name).read_bytes():
            raise ValueError("Original workload/profile changed: "+name)
    if (folder/"aos.mk").read_bytes()!=(REFERENCE/"aos.mk").read_bytes()+additions.encode() or \
            (folder/"native-source/kernel/rhino/k_mm.c").read_bytes()!=patched((folder/"original-k_mm.c").read_bytes()):
        raise ValueError("Native changes exceed explicit allocator observation points/wrappers")
    if sha(folder/"original-k_mm.c")!="eabff1b7db1f9b802a5c4cb656047b7e534283aa1d88c95cef6f47428f120fc3":
        raise ValueError("Pinned allocator input differs")
    if verify_upstream:
        provenance(folder)
    expected=[{"path":n,"url":UPSTREAM+n,"sha256":sha(native_file(folder,n))} for n in NATIVE]
    if json.loads((folder/"official-native-source.json").read_text())!=expected:
        raise ValueError("Official native source coverage differs")
    compatibility=folder/"compiler-compatibility"
    abi=json.loads((compatibility/"abi.json").read_text())
    wrapper="xtensa-esp32-elf-gcc-legacy-newlib.sh"
    if not abi["abi_size_checks"]=="pass" or abi["board_resets"] or abi["ranking_eligible"] or \
            (compatibility/wrapper).read_bytes()!=(ROOT/"firmware/bsp/esp32/alios_board"/wrapper).read_bytes():
        raise ValueError("Legacy SDK compiler/ABI route differs")
    sizes=[]
    for row in abi["probes"]:
        path=compatibility/(row["compiler"]+".o")
        if sha(path)!=row["object_sha256"]:
            raise ValueError("ABI probe object changed")
        with path.open("rb") as stream:
            actual={s.name:s["st_size"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols() if s.name.startswith("abi_")}
        if actual!=row["sizes"]:
            raise ValueError("Compiled public C ABI changed")
        sizes.append(actual)
    if sizes!=[{"abi_time":4,"abi_stat":60,"abi_jmpbuf":68,"abi_file":104,"abi_reent":240}]*2:
        raise ValueError("SDK public C ABI sizes differ")
    for name,value in abi["legacy_header_sha256"].items():
        if sha(compatibility/"legacy-headers"/name)!=value:
            raise ValueError("Pinned legacy SDK header changed")
    for name,value in abi["sdk_library_sha256"].items():
        if sha(folder/Path(name).name)!=value:
            raise ValueError("Pinned SDK library changed")
    mapping=(folder/"application.map").read_text()
    if "platform/mcu/esp32//libc.a" not in mapping or "13.2.0" not in (folder/"compiler.txt").read_text():
        raise ValueError("Actual compiler or SDK library link route differs")
    log=(folder/"build.log").read_text().replace("\\\n"," ")
    compiled=[]
    commands=[shlex.split(l) for l in log.splitlines() if " -c " in l and "xtensa-esp32-elf-gcc" in l]
    for args in commands:
        c_unit=any(a.endswith(".c") for a in args)
        if "iotos-rhino-gcc13-legacy-tools" not in args[0] or c_unit and ( \
                [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)",a)][-1:]!=["-Os"] or "-DBENCH_RAM_LIFETIMES=1" not in args):
            raise ValueError("An actual source unit differs in compiler/observer/optimization")
        compiled.extend(a for a in args if a.endswith((".c",".S")))
    required={n for n in NATIVE if n.endswith(".c")}|{"app/example/hartstone/main.c","app/example/hartstone/workload.c","app/example/hartstone/census.c","platform/arch/xtensa/lx6/port.c"}
    if any(compiled.count(n)!=1 for n in required):
        raise ValueError("Original/native/observer compilation incomplete")
    for args in commands:
        if any(a.startswith("app/example/hartstone/") for a in args) and not {"-DPH_EXPERIMENT=4","-fno-fast-math","-ffp-contract=off"}<=set(args):
            raise ValueError("Original PH4/math compiler flags differ")
    if any("--wrap="+n not in (folder/"link.opts").read_text() for n in WRAPS):
        raise ValueError("Native observer wrappers not all linked")
    port=check_native_port(folder,allow_nested=True,gcc13_noop=True)
    if port.startswith("historical"):
        raise ValueError("Historical unsafe native context port selected")
    audit_elf_image(folder/"application.elf",folder/"application.bin")
    footprint=static_footprint(folder/"application.elf")
    with (folder/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        layout=symbol_values(elf,"bench_h_layout",18)
        if layout!=LAYOUT or symbol_values(elf,"g_region_num",1)!=[2]:
            raise ValueError("Native heap/thread/semaphore/CP layout differs")
        values=symbol_values(elf,"g_mm_region",4)
        regions=[values[:2],values[2:]]
        capacity=region_accounting(footprint["ram_sections"],regions,False)
        task_layout=workload_layout(elf)
        heads={die.get_DIE_from_attribute("DW_AT_type").attributes["DW_AT_byte_size"].value
               for cu in elf.get_dwarf_info().iter_CUs() for die in cu.iter_DIEs()
               if die.tag=="DW_TAG_typedef" and die.attributes.get("DW_AT_name") and die.attributes["DW_AT_name"].value==b"k_mm_head"}
        if heads!={156}:
            raise ValueError("Native initialized heap-header layout differs")
        pool_start=regions[0][0]+((156+7)&~7)+2*layout[2]+layout[3]+layout[4]
        task=elf.get_section_by_name(".symtab").get_symbol_by_name("tasks")[0]
        if task["st_size"]!=45*task_layout["bytes"]:
            raise ValueError("Original 45 worker slots changed")
        slots={"address":task["st_value"],"bytes":task["st_size"],**task_layout}
        symbols=elf.get_section_by_name(".symtab")
        irq=symbols.get_symbol_by_name("port_IntStack")[0]
        irq_end=symbols.get_symbol_by_name("port_IntStackTop")[0]
        irq_section=elf.get_section(irq["st_shndx"])
        idle=symbols.get_symbol_by_name("g_idle_task_stack")[0]
        idle_tcb=symbols.get_symbol_by_name("g_idle_task")[0]
        if irq_end["st_value"]-irq["st_value"]!=1536 or irq_section.name!=".dram0.data" or \
                not irq_section["sh_addr"]<=irq["st_value"]<irq_end["st_value"]<=irq_section["sh_addr"]+irq_section["sh_size"] or \
                idle["st_size"]!=1024 or idle_tcb["st_size"]!=136 or elf.get_section(idle["st_shndx"]).name!=".dram0.bss":
            raise ValueError("Original static interrupt/idle stack reservation changed")
        irq_stack={"start":irq["st_value"],"reserved_bytes":1536,"already_in_static_sram":True,"live_use_peak_measured":False}
        idle_stack={"start":idle["st_value"],"reserved_bytes":1024,"tcb":idle_tcb["st_value"],"already_in_static_sram":True}
    machine=calls(folder,required=[("k_mm_init","bench_h_heap_ready"),("bench_h_heap_ready","bench_h_observe"),
        ("k_mm_alloc","bench_h_observe"),("k_mm_free","bench_h_observe"),("k_mm_realloc","bench_h_observe"),
        ("k_mm_realloc","k_mm_alloc"),("k_mm_realloc","k_mm_free"),
        ("task_create$isra$0","__wrap_krhino_task_create_hook"),
        ("krhino_task_dyn_del","__wrap_krhino_task_del_hook"),
        ("__wrap_krhino_task_create_hook","krhino_task_create_hook"),
        ("__wrap_krhino_task_del_hook","krhino_task_del_hook"),("__wrap_krhino_mm_free","krhino_mm_free"),
        ("dyn_mem_proc_task","__wrap_krhino_mm_free"),("idle_task","__wrap_krhino_idle_hook"),
        ("__wrap_krhino_idle_hook","krhino_idle_hook"),("__wrap_krhino_idle_hook","krhino_task_stack_min_free"),
        ("__wrap_application_start","application_start"),("application_start","__wrap_krhino_task_suspend"),
        ("__wrap_krhino_task_suspend","krhino_task_suspend"),("worker","__wrap_krhino_sem_take"),
        ("__wrap_krhino_sem_take","krhino_sem_take"),("__wrap_esp_timer_create","esp_timer_create"),
        ("__wrap_esp_timer_delete","esp_timer_delete")],require_iram=False,supplemental=suspension_branch(folder))
    return {"audit":"pass","official_native_files_checked":len(expected),"machine_calls":machine,
        "original_workload_unchanged":True,"source_compiled_units":len(commands),"native_port":port,
        "native_layout":layout,"heap_regions":regions,"native_heap_capacity_bytes":capacity,"workload_slots":slots,
        "initialized_fixed_pool":{"start":pool_start,"bytes":8192,"slot_bytes":32,"native_head_bytes":156},
        "interrupt_stack":irq_stack,"static_idle_stack":idle_stack,
        "native_stats_structural_bias_bytes":24,"clock_hz":240000000,"cores":1,"tick_hz":100,
        "tick_divisors":hardware_tick_divisors(folder,expected_hz=100),"compiler":"GCC13 / GCC5 headers / pinned SDK libc",
        **footprint,"whole_live_ram_peak_bytes":None,"ranking_eligible":False}


def header(lines,proof):
    rows=[fields(s,2) for s in lines if s.startswith("RHINO_RAM layout ")]
    if rows!=[{"index":i,"value":v} for i,v in enumerate(proof["native_layout"])]:
        raise ValueError("Runtime native ABI differs from actual ELF")
    rows=[fields(s,2) for s in lines if s.startswith("RHINO_RAM region ")]
    if rows!=[{"index":i,"start":a,"bytes":n} for i,(a,n) in enumerate(proof["heap_regions"])]:
        raise ValueError("Runtime region descriptors differ from actual ELF")
    begin=[fields(s,2) for s in lines if s.startswith("RHINO_RAM BEGIN ")]
    if len(begin)!=1 or begin[0]["cores"]!=1 or begin[0]["tick_hz"]!=100 or begin[0]["window"]!="native-heap-ready-through-controller-idle" or \
            begin[0]["clock_hz"] not in (160000000,240000000) or not 0<begin[0]["ready_occupied"]<proof["native_heap_capacity_bytes"] or \
            lines.count("RHINO_RAM END")!=1 or any(re.search(r"invalid=[1-9]|invalid-command|status=FAIL|panic|fatal|assert|Exception",s,re.I) for s in lines):
        raise ValueError("Native lifecycle begin/ready/error/end differs")
    return begin[0]


def validation(folder,proof):
    lines=[r["line"] for r in read_raw_capture(folder,1)]
    header(lines,proof)
    rows=[fields(s,1) for s in lines if s.startswith("RHINO_RAM validation=")]
    if len(rows)!=1 or rows[0]["validation"]!="PASS" or rows[0]["invalid"] or rows[0]["base"]!=rows[0]["final"] or \
            not rows[0]["base"]<rows[0]["required_overlap_peak"]<=rows[0]["observed_peak"] or \
            sum(s.startswith("rst:0x") for s in lines)!=1 or any(s.startswith("HARTSTONE PH ") for s in lines):
        raise ValueError("Native moving-realloc overlap oracle failed or counted as a workload")
    if lines.count("RHINO_RAM validation_idle_output=PASS")!=1 or not any(s.startswith("RHINO_RAM phase=controller-suspended ") for s in lines):
        raise ValueError("Native idle terminal-output path was not independently validated")
    return {"audit":"pass",**rows[0],"independent_workload_resets":0,"native_idle_output_checked":True}


def lifetimes(lines,proof,step):
    begin=header(lines,proof)
    samples=[fields(s,1) for s in lines if s.startswith("RHINO_RAM phase=")]
    phases=["application-entry","before-controller-suspend","controller-suspended"]
    bias=proof["native_stats_structural_bias_bytes"]
    capacity=proof["native_heap_capacity_bytes"]
    if [s["phase"] for s in samples]!=phases or any(s["invalid"] or not 0<s["occupied"]<=s["peak"]<=capacity or
            s["occupied"]!=capacity-s["fixed_free"]-s["large_free"] or s["occupied"]!=s["native_used"]+bias or
            s["peak"]!=s["native_peak"]+bias or not 0<=s["fixed_free"]<=8192 or s["fixed_free"]%32 or not s["observations"]
            for s in samples) or any(b[k]<a[k] for a,b in zip(samples,samples[1:]) for k in ("peak","observations")) or \
            begin["ready_occupied"]>samples[0]["peak"]:
        raise ValueError("Native heap walk, fixed-pool, oracle or lifetime phase differs")
    rows=[fields(s,2) for s in lines if s.startswith("RHINO_RAM thread ")]
    finals=[fields(s,2) for s in lines if s.startswith("RHINO_RAM final ")]
    timers=[fields(s,2) for s in lines if s.startswith("RHINO_RAM timer ")]
    if len(finals)!=1 or finals[0]["invalid"] or len(rows)!=finals[0]["created"] or len(timers)!=finals[0]["timers"] or \
            [r["id"] for r in rows]!=list(range(len(rows))) or [r["id"] for r in timers]!=list(range(len(timers))):
        raise ValueError("Native lifetime registry incomplete")
    final=finals[0]; workers=[r for r in rows if r["role"]==0]
    if len(workers)!=5+step or not 5<=len(workers)<=45 or sum(r["present"] for r in rows)!=final["native_active"] or \
            len({r["tcb"] for r in rows if r["present"]})!=final["native_active"]:
        raise ValueError("Original workers or full native task inventory differs")
    slot=proof["workload_slots"]; offsets=slot["members"]
    pool=proof["initialized_fixed_pool"]
    for r in rows:
        if not r["stack"]<=r["cp"] or r["cp"]+96>r["stack"]+r["reserved"] or \
                r["spare"]+4>r["reserved"] or r["spare"]%4 or r["hwm_measured"] not in (0,1):
            raise ValueError("Native reserved stack/CP/high-water bounds differ")
        if r["present"]:
            if r["deleted"] or r["stack_freed"] or r["tcb_freed"] or r["status"]==7 or \
                    (r["tcb"]==final["idle"])==bool(r["hwm_measured"]) or \
                    r["dynamic"]==2 and (r["stack_usable"]<r["reserved"] or r["tcb_usable"]<136):
                raise ValueError("Native active task or actually measured noncurrent stack differs")
        elif not r["deleted"] or r["status"]!=7 or r["dynamic"]==2 and not (r["stack_freed"] and r["tcb_freed"]):
            raise ValueError("Deleted dynamic task lacks actual stack/TCB frees")
    for index,r in enumerate(workers):
        base=slot["address"]+index*slot["bytes"]
        if r["tcb"]!=base+offsets["native"] or r["gate"]!=base+offsets["gate"] or r["reserved"]!=4096 or \
                r["dynamic"]!=1 or r["stack_usable"]<4096 or not r["present"] or r["status"]!=2 or r["value"] or \
                r["blocked"]!=r["gate"] or r["waiter_next"]!=r["tcb"]+36 or r["waiter_prev"]!=r["tcb"]+36 or \
                r["node_next"]!=r["gate"] or r["node_prev"]!=r["gate"]:
            raise ValueError("Original persistent worker slot/gate/native waiter differs")
        if not any(a<=r["stack"]-16<r["stack"]+r["stack_usable"]<=a+n for a,n in proof["heap_regions"]):
            raise ValueError("Original worker stack allocation escapes the actual native heap")
        matches=[t for t in timers if not t["deleted"] and t["output"]==base+offsets["timer"]]
        if len(matches)!=1 or matches[0]["argument"]!=base+offsets["released"] or matches[0]["freed"] or not matches[0]["usable"]:
            raise ValueError("Original worker timer handle/release ownership differs")
        timer=matches[0]
        if timer["usable"]!=32 or not pool["start"]<=timer["handle"]<pool["start"]+pool["bytes"] or (timer["handle"]-pool["start"])%32:
            raise ValueError("Original worker timer is not a live slot of the actual initialized native pool")
    if len(timers)!=len(workers)+1 or sum(t["deleted"] for t in timers)!=1 or not timers[0]["deleted"] or not timers[0]["freed"]:
        raise ValueError("Original temporary probe timer was not deleted and actually freed")
    retained_bytes=sum(r["stack_usable"]+16 for r in workers)+sum(t["usable"] for t in timers if not t["deleted"])
    if retained_bytes!=samples[-1]["occupied"]-samples[0]["occupied"] or samples[0]["fixed_free"]-samples[-1]["fixed_free"]!=len(workers)*32:
        raise ValueError("Native post-entry heap/fixed-pool growth is not fully attributed to retained worker stacks and timers")
    controllers=[r for r in rows if r["role"]==1]
    idle=[r for r in rows if r["role"]==2]
    if len(controllers)!=1 or controllers[0]["tcb"]!=final["controller"] or controllers[0]["status"]!=3 or not controllers[0]["present"] or \
            len(idle)!=1 or idle[0]["tcb"]!=final["idle"] or not idle[0]["present"] or idle[0]["hwm_measured"]:
        raise ValueError("Native controller suspension not observed by the existing idle")
    if [idle[0]["tcb"],idle[0]["stack"],idle[0]["reserved"]]!=[proof["static_idle_stack"][k] for k in ("tcb","start","reserved_bytes")]:
        raise ValueError("Observed idle task differs from the unchanged actual ELF static stack")
    positions=[next(i for i,s in enumerate(lines) if s.startswith("RHINO_RAM phase="+p)) for p in phases]
    end=next(i for i,s in enumerate(lines) if s.startswith("HARTSTONE PH SERIES status="))
    if not positions[0]<end<positions[1]<positions[2]:
        raise ValueError("Original workload and actual suspended-controller boundary order differs")
    return {"samples":samples,"records":rows,"timers":timers,"final":final,
        "workers_retained_blocked":len(workers),"native_heap_peak_bytes":samples[-1]["peak"],
        "retained_allocation_growth_bytes":retained_bytes,"allocation_growth_fully_attributed":True,
        "stack_and_timer_owners_checked":True,"controller_suspended_observed_from_existing_idle":True,
        "current_idle_stack_hwm_measured":False,"forced_worker_deletion":False}


def audit(directory,source):
    campaign=envelope(directory)
    if campaign["kind"]!="rhino-ram" or campaign["board_mac"]!="34:98:7a:a2:85:28" or campaign["independent_resets"]!=3:
        raise ValueError("Wrong board or incomplete Rhino lifecycle campaign")
    proof=build(source)
    for p in (directory/"build").iterdir():
        if sha(p)!=sha(source/p.name):
            raise ValueError("Captured image differs from audited native source")
    verified(directory/"captures",directory/"build",campaign["board_mac"])
    check=validation(directory/"validation",proof)
    runs=[]
    for index,rows in enumerate(independent_captures(directory/"captures"),1):
        verified(directory/"captures",directory/"build",campaign["board_mac"],logs=("verify-run%d.log"%index,))
        original=series(directory/"captures"/("reset%d.jsonl"%index),"AliOS-Rhino",4,high_resolution=True)
        if original["completion"]!="FIRST_LOSS_REACHED":
            raise ValueError("Original PH4 sequence incomplete")
        life=lifetimes([r["line"] for r in rows],proof,original["first_loss_step"])
        runs.append({"original_ph4":original,"lifetimes":life,"heap_native_peak_bytes":life["native_heap_peak_bytes"],
            "static_sram_bytes":proof["static_sram_bytes"],
            "static_plus_native_heap_peak_bytes":proof["static_sram_bytes"]+life["native_heap_peak_bytes"],"ranking_eligible":False})
    return {"audit":"pass","os":"AliOS-Rhino","independent_resets":3,"build":proof,"validation":check,"runs":runs,
        "original_flash_restored":True,"whole_live_ram_peak_bytes":None,"full_live_ram_ranking_eligible":False,
        "ranking_eligible":False,"energy_measured":False,"external_independent_replication":False,
        "scope":"native initialized-heap peak, fixed-pool free slots and all original persistent workers/timers through actual controller suspension; observer-inclusive, not simultaneous live stack use"}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build",type=Path)
    parser.add_argument("--verify-upstream",action="store_true")
    parser.add_argument("--prepare-branch",type=Path,metavar="OBJDUMP")
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.prepare_branch:
        prepare_branch(args.build,args.prepare_branch)
        raise SystemExit(0)
    result=audit(args.capture,args.build) if args.capture else build(args.build,args.verify_upstream)
    if args.output: args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
