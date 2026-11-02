#!/usr/bin/env python3
"""Audit original RIOT retained workers and the four-region native heap window."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile

from build_esp32_riot_ram_lifetimes import NATIVE,SDK_FILES,SUPPORT,SUPPORT_SDK,patched
from audit_esp32_riot_original import UPSTREAM
from audit_esp32_hartstone_ram_riot import SDK
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope,independent_captures,verified
from audit_esp32_hartstone_series import audit as series
from audit_esp32_resources import audit_elf_image,static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_zephyr_thread import read_raw_capture
from audit_esp32_zephyr_ram_lifetimes import fields
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
OBSERVER=ROOT/"firmware/bsp/esp32/resource_census/riot_lifetimes"
REFERENCE=ROOT/"artifacts/reports/hartstone-riot-native-v4/ph4"
OLD=ROOT/"artifacts/reports/ram-hartstone-riot-v1/riot/ph4"
LIBRARY_SHA="45c26de978a78a4ee8b4be8965f63fc5bdc6b1a0c4403dd47967178df81e0146"
ORIGINAL=("main.c","workload.c","small_whetstone.c","small_whetstone.h","ph_us_schedule.h")
LAYOUT_NAMES=("tcb_bytes","pid_bytes","rq_offset","blocked","stopped","stacktest","sema_bytes","mutex_offset","cp_bytes","mallinfo_bytes","fordblks_offset")


def official_files(folder):
    extra = ("cpu/esp_common/thread_arch.c",) if json.loads((folder/"build.json").read_text()).get("native_stack_coverage") else ()
    return [(n,UPSTREAM+n,folder/"original-init.c" if n=="core/lib/init.c" else folder/"native-source"/n) for n in NATIVE+extra]+[
        ("sdk/"+n,"https://raw.githubusercontent.com/espressif/esp-idf/"+SDK+"/"+n,folder/"native-source/sdk"/n) for n in SDK_FILES]+[
        ("sdk-package-Makefile",UPSTREAM+"pkg/esp32_sdk/Makefile",folder/"sdk-package-Makefile")]+[
        (n,UPSTREAM+n,folder/"supporting-source"/n) for n in SUPPORT]+[
        ("sdk/"+n,"https://raw.githubusercontent.com/espressif/esp-idf/"+SDK+"/"+n,folder/"supporting-source/sdk"/n) for n in SUPPORT_SDK]


def provenance(folder):
    prior=OLD/"official-native-source.json"
    reused={r["path"]:r for r in json.loads(prior.read_text())} if prior.exists() else {}
    result=[]
    for name,url,path in official_files(folder):
        value=sha(path)
        row={"path":name,"url":url,"sha256":value}
        if reused.get(name)!=row:
            with urlopen(url,timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest()!=value:
                    raise ValueError("Native source differs from pinned upstream: "+name)
        result.append(row)
    (folder/"official-native-source.json").write_text(json.dumps(result,indent=2)+"\n")
    native=json.loads((folder/"official-native-library.json").read_text())
    if native["library_sha256"]!=sha(folder/"libg_nano.a") or native["library_sha256"]!=LIBRARY_SHA:
        raise ValueError("Linked Newlib-nano payload differs from vendor-verified archive")
    (folder/"official-native-library.json").write_text(json.dumps(native,indent=2)+"\n")


def build(folder,verify_upstream=False):
    manifest=json.loads((folder/"build.json").read_text())
    if manifest["status"]!="build_pass_not_measured" or manifest["board_resets"] or manifest["ranking_eligible"]:
        raise ValueError("Source-only build incorrectly qualified")
    for n,v in manifest["files"].items():
        p=(folder/n).resolve()
        if not p.is_relative_to(folder.resolve()) or sha(p)!=v:
            raise ValueError("Changed source/image manifest")
    for p in OBSERVER.iterdir():
        if p.is_file():
            expected = p.read_bytes()
            if manifest.get("native_stack_coverage"):
                from build_esp32_riot_stack_coverage import EXTENSION,extended_source,extended_makefile
                if p.name == "census.c":
                    expected = extended_source(p.read_text(),EXTENSION.read_text()).encode()
                elif p.name == "Makefile":
                    expected = extended_makefile(p.read_text()).encode()
            if expected!=(folder/"observer"/p.name).read_bytes():
                raise ValueError("Unreviewed observation implementation")
    for n in ORIGINAL:
        if (folder/n).read_bytes()!=(REFERENCE/n).read_bytes():
            raise ValueError("Original persistent-worker workload or math changed")
    if (folder/"native-source/core/lib/init.c").read_bytes()!=patched((folder/"original-init.c").read_bytes()):
        raise ValueError("Native intervention exceeds the existing idle observation call")
    if (folder/"config").read_bytes()!=(REFERENCE/"config.h").read_bytes() or \
            (folder/"reference-config").read_bytes()!=(REFERENCE/"config.h").read_bytes() or \
            (folder/"original-Makefile").read_bytes()!=(REFERENCE/"Makefile").read_bytes():
        raise ValueError("Native clock/core/timer/thread configuration changed")
    expected_wrapper=ROOT/"artifacts/reports/esp32-riot-gcc13-legacy-v1/compiler-compatibility/gcc13-legacy-newlib.sh"
    if (folder/"compiler-wrapper.sh").read_bytes()!=expected_wrapper.read_bytes() or "13.2.0" not in (folder/"compiler.txt").read_text():
        raise ValueError("GCC13/legacy Newlib compatibility route changed")
    if verify_upstream:
        provenance(folder)
    expected=[{"path":n,"url":u,"sha256":sha(p)} for n,u,p in official_files(folder)]
    if json.loads((folder/"official-native-source.json").read_text())!=expected:
        raise ValueError("Pinned native source coverage/provenance differs")
    library=json.loads((folder/"official-native-library.json").read_text())
    if sha(folder/"libg_nano.a")!=LIBRARY_SHA or library["library_sha256"]!=LIBRARY_SHA or library["release"]!="esp-13.2.0_20230928" or \
            library["archive_sha256"]!="bae7da23ea8516fb7e42640f4420c4dd1ebfd64189a14fc330d73e173b3a038b" or \
            library["archive_bytes"]!=112588084:
        raise ValueError("Precompiled native allocator provenance differs")
    mapped=(folder/"application.map").read_text()
    for member in ("mallocr","freer","reallocr","mallinfor","mlock","msizer"):
        if not re.search(r"xtensa-esp-elf/lib/esp32/libg_nano\.a\(libc_a-"+member+r"\.o\)",mapped):
            raise ValueError("Actual image does not link the pinned GCC13 native allocator member: "+member)
    log=re.sub(r"\x1b\[[0-9;]*m","",(folder/"build.log").read_text()).replace("\\\n"," ")
    commands=[shlex.split(l) for l in log.splitlines() if "gcc13-legacy-newlib.sh" in l and " -c " in l]
    for suffix in ("/app/main.c","/app/workload.c","/app/census.c","/core/lib/init.c","/core/thread.c","/core/sched.c",
                   "/sys/sema/sema.c","/sys/newlib_syscalls_default/syscalls.c","/cpu/esp_common/esp-xtensa/thread_arch.c",
                   "/cpu/esp_common/freertos/task.c","/cpu/esp32/startup.c","/components/esp_timer/src/esp_timer.c"):
        selected=[r for r in commands if any(s.endswith(suffix) for s in r)]
        if len(selected)!=1 or [s for s in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)",s)]!=["-Os"] or not {
                "-DPH_EXPERIMENT=4","-DPH_HIGH_RES=1","-fno-fast-math","-ffp-contract=off",
                "-DTHREAD_PRIORITY_MAIN=14","-DMAXTHREADS=48","-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1"}<=set(selected[0]):
            raise ValueError("Original/native compilation differs: "+suffix)
    audit_elf_image(folder/"application.elf",folder/"application.bin")
    footprint=static_footprint(folder/"application.elf")
    with (folder/"application.elf").open("rb") as stream:
        elf=ELFFile(stream); symbols=elf.get_section_by_name(".symtab")
        item=symbols.get_symbol_by_name("bench_r_layout")[0]
        section=elf.get_section(item["st_shndx"]); pos=item["st_value"]-section["sh_addr"]
        layout=list(struct.unpack("<11I",section.data()[pos:pos+44]))
        if item["st_size"]!=44 or layout!=[48,2,12,3,0,8,12,8,96,40,32]:
            raise ValueError("Native thread/semaphore/Newlib ABI differs")
        reservations={}
        for name,size in (("tasks",45*28),("stacks",45*4),("pids",45*2),("gates",45*12),("main_stack",3584),("idle_stack",2048)):
            sym=symbols.get_symbol_by_name(name)[0]
            if sym["st_size"]!=size:
                raise ValueError("Original/native resource reservation changed")
            reservations[name]=[sym["st_value"],size]
        regions=[]
        for suffix in ("","1","2","3"):
            a=symbols.get_symbol_by_name("_sheap"+suffix)[0]["st_value"]
            b=symbols.get_symbol_by_name("_eheap"+suffix)[0]["st_value"]
            regions.append([a,b-a])
        region_accounting(footprint["ram_sections"],regions,False)
    machine=calls(folder,required=[("main_trampoline","__wrap_main"),("idle_thread","bench_r_idle"),
        ("kernel_init","__wrap_thread_create"),("__wrap_thread_create","thread_create"),
        ("thread_create","thread_stack_init"),("main","__wrap_thread_create"),("main","malloc"),
        ("__wrap_main","main"),("worker","__wrap__sema_wait_ztimer"),("__wrap__sema_wait_ztimer","_sema_wait_ztimer"),
        ("__wrap___malloc_unlock","__malloc_unlock"),("__wrap___malloc_unlock","observe"),("observe","_mallinfo_r"),
        ("_mallinfo_r","__wrap___malloc_unlock"),("_malloc_r","__wrap___malloc_unlock"),("_free_r","__wrap___malloc_unlock"),
        ("_realloc_r","_malloc_r"),("_realloc_r","_free_r"),("__wrap__sbrk_r","_sbrk_r"),
        ("bench_r_idle","measure_stack_free_internal"),("system_startup_cpu0","esp_timer_init"),
        ("esp_timer_init","xTaskCreatePinnedToCore"),("xTaskCreatePinnedToCore","malloc"),
        ("xTaskCreatePinnedToCore","__wrap_thread_create")],require_iram=False)
    return {"audit":"pass","official_native_files_checked":len(expected),"machine_calls":machine,
        "original_workload_unchanged":True,"native_layout":layout,"heap_regions":regions,"static_reservations":reservations,
        "compiler":"GCC13 / GCC12 headers / GCC13 Newlib-nano", "native_allocator":"vendor-pinned precompiled GCC13 Newlib-nano, not source rebuilt",
        "clock_hz":240000000,"cores":1,"tick_hz":0,**footprint,"ranking_eligible":False,"whole_live_ram_peak_bytes":None}


def observations(lines, proof):
    if lines.count("RIOT_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=0 window=first-allocator-unlock-through-main-idle")!=1 or \
            lines.count("RIOT_RAM END")!=1 or any(re.search(r"panic|fatal|assert|invalid-command|Exception|status=FAIL",s,re.I) for s in lines):
        raise ValueError("Native lifecycle window/error/completion differs")
    layout=[fields(s,2) for s in lines if s.startswith("RIOT_RAM layout ")]
    if layout!=[dict(zip(LAYOUT_NAMES,proof["native_layout"]))]:
        raise ValueError("Runtime ABI differs from actual ELF")
    samples=[fields(s,1) for s in lines if s.startswith("RIOT_RAM phase=")]
    heaps=[fields(s,2) for s in lines if s.startswith("RIOT_RAM heap ")]
    phases=["application-entry","series-return","main-exited"]
    if [s["phase"] for s in samples]!=phases or len(heaps)!=12 or any(
            s["invalid"] or not 0<s["occupied"]<=s["peak"] or not 0<s["unlocks"]<=s["observations"] or not s["sbrks"] for s in samples) or any(
            b[k]<a[k] for a,b in zip(samples,samples[1:]) for k in ("peak","observations","unlocks","sbrks")):
        raise ValueError("Native allocator phase/event ledger differs")
    for index,phase in enumerate(phases):
        rows=heaps[index*4:(index+1)*4]
        if any(s["phase"]!=phase or [s["start"],s["reserved"]]!=expected or not 0<=s["committed"]<=s["reserved"]
               for s,expected in zip(rows,proof["heap_regions"])) or \
                samples[index]["occupied"]>sum(s["committed"] for s in rows):
            raise ValueError("Four-region committed heap ledger differs from actual ELF")
    return samples,heaps


def validation(folder, proof):
    lines=[r["line"] for r in read_raw_capture(folder,1)]
    values=[fields(s,1) for s in lines if s.startswith("RIOT_RAM validation=")]
    if len(values)!=1 or values[0].get("validation")!="PASS" or values[0]["invalid"] or \
            values[0]["base"]!=values[0]["final"] or not values[0]["base"]<values[0]["required_overlap_peak"]<=values[0]["observed_peak"] or \
            lines.count("RIOT_RAM END")!=1 or sum(s.startswith("rst:0x") for s in lines)!=1 or \
            any(s.startswith("HARTSTONE PH ") for s in lines) or \
            [fields(s,2) for s in lines if s.startswith("RIOT_RAM layout ")]!=[dict(zip(LAYOUT_NAMES,proof["native_layout"]))]:
        raise ValueError("Native moving-realloc overlap validation failed or counted as a workload")
    return {"audit":"pass",**values[0],"independent_workload_resets":0}


def task_lifetimes(lines, samples, heaps, step, proof):
    records=[fields(s,2) for s in lines if s.startswith("RIOT_RAM thread ")]
    totals=[fields(s,2) for s in lines if s.startswith("RIOT_RAM tasks ")]
    workers=step+5
    expected={"created":workers+3,"stopped":1,"active":workers+2,"workers":workers,"native_active":workers+2,"invalid":0}
    if totals!=[expected] or [fields(s,2) for s in lines if s.startswith("RIOT_RAM final ")]!=[{"invalid":0}] or \
            len(records)!=workers+3 or len({s["pid"] for s in records})!=len(records) or \
            len({s["tcb"] for s in records})!=len(records):
        raise ValueError("Original retained-worker/main-exit inventory incomplete")
    intervals=[]; gates=[]; roles=[]; native_bytes=0
    for s in records:
        role=s["role"]; roles.append(role)
        aligned=(s["stack"]+3)&~3
        if role not in (0,1,2,3) or s["pid"]<=0 or s["tcb"]!=(s["stack"]+s["reserved"]-48)&~3 or \
                s["effective_flags"]!=s["original_flags"]|8 or not 0<=s["spare"]<=s["tcb"]-aligned:
            raise ValueError("Native embedded TCB/stack bounds or native fill flags differ")
        if role==0:
            gate_base=proof["static_reservations"]["gates"][0]
            index,remainder=divmod(s["gate"]-gate_base,12)
            if remainder or index not in range(workers) or s["reserved"]!=4096 or s["usable"]<4096 or \
                    s["original_flags"]!=5 or s["present"]!=1 or s["status"]!=3 or s["hwm_measured"]!=1 or \
                    s["value"] or s["gate_state"] or s["waiter"]!=s["tcb"]+12 or s["next"]:
                raise ValueError("Original worker/gate/waiter lifetime is not retained and blocked")
            if not any(h["start"]<=s["stack"]-4<s["stack"]+s["usable"]<=h["start"]+h["committed"] for h in heaps[-4:]):
                raise ValueError("Retained native allocation escapes committed heap")
            native_bytes+=s["usable"]+4
            gates.append(index)
        elif role==3:
            if s["pid"]!=1 or s["reserved"]!=3632 or s["usable"] or s["original_flags"]!=12 or \
                    s["present"]!=1 or s["status"]!=2 or s["hwm_measured"]!=1 or \
                    any(s[k] for k in ("gate","value","gate_state","waiter","next")) or \
                    not any(h["start"]<=s["stack"]<s["stack"]+s["reserved"]<=h["start"]+h["committed"] for h in heaps[:4]):
                raise ValueError("Native pre-main heap-backed timer thread is not accounted")
        else:
            name="main_stack" if role==1 else "idle_stack"
            if [s["stack"],s["reserved"]]!=proof["static_reservations"][name] or s["usable"] or s["original_flags"]!=12 or \
                    s["present"]!=(role==2) or s["status"]!=(11 if role==2 else 0) or s["hwm_measured"]!=(role==1) or \
                    any(s[k] for k in ("gate","value","gate_state","waiter","next")):
                raise ValueError("Native main retirement or retained current idle evidence differs")
        intervals.append((s["stack"],s["stack"]+s["reserved"]))
    intervals.sort()
    if sorted(roles)!=[0]*workers+[1,2,3] or sorted(gates)!=list(range(workers)) or \
            any(a[1]>b[0] for a,b in zip(intervals,intervals[1:])) or samples[-1]["occupied"]<native_bytes:
        raise ValueError("Retained worker inventory overlaps, omits gates or exceeds native heap occupation")
    return {"worker_lifetimes":workers,"workers_retained_blocked":workers,"main_native_exit_observed_from_idle":True,
        "thread_control_blocks_and_coprocessor_areas_inside_stack_allocations":True,
        "retained_native_boot_threads":1,"native_timer_stack_reserved_bytes":3632,
        "stack_high_waters_not_summed":True,"records":records,"final":totals[0]}


def audit(directory, source):
    campaign=envelope(directory)
    if campaign["kind"]!="riot-ram" or campaign["board_mac"]!="34:98:7a:a2:85:28" or campaign["independent_resets"]!=3:
        raise ValueError("Wrong board or incomplete RIOT lifetime campaign")
    proof=build(source)
    for path in (directory/"build").iterdir():
        if sha(path)!=sha(source/path.name):
            raise ValueError("Captured image differs from qualified source")
    verified(directory/"captures",directory/"build",campaign["board_mac"])
    check=validation(directory/"validation",proof)
    runs=[]
    for index,rows in enumerate(independent_captures(directory/"captures"),1):
        verified(directory/"captures",directory/"build",campaign["board_mac"],logs=("verify-run%d.log"%index,))
        original=series(directory/"captures"/("reset%d.jsonl"%index),"RIOT",4,high_resolution=True)
        if original["completion"]!="FIRST_LOSS_REACHED":
            raise ValueError("Original persistent-worker PH4 sequence incomplete")
        lines=[r["line"] for r in rows]
        samples,heaps=observations(lines,proof)
        positions=[next(i for i,s in enumerate(lines) if s.startswith("RIOT_RAM phase="+p))
                   for p in ("application-entry","series-return","main-exited")]
        terminal=next(i for i,s in enumerate(lines) if s.startswith("HARTSTONE PH SERIES status="))
        if [fields(s,1) for s in lines if s.startswith("RIOT_RAM returned=")]!=[{"returned":0}] or \
                not positions[0]<terminal<positions[1]<positions[2]:
            raise ValueError("Original main return/native idle confirmation order differs")
        tasks=task_lifetimes(lines,samples,heaps,original["first_loss_step"],proof)
        runs.append({"original_ph4":original,"samples":samples,"native_heap_regions":heaps,"tasks":tasks,
            "heap_native_peak_bytes":samples[-1]["peak"],"static_sram_bytes":proof["static_sram_bytes"],
            "static_plus_native_heap_peak_bytes":proof["static_sram_bytes"]+samples[-1]["peak"],"ranking_eligible":False})
    return {"audit":"pass","os":"RIOT","independent_resets":3,"build":proof,"validation":check,"runs":runs,
        "original_flash_restored":True,"whole_live_ram_peak_bytes":None,"full_live_ram_ranking_eligible":False,
        "ranking_eligible":False,"energy_measured":False,"external_independent_replication":False,
        "scope":"native four-region committed-minus-free allocator peak and all original persistent workers retained on their own gates through main exit; observer-inclusive, not simultaneous live stack use"}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build",type=Path)
    parser.add_argument("--verify-upstream",action="store_true")
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.verify_upstream:
        provenance(args.build)
    result=audit(args.capture,args.build) if args.capture else build(args.build)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
