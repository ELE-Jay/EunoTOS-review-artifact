#!/usr/bin/env python3
"""Audit native Zephyr static-buffer lifetimes and original heap statistics."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile

from build_esp32_zephyr_ram_lifetimes import NATIVE, native_edits, patched
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_hartstone_series import audit as series
from audit_esp32_ram_census import region_accounting
from audit_esp32_resources import audit_elf_image, static_footprint
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "firmware/bsp/esp32/resource_census/zephyr_lifetimes"
REFERENCE = ROOT / "artifacts/reports/hartstone-native-us-v1/zephyr/ph4"
OLD = ROOT / "artifacts/reports/ram-hartstone-zephyr-v1/zephyr/ph4"
UPSTREAM = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/"
HAL = "https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/87e7902d7184a8280b4d13bce79801a723f4ddd8/"
HAL_FILES = ("components/esp_hw_support/esp_clk.c", "components/esp_hw_support/include/esp_private/esp_clk.h")
ORIGINAL = ("series.c", "math_compat.h", "errno_bridge.c", "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h")


def official_files(folder):
    edits,extra = native_edits(),()
    if json.loads((folder/"build.json").read_text()).get("native_stack_coverage"):
        from build_esp32_zephyr_stack_coverage import stack_native_edits,EXTRA_NATIVE
        edits,extra = stack_native_edits(),(EXTRA_NATIVE,)
    return [(n, UPSTREAM+n, folder / ("original-native" if n in edits else "native-source") / n) for n in NATIVE+extra] + \
        [(n, UPSTREAM+n, folder/n) for n in ("west.yml","VERSION")] + \
        [("hal/"+n, HAL+n, folder/"native-source/hal"/n) for n in HAL_FILES]


def provenance(folder):
    prior = OLD/"official-native-source.json"
    reused = {r["path"]:r for r in json.loads(prior.read_text())} if prior.exists() else {}
    result = []
    for name,url,path in official_files(folder):
        digest = sha(path)
        previous = reused.get(name)
        if previous != {"path":name,"url":url,"sha256":digest}:
            with urlopen(url, timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest() != digest:
                    raise ValueError("Native source differs from fixed official version: " + name)
        result.append({"path":name,"url":url,"sha256":digest})
    (folder/"official-native-source.json").write_text(json.dumps(result,indent=2)+"\n")


def build(folder, verify_upstream=False):
    manifest = json.loads((folder/"build.json").read_text())
    if manifest["status"] != "build_pass_not_measured" or manifest["board_resets"] or manifest["ranking_eligible"]:
        raise ValueError("Source-only build incorrectly qualified")
    for name,value in manifest["files"].items():
        path = (folder/name).resolve()
        if not path.is_relative_to(folder.resolve()) or sha(path) != value:
            raise ValueError("Changed source/image manifest")
    for path in OBSERVER.iterdir():
        if path.is_file():
            expected = path.read_bytes()
            if manifest.get("native_stack_coverage") and path.name == "census.c":
                from build_esp32_zephyr_stack_coverage import extended_source,EXTENSION
                expected = extended_source(path.read_text(),EXTENSION.read_text()).encode()
            if expected != (folder/"observer"/path.name).read_bytes():
                raise ValueError("Unreviewed native lifecycle observer")
    for name in ORIGINAL:
        if (folder/name).read_bytes() != (REFERENCE/name).read_bytes():
            raise ValueError("Original workload/math/release schedule changed")
    selected = native_edits()
    if manifest.get("native_stack_coverage"):
        from build_esp32_zephyr_stack_coverage import stack_native_edits
        selected = stack_native_edits()
    for name,edits in selected.items():
        if (folder/"native-source"/name).read_bytes() != patched((folder/"original-native"/name).read_bytes(),edits):
            raise ValueError("Native changes exceed the declared observation calls")
    allowed = {"CONFIG_INIT_STACKS","CONFIG_SYS_HEAP_RUNTIME_STATS","CONFIG_THREAD_ABORT_HOOK",
               "CONFIG_BENCH_Z_LIFETIMES","CONFIG_TAINT","CONFIG_TAINT_BLOBS"}
    parse = lambda p: dict(s.split("=",1) for s in p.read_text().splitlines() if s.startswith("CONFIG_"))
    cfg, ref = parse(folder/"config"),parse(REFERENCE/"config")
    if (folder/"reference-config").read_bytes() != (REFERENCE/"config").read_bytes() or \
            {k:v for k,v in cfg.items() if k not in allowed} != {k:v for k,v in ref.items() if k not in allowed} or \
            any(cfg.get(k) != "y" for k in allowed-{"CONFIG_TAINT","CONFIG_TAINT_BLOBS"}):
        raise ValueError("Configuration change exceeds stack fill and native observation/statistics")
    if verify_upstream:
        provenance(folder)
    expected = [{"path":n,"url":u,"sha256":sha(p)} for n,u,p in official_files(folder)]
    if json.loads((folder/"official-native-source.json").read_text()) != expected:
        raise ValueError("Fixed native source provenance/coverage differs")
    commands = json.loads((folder/"compile_commands.json").read_text())
    for suffix in ("/kernel/init.c","/kernel/thread.c","/kernel/sched.c","/kernel/idle.c",
                   "/lib/heap/heap.c","/lib/heap/heap_stats.c","/lib/heap/heap_validate.c",
                   "/zephyr_lifetimes/census.c","/src/series.c","/main/small_whetstone.c"):
        rows = [r for r in commands if r["file"].endswith(suffix)]
        if len(rows) != 1 or [a for a in shlex.split(rows[0]["command"]) if a.startswith("-O")] != ["-Os"]:
            raise ValueError("Native/observer/original compilation differs: " + suffix)
        if suffix.startswith("/kernel/") and not rows[0]["file"].startswith("/dev/shm/iotos-zephyr-lifetimes-work-"):
            raise ValueError("Native kernel was not built from the isolated observed tree")
        if suffix in ("/src/series.c","/main/small_whetstone.c") and not {
                "-DPH_EXPERIMENT=4","-DPH_HIGH_RES=1","-fno-fast-math","-ffp-contract=off"} <= set(shlex.split(rows[0]["command"])):
            raise ValueError("Original experiment/timer/math flags changed")
    if "13.2.0" not in (folder/"compiler.txt").read_text():
        raise ValueError("Compiler profile differs")
    audit_elf_image(folder/"application.elf",folder/"application.bin",ram_only_header=True)
    footprint = static_footprint(folder/"application.elf")
    with (folder/"application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        abi = symbols.get_symbol_by_name("bench_z_layout")[0]
        section = elf.get_section(abi["st_shndx"])
        offset = abi["st_value"]-section["sh_addr"]
        layout = list(struct.unpack("<4I",section.data()[offset:offset+16]))
        if abi["st_size"] != 16 or layout != [96,8,13,1]:
            raise ValueError("Native thread ABI differs from declared static-resource profile")
        reservations = {}
        for name,size in (("stacks",37*4096),("threads",37*layout[0]),("tasks",37*32),
                          ("kheap__system_heap",4096),("z_interrupt_stacks",2048),("z_main_stack",4096),
                          ("z_main_thread",layout[0]),("z_idle_threads",layout[0]),("z_idle_stacks",1024)):
            rows = symbols.get_symbol_by_name(name) or []
            if len(rows) != 1 or rows[0]["st_size"] != size:
                raise ValueError("Native static reservation differs: " + name)
            sym = rows[0]
            if not any(int(s["address"],16) <= sym["st_value"] < sym["st_value"]+size <= int(s["address"],16)+s["bytes"]
                       for s in footprint["ram_sections"]):
                raise ValueError("Static reservation escapes ELF SRAM")
            reservations[name] = [sym["st_value"],size]
        for name in ("malloc_arena","z_malloc_heap","k_thread_stack_alloc","esp_wifi_init","k_sys_work_q"):
            if any(s["st_shndx"] != "SHN_UNDEF" for s in symbols.get_symbol_by_name(name) or []):
                raise ValueError("Unaccounted dynamic/external resource linked")
    machine = calls(folder, required=[("bg_thread_main","__wrap_main"),("__wrap_main","main"),
        ("z_setup_new_thread","bench_z_create"),("z_thread_halt","thread_abort_hook"),
        ("z_thread_abort","z_thread_halt"),("z_impl_k_thread_abort","z_thread_abort"),
        ("z_thread_entry","z_impl_k_thread_abort"),("idle","bench_z_idle"),
        ("main","__wrap_z_impl_k_thread_join"),("__wrap_z_impl_k_thread_join","z_impl_k_thread_join"),
        ("__wrap_z_impl_k_thread_join","scan_retired"),("bench_z_idle","scan_retired"),
        ("scan_retired","z_impl_k_thread_stack_space_get"),("report","sys_heap_validate"),
        ("report","sys_heap_runtime_stats_get"),("__wrap_sys_heap_init","sys_heap_init"),
        ("statics_init","k_heap_init"),("k_heap_init","__wrap_sys_heap_init")],require_iram=False)
    return {"audit":"pass","official_native_files_checked":len(expected),"machine_calls":machine,
        "original_workload_unchanged":True,"clock_hz":240000000,"cores":1,"tick_hz":100000,
        "native_layout":layout,"static_reservations":reservations,**footprint,
        "ranking_eligible":False,"whole_live_ram_peak_bytes":None}


def fields(line, start):
    return {k:int(v) if v.isdecimal() else v for k,v in (t.split("=",1) for t in line.split()[start:])}


def observations(lines, phases, proof):
    if lines.count("ZEPHYR_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100000 window=heap-init-through-main-idle-confirmation") != 1 or \
            lines.count("ZEPHYR_RAM END") != 1 or any(re.search(r"panic|fatal|assert|invalid-command|Exception|error:",s,re.I) for s in lines):
        raise ValueError("Native lifecycle window or error/completion differs")
    layout = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM layout ")]
    if layout != [dict(zip(("tcb_bytes","dead_mask","state_offset","stack_element"),proof["native_layout"]))]:
        raise ValueError("Runtime ABI witness differs from actual ELF")
    samples = [fields(s,1) for s in lines if s.startswith("ZEPHYR_RAM phase=")]
    heaps = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM heap ")]
    if [s["phase"] for s in samples] != phases or [s["phase"] for s in heaps] != phases or any(
            s["invalid"] or s["heaps"] != 1 or s["created"] != s["retired"]+s["active"] for s in samples) or any(
            [s["start"],s["reserved"]] != proof["static_reservations"]["kheap__system_heap"] or s["valid"] != 1 or
            not 0 <= s["allocated"] <= s["peak"] <= s["reserved"] or not 0 < s["free"] <= s["reserved"] for s in heaps) or any(
            b[k] < a[k] for a,b in zip(samples,samples[1:]) for k in ("created","dead","joined","retired","peak_active")) or any(
            b["peak"] < a["peak"] for a,b in zip(heaps,heaps[1:])):
        raise ValueError("Native heap walk/statistics or task ledger does not reconcile")
    region_accounting(proof["ram_sections"],[tuple(proof["static_reservations"]["kheap__system_heap"])],True)
    return samples,heaps


def validation(folder, proof):
    rows = read_raw_capture(folder,1)
    lines = [r["line"] for r in rows]
    values = [fields(s,1) for s in lines if s.startswith("ZEPHYR_RAM validation=")]
    layout = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM layout ")]
    if len(values) != 1 or values[0].get("validation") != "PASS" or values[0]["invalid"] or \
            values[0]["base"] != values[0]["final"] or not values[0]["base"] < values[0]["required_overlap_peak"] <= values[0]["observed_peak"] or \
            lines.count("ZEPHYR_RAM END") != 1 or sum(s.startswith("rst:0x") for s in lines) != 1 or \
            any(s.startswith("HARTSTONE PH ") for s in lines) or \
            layout != [dict(zip(("tcb_bytes","dead_mask","state_offset","stack_element"),proof["native_layout"]))]:
        raise ValueError("Native heap validation failed or was counted as original workload")
    return {"audit":"pass",**values[0],"independent_workload_resets":0}


def task_lifetimes(lines, samples, first_loss_step, proof):
    roles = [fields(s,1) for s in lines if s.startswith("ZEPHYR_RAM role=")]
    stacks = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM stack ")]
    final = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM final ")]
    count = first_loss_step+5
    lifetimes = sum(range(5,count+1))
    if final != [{"invalid":0}] or len(roles) != 3 or [r["role"] for r in roles] != ["worker","main","system"] or \
            roles[0] != {"role":"worker","created":lifetimes,"dead":lifetimes,"retired":lifetimes,"active":0} or \
            roles[1] != {"role":"main","created":1,"dead":1,"retired":1,"active":0} or \
            roles[2]["created"] != 1 or roles[2]["active"] != 1 or roles[2]["dead"] or roles[2]["retired"] or \
            any(sum(r[k] for r in roles) != samples[-1][k] for k in ("created","dead","retired","active")) or \
            samples[-1]["joined"] != lifetimes or samples[-2]["retired"] != lifetimes or \
            samples[-1]["retired"] != lifetimes+1 or samples[0]["created"] != roles[2]["created"]+1 or \
            samples[0]["dead"] or samples[0]["joined"] or samples[0]["retired"]:
        raise ValueError("Native create/dead/join/main-switch-out ledger differs")
    if len(stacks) != count+roles[2]["created"]+1 or len({s["tcb"] for s in stacks}) != len(stacks):
        raise ValueError("Static slot inventory incomplete or duplicated")
    intervals = []
    worker_indices = []
    for s in stacks:
        role = s["role"]
        if role not in (0,1,2) or not s["generations"] or not s["span"] or \
                not s["stack"] <= s["start"] < s["start"]+s["span"] <= s["stack"]+s["reserved"] or \
                s["hwm_measured"] not in (0,1) or not 0 <= s["spare"] <= s["span"]:
            raise ValueError("Native stack bounds/high-water record differs")
        if role == 0:
            base = proof["static_reservations"]["threads"][0]
            index,remainder = divmod(s["tcb"]-base,proof["native_layout"][0])
            if remainder or index not in range(count) or s["stack"] != proof["static_reservations"]["stacks"][0]+index*4096 or \
                    s["reserved"] != 4096 or s["generations"] != first_loss_step+1-max(0,index-4):
                raise ValueError("Original TCB/stack slot generation/reuse differs")
            worker_indices.append(index)
        else:
            tcb_name,stack_name = ("z_main_thread","z_main_stack") if role==1 else ("z_idle_threads","z_idle_stacks")
            if s["tcb"] != proof["static_reservations"][tcb_name][0] or \
                    [s["stack"],s["reserved"]] != proof["static_reservations"][stack_name] or s["generations"] != 1:
                raise ValueError("Main/idle storage differs from actual native ELF objects")
        if role in (0,1):
            if s["dead"] != 1 or s["retired"] != 1 or s["joined"] != (role==0) or \
                    s["hwm_measured"] != 1 or not s["state"] & proof["native_layout"][1]:
                raise ValueError("Native dead/join/high-water completion missing")
        elif s["dead"] or s["retired"] or s["joined"] or s["state"] & proof["native_layout"][1]:
            raise ValueError("Retained system task state differs")
        for a,size in ((s["tcb"],proof["native_layout"][0]),(s["stack"],s["reserved"])):
            if not any(int(r["address"],16) <= a < a+size <= int(r["address"],16)+r["bytes"] for r in proof["ram_sections"]):
                raise ValueError("TCB/stack allocation escapes ELF SRAM")
            intervals.append((a,a+size))
    intervals.sort()
    if sorted(worker_indices) != list(range(count)) or any(a[1]>b[0] for a,b in zip(intervals,intervals[1:])):
        raise ValueError("Static TCB/stack storage overlaps or omits original workers")
    return {"worker_lifetimes":lifetimes,"worker_slots_used":count,"all_worker_joins_completed":True,
        "main_native_exit_observed_from_idle":True,"static_buffers_released":False,"stack_high_waters_not_summed":True,
        "roles":roles,"stack_records":stacks,"final":samples[-1]}


def audit(directory, source):
    campaign = envelope(directory)
    if campaign["kind"] != "zephyr-ram" or campaign["board_mac"] != "34:98:7a:a2:85:28" or campaign["independent_resets"] != 3:
        raise ValueError("Wrong board or incomplete Zephyr lifecycle campaign")
    proof = build(source)
    for path in (directory/"build").iterdir():
        if sha(path) != sha(source/path.name):
            raise ValueError("Measured image differs from source-qualified build")
    verified(directory/"captures",directory/"build",campaign["board_mac"])
    check = validation(directory/"validation",proof)
    captures = independent_captures(directory/"captures")
    runs = []
    for index,rows in enumerate(captures,1):
        verified(directory/"captures",directory/"build",campaign["board_mac"],logs=("verify-run%d.log"%index,))
        original = series(directory/"captures"/("reset%d.jsonl"%index),"Zephyr",4,high_resolution=True)
        if original["completion"] != "FIRST_LOSS_REACHED":
            raise ValueError("Original PH4 first-loss sequence incomplete")
        lines = [r["line"] for r in rows]
        samples,heaps = observations(lines,["application-entry","series-return","main-exited"],proof)
        returned = [fields(s,1) for s in lines if s.startswith("ZEPHYR_RAM returned=")]
        positions = [next(i for i,s in enumerate(lines) if s.startswith("ZEPHYR_RAM phase="+p))
                     for p in ("application-entry","series-return","main-exited")]
        terminal = next(i for i,s in enumerate(lines) if s.startswith("HARTSTONE PH SERIES status="))
        if returned != [{"returned":0}] or not positions[0] < terminal < positions[1] < positions[2]:
            raise ValueError("Original main return/native idle confirmation boundary differs")
        tasks = task_lifetimes(lines,samples,original["first_loss_step"],proof)
        runs.append({"original_ph4":original,"samples":samples,"native_heap_stats":heaps,"tasks":tasks,
            "static_sram_bytes":proof["static_sram_bytes"],"heap_native_peak_bytes":heaps[-1]["peak"],
            "heap_and_stacks_already_in_static_sram":True,"ranking_eligible":False})
    return {"audit":"pass","os":"Zephyr","independent_resets":3,"build":proof,"validation":check,"runs":runs,
        "original_flash_restored":True,"whole_live_ram_peak_bytes":None,"full_live_ram_ranking_eligible":False,
        "ranking_eligible":False,"energy_measured":False,"external_independent_replication":False,
        "scope":"native static resource reservations, heap initialization/statistics and all original worker joins through main exit observed from existing idle; not simultaneous live stack use"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build",type=Path)
    parser.add_argument("--verify-upstream",action="store_true")
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    if args.verify_upstream:
        provenance(args.build)
    result = audit(args.capture,args.build) if args.capture else build(args.build)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
