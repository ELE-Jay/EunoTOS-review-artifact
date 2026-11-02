#!/usr/bin/env python3
"""Collect/replay native Zephyr message-task allocations, never a live-RAM score."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import shlex
import signal

from build_esp32_zephyr_message_lifetimes import (BASE, NATIVE, EXTRA, ALLOWED, STACK_NATIVE,
    STACK_INIT_EDIT, config, observer_source, native_edits, patched, startup_init_source, startup_observer_sources)
from run_esp32_followup import Board, sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
OBSERVER = ROOT / "firmware/bsp/esp32/resource_census"
MAC = "34:98:7a:a2:85:28"


def fields(line, start=1):
    return {k:int(v) if v.isdecimal() else v for k,v in (s.split("=", 1) for s in line.split()[start:])}


def build_proof(source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import audit_elf_image, static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    manifest = json.loads((source / "build.json").read_text())
    coverage = manifest.get("message_native_stack_coverage", False)
    startup = manifest.get("application_startup_stack_coverage", False)
    tick = manifest.get("native_tick_stack_snapshots", False)
    lifecycle = manifest.get("task_lifecycle_validation", False)
    vectors = manifest.get('application_startup_vector_coverage',False)
    if type(vectors) is not bool or vectors and not startup:
        raise ValueError('Invalid startup vector observation declaration')
    if type(lifecycle) is not bool or lifecycle and coverage:
        raise ValueError("Invalid finite task lifecycle validation declaration")
    if type(coverage) is not bool or type(startup) is not bool or type(tick) is not bool or (startup and not coverage) or (tick and not startup):
        raise ValueError("Invalid native stack observation declaration")
    if manifest["status"] != "build_pass_not_measured" or manifest["ranking_eligible"]:
        raise ValueError("Build evidence misqualified")
    for name, digest in manifest["files"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source.resolve()) or sha(path) != digest:
            raise ValueError("Changed build evidence: "+name)
    reference = REPORTS / BASE
    for name in ("main.c", "port.c", "test.c", "tm_override.h"):
        if (source / "observer/src" / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError("Original workload changed: "+name)
    for name in ("tm_api.h", "tm_porting_layer.h", "tm_message_processing_test.c"):
        if (source / "observer/src" / name).read_bytes() != (
                ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / name).read_bytes():
            raise ValueError("Original message API/body changed: "+name)
    for name in ("zephyr_message_trace.h", "zephyr_message_tail.c"):
        if (source / "observer" / name).read_bytes() != (OBSERVER / name).read_bytes():
            raise ValueError("Observation extension changed")
    expected = observer_source((OBSERVER / "zephyr_lifetimes/census.c").read_text(),
        (OBSERVER / "zephyr_message_tail.c").read_text(),
        (OBSERVER / "zephyr_message_stack.inc").read_text() if coverage else None,
        startup_observer_sources(OBSERVER / 'zephyr_startup_stack',vectors)['startup-stack.inc'] if startup else None,
        (OBSERVER / "zephyr_tick_stacks.inc").read_text() if tick else None,
        (OBSERVER / "zephyr_task_lifecycle_validation.inc").read_text() if lifecycle else None)
    if (source / "observer/census.c").read_text() != expected:
        raise ValueError("Observation source differs")
    old = REPORTS / "esp32-zephyr-lifetimes-v4"
    for name in NATIVE:
        if coverage and name == "kernel/init.c":
            original = source / "original-native" / name
            if original.read_bytes() != (old / "native-source" / name).read_bytes() or (
                    source / "native-source" / name).read_bytes() != (startup_init_source(original.read_bytes()) if
                        startup else patched(original.read_bytes(), STACK_INIT_EDIT)):
                raise ValueError("Native message startup observation differs")
        elif name in native_edits():
            original = source / "original-native" / name
            if original.read_bytes() != (old / "original-native" / name).read_bytes() or (
                    source / "native-source" / name).read_bytes() != patched(original.read_bytes(), native_edits()[name]):
                raise ValueError("Pinned native observation patch differs: "+name)
        elif (source / "native-source" / name).read_bytes() != (old / "native-source" / name).read_bytes():
            raise ValueError("Previously verified native source differs: "+name)
    if coverage and ((source / "native-source" / STACK_NATIVE).read_bytes() != (
            REPORTS / "esp32-zephyr-stack-coverage-v1/native-source" / STACK_NATIVE).read_bytes() or
            (source / "observer/zephyr_message_stack.inc").read_bytes() != (OBSERVER / "zephyr_message_stack.inc").read_bytes()):
        raise ValueError("Pinned native stack source/extension differs")
    official = json.loads((REPORTS / "zephyr-message-listener-source.json").read_text())
    if official != {n:sha(source / "native-source" / n) for n in EXTRA}:
        raise ValueError("Native heap listener differs from pinned v3.7.0")
    cfg, ref = config(source / "config"), config(reference / "config")
    allowed = ALLOWED | ({"CONFIG_KERNEL_ENTRY"} if startup else set())
    if (source / "reference-config").read_bytes() != (reference / "config").read_bytes() or {
            k:v for k,v in cfg.items() if k not in allowed} != {k:v for k,v in ref.items() if k not in allowed} or any(
            cfg.get(k) != "y" for k in ALLOWED-{"CONFIG_TAINT", "CONFIG_TAINT_BLOBS"}):
        raise ValueError("Observation changed original experiment configuration")
    if startup and cfg.get("CONFIG_KERNEL_ENTRY") != '"bench_z_startup_entry"':
        raise ValueError("Declared startup entry differs")
    commands = json.loads((source / "compile_commands.json").read_text())
    for suffix in ("/src/main.c", "/src/port.c", "/src/test.c", "/census.c", "/kernel/thread.c",
                   "/lib/heap/heap.c", "/lib/heap/heap_stats.c", "/lib/heap/heap_listener.c"):
        rows = [r for r in commands if r["file"].endswith(suffix)]
        if len(rows) != 1 or [a for a in shlex.split(rows[0]["command"]) if a.startswith("-O")] != ["-Os"]:
            raise ValueError("Compilation profile differs: "+suffix)
    if "13.2.0" not in (source / "compiler.txt").read_text():
        raise ValueError("Compiler differs")
    audit_elf_image(source / "application.elf", source / "application.bin", ram_only_header=True)
    footprint = static_footprint(source / "application.elf")
    reservations = {}
    with (source / "application.elf").open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        for name, size in (("stacks", 6*4096), ("threads", 6*96), ("queue_storage", 64),
                           ("kheap__system_heap", 4096), ("z_main_stack", 4096), ("z_main_thread", 96),
                           ("z_idle_stacks", 1024), ("z_idle_threads", 96), ("z_interrupt_stacks", 2048),
                           ("tm_z_events", 128*24)):
            rows = symbols.get_symbol_by_name(name) or []
            if len(rows) != 1 or rows[0]["st_size"] != size:
                raise ValueError("Static allocation differs: "+name)
            reservations[name] = [rows[0]["st_value"], size]
        for name in ("malloc_arena", "z_malloc_heap", "k_thread_stack_alloc", "esp_wifi_init", "k_sys_work_q"):
            if any(s["st_shndx"] != "SHN_UNDEF" for s in symbols.get_symbol_by_name(name) or []):
                raise ValueError("External/unaccounted allocator linked: "+name)
        if lifecycle:
            if (source / "observer/zephyr_task_lifecycle_validation.inc").read_bytes() != (OBSERVER / "zephyr_task_lifecycle_validation.inc").read_bytes():
                raise ValueError("Finite lifecycle validation source differs")
            for name,size in (("bench_z_lifecycle_stack",4096),("bench_z_lifecycle_thread",96)):
                rows=symbols.get_symbol_by_name(name) or []
                if len(rows)!=1 or rows[0]["st_size"]!=size:
                    raise ValueError("Finite validation static storage differs")
                reservations[name]=[rows[0]["st_value"],size]
    machine = calls(source, [("bg_thread_main", "__wrap_main"), ("__wrap_main", "main"),
        ("z_setup_new_thread", "bench_z_create"), ("z_thread_halt", "thread_abort_hook"),
        ("tm_message_processing_thread_report", "__wrap_tm_thread_sleep"),
        ("k_heap_init", "__wrap_sys_heap_init"), ("__wrap_sys_heap_init", "sys_heap_init"),
        ("sys_heap_alloc", "__wrap_heap_listener_notify_alloc"),
        ("sys_heap_aligned_alloc", "__wrap_heap_listener_notify_alloc"),
        ("sys_heap_aligned_realloc", "__wrap_heap_listener_notify_alloc"),
        ("sys_heap_aligned_realloc", "__wrap_heap_listener_notify_free"),
        ("sys_heap_free", "__wrap_heap_listener_notify_free"),
        ("__wrap_heap_listener_notify_alloc", "tm_z_record"),
        ("__wrap_heap_listener_notify_free", "tm_z_record")], require_iram=False)
    extra = {}
    if coverage:
        extra = {"message_native_stack_coverage":True, "native_stack_calls":calls(source, [
            ("z_cstart", "bench_z_message_stack_begin"),
            ("__wrap_main", "tm_z_stack_report"), ("__wrap_tm_thread_sleep", "tm_z_stack_report"),
            ("tm_z_stack_report", "z_stack_space_get"),
            ("tm_z_stack_report", "z_impl_k_thread_stack_space_get")], require_iram=False)}
    if startup:
        from audit_esp32_zephyr_startup_stack import build as startup_build
        extra.update(startup_build(source))
    if tick:
        from audit_esp32_zephyr_tick_stacks import build as tick_build
        if (source/"observer/zephyr_tick_stacks.inc").read_bytes() != (OBSERVER/"zephyr_tick_stacks.inc").read_bytes():
            raise ValueError("Native tick extension differs")
        extra.update(tick_build(source))
    if lifecycle:
        extra.update(task_lifecycle_validation=True,lifecycle_calls=calls(source,
            [("validate","bench_z_validate_task_lifetimes"),
             ("bench_z_validate_task_lifetimes","z_impl_k_thread_create"),
             ("bench_z_validate_task_lifetimes","__wrap_z_impl_k_thread_join")],require_iram=False))
    return {"audit":"pass", **footprint, "reservations":reservations, "machine_calls":machine, **extra,
        "baseline_static_sram_bytes":static_footprint(reference / "zephyr.elf")["static_sram_bytes"],
        "original_workload_unchanged":True, "clock_mhz":240, "cores":1, "tick_hz":100}


def native_stack_observations(lines, proof, validation=False):
    phases = ["validation-end"] if validation else ["application-entry", "message-end"]
    irq = [fields(s) for s in lines if s.startswith("TM_Z_STACK ")]
    tasks = [fields(s) for s in lines if s.startswith("TM_Z_STACK_TASK ")]
    if [r.get("phase") for r in irq] != phases or any(r.get("phase") not in phases for r in tasks):
        raise ValueError("Native stack phase inventory differs")
    reservations = proof["reservations"]
    irq_start, irq_size = reservations["z_interrupt_stacks"]
    main, idle = [reservations[n][0] for n in ("z_main_thread", "z_idle_threads")]
    bounds = {main:reservations["z_main_stack"], idle:reservations["z_idle_stacks"]}
    for i in (0, 5):
        bounds[reservations["threads"][0]+96*i] = [reservations["stacks"][0]+4096*i, 4096]
    previous = {}
    for r in irq:
        phase = r["phase"]
        expected = set(bounds) if phase == "message-end" else {main, idle}
        current = reservations["threads"][0]+5*96 if phase == "message-end" else main
        if set(r) != {"phase","irq","reserved","initial","boot_sp","spare","touched","current","nesting"} or (
                r["irq"],r["reserved"],r["initial"],r["current"],r["nesting"]) != (
                irq_start,irq_size,irq_size,current,0) or irq_start <= r["boot_sp"] < irq_start+irq_size or \
                r["boot_sp"] % 16 or not 0 <= r["spare"] <= irq_size or r["touched"] != irq_size-r["spare"]:
            raise ValueError("Native IRQ fill/context/watermark differs")
        group = [s for s in tasks if s["phase"] == phase]
        if len(group) != len(expected) or {s["tcb"] for s in group} != expected:
            raise ValueError("Native retained task-stack inventory differs")
        for s in group:
            if set(s) != {"phase","tcb","start","span","spare","touched","current"} or \
                    [s["start"],s["span"]] != bounds[s["tcb"]] or s["current"] != int(s["tcb"]==current) or \
                    not 0 <= s["spare"] <= s["span"] or s["touched"] != s["span"]-s["spare"]:
                raise ValueError("Native retained stack bounds/current/watermark differs")
            if s["touched"] < previous.get(s["tcb"],0):
                raise ValueError("Native stack touch watermark regressed")
            previous[s["tcb"]] = s["touched"]
    if len(irq) == 2 and (irq[1]["spare"] > irq[0]["spare"] or irq[1]["boot_sp"] != irq[0]["boot_sp"]):
        raise ValueError("Native IRQ watermark/startup context changed")
    return {"irq":irq,"tasks":tasks,"native_initial_irq_fill_verified":True,
        "current_report_task_included":not validation,"already_inside_static_sram":True,
        "scope":"native historical touch watermarks in the observer image, not simultaneous live stack bytes",
        "bootloader_and_inherited_startup_peak_measured":False,"whole_live_ram_peak_bytes":None}


def replay(events):
    pools, live, peak, pending = {}, {}, {}, None
    for index, e in enumerate(events):
        seq, h, p, kind, size, allocated, maximum = (e[n] for n in ("event", "heap", "pointer", "kind", "bytes", "allocated", "peak"))
        if seq != index or kind not in (0, 1, 2):
            raise ValueError("Reordered/unknown event")
        if kind == 0:
            if pending or h in pools or not p or size <= 0 or allocated or maximum:
                raise ValueError("Invalid native heap initialization")
            pools[h], peak[h] = (p, size), 0
            continue
        if h not in pools or not pools[h][0] <= p < p+size <= sum(pools[h]) or size <= 0:
            raise ValueError("Event outside registered heap")
        key = (h, p)
        if pending is not None:
            if (key, kind, size) != (pending[0], 2, pending[1]):
                raise ValueError("In-place realloc must emit paired old-size release")
            pending = None
        elif kind == 1:
            if key in live:
                # Native realloc emits new-size alloc then old-size free for the SAME block.
                # This replaces its size atomically; it is not a second live allocation.
                pending = (key, live[key])
            live[key] = size
        elif live.pop(key, None) != size:
            raise ValueError("Free without matching live block")
        intervals = sorted((pointer, pointer+length) for (heap, pointer), length in live.items() if heap == h)
        if any(a[1] > b[0] for a,b in zip(intervals, intervals[1:])):
            raise ValueError("Live native allocations overlap")
        current = sum(v for (heap, _), v in live.items() if heap == h)
        peak[h] = max(peak[h], current)
        if (allocated, maximum) != (current, peak[h]):
            raise ValueError("Event replay disagrees with native current/peak")
    if pending or not pools:
        raise ValueError("Incomplete event history")
    return {"pools":pools, "live":live, "peak":peak,
            "occupied":{h:sum(v for (heap, _), v in live.items() if heap == h) for h in pools}}


def read_run(folder, index, proof, validation=False):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_tm_basic import audit as original_audit
    from audit_esp32_ram_census import region_accounting
    lines = [r["line"] for r in read_raw_capture(folder, index)]
    if sum(s.startswith("rst:0x") for s in lines) != 1 or lines.count(
            "ZEPHYR_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100 window=heap-init-through-third-message-report") != 1 or any(
            re.search(r"panic|fatal|assert|invalid-command|Exception|error:", s, re.I) for s in lines):
        raise ValueError("Boot/profile/error check failed")
    if [fields(s, 2) for s in lines if s.startswith("ZEPHYR_RAM layout ")] != [
            {"tcb_bytes":96, "dead_mask":8, "state_offset":13, "stack_element":1}]:
        raise ValueError("Runtime thread ABI differs from audited object layout")
    events = [fields(s) for s in lines if s.startswith("TM_Z_RAM event=")]
    trace = [fields(s, 2) for s in lines if s.startswith("TM_Z_RAM trace ")]
    if trace != [{"events":len(events), "overflow":0}] or not 0 < len(events) < 128:
        raise ValueError("Trace missing/overflowed")
    history = replay(events)
    heaps = [fields(s, 2) for s in lines if s.startswith("ZEPHYR_RAM heap ")]
    samples = [fields(s) for s in lines if s.startswith("ZEPHYR_RAM phase=")]
    phases = ["validation-end"] if validation else ["application-entry", "message-end"]
    if [s["phase"] for s in samples] != phases or [s["phase"] for s in heaps] != phases or any(
            s["invalid"] or s["heaps"] != 1 or s["created"] != s["active"]+s["retired"] for s in samples):
        raise ValueError("Workload boundaries/native task counts differ")
    if len(history["pools"]) != 1 or list(history["pools"].values()) != [tuple(proof["reservations"]["kheap__system_heap"])]:
        raise ValueError("Heap inventory differs from ELF")
    for heap in heaps:
        if [heap["start"], heap["reserved"]] != proof["reservations"]["kheap__system_heap"] or heap["valid"] != 1 or not (
                0 <= heap["allocated"] <= heap["peak"] <= heap["reserved"]) or not 0 < heap["free"] <= heap["reserved"]:
            raise ValueError("Native heap validation differs")
    if any(b["peak"] < a["peak"] for a,b in zip(heaps,heaps[1:])):
        raise ValueError("Native peak regressed across workload boundaries")
    if list(history["occupied"].values()) != [heaps[-1]["allocated"]] or list(history["peak"].values()) != [heaps[-1]["peak"]]:
        raise ValueError("Final native statistics and event history disagree")
    region_accounting(proof["ram_sections"], list(history["pools"].values()), True)
    extra = {"native_stack_observations":native_stack_observations(lines,proof,validation)} if proof.get(
        "message_native_stack_coverage") else {}
    if proof.get("application_startup_stack_coverage"):
        from audit_esp32_zephyr_startup_stack import observations
        extra["application_startup_stack"] = observations(lines, proof)
    if validation:
        values = [fields(s) for s in lines if s.startswith("ZEPHYR_RAM validation=")]
        if len(values) != 1 or values[0].get("validation") != "PASS" or values[0]["invalid"] or values[0]["base"] != values[0]["final"] or not (
                values[0]["base"] < values[0]["required_overlap_peak"] <= values[0]["observed_peak"] <= heaps[-1]["peak"]) or lines.count("ZEPHYR_RAM END") != 1 or any("Thread-Metric" in s for s in lines):
            raise ValueError("Separate allocator validation failed")
        if proof.get("task_lifecycle_validation"):
            extra["task_lifecycles"]=task_lifecycles(lines,proof,samples[-1],heaps[-1])
        return {"audit":"pass", "events":len(events), **values[0], **extra}
    original = original_audit(folder / ("reset%d.jsonl" % index), "Zephyr", "message_processing")
    if lines.count("Thread-Metric queue self-check PASS") != 1 or lines.count("TM_Z_RAM END invalid=0 original_reports=3") != 1:
        raise ValueError("Original queue correctness/completion missing")
    roles = [fields(s) for s in lines if s.startswith("ZEPHYR_RAM role=")]
    if roles != [dict(role=r, created=n, dead=0, retired=0, active=n) for r,n in (("worker",2),("main",1),("system",1))]:
        raise ValueError("Original task lifetime/retention differs")
    stacks = [fields(s, 2) for s in lines if s.startswith("ZEPHYR_RAM stack ")]
    if len(stacks) != 4 or len({s["tcb"] for s in stacks}) != 4:
        raise ValueError("Task inventory missing or duplicated")
    workers = []
    for s in stacks:
        if s["role"] == 0:
            base = proof["reservations"]["threads"][0]
            i, rem = divmod(s["tcb"]-base, 96)
            if rem or i not in (0, 5) or s["stack"] != proof["reservations"]["stacks"][0]+i*4096 or s["reserved"] != 4096:
                raise ValueError("Original two static task slots differ")
            workers.append(i)
        elif s["role"] in (1,2):
            stack_name, tcb = ("z_main_stack", "z_main_thread") if s["role"] == 1 else ("z_idle_stacks", "z_idle_threads")
            if [s["stack"], s["reserved"]] != proof["reservations"][stack_name] or s["tcb"] != proof["reservations"][tcb][0]:
                raise ValueError("Main/idle object differs")
        else:
            raise ValueError("Unknown task role")
        if s["generations"] != 1 or any(s[n] for n in ("dead", "joined", "retired")) or s["state"] & 8 or not (
                s["stack"] <= s["start"] < s["start"]+s["span"] <= s["stack"]+s["reserved"]) or s["hwm_measured"] not in (0,1) or not 0 <= s["spare"] <= s["span"]:
            raise ValueError("Retained stack bounds/lifetime differs")
    if sorted(workers) != [0, 5] or samples[0]["created"] != 2 or samples[-1]["created"] != 4 or samples[-1]["peak_active"] != 4 or any(
            s[n] for s in samples for n in ("dead", "joined", "retired")):
        raise ValueError("Lifecycle boundaries disagree")
    if proof.get("native_tick_stack_snapshots"):
        from audit_esp32_zephyr_tick_stacks import observations
        extra["native_tick_stack_snapshots"] = observations(lines,proof,events)
    return {"audit":"pass", "original_message":original, "events":len(events), **extra, "native_heap_peak_bytes":heaps[-1]["peak"],
        "native_heap_final_bytes":heaps[-1]["allocated"], "static_sram_bytes":proof["static_sram_bytes"],
        "heap_and_stacks_already_in_static_sram":True, "roles":roles, "stacks":stacks,
        "whole_live_ram_peak_bytes":None, "ranking_eligible":False}


def task_lifecycles(lines, proof, summary, heap):
    rows=[fields(s) for s in lines if s.startswith("ZEPHYR_TASK_LIFE cycle=")]
    tcb=proof["reservations"]["bench_z_lifecycle_thread"][0]
    stack,size=proof["reservations"]["bench_z_lifecycle_stack"]
    if len(rows)!=4 or any(s.startswith("ZEPHYR_TASK_LIFE failure=") for s in lines):
        raise ValueError("Finite native Zephyr task lifecycles incomplete")
    for index,row in enumerate(rows):
        if row["cycle"]!=index or row["generation"]!=index+1 or row["tcb"]!=tcb or \
                [row["stack"],row["reserved"]]!=[stack,size] or \
                not stack<=row["start"]<row["start"]+row["span"]<=stack+size or \
                not 0<=row["spare"]<=row["span"] or \
                any(row[k]!=1 for k in ("dead","joined","retired")) or \
                row["heap"]!=heap["allocated"] or row["active"]!=summary["active"]:
            raise ValueError("Native task generation, retirement or storage identity differs")
    if [summary[k] for k in ("created","dead","joined","retired","active")] != [6,4,4,4,2]:
        raise ValueError("Native lifecycle counters do not reconcile")
    return {"completed":4,"reused_static_address_pairs":3,"cycles":rows,
            "storage":"same native static TCB and 4096-byte stack, reinitialized only after join",
            "heap_changed_by_tasks":False,"benchmark_result":False,"whole_live_ram_peak_bytes":None}


def collect(root, output, source, port, validation_only=False):
    proof = build_proof(source)
    if validation_only and not proof.get("task_lifecycle_validation"):
        raise ValueError("Validation-only collection requires the finite native lifecycle image")
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build = output / "build"
        build.mkdir()
        for name in ("application.elf", "application.bin"):
            shutil.copyfile(source / name, build / name)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(Path(__file__).with_name("run_esp32_followup.py"), output / "board-helper.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        plan={"resets":5, "seconds":100, "board_mac":MAC,
            "build_manifest_sha256":sha(source / "build.json"), "old_results_replaced":False}
        if validation_only:
            plan.update(seconds=15,validation_only=True)
        (output / "plan.json").write_text(json.dumps(plan,indent=2)+"\n")
        board = Board(root, output, MAC, port)
        campaign = {"mode":"zephyr-message-lifetimes", "status":"incomplete", "board_mac":MAC, "independent_resets":0,
            "started_utc":datetime.now(timezone.utc).isoformat(), "original_flash_restored":False,
            "old_cohort_modified":False, "energy_measured":False, "external_independent_replication":False}
        if validation_only:
            campaign["mode"]="zephyr-message-task-lifecycle-validation"
        try:
            board.backup()
            try:
                captures, validation = output / "captures", output / "validation"
                captures.mkdir()
                validation.mkdir()
                pairs = board.flash(captures, build)
                try:
                    board.capture(validation, 1, 15, stop="ZEPHYR_RAM END", send="validate")
                    first_validation=read_run(validation, 1, proof, validation=True)
                    board.verify(pairs, validation / "verify-run1.log")
                    if validation_only:
                        (validation/"result1.json").write_text(json.dumps(first_validation,indent=2)+"\n")
                        campaign["independent_resets"]=1
                        for index in range(2,6):
                            board.capture(validation,index,15,stop="ZEPHYR_RAM END",send="validate")
                            board.verify(pairs,validation/("verify-run%d.log"%index))
                            result=read_run(validation,index,proof,validation=True)
                            (validation/("result%d.json"%index)).write_text(json.dumps(result,indent=2)+"\n")
                            campaign["independent_resets"]+=1
                            print("ZEPHYR TASK LIFECYCLE",index,result["task_lifecycles"]["completed"],flush=True)
                        campaign["status"]="collection_complete_audit_pending"
                        return
                    for index in range(1, 6):
                        board.capture(captures, index, 100, stop="TM_Z_RAM END")
                        board.verify(pairs, captures / ("verify-run%d.log" % index))
                        result = read_run(captures, index, proof)
                        (captures / ("result%d.json" % index)).write_text(json.dumps(result, indent=2)+"\n")
                        campaign["independent_resets"] += 1
                        print("ZEPHYR MESSAGE RAM", index, result["events"], result["native_heap_peak_bytes"], flush=True)
                    campaign["status"] = "collection_complete_audit_pending"
                finally:
                    board.verify(pairs, captures / "verify-after.log")
            finally:
                board.restore()
                campaign["original_flash_restored"] = True
        finally:
            campaign["completed_utc"] = datetime.now(timezone.utc).isoformat()
            campaign["files"] = {p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file()}
            (output / "campaign.json").write_text(json.dumps(campaign, indent=2)+"\n")


def audit(output, source):
    from audit_esp32_followup import envelope, independent_captures, verified
    campaign, proof = envelope(output), build_proof(source)
    plan = json.loads((output / "plan.json").read_text())
    if campaign["mode"]=="zephyr-message-task-lifecycle-validation":
        if not proof.get("task_lifecycle_validation") or campaign["independent_resets"]!=5 or plan!={
                "resets":5,"seconds":15,"board_mac":MAC,"build_manifest_sha256":sha(source/"build.json"),
                "old_results_replaced":False,"validation_only":True}:
            raise ValueError("Finite native Zephyr lifecycle campaign incomplete or changed")
        for name in ("application.elf","application.bin"):
            if sha(output/"build"/name)!=sha(source/name):
                raise ValueError("Finite validation image changed")
        verified(output/"captures",output/"build",MAC)
        independent_captures(output/"validation",indices=range(1,6))
        runs=[]
        for index in range(1,6):
            verified(output/"validation",output/"build",MAC,logs=("verify-run%d.log"%index,))
            result=read_run(output/"validation",index,proof,validation=True)
            if result!=json.loads((output/"validation"/("result%d.json"%index)).read_text()):
                raise ValueError("Finite validation result differs from raw native replay")
            runs.append(result)
        return {"audit":"pass","os":"Zephyr","independent_resets":5,"build":proof,"runs":runs,
                "original_flash_restored":True,"benchmark_result":False,"whole_live_ram_peak_bytes":None,
                "ranking_eligible":False,"scope":"Separate finite native thread return/join/retirement and static storage reuse; not original workload performance or complete live RAM"}
    if campaign["mode"] != "zephyr-message-lifetimes" or campaign["board_mac"] != MAC or campaign["independent_resets"] != 5 or plan["resets"] != 5 or plan["build_manifest_sha256"] != sha(source / "build.json"):
        raise ValueError("Incomplete/changed experiment")
    for name in ("application.elf", "application.bin"):
        if sha(output / "build" / name) != sha(source / name):
            raise ValueError("Collected image differs from audited build")
    verified(output / "captures", output / "build", MAC)
    independent_captures(output / "captures", indices=range(1,6))
    runs = []
    for i in range(1,6):
        verified(output / "captures", output / "build", MAC, logs=("verify-run%d.log" % i,))
        result = read_run(output / "captures", i, proof)
        if result != json.loads((output / "captures" / ("result%d.json" % i)).read_text()):
            raise ValueError("Stored result disagrees with independent replay")
        runs.append(result)
    verified(output / "validation", output / "build", MAC, logs=("verify-run1.log",))
    return {"audit":"pass", "os":"Zephyr", "independent_resets":5, "build":proof,
        "validation":read_run(output / "validation", 1, proof, validation=True), "runs":runs,
        "original_flash_restored":True, "whole_live_ram_peak_bytes":None, "ranking_eligible":False,
        "scope":"native heap notifications and static task ownership from heap initialization through original third message report; not simultaneous live stack usage"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("build-audit", "collect", "audit"))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--root", type=Path, default=Path.home()/"esp32-pilot")
    p.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    p.add_argument("--validation-only",action="store_true")
    a = p.parse_args()
    if a.mode == "collect":
        def interrupted(signum, frame):
            signal.alarm(0)
            raise RuntimeError("Interrupted; restoring original Flash")
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGALRM,interrupted)
        signal.alarm(1500)
        try:
            collect(a.root, a.output, a.source, a.port, a.validation_only)
        finally:
            signal.alarm(0)
    else:
        value = build_proof(a.source) if a.mode == "build-audit" else audit(a.output, a.source)
        if a.mode == "audit":
            (a.output / "audit.json").write_text(json.dumps(value, indent=2)+"\n")
        print(json.dumps(value, indent=2))
