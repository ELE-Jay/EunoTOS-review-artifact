#!/usr/bin/env python3
"""Collect and replay NuttX native allocated-byte history for original TM message."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal

from nuttx_message_observer import BASE, sources, makefile, COMPACT_CAPACITIES
from run_esp32_followup import Board, sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
OBSERVER = ROOT / "firmware/bsp/esp32/resource_census"
MAC = "34:98:7a:a2:85:28"
IMAGES = ("application.elf", "application.bin", "bootloader.bin", "partitions.bin")


def fields(line, start=1):
    return {k:int(v) if re.fullmatch(r"-?\d+", v) else v for k,v in (s.split("=", 1) for s in line.split()[start:])}


def build_proof(source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import audit_elf_image, static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    from audit_esp32_nuttx_heap_events import STACK_NATIVE
    manifest = json.loads((source / "build.json").read_text())
    identities = manifest.get("allocation_identities", False)
    compact = manifest.get('compact_observer',False)
    if type(compact) is not bool or compact and manifest.get('observer_capacities') != COMPACT_CAPACITIES:
        raise ValueError('Unreviewed compact observation capacities')
    if compact and (sha(source/'compact-protocol.json') != manifest.get('compact_protocol_sha256') or
                    (source/'compact-protocol.json').read_bytes() != (ROOT/'registry/esp32_nuttx_compact_ram_v1.json').read_bytes()):
        raise ValueError('Compact observation protocol changed')
    lifecycle = manifest.get("task_lifecycle_validation", False)
    if type(lifecycle) is not bool or lifecycle and not identities:
        raise ValueError("Invalid finite task lifecycle validation mode")
    startup = manifest.get("application_startup_stack_coverage",False)
    tick = manifest.get('native_tick_stack_snapshots',False)
    control = manifest.get('native_tick_same_image_control',False)
    if type(control) is not bool or control and not tick:
        raise ValueError("Invalid same-image diagnostic mode")
    if type(startup) is not bool or type(tick) is not bool or startup and not identities or tick and not startup:
        raise ValueError("Invalid native startup observation mode")
    if type(identities) is not bool:
        raise ValueError("Invalid allocation identity mode")
    if manifest["status"] != "build_pass_not_measured" or not manifest.get("message_lifetimes") or manifest["ranking_eligible"]:
        raise ValueError("Build evidence misqualified")
    for name, digest in manifest["files"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source.resolve()) or sha(path) != digest:
            raise ValueError("Changed build evidence: " + name)
    reference = REPORTS / BASE
    for name in ("iotosbench_main.c", "port.c", "test.c", "tm_override.h"):
        if (source / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError("Original workload changed: " + name)
    for name in ("tm_api.h", "tm_porting_layer.h", "tm_message_processing_test.c"):
        if (source / name).read_bytes() != (ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / name).read_bytes():
            raise ValueError("Original Thread-Metric body/API changed")
    if (source / "Makefile").read_text() != makefile((reference / "Makefile").read_text(),startup=startup):
        raise ValueError("Compilation rule differs")
    for name, content in sources(OBSERVER, identities=identities,startup=startup,tick=tick,control=control,lifecycle=lifecycle,compact=compact).items():
        if (source / name).read_text() != content:
            raise ValueError("Unreviewed observer: " + name)
    old = REPORTS / "esp32-nuttx-retained-owners-v1"
    if (source / "allocator.patch").read_bytes() != (OBSERVER / "nuttx_heap_events/allocator.patch").read_bytes():
        raise ValueError("Changed native event points")
    for name in STACK_NATIVE:
        expected=(old / "native-source" / name).read_text()
        if startup:
            from nuttx_message_startup import NATIVE,instrument
            if name==NATIVE:
                if (source/"startup-original.c").read_text()!=expected:
                    raise ValueError("Native entry input differs")
                expected=instrument(expected)
        if (source / "native-source" / name).read_text()!=expected:
            raise ValueError("Native stack implementation changed")
    paths = sorted((source / "native-source/mm/mm_heap").glob("*"))
    if {p.name for p in paths} != {p.name for p in (old / "native-source/mm/mm_heap").glob("*")}:
        raise ValueError("Native allocator source inventory differs")
    for path in paths:
        expected = (old / "native-source/mm/mm_heap" / path.name).read_text()
        if identities:
            from nuttx_message_identities import instrument
            expected = instrument(path.name, expected)
        if path.read_text() != expected:
            raise ValueError("Native allocator differs from previously audited source: " + path.name)
    if identities:
        import difflib
        from nuttx_message_identities import EDITS, instrument
        expected_patch = "".join(line for name in EDITS for line in difflib.unified_diff(
            (old / "native-source/mm/mm_heap" / name).read_text().splitlines(True),
            instrument(name, (old / "native-source/mm/mm_heap" / name).read_text()).splitlines(True),
            fromfile="a/mm/mm_heap/"+name, tofile="b/mm/mm_heap/"+name))
        if (source / "identity.patch").read_text() != expected_patch:
            raise ValueError("Address-bearing native patch differs")
    clean = lambda p: {l for l in p.read_text().splitlines() if l.startswith("CONFIG_") and not l.startswith(
        ("CONFIG_BASE_DEFCONFIG=", "CONFIG_STACK_COLORATION="))}
    if (source / "reference-config").read_bytes() != (reference / "config").read_bytes() or clean(source / "config") != clean(reference / "config"):
        raise ValueError("Original configuration changed")
    cfg = (source / "config").read_text().splitlines()
    if any(s not in cfg for s in ("CONFIG_STACK_COLORATION=y", "CONFIG_USEC_PER_TICK=10000", "CONFIG_ARCH_INTERRUPTSTACK=0")) or "13.2.0" not in (source / "compiler.txt").read_text():
        raise ValueError("Observation/compiler/clock profile differs")
    for new, old_name in (("bootloader.bin", "bootloader-esp32.bin"), ("partitions.bin", "partition-table-esp32.bin")):
        if sha(source / new) != sha(reference / old_name):
            raise ValueError("Boot layout changed")
    audit_elf_image(source / "application.elf", source / "application.bin")
    footprint = static_footprint(source / "application.elf")
    reservations = {}
    with (source / "application.elf").open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        capacities = COMPACT_CAPACITIES if compact else {'events':1024,'stack_events':128,'stack_slots':128,'identities':256,'live_blocks':256}
        fixed = [("message_events", capacities['events']*16), ("message_stacks", capacities['stack_events']*20), ("g_idlestack", 3072)]
        if identities:
            fixed += [("message_identities", capacities['identities']*24), ("message_live", capacities['live_blocks']*8)]
        if compact:
            fixed += [('stacks',capacities['stack_slots']*12),('block_bytes',capacities['stack_slots']*4)]
        for name, size in fixed:
            found = symbols.get_symbol_by_name(name) or []
            if len(found) != 1 or found[0]["st_size"] != size:
                raise ValueError("Static observer/idle reservation differs: " + name)
            reservations[name] = [found[0]["st_value"], size]
        reservations["heap_start"] = (symbols.get_symbol_by_name("_sheap")[0]["st_value"]+7)&~7
    required = [("mm_initialize", "bench_ram_heap_init"), ("mm_addregion", "bench_ram_heap_delta"),
        ("mm_malloc", "bench_ram_heap_delta"), ("mm_free", "bench_ram_heap_delta"),
        ("mm_shrinkchunk", "bench_ram_heap_delta"), ("mm_realloc", "bench_ram_heap_delta"),
        ("mm_memalign", "bench_ram_heap_delta"), ("base_create_stack", "up_create_stack"),
        ("base_release_stack", "up_check_tcbstack"), ("base_release_stack", "up_release_stack"),
        ("__wrap_up_create_stack", "base_create_stack"), ("__wrap_up_release_stack", "base_release_stack"),
        ("__wrap_up_use_stack", "up_use_stack"), ("__wrap_iotosbench_main", "iotosbench_main"),
        ("tm_message_processing_thread_report", "__wrap_tm_thread_sleep")]
    if identities:
        required += [(name, "bench_ram_heap_identity") for name in
            ("mm_malloc", "mm_free", "mm_shrinkchunk", "mm_realloc", "mm_memalign")]
    if lifecycle:
        required += [("bench_n_validate_task_lifetimes", "pthread_create"),
                     ("bench_n_validate_task_lifetimes", "pthread_join")]
    machine = calls(source, required, require_iram=False)
    extra={}
    if startup:
        from audit_esp32_nuttx_message_startup import build as startup_build
        extra=startup_build(source,reservations)
    if tick:
        from audit_esp32_nuttx_tick_stacks import build as tick_build
        extra.update(tick_build(source))
    if control:
        extra.update(native_tick_same_image_control=True)
    if lifecycle:
        extra.update(task_lifecycle_validation=True)
    if compact:
        extra.update(compact_observer=True,observer_capacities=COMPACT_CAPACITIES)
    return {"audit":"pass", **footprint, "reservations":reservations, "machine_calls":machine,
        "baseline_static_sram_bytes":static_footprint(reference / "nuttx")["static_sram_bytes"],
        "original_workload_unchanged":True, "clock_mhz":240, "cores":1, "tick_hz":100,
        **({"allocation_identities":True} if identities else {}),**extra}


def replay(events):
    used = peak = 0
    counts = [0]*7
    for index, e in enumerate(events):
        k, delta = e["kind"], e["delta"]
        if e["event"] != index or k not in range(7) or (index == 0) != (k == 0):
            raise ValueError("Missing, reordered or unknown native event")
        if (k == 0 and delta != 368) or (k == 6 and delta != 16) or (k == 1 and delta <= 0) or (
                k in (2,5) and delta >= 0) or (k == 3 and delta > 0) or (k == 4 and delta < 0) or delta % 8:
            raise ValueError("Invalid allocator transition")
        used += delta
        peak = max(peak, used)
        counts[k] += 1
        if used < 368 or (e["occupied"], e["peak"]) != (used, peak):
            raise ValueError("Native current/peak disagrees with event replay")
    if not events or not counts[6]:
        raise ValueError("Missing heap initialization/region evidence")
    return {"occupied":used, "peak":peak, "counts":counts}


def stack_replay(events, regions):
    live, created, retired, peak = {}, 0, 0, 0
    for i, e in enumerate(events):
        tcb, pointer, usable, block = (e[n] for n in ("tcb", "allocation", "usable", "block"))
        if e["event"] != i or e["kind"] not in (1,2) or not 0 < usable <= block-8 or block % 8 or not any(
                start < pointer-8 < pointer+usable <= pointer-8+block < start+length for start,length in regions):
            raise ValueError("Stack history/bounds invalid")
        record = (pointer, usable, block)
        if e["kind"] == 1:
            if tcb in live:
                raise ValueError("Unretired stack reused")
            live[tcb] = record
            created += 1
        elif live.pop(tcb, None) != record:
            raise ValueError("Retirement without matching stack allocation")
        else:
            retired += 1
        intervals = sorted((p-8,p-8+b) for p,u,b in live.values())
        if any(a[1] > b[0] for a,b in zip(intervals,intervals[1:])):
            raise ValueError("Live stack blocks overlap")
        peak = max(peak, sum(b for p,u,b in live.values()))
    return {"live":live, "created":created, "retired":retired, "peak":peak}


def task_lifecycles(lines, events, tasks):
    cycles = [fields(s) for s in lines if s.startswith("NUTTX_TASK_LIFE cycle=")]
    if len(cycles) != 4:
        raise ValueError("Finite task lifecycles are incomplete")
    pairs, previous_event, previous_stack = [], 0, 0
    for i, row in enumerate(cycles):
        begin, end = row["before_event"], row["after_event"]
        first, last = row["before_stack"], row["after_stack"]
        if row["cycle"] != i or not previous_event <= begin < end <= len(events) or \
                not previous_stack <= first < last <= len(tasks) or last - first != 2 or \
                row["base"] != row["final"] or \
                any(replay(events[:j])["occupied"] != row["base"] for j in (begin, end)):
            raise ValueError("Task lifecycle boundaries or native heap baseline differ")
        if not begin < row["reclaim_event"] < end or \
                replay(events[:row["reclaim_event"]])["occupied"] != row["joined_occupied"]:
            raise ValueError("Post-join native deferred-free boundary differs")
        created, retired = tasks[first:last]
        names = ("tcb", "allocation", "usable", "block")
        if created["kind"] != 1 or retired["kind"] != 2 or \
                any(created[k] != retired[k] for k in names):
            raise ValueError("Task lifecycle lacks matching native stack retirement")
        pairs.append((created["tcb"], created["allocation"]))
        previous_event, previous_stack = end, last
    if len({(r["base"], r["active"]) for r in cycles}) != 1:
        raise ValueError("Task validation did not restore a stable native baseline")
    return {"completed":4, "reused_address_pairs":4-len(set(pairs)),
            "heap_returned_to_base":cycles[0]["base"], "cycles":cycles,
            "benchmark_result":False, "whole_live_ram_peak_bytes":None}


def read_run(folder, index, proof, validation=False):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_tm_basic import audit as original_audit
    from audit_esp32_ram_census import region_accounting
    lines = [r["line"] for r in read_raw_capture(folder, index)]
    if sum(s.startswith("rst:0x") for s in lines) != 1 or lines.count(
            "NUTTX_MESSAGE_RAM BEGIN clock_hz=240000000 cores=1 tick_hz=100 window=heap-init-through-third-message-report") != 1 or any(
            re.search(r"panic|fatal|assert|Exception|error:", s, re.I) for s in lines):
        raise ValueError("Boot/profile/error check failed")
    layout = [fields(s, 2) for s in lines if s.startswith("TM_N_RAM layout ")]
    if layout != [{"heap":proof["reservations"]["heap_start"], "control_bytes":368, "node_bytes":8}]:
        raise ValueError("Native heap ABI/placement differs")
    regions = [(r["start"],r["end"]-r["start"]) for r in (fields(s,2) for s in lines if s.startswith("RAM_EVENTS region "))]
    if not regions or regions[0][0] != layout[0]["heap"]+368:
        raise ValueError("Native heap region/control prefix differs")
    region_accounting(proof["ram_sections"], regions+[(layout[0]["heap"],368)], False)
    events = [fields(s) for s in lines if s.startswith("TM_N_RAM event=")]
    tasks = [fields(s) for s in lines if s.startswith("TM_N_STACK event=")]
    caps = proof.get('observer_capacities',{'events':1024,'stack_events':128})
    if [fields(s,2) for s in lines if s.startswith("TM_N_RAM trace ")] != [{"events":len(events), "stacks":len(tasks), "overflow":0}] or not 0 < len(events) <= caps['events'] or not 0 < len(tasks) <= caps['stack_events']:
        raise ValueError("Missing/overflowed buffered history")
    history, task_history = replay(events), stack_replay(tasks, regions)
    identity_result = {}
    if proof.get("allocation_identities"):
        from nuttx_message_identities import replay as replay_identities
        transitions = [fields(s) for s in lines if s.startswith("TM_N_ID at=")]
        blocks = [fields(s,2) for s in lines if s.startswith("TM_N_ID live ")]
        trace = [fields(s,2) for s in lines if s.startswith("TM_N_ID trace ")]
        identity_result = replay_identities(events, transitions, regions, layout[0]["heap"])
        live_set = {b["pointer"]:b["bytes"] for b in blocks}
        if len(live_set) != len(blocks) or live_set != identity_result["live"] or trace != [{
                "transitions":len(transitions), "live":len(blocks), "overflow":0}]:
            raise ValueError("Replayed live allocation set differs from native block walk")
        if any(live_set.get(pointer) != block for pointer,usable,block in task_history["live"].values()):
            raise ValueError("Live stack allocation is absent from heap identity set")
    samples = [fields(s) for s in lines if s.startswith("RAM_EVENTS phase=")]
    if not samples or any(s["invalid"] or s["oracle"] <= 0 or not 368 <= s["occupied"] <= s["peak"] <= 368+sum(n for _,n in regions) for s in samples):
        raise ValueError("Native heap walk invalid/out of bounds")
    final = samples[-1]
    if (final["occupied"],final["peak"]) != (history["occupied"],history["peak"]) or [final[n] for n in (
            "malloc", "free", "shrink", "grow", "align", "regions")] != history["counts"][1:]:
        raise ValueError("Native heap walk/counters disagree with complete history")
    startup={}
    if proof.get("application_startup_stack_coverage"):
        from nuttx_message_startup import observations
        startup={"application_startup_stack":observations(lines,proof)}
    if validation:
        values = [fields(s) for s in lines if s.startswith("RAM_EVENTS validation=")]
        if len(values) != 1 or values[0]["validation"] != "PASS" or values[0]["base"] != values[0]["final"] or not all(history["counts"][1:]) or lines.count("NUTTX_MESSAGE_RAM VALIDATION END") != 1 or any("Thread-Metric" in s for s in lines):
            raise ValueError("Separate allocator validation failed")
        lifetimes = {"task_lifecycles":task_lifecycles(lines,events,tasks)} if proof.get("task_lifecycle_validation") else {}
        return {"audit":"pass", "events":len(events), "peak":history["peak"], **values[0], **lifetimes,
            **({"allocation_identity_replay":identity_result} if identity_result else {}),**startup}
    original = original_audit(folder / ("reset%d.jsonl" % index), "NuttX", "message_processing")
    if lines.count("Thread-Metric queue self-check PASS") != 1 or lines.count("NUTTX_MESSAGE_RAM END invalid=0 original_reports=3") != 1 or [s["phase"] for s in samples] != ["application-entry", "message-end"]:
        raise ValueError("Original queue correctness/boundary incomplete")
    live = [fields(s,2) for s in lines if s.startswith("TM_N_STACK live ")]
    if len(live) != len(task_history["live"]) or len({s["tcb"] for s in live}) != len(live) or any(
            task_history["live"].get(s["tcb"]) != (s["allocation"],s["usable"],s["block"]) or not 0 <= s["high_water"] <= s["usable"] for s in live):
        raise ValueError("Final live stacks disagree with lifecycle replay")
    summary = [fields(s,2) for s in lines if s.startswith("TM_N_STACK summary ")]
    expected = {"created":task_history["created"], "retired":task_history["retired"], "active":len(live),
        "block_live":sum(s["block"] for s in live), "block_peak":task_history["peak"], "use_calls":0, "use_success":0, "invalid":0}
    if summary != [expected]:
        raise ValueError("Stack ownership counters disagree with event replay")
    idle = [fields(s,2) for s in lines if s.startswith("TM_N_STACK idle ")]
    if len(idle) != 1 or [idle[0]["address"],idle[0]["reserved"]] != proof["reservations"]["g_idlestack"] or idle[0]["irq_stack"] != "interrupted-task" or not 0 <= idle[0]["high_water"] <= idle[0]["reserved"]:
        raise ValueError("Static idle/interrupt stack scope differs")
    if proof.get('native_tick_stack_snapshots'):
        from audit_esp32_nuttx_tick_stacks import observations
        startup['native_tick_stack_snapshots']=observations(lines,proof,events,live)
        if proof.get('native_tick_same_image_control'):
            from audit_esp32_nuttx_tick_stacks import probe_cost
            startup['native_tick_probe_cost']=probe_cost(lines,startup['native_tick_stack_snapshots']['samples'])
    return {"audit":"pass", "original_message":original, "events":len(events), "native_heap_peak_bytes":history["peak"],
        "native_heap_final_bytes":history["occupied"], "static_sram_bytes":proof["static_sram_bytes"],
        "observed_allocated_software_bytes":proof["static_sram_bytes"]+history["peak"],
        "stack_summary":expected, "stacks":live, "idle":idle[0], "native_heap_regions":regions,
        "whole_live_ram_peak_bytes":None, "ranking_eligible":False,
        **({"allocation_identity_replay":identity_result} if identity_result else {}),**startup}


def reusable_first(previous,source,proof):
    from audit_esp32_followup import envelope,verified
    campaign=envelope(previous,allow_incomplete=True)
    plan=json.loads((previous/'plan.json').read_text())
    if campaign['mode']!='nuttx-message-lifetimes' or campaign['board_mac']!=MAC or \
            campaign['status']!='incomplete' or campaign['independent_resets'] not in (0,1) or \
            plan['resets']!=5 or plan['build_manifest_sha256']!=sha(source/'build.json'):
        raise ValueError('Previous first reset is not the same interrupted frozen experiment')
    for name in IMAGES:
        if sha(previous/'build'/name)!=sha(source/name):raise ValueError('Previous firmware differs')
    verified(previous/'captures',previous/'build',MAC)
    verified(previous/'captures',previous/'build',MAC,logs=('verify-run1.log',))
    return read_run(previous/'captures',1,proof)


def collect(root, output, source, port, reuse_first=None, validation_only=False):
    proof = build_proof(source)
    if validation_only and (not proof.get("task_lifecycle_validation") or reuse_first):
        raise ValueError("Validation-only capture requires the finite native lifecycle image")
    reused=reusable_first(reuse_first,source,proof) if reuse_first else None
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build = output / "build"
        build.mkdir()
        for name in IMAGES:
            shutil.copyfile(source / name, build / name)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(Path(__file__).with_name("run_esp32_followup.py"), output / "board-helper.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        plan={"resets":5, "seconds":110, "board_mac":MAC,
            "build_manifest_sha256":sha(source / "build.json"), "old_results_replaced":False}
        if validation_only:
            plan.update(seconds=25, validation_only=True)
        if reused:
            plan.update(reused_first_reset=True,reuse_reason='native TLS/argv logical stack-boundary validator correction',
                reused_first_campaign_sha256=sha(reuse_first/'campaign.json'))
            shutil.copytree(reuse_first,output/'reused-first-source')
        (output / "plan.json").write_text(json.dumps(plan, indent=2)+"\n")
        board = Board(root, output, MAC, port)
        campaign = {"mode":"nuttx-message-lifetimes", "status":"incomplete", "board_mac":MAC, "independent_resets":0,
            "started_utc":datetime.now(timezone.utc).isoformat(), "original_flash_restored":False,
            "old_cohort_modified":False, "energy_measured":False, "external_independent_replication":False}
        if validation_only:
            campaign["mode"] = "nuttx-message-task-lifecycle-validation"
        try:
            board.backup()
            try:
                captures, validation = output / "captures", output / "validation"
                captures.mkdir()
                validation.mkdir()
                pairs = board.flash(captures, build)
                try:
                    board.capture(validation, 1, 25, stop="NUTTX_MESSAGE_RAM VALIDATION END", send="iotosbench --validate-observer")
                    first_validation = read_run(validation, 1, proof, validation=True)
                    board.verify(pairs, validation / "verify-run1.log")
                    if validation_only:
                        (validation / "result1.json").write_text(json.dumps(first_validation,indent=2)+"\n")
                        campaign["independent_resets"] = 1
                        for index in range(2,6):
                            board.capture(validation,index,25,stop="NUTTX_MESSAGE_RAM VALIDATION END",send="iotosbench --validate-observer")
                            board.verify(pairs,validation/("verify-run%d.log"%index))
                            result = read_run(validation,index,proof,validation=True)
                            (validation/("result%d.json"%index)).write_text(json.dumps(result,indent=2)+"\n")
                            campaign["independent_resets"] += 1
                            print("NUTTX TASK LIFECYCLE",index,result["task_lifecycles"]["completed"],flush=True)
                        campaign["status"] = "collection_complete_audit_pending"
                        return
                    if reused:
                        for name in ('reset1.jsonl','reset1.raw','capture1.log','verify-run1.log'):
                            shutil.copyfile(reuse_first/'captures'/name,captures/name)
                        (captures/'result1.json').write_text(json.dumps(reused,indent=2)+'\n')
                        campaign['independent_resets']=1
                        print('NUTTX MESSAGE RAM first reset reused after corrected logical bounds',flush=True)
                    for index in range(2 if reused else 1, 6):
                        board.capture(captures, index, 110, stop="NUTTX_MESSAGE_RAM END", send="iotosbench")
                        board.verify(pairs, captures / ("verify-run%d.log" % index))
                        result = read_run(captures, index, proof)
                        (captures / ("result%d.json" % index)).write_text(json.dumps(result, indent=2)+"\n")
                        campaign["independent_resets"] += 1
                        print("NUTTX MESSAGE RAM", index, result["events"], result["native_heap_peak_bytes"], flush=True)
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
    if campaign["mode"] == "nuttx-message-task-lifecycle-validation":
        if not proof.get("task_lifecycle_validation") or campaign["independent_resets"] != 5 or plan != {
                "resets":5,"seconds":25,"board_mac":MAC,"build_manifest_sha256":sha(source/"build.json"),
                "old_results_replaced":False,"validation_only":True}:
            raise ValueError("Finite lifecycle validation campaign is incomplete or changed")
        for name in IMAGES:
            if sha(output/"build"/name) != sha(source/name):
                raise ValueError("Lifecycle validation image changed")
        verified(output/"captures",output/"build",MAC)
        independent_captures(output/"validation",indices=range(1,6))
        runs=[]
        for index in range(1,6):
            verified(output/"validation",output/"build",MAC,logs=("verify-run%d.log"%index,))
            result=read_run(output/"validation",index,proof,validation=True)
            if json.loads(json.dumps(result)) != json.loads((output/"validation"/("result%d.json"%index)).read_text()):
                raise ValueError("Lifecycle validation result differs from native raw replay")
            runs.append(result)
        return {"audit":"pass","os":"NuttX","independent_resets":5,"build":proof,"runs":runs,
                "original_flash_restored":True,"benchmark_result":False,"whole_live_ram_peak_bytes":None,
                "ranking_eligible":False,"scope":"Separate finite native pthread creation, join, stack retirement and heap return; not original workload performance or complete RAM peak"}
    extensions={'reused_first_reset','reuse_reason','reused_first_campaign_sha256'}
    base_plan={k:v for k,v in plan.items() if k not in extensions}
    if campaign["mode"] != "nuttx-message-lifetimes" or campaign["board_mac"] != MAC or campaign["independent_resets"] != 5 or base_plan != {
            "resets":5, "seconds":110, "board_mac":MAC, "build_manifest_sha256":sha(source / "build.json"), "old_results_replaced":False}:
        raise ValueError("Incomplete/changed experiment")
    for name in IMAGES:
        if sha(output / "build" / name) != sha(source / name):
            raise ValueError("Collected image differs from audited build")
    verified(output / "captures", output / "build", MAC)
    independent_captures(output / "captures", indices=range(1,6))
    runs = []
    for i in range(1,6):
        verified(output / "captures", output / "build", MAC, logs=("verify-run%d.log" % i,))
        result = read_run(output / "captures", i, proof)
        if json.loads(json.dumps(result)) != json.loads((output / "captures" / ("result%d.json" % i)).read_text()):
            raise ValueError("Stored result disagrees with raw replay")
        runs.append(result)
    if plan.get('reused_first_reset'):
        previous=output/'reused-first-source'
        if plan['reuse_reason']!='native TLS/argv logical stack-boundary validator correction' or \
                sha(previous/'campaign.json')!=plan['reused_first_campaign_sha256'] or \
                reusable_first(previous,source,proof)!=runs[0]:
            raise ValueError('Reused native first-reset identity/result differs')
        for name in ('reset1.jsonl','reset1.raw','capture1.log','verify-run1.log'):
            if (previous/'captures'/name).read_bytes()!=(output/'captures'/name).read_bytes():
                raise ValueError('Reused original raw evidence changed')
    elif any(k in plan for k in extensions):
        raise ValueError('Unexpected reuse fields')
    verified(output / "validation", output / "build", MAC, logs=("verify-run1.log",))
    return {"audit":"pass", "os":"NuttX", "independent_resets":5, "build":proof,
        **({'reused_resets':1} if plan.get('reused_first_reset') else {}),
        "validation":read_run(output / "validation", 1, proof, validation=True), "runs":runs,
        "original_flash_restored":True, "whole_live_ram_peak_bytes":None, "ranking_eligible":False,
        "scope":("all native allocation addresses, sizes, resize/free transitions and stack block lifetimes through original third message report; final live set equals native block walk; not exact live RAM"
            if proof.get("allocation_identities") else
            "all native allocated-byte deltas and stack block lifetimes from heap initialization through original third message report; not allocation-pointer replay or exact live RAM")}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("build-audit", "collect", "audit"))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--root", type=Path, default=Path.home()/"esp32-pilot")
    p.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    p.add_argument('--reuse-first',type=Path)
    p.add_argument('--validation-only',action='store_true')
    a = p.parse_args()
    if a.mode == "collect":
        def interrupted(signum,frame):
            signal.alarm(0)
            raise RuntimeError('Interrupted; restoring original Flash')
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGALRM,interrupted)
        signal.alarm(1500)
        try:
            collect(a.root, a.output, a.source, a.port,a.reuse_first,a.validation_only)
        finally:
            signal.alarm(0)
    else:
        value = build_proof(a.source) if a.mode == "build-audit" else audit(a.output, a.source)
        if a.mode == "audit":
            (a.output / "audit.json").write_text(json.dumps(value, indent=2)+"\n")
        print(json.dumps(value, indent=2))
