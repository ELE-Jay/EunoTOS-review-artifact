#!/usr/bin/env python3
"""Replay native allocator events and stack lifetimes, not simultaneous live RAM."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.request import urlopen

from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_hartstone_series import audit as series
from audit_esp32_resources import audit_elf_image, static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "firmware/bsp/esp32/resource_census/nuttx_heap_events"
REFERENCE = ROOT / "artifacts/reports/ram-hartstone-nuttx-v4/nuttx/ph4"
WORKLOAD = ROOT / "artifacts/reports/hartstone-native-us-v1/nuttx/ph4"
PATCHED = ("mm.h", "mm_initialize.c", "mm_malloc.c", "mm_free.c", "mm_shrinkchunk.c", "mm_realloc.c", "mm_memalign.c")
SAMPLE = re.compile(r"RAM_EVENTS phase=(\S+) occupied=(\d+) peak=(\d+) invalid=(\d+) oracle=(\d+) malloc=(\d+) free=(\d+) shrink=(\d+) grow=(\d+) align=(\d+) regions=(\d+)")
STACK_NATIVE = ("arch/xtensa/src/common/xtensa_createstack.c", "arch/xtensa/src/common/xtensa_releasestack.c",
                "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_initialstate.c",
                "arch/xtensa/src/esp32/esp32_start.c", "sched/init/nx_start.c")
STACK_UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
CLEANUP_NATIVE = ("sched/sched/sched_releasetcb.c", "sched/task/task_terminate.c", "sched/task/task_exit.c")
CLEANUP_APPS = ("nshlib/nsh_builtin.c", "builtin/exec_builtin.c")
APPS_UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/"
OWNERS_NATIVE = ("sched/task/task_setup.c", "sched/sched/sched.h",
                 "arch/xtensa/src/esp32/esp32_rt_timer.c", "arch/xtensa/src/esp32/esp32_rt_timer.h")


def verify_stack_sources(folder):
    import hashlib
    rows = []
    for name in STACK_NATIVE:
        with urlopen(STACK_UPSTREAM + name, timeout=60) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        if digest != sha(folder / "native-source" / name):
            raise ValueError("Native stack source differs from fixed official version: " + name)
        rows.append({"path": name, "url": STACK_UPSTREAM + name, "sha256": digest})
    (folder / "official-stack-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def verify_cleanup_sources(folder):
    import hashlib
    rows = []
    for prefix, paths, upstream in (("native-source/", CLEANUP_NATIVE, STACK_UPSTREAM),
                                    ("apps-source/", CLEANUP_APPS, APPS_UPSTREAM)):
        for name in paths:
            with urlopen(upstream + name, timeout=60) as response:
                digest = hashlib.sha256(response.read()).hexdigest()
            if digest != sha(folder / (prefix + name)):
                raise ValueError("Cleanup source differs from fixed official version: " + name)
            rows.append({"path": prefix + name, "url": upstream + name, "sha256": digest})
    (folder / "official-cleanup-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def verify_owner_sources(folder):
    import hashlib
    rows = []
    for name in OWNERS_NATIVE:
        with urlopen(STACK_UPSTREAM + name, timeout=60) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        if digest != sha(folder / "native-source" / name):
            raise ValueError("Native retained-owner source differs from fixed upstream: " + name)
        rows.append({"path":name,"url":STACK_UPSTREAM+name,"sha256":digest})
    (folder / "official-owner-source.json").write_text(json.dumps(rows,indent=2)+"\n")


def retained_owners(lines, teardown, worker_count, worker_lifetimes, layout, queue_region, regions):
    if layout is None or queue_region is None:
        raise ValueError("Retained object layout/queue must be bound to the actual image")
    hashes = [tuple(map(int,m.groups())) for line in lines if (m:=re.fullmatch(
        r"RAM_OWNERS pidhash before_slots=(\d+) before_block=(\d+) after_slots=(\d+) after_block=(\d+) allocation=(\d+)",line))]
    timers = [tuple(map(int,m.groups())) for line in lines if (m:=re.fullmatch(
        r"RAM_OWNERS timer allocation=(\d+) block=(\d+) state=(\d+) link=(\d+) prev=(\d+) next=(\d+)",line))]
    totals = [tuple(map(int,m.groups())) for line in lines if (m:=re.fullmatch(
        r"RAM_OWNERS summary created=(\d+) delete_requested=(\d+) pending=(\d+) pending_bytes=(\d+) hash_delta=(\d+) invalid=(\d+)",line))]
    parent_stack = [tuple(map(int,m.groups())) for line in lines if (m:=re.fullmatch(
        r"RAM_OWNERS parent_stack bytes=(\d+) high_water=(\d+)",line))]
    if len(hashes)!=1 or len(totals)!=1 or len(parent_stack)!=1 or not 0<parent_stack[0][1]<parent_stack[0][0] or lines.count("RAM_OWNERS END")!=1:
        raise ValueError("Native retained ownership records incomplete")
    initial_slots,initial_block,slots,hash_block,hash_pointer = hashes[0]
    created,deleted,pending,timer_bytes,hash_delta,bad = totals[0]
    if created!=worker_lifetimes or deleted!=created or pending!=worker_count or len(timers)!=pending or bad or \
            any(v<=0 or v&(v-1) for v in (initial_slots,slots)) or initial_slots>slots or \
            initial_block != ((initial_slots*layout[3]+15)&~7) or hash_block != ((slots*layout[3]+15)&~7) or \
            hash_delta!=hash_block-initial_block or sum(t[1] for t in timers)!=timer_bytes or \
            hash_delta+timer_bytes!=teardown["allocated_delta_bytes"] or \
            any(t[1]!=((layout[0]+15)&~7) or t[2]!=layout[2] or t[3]!=t[0]+layout[1] for t in timers):
        raise ValueError("Native PID-table/timer ownership does not reconcile with observed retained allocation")
    intervals = sorted([(p-8,p-8+size) for p,size,*_ in timers]+[(hash_pointer-8,hash_pointer-8+hash_block)])
    if any(a[1]>b[0] for a,b in zip(intervals,intervals[1:])) or any(
            not any(start<=a<b<=end for start,end in regions) for a,b in intervals):
        raise ValueError("Retained object heap ranges overlap or escape observed regions")
    links = {t[3]:t for t in timers}
    anchors = {p for t in timers for p in t[4:]}-set(links)
    if len(links)!=pending or len(anchors)!=1:
        raise ValueError("Native pending timer ring is incomplete")
    head = anchors.pop()
    if not queue_region[0]<=head<head+8<=queue_region[0]+queue_region[1]:
        raise ValueError("Pending timer list anchor lies outside the native timer state")
    first = [t[3] for t in timers if t[4]==head]
    if len(first)!=1:
        raise ValueError("Pending timer ring lacks a unique native list head")
    visited,previous,node = set(),head,first[0]
    while node!=head:
        if node in visited or node not in links or links[node][4]!=previous:
            raise ValueError("Pending timer ring is not reciprocal/complete")
        visited.add(node)
        previous,node = node,links[node][5]
    if len(visited)!=pending:
        raise ValueError("Pending timer ring omits recorded timers")
    return {"allocated_delta_fully_attributed":True,"allocated_delta_bytes":teardown["allocated_delta_bytes"],
        "pid_table":{"before_slots":initial_slots,"after_slots":slots,"before_block_bytes":initial_block,
                     "after_block_bytes":hash_block,"allocated_delta_bytes":hash_delta,"allocation":hash_pointer},
        "pending_native_timers":{"created":created,"delete_requested":deleted,"pending":pending,
            "allocated_bytes":timer_bytes,"native_list_head":head,"records":timers,"ring_verified":True},
        "parent_stack":{"native_usable_bytes":parent_stack[0][0],"high_water_bytes":parent_stack[0][1],"allocation_already_in_heap":True},
        "meaning":"native PID-table capacity and timer blocks queued for asynchronous deletion; still allocated, not subtracted from RAM"}


def cleanup_lifecycle(lines, samples, stacks, worker_lifetimes):
    maintenance = "RAM_CLEANUP maintenance=malloc-free requested=1 after-original-workload=1" in lines
    phases = ["parent-before-launch", "application-entry", "series-return", "parent-after-cleanup"]
    if maintenance:
        phases += ["parent-after-native-reclaim"]
    baseline = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_CLEANUP baseline parent=(\d+) occupied=(\d+) active=(\d+) blocks=(\d+) created=(\d+) retired=(\d+)", line))]
    launch = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_CLEANUP identity controller=(\d+) parent=(\d+)", line))]
    final = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_CLEANUP final controller=(\d+) parent=(\d+) wait_result=(\d+) status=(\d+) released=(\d+) absent=(\d+) occupied=(\d+) peak=(\d+) active=(\d+) blocks=(\d+) created=(\d+) retired=(\d+) invalid=(\d+)", line))]
    records = {phase: [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_CLEANUP stack phase=" + phase + r" pid=(\d+) allocation=(\d+) usable=(\d+) block=(\d+)", line))]
        for phase in ("before", "after")}
    if len(baseline) != 1 or len(launch) != 1 or len(final) != 1 or lines.count("RAM_CLEANUP END") != 1:
        raise ValueError("Native post-exit cleanup boundary incomplete")
    parent, before, active, blocks, created, retired = baseline[0]
    pid, owner, waited, status, released, absent, after, maximum, remaining, live_blocks, made, freed, bad = final[0]
    if launch[0] != (pid, parent) or owner != parent or waited != pid or status or released != 1 or absent != 1 or bad or \
            pid == parent or remaining != active or live_blocks != blocks or len(records["before"]) != active or \
            sorted(records["before"]) != sorted(records["after"]) or \
            sum(r[3] for r in records["after"]) != blocks or \
            made != created + worker_lifetimes + 1 or freed != retired + worker_lifetimes + 1 or \
            made != stacks[0] or freed != stacks[1] + 1 or remaining != stacks[2] - 1 or \
            [r["phase"] for r in samples] != phases or \
            (before, after, maximum) != (samples[0]["occupied"], samples[-1]["occupied"], samples[-1]["peak"]):
        raise ValueError("Native controller release, surviving stacks or allocation ledger differs")
    reclamation = None
    if maintenance:
        deferred = [tuple(map(int,m.groups())) for line in lines if (m:=re.fullmatch(
            r"RAM_CLEANUP deferred count=(\d+) bytes=(\d+)",line))]
        if len(deferred) != 1 or lines.count("RAM_CLEANUP maintenance=malloc-free requested=1 after-original-workload=1") != 1 or \
                lines.count("RAM_CLEANUP reclaim pending=0") != 1 or \
                samples[-2]["occupied"] - after != deferred[0][1] or \
                samples[-1]["malloc"] - samples[-2]["malloc"] != 1 or \
                samples[-1]["free"] - samples[-2]["free"] != deferred[0][0] + 1 or \
                samples[-1]["oracle"] != samples[-2]["oracle"] + 1:
            raise ValueError("Native deferred-free reclamation does not reconcile with allocator events")
        reclamation = {"pending_blocks_before":deferred[0][0],"pending_bytes_before":deferred[0][1],
            "pending_blocks_after":0,"post_workload_maintenance":"one native malloc(1)/free pair",
            "native_reclaim_before_after_occupied_bytes":[samples[-2]["occupied"],after],
            "peak_before_maintenance_bytes":samples[-2]["peak"],"peak_after_maintenance_bytes":maximum,
            "not_part_of_original_performance_workload":True}
    return {"controller_pid": pid, "parent_pid": parent, "native_tcb_release_completed": True,
        "controller_pid_absent": True, "wait_exit_status": status, "created": made, "retired": freed,
        "active": remaining, "surviving_stack_records_unchanged": True,
        "allocated_before_launch_bytes": before, "allocated_after_cleanup_bytes": after,
        "allocated_delta_bytes": after - before, "allocation_balance_closed": before == after,
        "allocated_heap_peak_through_cleanup_bytes": maximum,
        "scope": "native heap initialization through parent wait, controller stack/TCB release and post-exit allocation oracle",
        **({"native_deferred_reclamation":reclamation} if reclamation else {})}


def stack_ownership(lines, stack_totals):
    records = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"STACK_LIFE live allocation=(\d+) usable=(\d+) block=(\d+)", line))]
    summary = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"STACK_LIFE summary created=(\d+) retired=(\d+) active=(\d+) block_live=(\d+) block_peak=(\d+) use_calls=(\d+) use_success=(\d+) invalid=(\d+)", line))]
    idle = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"STACK_LIFE idle address=(\d+) reserved=(\d+) high_water=(\d+) irq_stack=interrupted-task", line))]
    headers = [int(m[1]) for line in lines if (m := re.fullmatch(r"STACK_LIFE node_header=(\d+)", line))]
    if lines.count("STACK_LIFE BEGIN ownership=allocated-blocks live_stack_usage_peak=not-measured") != 1 or \
            len(summary) != 1 or len(idle) != 1 or headers != [8]:
        raise ValueError("Stack ownership/header/idle evidence incomplete")
    created, retired, active, current, peak, calls, external, bad = summary[0]
    if (created, retired, active) != stack_totals[:3] or len(records) != active or calls or external or bad or \
            sum(block for _, _, block in records) != current or not 0 < current <= peak or \
            any(not 0 < used <= block - 8 for _, used, block in records) or not 0 <= idle[0][2] <= idle[0][1]:
        raise ValueError("Stack block ownership/lifecycle invariant differs")
    intervals = sorted((pointer - 8, pointer - 8 + block) for pointer, _, block in records)
    intervals.append((idle[0][0], idle[0][0] + idle[0][1]))
    intervals.sort()
    if any(a[1] > b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("Stack allocation/idle ranges overlap")
    return {"created": created, "retired": retired, "active": active,
        "live_blocks": [{"allocation": p, "usable_bytes": u, "allocated_block_bytes": b} for p, u, b in records],
        "live_allocated_stack_block_bytes": current, "peak_allocated_stack_block_bytes": peak,
        "static_idle_stack": {"address": idle[0][0], "reserved_bytes": idle[0][1], "high_water_bytes": idle[0][2]},
        "external_stack_provider_calls": calls, "irq_stack": "interrupted-task",
        "block_peak_scope": "registered blocks at stack create/retire hooks; allocator-internal transient occupation is covered by the separate native heap event peak",
        "already_in_heap_or_static": True, "simultaneous_live_stack_peak_measured": False}


def build(folder):
    report = json.loads((folder / "build.json").read_text())
    if report["status"] != "build_pass_not_measured" or report["board_resets"] or report["ranking_eligible"]:
        raise ValueError("Build-only observer qualification differs")
    for name, digest in report["files"].items():
        path = (folder / name).resolve()
        if not path.is_relative_to(folder.resolve()) or sha(path) != digest:
            raise ValueError("Observer build evidence changed")
    lifetimes = report.get("stack_lifetime_extension", False)
    cleanup = report.get("task_cleanup_extension", False)
    owners = report.get("retained_owners_extension",False)
    owner_layout,queue_region = None,None
    if cleanup and not lifetimes:
        raise ValueError("Task cleanup build lacks stack ownership extension")
    if cleanup and not report.get("native_reclaim_extension"):
        raise ValueError("Pre-reclamation prototype is retained as diagnostic evidence, not a qualified lifecycle image")
    bindings = [("allocator.patch", OBSERVER / "allocator.patch"),
                ("census.c", OBSERVER.parent / "nuttx_retained_owners.c" if owners else OBSERVER.parent / "nuttx_task_cleanup.c" if cleanup else
                    OBSERVER.parent / "nuttx_stack_lifetimes.c" if lifetimes else OBSERVER / "census.c")]
    if lifetimes:
        bindings.append(("base-census.inc", OBSERVER / "census.c"))
    if cleanup:
        bindings.append(("stack-census.inc", OBSERVER.parent / "nuttx_stack_lifetimes.c"))
    if owners:
        bindings.append(("cleanup-census.inc",OBSERVER.parent / "nuttx_task_cleanup.c"))
    for name, source in bindings:
        if (folder / name).read_bytes() != source.read_bytes():
            raise ValueError("Unreviewed observer implementation")
    with tempfile.TemporaryDirectory(prefix="iotos-native-patch-") as temporary:
        dest = Path(temporary)
        native = dest / "mm/mm_heap"
        native.mkdir(parents=True)
        for name in PATCHED:
            shutil.copyfile(folder / "native-source/mm/mm_heap" / name, native / name)
        subprocess.run(["patch", "--batch", "--fuzz=0", "-R", "-p1", "-i", str((folder / "allocator.patch").resolve())],
                       cwd=dest, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        if any((native / n).read_bytes() != (REFERENCE / "native-source/mm/mm_heap" / n).read_bytes() for n in PATCHED):
            raise ValueError("Native allocator intervention exceeds declared event points")
    for name in ("hartstone_series.c", "small_whetstone.c", "small_whetstone.h", "ph_rt_timer.h", "ph_us_schedule.h"):
        if (folder / name).read_bytes() != (WORKLOAD / name).read_bytes():
            raise ValueError("Original workload changed")
    clean = lambda path: {l for l in path.read_text().splitlines() if l.startswith("CONFIG_") and
                          not l.startswith(("CONFIG_BASE_DEFCONFIG=", "CONFIG_STACK_COLORATION="))}
    if clean(folder / "config") != clean(folder / "reference-config") or \
            "CONFIG_STACK_COLORATION=y" not in (folder / "config").read_text().splitlines():
        raise ValueError("Observer configuration change exceeds native stack coloration")
    if "13.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("Observer compiler differs")
    disassembly = (folder / "disassembly.txt").read_text()
    required_calls = [("mm_initialize", "bench_ram_heap_init"), ("mm_addregion", "bench_ram_heap_delta"),
            ("mm_malloc", "bench_ram_heap_delta"), ("mm_free", "bench_ram_heap_delta"),
            ("mm_shrinkchunk", "bench_ram_heap_delta"), ("mm_realloc", "bench_ram_heap_delta"),
            ("mm_memalign", "bench_ram_heap_delta"), ("__wrap_up_create_stack", "up_create_stack"),
            ("__wrap_up_release_stack", "up_check_tcbstack"), ("__wrap_up_release_stack", "up_release_stack")]
    if lifetimes:
        provenance = json.loads((folder / "official-stack-source.json").read_text())
        if len(provenance) != len(STACK_NATIVE) or {r["path"] for r in provenance} != set(STACK_NATIVE) or any(
                r["url"] != STACK_UPSTREAM + r["path"] or sha(folder / "native-source" / r["path"]) != r["sha256"]
                for r in provenance):
            raise ValueError("Fixed native stack source coverage/provenance differs")
        required_calls[-3:] = [("base_create_stack", "up_create_stack"),
            ("base_release_stack", "up_check_tcbstack"), ("base_release_stack", "up_release_stack")]
        required_calls += [("__wrap_up_create_stack", "base_create_stack"),
            ("__wrap_up_release_stack", "base_release_stack"), ("__wrap_up_use_stack", "up_use_stack"),
            ("__wrap_hartstone_main", "base_hartstone_main"),
            ("base_hartstone_main", "run_series_with_stack_ownership")]
        for name in ("xtensa_createstack.c", "xtensa_releasestack.c"):
            relative = Path("native-source/arch/xtensa/src/common") / name
            if (folder / relative).read_bytes() != (REFERENCE / relative).read_bytes():
                raise ValueError("Native stack creation/retirement changed")
        if "CONFIG_ARCH_INTERRUPTSTACK=0" not in (folder / "config").read_text().splitlines():
            raise ValueError("Native interrupt stack ownership differs")
    if cleanup:
        expected = {"native-source/" + n: STACK_UPSTREAM + n for n in CLEANUP_NATIVE}
        expected.update({"apps-source/" + n: APPS_UPSTREAM + n for n in CLEANUP_APPS})
        provenance = json.loads((folder / "official-cleanup-source.json").read_text())
        if len(provenance) != len(expected) or {r["path"] for r in provenance} != set(expected) or any(
                r["url"] != expected[r["path"]] or sha(folder / r["path"]) != r["sha256"] for r in provenance):
            raise ValueError("Native teardown/parent source provenance differs")
        required_calls += [("nsh_builtin", "__wrap_exec_builtin"), ("nsh_builtin", "__wrap_waitpid"),
            ("__wrap_exec_builtin", "exec_builtin"), ("__wrap_waitpid", "waitpid"),
            ("nxtask_terminate", "__wrap_nxsched_release_tcb"),
            ("__wrap_nxsched_release_tcb", "nxsched_release_tcb"),
            ("nxsched_release_tcb", "__wrap_up_release_stack")]
    if owners:
        provenance = json.loads((folder / "official-owner-source.json").read_text())
        if len(provenance)!=len(OWNERS_NATIVE) or {r["path"] for r in provenance}!=set(OWNERS_NATIVE) or any(
                r["url"]!=STACK_UPSTREAM+r["path"] or sha(folder / "native-source" / r["path"])!=r["sha256"] for r in provenance):
            raise ValueError("Native retained-owner source provenance differs")
        required_calls = [("owners_base_exec_builtin" if a=="__wrap_exec_builtin" else
                           "owners_base_waitpid" if a=="__wrap_waitpid" else a,b) for a,b in required_calls]
        required_calls += [("__wrap_exec_builtin","owners_base_exec_builtin"),("__wrap_waitpid","owners_base_waitpid"),
            ("hartstone_main","__wrap_rt_timer_create"),("hartstone_main","__wrap_rt_timer_delete"),
            ("__wrap_rt_timer_create","rt_timer_create"),("__wrap_rt_timer_delete","rt_timer_delete")]
    for caller, callee in required_calls:
        body = re.search(r"^[0-9a-f]+ <" + caller + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
        if body is None or not re.search(r"\bcall\w*\s+[^<]*<" + callee + r">", body[1]):
            raise ValueError("Required native event/lifecycle call missing: " + caller + " -> " + callee)
    if cleanup:
        from elftools.elf.elffile import ELFFile
        with (folder / "application.elf").open("rb") as stream:
            elf = ELFFile(stream)
            symbols = elf.get_section_by_name(".symtab")
            if owners:
                import struct
                symbol = symbols.get_symbol_by_name("bench_owner_timer_layout")[0]
                section = elf.get_section(symbol["st_shndx"])
                offset = symbol["st_value"]-section["sh_addr"]
                if symbol["st_size"]!=16:
                    raise ValueError("Native timer layout word coverage differs")
                owner_layout = list(struct.unpack("<4I",section.data()[offset:offset+16]))
                if owner_layout!=[40,32,3,4]:
                    raise ValueError("Native retained timer ABI/layout differs")
                native_state = symbols.get_symbol_by_name("g_rt_priv")[0]
                queue_region = [native_state["st_value"],native_state["st_size"]]
            for caller, callee in required_calls:
                body = re.search(r"^[0-9a-f]+ <" + caller + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)[1]
                calls = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + callee + r">$", body, re.M)
                if not calls:
                    raise ValueError("Native cleanup call8 encoding missing")
                for address, encoding, target in calls:
                    address, target, value = int(address, 16), int(target, 16), int(encoding, 16)
                    sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                                s["sh_addr"] <= address and address + 3 <= s["sh_addr"] + s["sh_size"]]
                    displacement = value >> 6
                    if displacement & (1 << 17): displacement -= 1 << 18
                    if len(sections) != 1 or sections[0].data()[address - sections[0]["sh_addr"]:address - sections[0]["sh_addr"] + 3] != bytes.fromhex(encoding)[::-1] or \
                            value & 0x3f != 0x25 or (address & ~3) + 4 + displacement * 4 != target or \
                            not any(s["st_value"] == target for s in symbols.get_symbol_by_name(callee) or []):
                        raise ValueError("Native cleanup call bytes/target differ from actual ELF")
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    return {"audit": "pass", "native_event_sites": 7, "source_body_unchanged": True,
        "scope": report["scope"], "static": static_footprint(folder / "application.elf"), "ranking_eligible": False,
        **({"stack_lifetime_extension": True} if lifetimes else {}),
        **({"task_cleanup_extension": True} if cleanup else {}),
        **({"retained_owners_extension":True,"native_timer_layout":owner_layout,"native_timer_state_region":queue_region} if owners else {})}


def capture(folder, index, owner_layout=None, queue_region=None):
    rows = read_raw_capture(folder, index)
    lines = [r["line"] for r in rows]
    resets = [r for r in rows if r["line"].startswith("rst:0x")]
    cleanup = any(line.startswith("RAM_CLEANUP baseline ") for line in lines)
    owners = any(line.startswith("RAM_OWNERS ") for line in lines)
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines[-1] != ("RAM_OWNERS END" if owners else "RAM_CLEANUP END" if cleanup else "RAM_EVENTS END") or any(
            re.search(r"panic|abort|assert|exception|RAM_(?:EVENTS|CLEANUP).*invalid=[1-9]", line, re.I) for line in lines):
        raise ValueError("RAM capture incomplete or native observer invariant failed")
    samples = [dict(zip(("phase", "occupied", "peak", "invalid", "oracle", "malloc", "free", "shrink", "grow", "align", "regions"),
                       (m[1], *map(int, m.groups()[1:])))) for line in lines if (m := SAMPLE.fullmatch(line))]
    if not samples or any(r["occupied"] > r["peak"] or r["invalid"] or not r["oracle"] for r in samples) or \
            any(a["peak"] > b["peak"] for a, b in zip(samples, samples[1:])):
        raise ValueError("Invalid native event/oracle samples")
    validation = [m for line in lines if (m := re.fullmatch(r"RAM_EVENTS validation=PASS base=(\d+) final=(\d+)", line))]
    if validation:
        if len(validation) != 1 or validation[0][1] != validation[0][2] or [r["phase"] for r in samples] != [
                "validation-malloc", "validation-shrink", "validation-grow", "validation-aligned", "validation-realloc", "validation-freed"]:
            raise ValueError("Allocator oracle validation incomplete")
        return {"kind": "observer_validation", "samples": samples, "benchmark_result": False}
    main_samples = [r for r in samples if r["phase"] in ("application-entry", "series-return")]
    if [r["phase"] for r in (main_samples if cleanup else samples)] != ["application-entry", "series-return"] or lines.count(
            "RAM_EVENTS BEGIN clock_hz=240000000 window=heap-initialize-through-series-return stack=native-coloration") != 1:
        raise ValueError("Original resource observation window differs")
    stacks = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_EVENTS stacks created=(\d+) retired=(\d+) active=(\d+) peak_active=(\d+) retired_max_high_water=(\d+)", line))]
    if len(stacks) != 1 or stacks[0][0] != stacks[0][1] + stacks[0][2] or not stacks[0][1]:
        raise ValueError("Stack create/retire/live ledger incomplete")
    active = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(r"RAM_EVENTS active_stack bytes=(\d+) high_water=(\d+)", line))]
    if len(active) != stacks[0][2] or any(used > allocated for allocated, used in active):
        raise ValueError("Surviving stack observations incomplete")
    original = series(folder / ("reset%d.jsonl" % index), "NuttX", 4, high_resolution=True)
    if original["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("Original PH4 series not complete")
    boundary = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RAM_EVENTS boundary boot_peak=(\d+) boot_malloc=(\d+) result=(\d+) invalid=(\d+)", line))]
    worker_count = 5 + original["first_loss_step"]
    worker_lifetimes = sum(range(5, worker_count + 1))
    if len(boundary) != 1 or boundary[0][2:] != (0, 0) or boundary[0][0] != main_samples[0]["peak"] or \
            boundary[0][1] != main_samples[0]["malloc"] or stacks[0][1] != worker_lifetimes or \
            stacks[0][0] != worker_lifetimes + 3 or stacks[0][2] != 3 or stacks[0][3] != worker_count + 3:
        raise ValueError("Original workload worker/stack lifetime coverage differs")
    ownership = stack_ownership(lines, stacks[0]) if any(line.startswith("STACK_LIFE summary ") for line in lines) else None
    if ownership:
        regions = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
            r"RAM_EVENTS region start=(\d+) end=(\d+)", line))]
        if len(regions) != 3 or any(end <= start for start, end in regions) or any(
                not any(start <= block["allocation"] - 8 < block["allocation"] - 8 +
                        block["allocated_block_bytes"] <= end for start, end in regions)
                for block in ownership["live_blocks"]):
            raise ValueError("Native stack block lies outside observed native heap regions")
        ownership["native_heap_regions"] = [(start, end - start) for start, end in regions]
    teardown = cleanup_lifecycle(lines, samples, stacks[0], worker_lifetimes) if cleanup else None
    if owners and (ownership is None or teardown is None):
        raise ValueError("Retained owners require complete native heap, stack and teardown evidence")
    retained = retained_owners(lines,teardown,worker_count,worker_lifetimes,owner_layout,queue_region,regions) if owners else None
    return {"kind": "original_ph4_ram", "samples": samples, "stacks": stacks[0], "active_stacks": active,
        "original_series": original, "allocated_heap_peak_bytes": samples[-1]["peak"],
        "worker_count": worker_count, "reference_worker_count": 42,
        "reference_worker_coverage": worker_count >= 42, "worker_stack_lifetimes": worker_lifetimes,
        "pre_application_allocated_peak_bytes": boundary[0][0],
        "simultaneous_live_stack_peak_measured": False, "rom_pre_heap_peak_measured": False,
        "ranking_eligible": False, **({"stack_ownership": ownership} if ownership else {}),
        **({"post_exit_cleanup": teardown} if teardown else {}),
        **({"retained_native_ownership":retained} if retained else {})}


def audit(folder, source):
    campaign = envelope(folder)
    if campaign["kind"] != "ram" or campaign["board_mac"] != "34:98:7a:a2:85:28":
        raise ValueError("Wrong observer campaign/board")
    proof = build(source)
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin", "build.json"):
        if sha(folder / "build" / name) != sha(source / name):
            raise ValueError("Observed image differs from native event build")
    verified(folder / "captures", folder / "build", campaign["board_mac"])
    independent_captures(folder / "captures")
    validation = capture(folder / "validation", 1)
    if validation["kind"] != "observer_validation":
        raise ValueError("Missing same-image allocator validation")
    runs = [capture(folder / "captures", i, proof.get("native_timer_layout"),proof.get("native_timer_state_region")) for i in (1, 2, 3)]
    if bool(proof.get("task_cleanup_extension")) != bool(campaign.get("task_cleanup_extension")) or any(
            bool(proof.get("task_cleanup_extension")) != ("post_exit_cleanup" in run) for run in runs):
        raise ValueError("Observed cleanup window differs from qualified image")
    if proof.get("task_cleanup_extension") and any("native_deferred_reclamation" not in r["post_exit_cleanup"] for r in runs):
        raise ValueError("Observed cleanup omits the declared native deferred-free reclamation")
    if bool(proof.get("retained_owners_extension"))!=bool(campaign.get("retained_owners_extension")) or any(
            bool(proof.get("retained_owners_extension"))!=("retained_native_ownership" in r) for r in runs):
        raise ValueError("Observed retained ownership differs from qualified image")
    if proof.get("stack_lifetime_extension"):
        from elftools.elf.elffile import ELFFile
        with (source / "application.elf").open("rb") as stream:
            symbols = ELFFile(stream).get_section_by_name(".symtab")
            idle = symbols.get_symbol_by_name("g_idlestack")[0]
            sheap = symbols.get_symbol_by_name("_sheap")[0]["st_value"]
            for run in runs:
                record = run.get("stack_ownership", {}).get("static_idle_stack")
                if record is None or (record["address"], record["reserved_bytes"]) != (idle["st_value"], idle["st_size"]):
                    raise ValueError("Native idle stack differs from ELF allocation")
                region_accounting(proof["static"]["ram_sections"], [(record["address"], record["reserved_bytes"])], True)
                regions = run["stack_ownership"]["native_heap_regions"]
                if regions[0][0] - sheap != 368:
                    raise ValueError("Native heap-control ownership/size differs")
                capacity = region_accounting(proof["static"]["ram_sections"], regions + [(sheap, 368)], False)
                if run["allocated_heap_peak_bytes"] > capacity:
                    raise ValueError("Native heap peak exceeds physically disjoint heap capacity")
                run["allocated_software_ram_bytes"] = proof["static"]["static_sram_bytes"] + run["allocated_heap_peak_bytes"]
                run["stack_ownership"]["heap_control_bytes_already_in_peak"] = 368
    return {"audit": "pass", "board": "B1", "validation": validation, "build": proof, "runs": runs,
        "independent_workload_resets": 3, "observer_validation_resets": 1,
        "full_live_ram_ranking_eligible": False, "energy_measured": False}


def incomplete_cleanup(folder, source):
    campaign = envelope(folder, allow_incomplete=True)
    report = json.loads((source / "build.json").read_text())
    if campaign["status"] != "incomplete" or not campaign.get("task_cleanup_extension") or \
            report.get("native_reclaim_extension") or not report.get("task_cleanup_extension"):
        raise ValueError("Not the retained pre-reclamation interrupted prototype")
    for name,value in report["files"].items():
        if sha(source / name) != value:
            raise ValueError("Prototype build evidence changed")
    for name in ("application.elf","application.bin","bootloader.bin","partitions.bin","build.json"):
        if sha(folder / "build" / name) != sha(source / name):
            raise ValueError("Prototype capture/build identity differs")
    helper = (folder / "board-helper.py").read_text()
    if "    def verify(" in helper or "board.verify(pairs," not in (folder / "runner.py").read_text() or \
            any((folder / "captures" / n).exists() for n in ("verify-run1.log","reset2.jsonl","reset3.jsonl")):
        raise ValueError("Prototype missing-helper-method interruption differs")
    validation = read_raw_capture(folder / "validation",1)
    rows = read_raw_capture(folder / "captures",1)
    if validation[-1]["line"] != "RAM_EVENTS END" or rows[-1]["line"] != "RAM_CLEANUP END" or \
            sum(r["line"].startswith("rst:0x") for r in rows) != 1 or \
            not any("RAM_CLEANUP STACK_LIFE BEGIN" in r["line"] and "launched controller=" in r["line"] for r in rows):
        raise ValueError("Prototype raw diagnostic or interleaved UART witness differs")
    return {"audit":"pass","status":"interrupted_diagnostic_only","independent_resets":0,
        "raw_capture_records":1,"ranking_eligible":False,"full_live_ram_ranking_eligible":False,
        "original_flash_restored":True,"energy_measured":False,
        "reason":"collector loaded a helper without verify(); parent/child UART header interleaved; no admitted RAM result",
        "next_action":"qualified helper and non-overlapping output; separately observe deferred-free reclamation"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--verify-upstream-stacks", action="store_true")
    parser.add_argument("--verify-upstream-cleanup", action="store_true")
    parser.add_argument("--incomplete", action="store_true")
    parser.add_argument("--verify-upstream-owners", action="store_true")
    args = parser.parse_args()
    if args.verify_upstream_stacks:
        verify_stack_sources(args.source)
    if args.verify_upstream_cleanup:
        verify_cleanup_sources(args.source)
    if args.verify_upstream_owners:
        verify_owner_sources(args.source)
    if args.incomplete and not args.campaign:
        parser.error("Incomplete prototype audit needs a campaign")
    result = (incomplete_cleanup(args.campaign,args.source) if args.incomplete else audit(args.campaign, args.source)) if args.campaign else build(args.source)
    (args.campaign or args.source).joinpath("audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("static", "runs", "validation", "build")}))
