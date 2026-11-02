#!/usr/bin/env python3
"""Capture and replay five independent original-message allocation histories."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal

from run_esp32_followup import Board, sha

MAC = "34:98:7a:a2:85:28"
ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
REFERENCE = REPORTS / "tm-freertos-native-aligned-v1/message_processing"
SAMPLE = re.compile(r"FREERTOS_RAM phase=(\S+) occupied=(\d+) peak=(\d+) invalid=(\d+) register=(\d+) alloc=(\d+) free=(\d+) resize=(\d+) align=(\d+)")
EVENT = re.compile(r"TM_RAM event=(\d+) kind=(\d+) pool=(\d+) pointer=(\d+) delta=(-?\d+)")
POOL = re.compile(r"FREERTOS_RAM pool start=(\d+) bytes=(\d+) occupied=(\d+) metadata=(\d+) native_bias=(\d+) checks=(\d+)")


def build_proof(source):
    from build_esp32_tm_ram_lifetimes import observer_source, TICK_TRACE
    from build_esp32_freertos_ram_lifetimes import native_edits, patched
    from audit_esp32_resources import audit_elf_image, static_footprint
    from audit_esp32_freertos_ram_lifetimes import calls
    manifest = json.loads((source / "build.json").read_text())
    coverage = manifest.get("message_ordinary_irq_stack_coverage",False)
    startup = manifest.get("application_startup_stack_coverage",False)
    tick = manifest.get("native_tick_stack_snapshots",False)
    lifecycle = manifest.get("task_lifecycle_validation", False)
    compact = manifest.get("compact_observer", False)
    handoff = manifest.get("startup_heap_handoff", False)
    peak_context = manifest.get("allocation_peak_context", False)
    step_stacks = manifest.get("continuous_instruction_stack_trace", False)
    boundary_stacks = manifest.get("compiler_boundary_stack_trace", False)
    boundary_fast = manifest.get("compiler_boundary_fast_pruning", False)
    boundary_inline = manifest.get("compiler_boundary_inline_guards", False)
    stack_entry = manifest.get("compiler_stack_entry_guards", False)
    threshold = manifest.get("single_threshold_guards", False)
    native_sp = manifest.get("native_assembly_sp_trace", False)
    readback_address = manifest.get("boot_readback_state_address")
    if readback_address is not None and (not startup or type(readback_address) is not int or
            readback_address % 4 or not 0x3fff0000 <= readback_address <= 0x3fffffd8):
        raise ValueError("Invalid paired bootloader state address")
    if type(step_stacks) is not bool or step_stacks and (not compact or not handoff or not peak_context or readback_address is None):
        raise ValueError("Invalid continuous instruction-stack declaration")
    if type(boundary_stacks) is not bool or boundary_stacks and (step_stacks or tick or not compact or not handoff or readback_address is None):
        raise ValueError("Invalid compiler-boundary stack declaration")
    if type(boundary_fast) is not bool or boundary_fast and not boundary_stacks:
        raise ValueError("Invalid boundary depth pruning declaration")
    if type(boundary_inline) is not bool or boundary_inline and not (boundary_fast and native_sp):
        raise ValueError("Invalid inline guard declaration")
    if type(stack_entry) is not bool or stack_entry and not boundary_inline:
        raise ValueError("Invalid generated-stack-entry declaration")
    if type(threshold) is not bool or threshold and not stack_entry:
        raise ValueError("Invalid single-threshold declaration")
    if type(native_sp) is not bool or native_sp and (step_stacks or tick or not compact or not handoff or readback_address is None):
        raise ValueError("Invalid native assembly SP declaration")
    if type(peak_context) is not bool or peak_context and (not handoff or not compact):
        raise ValueError("Invalid allocation-peak context declaration")
    if type(handoff) is not bool or handoff and not startup:
        raise ValueError("Invalid startup-heap handoff declaration")
    if type(compact) is not bool or manifest.get("trace_capacity") != (128 if compact else 1024) or compact and manifest.get("task_capacity") != 16:
        raise ValueError("Invalid bounded observer capacity")
    if type(lifecycle) is not bool:
        raise ValueError("Invalid task lifecycle validation declaration")
    if type(coverage) is not bool:
        raise ValueError("Invalid message IRQ stack declaration")
    for name, digest in manifest["files"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source.resolve()) or sha(path) != digest:
            raise ValueError("Build evidence changed: " + name)
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    tail = observer.parent / "freertos_message_tail.c"
    extension = (observer.parent / "freertos_stack_coverage/stack-coverage.inc").read_text() if coverage else None
    startup_extension=(observer.parent/"freertos_startup_stack/startup-stack.inc").read_text() if startup else None
    tick_extension=(observer.parent/"freertos_tick_stacks.inc").read_text() if tick else None
    lifecycle_extension=(observer.parent/"freertos_task_lifecycle_validation.inc").read_text() if lifecycle else None
    handoff_extension=(observer.parent/"freertos_startup_stack/heap-handoff.inc").read_text() if handoff else None
    peak_extension=(observer.parent/"freertos_peak_context.inc").read_text() if peak_context else None
    readback_extension=(observer.parent/"freertos_startup_stack/boot-readback.inc").read_text() if readback_address is not None else None
    if type(tick) is not bool or tick and not startup:
        raise ValueError("Invalid native tick snapshot declaration")
    if type(startup) is not bool or startup and not coverage:
        raise ValueError("Invalid startup observation declaration")
    step_extension = (observer.parent / "continuous_step_stacks/step-stacks.inc").read_text() if step_stacks else None
    boundary_extension = (observer.parent / "function_boundary_stacks/boundary-stacks.inc").read_text() if boundary_stacks else None
    native_extension = (observer.parent / "native_asm_stacks/native-stacks.inc").read_text() if native_sp else None
    if (source / "observer/census.c").read_text() != observer_source((observer / "census.c").read_text(), tail.read_text(), extension,startup_extension,tick_extension,lifecycle_extension,compact,handoff_extension,peak_extension,readback_extension,step_extension,boundary_extension,boundary_fast,native_extension,boundary_inline,threshold):
        raise ValueError("Unreviewed observation source")
    extra={}
    if boundary_stacks:
        from measure_esp32_message_boundaries import boundary_build_proof
        extra.update(compiler_boundary_stack_trace=True, boundary_observer=boundary_build_proof(source))
        if stack_entry:
            extra['compiler_stack_entry_guards'] = True
        if threshold:
            extra['single_threshold_guards'] = True
    if native_sp:
        from measure_esp32_native_sp import native_build_proof, NATIVE_TRACE
        from build_esp32_tm_ram_lifetimes import BOUNDARY_TRACE
        native_header = BOUNDARY_TRACE if boundary_stacks else NATIVE_TRACE
        if (source/"native-stacks.inc").read_text() != native_extension or (source/"native-source/freertos/config/include/freertos/bench_task_trace.h").read_bytes() != (observer/"bench_task_trace.h").read_bytes()+native_header:
            raise ValueError("Native SP source or TCB assertion differs")
        extra.update(native_assembly_sp_trace=True,native_sp_observer=native_build_proof(source))
    if step_stacks:
        from measure_esp32_message_steps import step_build_proof
        extra.update(continuous_instruction_stack_trace=True, step_observer=step_build_proof(source))
    if coverage:
        from elftools.elf.elffile import ELFFile
        portasm="FreeRTOS-Kernel/portable/xtensa/portasm.S"
        pinned = (REPORTS/"riot-yield-freertos-v1/native-source/components/freertos"/portasm).read_bytes()
        expected = pinned
        if native_sp:
            from measure_esp32_native_sp import patch_portasm
            if (source/"native-portasm-original.S").read_bytes() != pinned:
                raise ValueError("Native SP assembly base differs from pinned SDK")
            expected = patch_portasm(pinned.decode()).encode()
        if (source/"stack-coverage.inc").read_text()!=extension or (source/"native-source/freertos"/portasm).read_bytes() != expected:
            raise ValueError("Native IRQ observation/vector differs from pinned SDK")
        with (source/"application.elf").open("rb") as stream:
            symbols=ELFFile(stream).get_section_by_name(".symtab")
            irq=symbols.get_symbol_by_name("port_IntStack")[0]
            if irq["st_size"]!=1536:
                raise ValueError("Original IRQ stack capacity differs")
        extra.update({"message_ordinary_irq_stack_coverage":True,
            "interrupt_stack":{"address":irq["st_value"],"reserved_bytes":irq["st_size"]},
            "ordinary_irq_stack_calls":calls(source,[("vTaskStartScheduler","__wrap_xPortStartScheduler"),
                ("__wrap_xPortStartScheduler","xPortStartScheduler"),("__wrap_tm_thread_sleep","bench_irq_stack_report")])})
    if startup:
        from audit_esp32_freertos_startup_stack import build
        extra.update(build(source))
    if handoff:
        if (source / "heap-handoff.inc").read_text() != handoff_extension:
            raise ValueError("Startup-heap handoff source differs")
        extra.update(startup_heap_handoff=True)
    if tick:
        if (source/"tick-stacks.inc").read_text()!=tick_extension or (source/"native-source/freertos/config/include/freertos/bench_task_trace.h").read_bytes() != (observer/"bench_task_trace.h").read_bytes()+TICK_TRACE:
            raise ValueError("Native trace point differs from the frozen snapshot observer")
        extra.update(native_tick_stack_snapshots=True,
            tick_snapshot_calls=calls(source,[("xTaskIncrementTick","bench_live_tick")]))
    if lifecycle:
        if (source / "task-lifecycle-validation.inc").read_text() != lifecycle_extension:
            raise ValueError("Task lifecycle validation source differs")
        extra.update(task_lifecycle_validation=True, task_lifecycle_calls=calls(source,
            [("validate", "bench_validate_task_lifetimes"), ("bench_lifecycle_worker", "vTaskDelete")]))
    for name in ("main.c", "port.c", "test.c", "tm_override.h", "CMakeLists.txt"):
        if (source / "observer/app/main" / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("Original workload/adapter changed: " + name)
    for name in ("config", "tm_message_processing_test.c"):
        if (source / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("Original configuration/test differs")
    if (source / "native-source/freertos/config/include/freertos/FreeRTOSConfig.h").read_bytes() != (
            (REFERENCE / "FreeRTOSConfig.h").read_bytes() + b'\n#include "bench_task_trace.h"\n'):
        raise ValueError("Scheduler change exceeds trace hooks")
    old = REPORTS / "esp32-freertos-lifetimes-v4"
    for name, edits in native_edits().items():
        original = source / "original-native/heap" / name
        if original.read_bytes() != (old / "original-native/heap" / name).read_bytes() or (
                source / "native-source/heap" / name).read_bytes() != patched(original.read_bytes(), edits):
            raise ValueError("Pinned native allocator patch differs")
    for name in ("FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/portable/xtensa/port.c", "heap_idf.c"):
        if (source / "native-source/freertos" / name).read_bytes() != (old / "native-source/freertos" / name).read_bytes():
            raise ValueError("Previously verified native kernel changed")
    if "13.2.0" not in (source / "compiler.txt").read_text():
        raise ValueError("Compiler differs")
    audit_elf_image(source / "application.elf", source / "application.bin")
    edges = [("multi_heap_register_impl", "bench_heap_register"), ("multi_heap_internal_unlock", "bench_heap_check"),
        ("tlsf_malloc", "bench_prepare_used"), ("tlsf_memalign_offs", "bench_prepare_used"),
        ("bench_prepare_used", "bench_tlsf_delta"), ("tlsf_free", "bench_tlsf_delta"), ("tlsf_realloc", "bench_tlsf_delta"),
        ("prvAddNewTaskToReadyList", "bench_life_create"), ("vTaskDelete", "bench_life_request"),
        ("prvDeleteTCB", "__wrap_vPortTCBPreDeleteHook"), ("prvDeleteTCB", "vPortFree"),
        ("main_task", "__wrap_app_main"), ("__wrap_app_main", "app_main"),
        ("tm_message_processing_thread_report", "__wrap_tm_thread_sleep")]
    footprint = static_footprint(source / "application.elf")
    if compact:
        extra.update(compact_observer=True, trace_capacity=128, task_capacity=16)
    if peak_context:
        if (source / "peak-context.inc").read_text() != peak_extension:
            raise ValueError("Allocation-peak context source differs")
        extra.update(allocation_peak_context=True, allocation_peak_calls=calls(source,
            [("record", "bench_peak_context"), ("bench_peak_context", "xTaskGetCurrentTaskHandle")]))
    return {"audit":"pass", **footprint, "machine_calls":calls(source, edges), **extra,
        "baseline_static_sram_bytes":static_footprint(REFERENCE / "iotosbench_tm.elf")["static_sram_bytes"],
        "profile":{"clock_mhz":240, "cores":1, "tick_hz":100, "compiler":"GCC13.2", "time_slicing":False},
        "original_workload_unchanged":True}


def replay_events(events, pools, *, require_terminal=True):
    occupancy, blocks, owners, requests, cleanups = {}, {}, {}, set(), set()
    # A recycled address belongs to a new allocation and task generation.
    pairs, generations, stack_tasks, pending_tcb = {}, {}, {}, None
    maximum = 0
    kinds = Counter()
    for expected, (sequence, kind, pool, pointer, delta) in enumerate(events):
        if sequence != expected or kind not in range(9):
            raise ValueError("Missing/reordered/unknown allocation event")
        kinds[kind] += 1
        if kind == 0:
            if pool != len(occupancy) or pool >= len(pools) or pointer != pools[pool][0] or delta != pools[pool][3]:
                raise ValueError("Heap registration metadata differs")
            occupancy[pool] = delta
        elif kind <= 4:
            if pool not in occupancy:
                raise ValueError("Event before heap registration")
            if kind in (1, 4):
                if pointer in blocks or delta <= 4:
                    raise ValueError("Duplicate/invalid allocation")
                blocks[pointer] = [pool, delta]
                generations[pointer] = generations.get(pointer, 0) + 1
            elif kind == 2:
                identity = (pointer, generations.get(pointer))
                if identity in owners:
                    tcb = identity if owners[identity][0] == 5 else stack_tasks[identity]
                    if tcb not in cleanups:
                        raise ValueError("Task storage freed before native cleanup")
                if blocks.pop(pointer, None) != [pool, -delta]:
                    raise ValueError("Free does not match a live block")
            else:
                if pointer not in blocks or blocks[pointer][0] != pool or blocks[pointer][1]+delta <= 4:
                    raise ValueError("Invalid in-place resize")
                blocks[pointer][1] += delta
            occupancy[pool] += delta
            start, size = pools[pool][:2]
            if not start <= pointer-4 < start+size or not 0 <= occupancy[pool] <= size:
                raise ValueError("Allocation outside native heap")
            if pointer in blocks and pointer+blocks[pointer][1]-4 > start+size:
                raise ValueError("Block crosses heap boundary")
        elif kind in (5, 6):
            identity = (pointer, generations.get(pointer))
            if identity in owners or pointer not in blocks or not 0 < delta <= blocks[pointer][1]-4 or not 0 <= pool <= 3:
                raise ValueError("Task TCB/stack lacks native allocation")
            owners[identity] = (kind, pool, delta)
            if kind == 5:
                if pending_tcb is not None:
                    raise ValueError("Task lacks its stack ownership event")
                pending_tcb = identity
            else:
                if pending_tcb is None or owners[pending_tcb][1] != pool:
                    raise ValueError("Stack lacks matching task creation")
                pairs[pending_tcb] = identity
                stack_tasks[identity] = pending_tcb
                pending_tcb = None
        elif kind == 7:
            identity = (pointer, generations.get(pointer))
            if identity not in pairs or owners.get(identity, (None, None))[:2] != (5, pool) or identity in requests or delta:
                raise ValueError("Task deletion without creation")
            requests.add(identity)
        elif kind == 8:
            identity = (pointer, generations.get(pointer))
            if identity not in requests or identity in cleanups or owners[identity][1] != pool or delta:
                raise ValueError("Task cleanup without deletion")
            cleanups.add(identity)
        maximum = max(maximum, sum(occupancy.values()))
    if pending_tcb is not None or require_terminal and (len(occupancy) != len(pools) or any(occupancy[i] != p[2] for i, p in enumerate(pools))):
        raise ValueError("Event replay and native final occupancy disagree")
    for i, p in enumerate(pools[:len(occupancy)]):
        if occupancy[i] != p[3] + sum(size for region, size in blocks.values() if region == i):
            raise ValueError("Live-block reconciliation differs")
    retired = 0
    for tcb, stack in pairs.items():
        tcb_live = tcb[0] in blocks and generations[tcb[0]] == tcb[1]
        stack_live = stack[0] in blocks and generations[stack[0]] == stack[1]
        if (not tcb_live or not stack_live) and tcb not in cleanups:
            raise ValueError("Task storage freed before native cleanup")
        retired += not tcb_live and not stack_live
    current_owners = {pointer: owner for (pointer, generation), owner in owners.items()
        if pointer in blocks and generations[pointer] == generation}
    return {"peak":maximum, "occupied":sum(occupancy.values()), "events":len(events),
            "kinds":dict(kinds), "blocks":blocks, "owners":current_owners,
            "delete_requests":len(requests), "cleanups":len(cleanups), "retired":retired}


def read_run(folder, index, proof, validation=False):
    from audit_esp32_zephyr_thread import read_raw_capture
    from audit_esp32_tm_basic import audit as original_audit
    from audit_esp32_ram_census import region_accounting
    rows = read_raw_capture(folder, index)
    lines = [r["line"] for r in rows]
    capacity = proof.get("trace_capacity", 1024)
    if lines.count(f"TM_RAM BEGIN clock_mhz=240 cores=1 tick_hz=100 capacity={capacity}") != 1 or sum(s.startswith("rst:0x") for s in lines) != 1:
        raise ValueError("Wrong profile or reset count")
    if any(re.search(r"panic|abort|Guru Meditation|Exception|ASSERT|FATAL|invalid-command|watchdog", s, re.I) for s in lines):
        raise ValueError("Device reported an error")
    samples = [(m[1], *map(int, m.groups()[1:])) for s in lines if (m := SAMPLE.fullmatch(s))]
    if not samples or any(s[3] for s in samples):
        raise ValueError("Native heap cross-check or trace overflow failed")
    if validation:
        expected = ["validation-base", "validation-moved", "validation-shrink", "validation-grow", "validation-aligned", "validation-freed"]
        if proof.get("task_lifecycle_validation"):
            expected += ["lifecycle-base", "lifecycle-freed"]
        passed = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
            r"FREERTOS_RAM validation=PASS base=(\d+) final=(\d+) required_overlap_peak=(\d+) observed_peak=(\d+)", s))]
        if [s[0] for s in samples] != expected or len(passed) != 1 or lines.count("FREERTOS_RAM END") != 1:
            raise ValueError("Separate allocator validation incomplete")
        before, after, overlap, maximum = passed[0]
        if not (before == after == samples[0][1] == samples[5][1] < overlap <= maximum == samples[5][2]) or samples[5][7] < 2 or not samples[5][8]:
            raise ValueError("Allocator overlap/resize/return-to-base validation failed")
        extra={}
        if proof.get("task_lifecycle_validation"):
            from replay_esp32_freertos_message import history
            markers = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
                r"FREERTOS_RAM lifecycle=PASS cycles=4 base=(\d+) final=(\d+) start_event=(\d+) end_event=(\d+) reused=(\d+)", s))]
            events = [tuple(map(int, m.groups())) for s in lines if (m := EVENT.fullmatch(s))]
            pools = [tuple(map(int, m.groups())) for s in lines if (m := POOL.fullmatch(s))]
            if len(markers) != 1:
                raise ValueError("Task lifecycle witness missing/repeated")
            base, final, start, end, reused = markers[0]
            endings = [s for s in lines if s.startswith("FREERTOS_RAM lifecycle_trace ")]
            if endings != [f"FREERTOS_RAM lifecycle_trace events={len(events)} invalid=0"] or \
                    not 0 < start < end == len(events) < capacity or base != final or base != samples[-2][1] or final != samples[-1][1]:
                raise ValueError("Task lifecycle trace boundaries differ")
            replay = replay_events(events, pools)
            separate = history(lines, phases=expected)
            if (replay["peak"], replay["occupied"]) != (separate["heap_peak_bytes"], separate["heap_final_bytes"]) or \
                    replay["occupied"] != final or sum(e[4] for e in events[:start] if e[1] < 5) != base:
                raise ValueError("Separate lifecycle byte replay differs")
            lifecycle = events[start:end]
            if any(sum(e[1] == kind for e in lifecycle) != 4 for kind in (5, 6, 7, 8)):
                raise ValueError("Four complete task lifetimes were not observed")
            created = [e[3] for e in lifecycle if e[1] == 5]
            stacks = [e[3] for e in lifecycle if e[1] == 6]
            observed_reuse = 4 - len(set(zip(created, stacks)))
            if reused != observed_reuse:
                raise ValueError("Lifecycle address-reuse witness differs")
            extra["task_lifecycles"] = {"completed": 4, "reused_address_pairs": reused,
                "heap_returned_to_base": base, "heap_peak_bytes": replay["peak"],
                "start_event": start, "end_event": end, "separate_replay": "pass",
                "benchmark_result": False, "whole_live_ram_peak_bytes": None}
        if proof.get("message_ordinary_irq_stack_coverage"):
            from audit_esp32_freertos_stack_coverage import observations
            extra.update(ordinary_irq_stack=observations(lines,proof))
        if proof.get("application_startup_stack_coverage"):
            from audit_esp32_freertos_startup_stack import observations as startup_observations
            extra["application_startup_stack"]=startup_observations(lines,proof)
        if proof.get("startup_heap_handoff"):
            if not proof.get("task_lifecycle_validation"):
                raise ValueError("Handoff validation requires the complete validation event stream")
            from audit_esp32_freertos_startup_stack import heap_handoff
            extra["startup_heap_handoff"] = heap_handoff(lines, events, pools)
        if proof.get("allocation_peak_context"):
            from audit_esp32_freertos_peak_context import observations as peak_observations
            extra["allocation_peak_context"] = peak_observations(lines, events, pools, proof)
        if proof.get("compiler_boundary_stack_trace"):
            from measure_esp32_message_boundaries import observations
            extra["boundary_stack"] = observations(lines, events,
                proof["boundary_observer"].get("same_epoch_depth_pruning", False),
                "inline_guards" in proof["boundary_observer"])
        if proof.get("native_assembly_sp_trace"):
            from measure_esp32_native_sp import observations
            extra["native_sp"] = observations(lines, events, proof["native_sp_observer"])
        return {"audit":"pass", "base_final_bytes":before, "overlap_peak_bytes":maximum, **extra}
    original = original_audit(folder / ("reset%d.jsonl" % index), "FreeRTOS", "message_processing")
    if [s[0] for s in samples] not in (["application-entry", "message-end"], ["application-entry", "application-return", "message-end"]):
        raise ValueError("Workload boundaries differ")
    pools = [tuple(map(int, m.groups())) for s in lines if (m := POOL.fullmatch(s))]
    events = [tuple(map(int, m.groups())) for s in lines if (m := EVENT.fullmatch(s))]
    endings = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(r"TM_RAM END events=(\d+) invalid=(\d+) original_reports=3", s))]
    if len(endings) != 1 or endings[0] != (len(events), 0) or not 0 < len(events) < capacity:
        raise ValueError("Incomplete/overflowed event stream")
    replay = replay_events(events, pools)
    final = samples[-1]
    if (replay["occupied"], replay["peak"]) != final[1:3] or [replay["kinds"].get(i, 0) for i in range(5)] != list(final[4:9]):
        raise ValueError("Independent history differs from firmware counters")
    region_accounting(proof["ram_sections"], [p[:2] for p in pools], False)
    live = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM live tcb=(\d+) stack=(\d+) span=(\d+) tcb_bytes=(\d+) kind=(\d+) role=(\d+) stack_heap=(\d+) tcb_heap=(\d+) stack_block=(\d+) tcb_block=(\d+) spare=(\d+)", s))]
    for tcb, stack, span, tcb_size, kind, role, sh, th, sb, tb, spare in live:
        if kind not in (0, 1, 2) or sh != 1 or th != 1 or not 0 <= spare <= span or replay["blocks"].get(stack, [None, None])[1] != sb or replay["blocks"].get(tcb, [None, None])[1] != tb:
            raise ValueError("Live task storage/high-water differs from allocator history")
        if replay["owners"].get(tcb) != (5, role, tcb_size) or replay["owners"].get(stack) != (6, role, span):
            raise ValueError("Live task ownership differs")
    if len([r for r in live if r[5] == 0 and r[8] == 4100 and r[2] == ((r[1]+4095)&~15)-r[1]+1]) != 2:
        raise ValueError("Original two 4096-byte TM task stacks differ")
    summaries = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM tasks created=(\d+) requested=(\d+) cleanup=(\d+) retired=(\d+) active=(\d+) peak_active=(\d+) retired_max_used=(\d+) invalid=(\d+)", s))]
    if len(summaries) != 1:
        raise ValueError("Task lifecycle summary missing")
    made, requested, cleaned, retired, active, maximum, used, bad = summaries[0]
    if bad or made != replay["kinds"].get(5, 0) or made != replay["kinds"].get(6, 0) or made != retired+active or active != len(live) or requested != replay["delete_requests"] or cleaned != replay["cleanups"] or retired != replay["retired"]:
        raise ValueError("Task lifecycle count mismatch")
    extra={}
    if proof.get("message_ordinary_irq_stack_coverage"):
        from audit_esp32_freertos_stack_coverage import observations
        extra={"ordinary_irq_stack":observations(lines,proof,terminal_prefix="TM_RAM END ")}
    if proof.get("application_startup_stack_coverage"):
        from audit_esp32_freertos_startup_stack import observations as startup_observations
        extra["application_startup_stack"]=startup_observations(lines,proof,live)
    if proof.get("startup_heap_handoff"):
        from audit_esp32_freertos_startup_stack import heap_handoff
        extra["startup_heap_handoff"] = heap_handoff(lines, events, pools)
    if proof.get("native_tick_stack_snapshots"):
        from audit_esp32_freertos_tick_stacks import observations as tick_observations
        extra["native_tick_stack_snapshots"]=tick_observations(lines,proof,events,live)
    if proof.get("allocation_peak_context"):
        from audit_esp32_freertos_peak_context import observations as peak_observations
        extra["allocation_peak_context"] = peak_observations(lines, events, pools, proof)
    if proof.get("compiler_boundary_stack_trace"):
        from measure_esp32_message_boundaries import observations
        extra["boundary_stack"] = observations(lines, events,
            proof["boundary_observer"].get("same_epoch_depth_pruning", False),
            "inline_guards" in proof["boundary_observer"])
    if proof.get("native_assembly_sp_trace"):
        from measure_esp32_native_sp import observations
        extra["native_sp"] = observations(lines, events, proof["native_sp_observer"])
    return {"audit":"pass", "original_message":original, "events":len(events), "heap_peak_bytes":replay["peak"], **extra,
        "heap_final_bytes":replay["occupied"], "application_entry_heap_bytes":samples[0][1],
        "software_reserved_and_allocated_peak_bytes":proof["static_sram_bytes"]+replay["peak"],
        "tasks":{"created":made, "delete_requested":requested, "cleaned":cleaned, "retired":retired, "active":active},
        "live_tasks":[list(r) for r in live], "full_live_ram_peak_bytes":None}


def reusable_first(previous, source, proof):
    from audit_esp32_followup import envelope, verified
    campaign = envelope(previous, allow_incomplete=True)
    plan = json.loads((previous / "plan.json").read_text())
    if campaign["mode"] != "tm-message-lifetimes" or campaign["board_mac"] != MAC or plan["resets"] != 5 or plan["build_manifest_sha256"] != sha(source / "build.json"):
        raise ValueError("Previous round is not from the same frozen five-reset experiment")
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
        if sha(previous / "build" / name) != sha(source / name):
            raise ValueError("Previous round image differs")
    verified(previous / "captures", previous / "build", MAC)
    verified(previous / "captures", previous / "build", MAC, logs=("verify-run1.log",))
    return read_run(previous / "captures", 1, proof)


def collect(root, output, source, port, reuse_first=None, validation_only=False):
    proof = build_proof(source)
    boundary = proof.get("compiler_boundary_stack_trace", False)
    native_sp = proof.get("native_assembly_sp_trace", False)
    extended = boundary or native_sp
    if validation_only and (not proof.get("task_lifecycle_validation") or reuse_first):
        raise ValueError("Finite lifecycle validation requires its reviewed image and fresh resets")
    reused = reusable_first(reuse_first, source, proof) if reuse_first else None
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build = output / "build"
        build.mkdir()
        for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
            shutil.copyfile(source / name, build / name)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(Path(__file__).with_name("run_esp32_followup.py"), output / "board-helper.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        (output / "plan.json").write_text(json.dumps({"resets":5, "seconds":15 if validation_only else 150 if extended else 100, "board_mac":MAC,
            "build_manifest_sha256":sha(source / "build.json"), "old_results_replaced":False,
            **({"validation_only":True} if validation_only else {}),
            "reused_first_reset":reused is not None,
            "reuse_reason":"native static-API heap ownership and aligned stack-span validator correction" if reused else None}, indent=2)+"\n")
        if reused:
            shutil.copytree(reuse_first, output / "reused-first-source")
        board = Board(root, output, MAC, port)
        campaign = {"mode":"tm-task-lifecycle-validation" if validation_only else "tm-message-lifetimes", "status":"incomplete", "board_mac":MAC, "independent_resets":0,
            "started_utc":datetime.now(timezone.utc).isoformat(), "original_flash_restored":False,
            "old_cohort_modified":False, "energy_measured":False, "external_independent_replication":False}
        try:
            board.backup()
            try:
                captures = output / "captures"
                captures.mkdir()
                pairs = board.flash(captures, build)
                try:
                    if not validation_only:
                        validation = output / "validation"
                        validation.mkdir()
                        board.capture(validation, 1, 30 if extended else 15,
                            stop="NATIVE_SP END" if native_sp else "BOUNDARY_RAM END" if boundary else "FREERTOS_RAM END", send="validate",
                            **({"monotonic_clock":True} if extended else {}))
                        read_run(validation, 1, proof, validation=True)
                        board.verify(pairs, validation / "verify-run1.log")
                    if reused:
                        for name in ("reset1.jsonl", "reset1.raw", "capture1.log", "verify-run1.log"):
                            shutil.copyfile(reuse_first / "captures" / name, captures / name)
                        (captures / "result1.json").write_text(json.dumps(reused, indent=2)+"\n")
                        campaign["independent_resets"] = 1
                        print("TM RAM 1 reused after corrected native ownership audit", flush=True)
                    for index in range(2 if reused else 1, 6):
                        board.capture(captures, index, 15 if validation_only else 150 if extended else 100,
                            stop="FREERTOS_RAM END" if validation_only else "TM_RAM END",
                            send="validate" if validation_only else None,
                            **({"monotonic_clock":True} if extended else {}))
                        board.verify(pairs, captures / ("verify-run%d.log" % index))
                        result = read_run(captures, index, proof, validation=validation_only)
                        (captures / ("result%d.json" % index)).write_text(json.dumps(result, indent=2)+"\n")
                        campaign["independent_resets"] += 1
                        print("TM RAM", index, result.get("task_lifecycles", result.get("tasks")), flush=True)
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
    validation_only = plan.get("validation_only", False)
    mode = "tm-task-lifecycle-validation" if validation_only else "tm-message-lifetimes"
    if campaign["mode"] != mode or campaign["board_mac"] != MAC or campaign["independent_resets"] != 5 or plan["resets"] != 5 or plan["build_manifest_sha256"] != sha(source / "build.json"):
        raise ValueError("Incomplete or changed frozen campaign")
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
        if sha(output / "build" / name) != sha(source / name):
            raise ValueError("Measured image differs from qualified build")
    verified(output / "captures", output / "build", MAC)
    independent_captures(output / "captures", range(1, 6))
    if validation_only:
        if not proof.get("task_lifecycle_validation") or plan["seconds"] != 15:
            raise ValueError("Unreviewed finite lifecycle validation")
        runs = [read_run(output / "captures", i, proof, validation=True) for i in range(1, 6)]
        for i, result in enumerate(runs, 1):
            verified(output / "captures", output / "build", MAC, logs=("verify-run%d.log" % i,))
            if result != json.loads((output / "captures" / ("result%d.json" % i)).read_text()):
                raise ValueError("Finite lifecycle validation raw replay differs")
        return {"audit":"pass", "board_mac":MAC, "independent_resets":5, "runs":runs,
            "build":proof, "original_flash_restored":True, "ranking_eligible":False,
            "benchmark_result":False, "whole_ram_status":"正在测，未加入评分", "full_live_ram_peak_bytes":None,
            "scope":"finite task create/delete/native cleanup/address reuse measurement validation; not original workload throughput or a complete live-RAM peak"}
    validation = read_run(output / "validation", 1, proof, validation=True)
    verified(output / "validation", output / "build", MAC, logs=("verify-run1.log",))
    runs = [read_run(output / "captures", i, proof) for i in range(1, 6)]
    if plan.get("reused_first_reset"):
        if reusable_first(output / "reused-first-source", source, proof) != runs[0]:
            raise ValueError("Reused first reset differs from original evidence")
        for name in ("reset1.jsonl", "reset1.raw", "capture1.log", "verify-run1.log"):
            if (output / "captures" / name).read_bytes() != (output / "reused-first-source/captures" / name).read_bytes():
                raise ValueError("Reused raw evidence changed")
    for i, result in enumerate(runs, 1):
        if result != json.loads((output / "captures" / ("result%d.json" % i)).read_text()):
            raise ValueError("Raw replay differs from collected result")
    return {"audit":"pass", "board_mac":MAC, "independent_resets":5, "separate_validation":validation,
        "build":proof, "runs":runs, "reused_resets":int(plan.get("reused_first_reset", False)), "original_flash_restored":True, "ranking_eligible":False,
        "whole_ram_status":"正在测，未加入评分", "full_live_ram_peak_bytes":None,
        "scope":"native heap registration to third original report; static reservations plus live native allocations, observer included",
        "remaining":(["pre-allocator/unmanaged scope", "simultaneous live stack and version-specific observer perturbation"]
            if proof.get("message_ordinary_irq_stack_coverage") else
            ["matching Zephyr/NuttX message lifecycle captures", "pre-allocator/unmanaged scope", "simultaneous live stack and observer perturbation"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build-audit", "collect", "audit"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    parser.add_argument("--reuse-first", type=Path)
    parser.add_argument("--validation-only", action="store_true")
    args = parser.parse_args()
    if args.mode == "collect":
        def interrupted(signum, frame):
            signal.alarm(0)
            raise RuntimeError("Collection interrupted; restoring verified original Flash")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(1500)
        try:
            collect(args.root, args.output, args.source, args.port, args.reuse_first, args.validation_only)
        finally:
            signal.alarm(0)
    else:
        result = build_proof(args.source) if args.mode == "build-audit" else audit(args.output, args.source)
        if args.mode == "audit":
            (args.output / "audit.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
        print(json.dumps(result, indent=2, ensure_ascii=False))
