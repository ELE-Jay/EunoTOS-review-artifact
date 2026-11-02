#!/usr/bin/env python3
"""Reconcile simultaneous native contexts against allocation-event prefixes."""
import re

from run_esp32_tm_ram_lifetimes import replay_events

HEADER = re.compile(r"FREERTOS_PEAK phase=(\d+) heap=(\d+) events=(\d+) sp=(\d+) current=(\d+) ps=(\d+) nesting=(\d+) tasks=(\d+)")
TASK = re.compile(r"FREERTOS_PEAK phase=(\d+) task=(\d+) tcb=(\d+) saved=(\d+)")


def observations(lines, events, pools, proof):
    headers, entries = {}, {}
    for line in lines:
        if not line.startswith("FREERTOS_PEAK "):
            continue
        if match := HEADER.fullmatch(line):
            phase, *values = map(int, match.groups())
            if phase not in range(3) or phase in headers:
                raise ValueError("Repeated or unknown allocation-peak phase")
            headers[phase] = values
        elif match := TASK.fullmatch(line):
            phase, index, tcb, saved = map(int, match.groups())
            if phase not in headers or index != len(entries.setdefault(phase, [])):
                raise ValueError("Missing/reordered allocation-peak task")
            entries[phase].append((tcb, saved))
        else:
            raise ValueError("Malformed allocation-peak context")
    if 0 not in headers or 2 not in headers:
        raise ValueError("Startup and post-handoff allocation-peak contexts required")
    result = []
    for phase, (heap, cursor, sp, current, ps, nesting, count) in sorted(headers.items()):
        if not 0 < cursor <= len(events) or not 0 <= count <= 8 or nesting > 1 or ps & 15 < 1:
            raise ValueError("Invalid allocation-peak context boundary")
        prefix = events[:cursor]
        replay = replay_events(prefix, pools, require_terminal=False)
        if replay["occupied"] != heap:
            raise ValueError("Allocation-peak context is not bound to its heap-event prefix")
        pairs, pending = {}, None
        for _, kind, _, address, delta in prefix:
            if kind == 5:
                pending = (address, delta)
            elif kind == 6:
                if pending is None:
                    raise ValueError("Task stack without its TCB")
                pairs[pending[0]] = (address, delta)
                pending = None
        owners = replay["owners"]
        live = {tcb: pair for tcb, pair in pairs.items()
                if owners.get(tcb, (None,))[0] == 5 and owners.get(pair[0], (None,))[0] == 6}
        rows = entries.get(phase, [])
        if len(rows) != count or len(set(tcb for tcb, _ in rows)) != count or set(live) != {tcb for tcb, _ in rows}:
            raise ValueError("Allocation-peak task inventory differs from native ownership")
        stacks = []
        irq = proof["interrupt_stack"]
        irq_low, irq_high = irq["address"], irq["address"] + irq["reserved_bytes"]
        if phase == 0:
            if current or nesting or not 0x3ffe0440 <= sp <= 0x3ffe3f20:
                raise ValueError("Pre-scheduler context is not on the native startup stack")
            context = "application startup stack"
        elif nesting:
            if current not in live or not irq_low <= sp < irq_high:
                raise ValueError("Interrupt context is not on the native IRQ stack")
            context = "native IRQ stack"
        else:
            if current not in live:
                raise ValueError("Running native task lacks current stack ownership")
            low, span = live[current]
            if not low <= sp < low + span:
                raise ValueError("Current SP is outside its owned native task stack")
            context = "native task stack"
        for tcb, saved in rows:
            low, span = live[tcb]
            high = low + span - 1
            if not low <= saved < high or saved & 15 or high & 15:
                raise ValueError("Saved native task SP is outside its owned stack")
            effective = sp if tcb == current and not nesting else saved
            stacks.append({"tcb": tcb, "stack": low, "span": span, "saved_sp": saved,
                           "observed_sp": effective, "reserved_span_below_top_bytes": high - effective})
        result.append({"phase": phase, "native_heap_occupied_bytes": heap,
                       "allocation_event_cursor": cursor, "observed_sp": sp,
                       "current_tcb": current, "ps": ps, "interrupt_nesting": nesting,
                       "current_context": context, "task_contexts": stacks})
    if max(row["native_heap_occupied_bytes"] for row in result) != replay_events(events, pools)["peak"]:
        raise ValueError("Native global heap high-water lacks its same-instant context")
    return {"phases": result, "global_heap_peak_has_context": True,
            "added_ram_bytes": 0, "whole_live_ram_peak_bytes": None,
            "scope": "Same-instant native contexts at each phase's allocated-heap high-water; observer frames included. Saved non-running contexts are reservations, not written-byte counts. This is not a continuous whole-lifetime live-stack peak."}
