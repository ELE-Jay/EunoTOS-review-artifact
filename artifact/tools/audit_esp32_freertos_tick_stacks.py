"""Reconcile simultaneous native saved-SP snapshots; never infer an exact peak."""
import re

SUMMARY = re.compile(r"FREERTOS_LIVE samples=(\d+) records=(\d+) skipped=(\d+) maximum=(\d+) capacity=128 frame=192")
RECORD = re.compile(r"FREERTOS_LIVE record=(\d+) tick=(\d+) sample=(\d+) current=(\d+) irq_sp=(\d+) heap=(\d+) events=(\d+) tasks=(\d+) task_sum=(\d+) irq_depth=(\d+) interrupted_sp=(\d+) ps=(\d+)")
TASK = re.compile(r"FREERTOS_LIVE record=(\d+) task=(\d+) tcb=(\d+) sp=(\d+)")


def observations(lines, proof, events, live):
    summaries = [m for line in lines if (m := SUMMARY.fullmatch(line))]
    records = [tuple(map(int, m.groups())) for line in lines if (m := RECORD.fullmatch(line))]
    tasks = [tuple(map(int, m.groups())) for line in lines if (m := TASK.fullmatch(line))]
    if len(summaries) != 1 or sum(line.startswith("FREERTOS_LIVE ") for line in lines) != 1+len(records)+len(tasks):
        raise ValueError("Missing/repeated/invalid native tick snapshot")
    samples, count, skipped, maximum = map(int, summaries[0].groups())
    if not 8000 <= samples <= 11000 or not 1 <= count <= 128 or count != len(records):
        raise ValueError("Incomplete native tick observation window")
    owners = {r[0]:r for r in live}
    if len(owners) != len(live) or not 1 <= len(owners) <= 8:
        raise ValueError("Native task identity list is ambiguous")
    if any(e[1] in (7,8) for e in events):
        raise ValueError("Snapshot parser requires the original retained-task lifecycle")
    heap = [0]
    created = {}
    for i, (_, kind, _, pointer, delta) in enumerate(events):
        heap.append(heap[-1]+(delta if kind <= 4 else 0))
        if kind == 5: created[pointer] = i+1
    irq_low = proof["interrupt_stack"]["address"]
    irq_top = irq_low+proof["interrupt_stack"]["reserved_bytes"]
    output, previous_sample, previous_tick, previous_max = [], 0, None, 0
    for expected, row in enumerate(records):
        index, tick, sample, current, irq_sp, occupied, event_count, n, total, irq_depth, interrupted, ps = row
        if index != expected or not previous_sample < sample <= samples or previous_tick is not None and tick <= previous_tick or \
                not 0 < event_count <= len(events) or heap[event_count] != occupied or \
                not irq_low <= irq_sp < irq_top or irq_sp % 16 or irq_top-irq_sp != irq_depth or ps&15 == 0:
            raise ValueError("Snapshot order, native heap epoch or IRQ stack differs")
        group = [r for r in tasks if r[0] == index]
        if n != len(owners) or len(group) != n or [r[1] for r in group] != list(range(n)) or \
                {r[2] for r in group} != set(owners) or current not in owners:
            raise ValueError("Incomplete simultaneous task set")
        calculated = 0
        values = []
        for _, _, tcb, sp in group:
            task = owners[tcb]
            low, span = task[1:3]
            top = low+span-1
            if created.get(tcb, len(events)+1) > event_count or not low <= sp < top or sp%16 or top%16:
                raise ValueError("Saved SP is not in a live native stack")
            if tcb == current and (interrupted != sp+192 or interrupted > top):
                raise ValueError("Actual interrupt frame reservation differs")
            calculated += top-sp
            values.append({"tcb":tcb,"stack_low":low,"stack_aligned_top":top,"saved_sp":sp,"reserved_span_bytes":top-sp})
        if total != calculated or total+irq_depth <= previous_max:
            raise ValueError("Simultaneous sum/record-high arithmetic differs")
        previous_max, previous_sample, previous_tick = total+irq_depth, sample, tick
        output.append({"tick":tick,"sample":sample,"heap_occupied_bytes":occupied,
            "heap_event_count":event_count,"current_tcb":current,"interrupted_task_sp":interrupted,
            "irq_sp":irq_sp,"irq_reserved_span_bytes":irq_depth,"tasks":values,
            "simultaneous_stack_reserved_span_bytes":previous_max})
    if previous_max != maximum or any(r[0] >= count for r in tasks):
        raise ValueError("Snapshot maximum or record binding differs")
    return {"samples":samples,"record_high_snapshots":output,"non_irq_calls_skipped":skipped,
        "maximum_sampled_stack_reserved_span_bytes":maximum,"new_ram_bytes_to_add":0,
        "exact_peak_established":False,"whole_live_ram_peak_bytes":None,
        "scope":"100-Hz native tick snapshots of existing stack reservations, observer included; not exact live or whole-RAM peak"}
