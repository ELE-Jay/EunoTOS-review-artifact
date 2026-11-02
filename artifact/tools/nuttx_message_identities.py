"""Address-bearing observations at the existing native allocator event points."""
from nuttx_message_observer import replace_once

EDITS = {
    "mm.h": ("void bench_ram_heap_init(FAR struct mm_heap_s *heap);",
        "void bench_ram_heap_identity(FAR struct mm_heap_s *heap, void *old_pointer, size_t old_bytes, void *new_pointer, size_t new_bytes);"),
    "mm_malloc.c": ("      bench_ram_heap_delta(heap, SIZEOF_MM_NODE(node), 1);",
        "      bench_ram_heap_identity(heap, NULL, 0, (char *)node + SIZEOF_MM_ALLOCNODE, SIZEOF_MM_NODE(node));"),
    "mm_free.c": ("  bench_ram_heap_delta(heap, -(ptrdiff_t)nodesize, 2);",
        "  bench_ram_heap_identity(heap, mem, nodesize, NULL, 0);"),
    "mm_shrinkchunk.c": ("  bench_ram_heap_delta(heap, (ptrdiff_t)SIZEOF_MM_NODE(node) - (ptrdiff_t)nodesize, 3);",
        "  bench_ram_heap_identity(heap, (char *)node + SIZEOF_MM_ALLOCNODE, nodesize, (char *)node + SIZEOF_MM_ALLOCNODE, SIZEOF_MM_NODE(node));"),
    "mm_realloc.c": ("      bench_ram_heap_delta(heap, (ptrdiff_t)SIZEOF_MM_NODE(oldnode) - (ptrdiff_t)oldsize, 4);",
        "      bench_ram_heap_identity(heap, oldmem, oldsize, newmem, SIZEOF_MM_NODE(oldnode));"),
    "mm_memalign.c": ("      bench_ram_heap_delta(heap, -(ptrdiff_t)(alignedchunk - rawchunk), 5);",
        "      bench_ram_heap_identity(heap, (void *)rawchunk, SIZEOF_MM_NODE(node) + alignedchunk - rawchunk, (void *)alignedchunk, SIZEOF_MM_NODE(node));"),
}


def instrument(name, text):
    if name not in EDITS:
        return text
    anchor, extra = EDITS[name]
    return replace_once(text, anchor, anchor + "\n" + extra)


def replay(events, identities, regions, heap):
    live, peak = {}, 0
    wanted = [e for e in events if e["kind"] in (1, 2, 3, 4, 5)]
    if len(wanted) != len(identities):
        raise ValueError("Allocation identity event coverage differs")
    for event, item in zip(wanted, identities):
        old, old_size, new, new_size = (item[n] for n in ("old", "old_bytes", "new", "new_bytes"))
        k = event["kind"]
        if item["at"] != event["event"] or item["heap"] != heap or new_size-old_size != event["delta"]:
            raise ValueError("Identity and native byte event disagree")
        if (not old) != (not old_size) or (not new) != (not new_size) or (k == 1) != (old == 0) or (k == 2) != (new == 0):
            raise ValueError("Allocation/free identity shape differs")
        if old and live.pop(old, None) != old_size:
            raise ValueError("Retirement or resize lacks matching live allocation")
        if k == 3 and (old != new or new_size > old_size) or k == 4 and new_size < old_size or k == 5 and new <= old:
            raise ValueError("Native resize/alignment address semantics differ")
        if new:
            if new in live or new_size % 8 or new_size < 8 or not any(
                    start < new-8 < new-8+new_size <= start+length-8 for start, length in regions):
                raise ValueError("New live allocation overlaps identity or escapes region")
            live[new] = new_size
        intervals = sorted((p-8, p-8+n) for p,n in live.items())
        if any(a[1] > b[0] for a,b in zip(intervals, intervals[1:])):
            raise ValueError("Simultaneously live native blocks overlap")
        peak = max(peak, sum(live.values()))
        overhead = 368 + 16*sum(e["kind"] == 6 for e in events[:event["event"]+1])
        if sum(live.values()) + overhead != event["occupied"]:
            raise ValueError("Live block set disagrees with native occupied bytes")
    return {"live":live, "block_peak_bytes":peak, "transitions":len(identities)}
