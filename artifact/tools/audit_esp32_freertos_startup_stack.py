"""Bind the application-entry canary window; never call it a whole-RAM peak."""
import json
from pathlib import Path
import re
import struct

from elftools.elf.elffile import ELFFile
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_hartstone_ram_riot import symbol_bytes
from audit_esp32_zephyr_syskernel_sema import literal_word
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
SOURCES={
    "components/esp_system/port/cpu_start.c":"308c15c5d3d23202f39b89feea3faaf59e1447cb1c08f28166cce71fc16c054c",
    "components/heap/port/esp32/memory_layout.c":"44908072bd89d244a3f3648725c16803532a362a7f6917b280180aa2c08e9504",
    "components/freertos/app_startup.c":"16541a28d8f255dd304b2908adc9716e54a9e0c3b73f39f3cc69ed20501ee848",
    "components/esp_system/startup.c":"48b51915e29026f86f094e732b3a18b23098ef6ecb96c4cb604291939156ad12",
}


def verify_trampoline(elf,symbols,text,name,constants,continuation):
    entry=symbols.get_symbol_by_name(name)[0]
    original=symbols.get_symbol_by_name(continuation)[0]
    found=re.search(r"^([0-9a-f]+) <"+re.escape(name)+r">:\n(.*?)(?=\n\n|\Z)",text,re.M|re.S)
    if found is None or int(found[1],16)!=entry["st_value"]:
        raise ValueError("Installed startup entry body missing")
    code=elf.get_section(entry["st_shndx"])
    rows=[]
    for address,encoding,instruction in re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.+)$",found[2],re.M):
        pc=int(address,16)
        if not entry["st_value"]<=pc<entry["st_value"]+entry["st_size"]:
            continue
        at=pc-code["sh_addr"]
        if code.data()[at:at+len(encoding)//2]!=int(encoding,16).to_bytes(len(encoding)//2,"little"):
            raise ValueError("Startup disassembly differs from ELF instructions")
        if re.match(r"(?:entry|call\w*|rsil|wsr\w*)\s",instruction) or re.match(
                r"(?:mov\S*|add\S*|sub\S*|l32r|l32i\S*)\s+a1,",instruction):
            raise ValueError("Pre-entry trampoline changes stack, call window or processor state")
        rows.append((pc,encoding,instruction))
    literals=[literal_word(elf,f"{pc:x}: {encoding} {instruction}",int(re.match(r"l32r\s+a(\d+)",instruction)[1]))
        for pc,encoding,instruction in rows if instruction.startswith("l32r")]
    if literals!=constants or not re.fullmatch(r"j\s+[0-9a-f]+ <"+re.escape(continuation)+">",rows[-1][2]):
        raise ValueError("Native paint bounds/state/pattern/continuation differ")
    pc,encoding,_=rows[-1]
    word=int(encoding,16)
    delta=word>>6
    if delta&(1<<17): delta-=1<<18
    if word&63!=6 or pc+4+delta!=original["st_value"]:
        raise ValueError("Encoded tail jump does not enter the original startup")


def build(source):
    folder=ROOT/"firmware/bsp/esp32/resource_census/freertos_startup_stack"
    manifest = json.loads((source / "build.json").read_text())
    readback = manifest.get("boot_readback_state_address")
    for name,path in (("startup-stack.inc",source/"startup-stack.inc"),("startup-entry.S",source/"observer/startup-entry.S")):
        if path.read_bytes()!=(folder/name).read_bytes():
            raise ValueError("Startup observation source changed")
    for name,digest in SOURCES.items():
        if sha(source/"native-startup"/name)!=digest:
            raise ValueError("Native startup differs from official ESP-IDF v5.2.5: "+name)
    cmake=(source/"observer/CMakeLists.txt").read_text()
    entry_name = "bench_boot_handoff_entry" if readback is not None else "bench_startup_entry"
    if cmake.count('"startup-entry.S"')!=1 or cmake.count('"-Wl,-e,' + entry_name + '"')!=1 or \
            cmake.count('"-Wl,--wrap=heap_caps_enable_nonos_stack_heaps"')!=1:
        raise ValueError("Startup source/entry/handoff link options missing")
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        state=symbols.get_symbol_by_name("bench_startup_state")[0]
        entry=symbols.get_symbol_by_name("bench_startup_entry")[0]
        installed=symbols.get_symbol_by_name(entry_name)[0]
        original=symbols.get_symbol_by_name("call_start_cpu0")[0]
        section=elf.get_section(state["st_shndx"])
        bss=[symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("_bss_start","_bss_end")]
        if state["st_size"]!=40 or section["sh_type"]!="SHT_NOBITS" or not section.name.startswith(".noinit") or \
                not (state["st_value"]+40<=bss[0] or state["st_value"]>=bss[1]) or \
                elf["e_entry"]!=installed["st_value"] or struct.unpack_from("<I",(source/"application.bin").read_bytes(),4)[0]!=installed["st_value"]:
            raise ValueError("Actual entry or pre-BSS persistent state differs")
        reserved=struct.unpack("<II",symbol_bytes(elf,symbols,"reserved_region_rom_pro_data",8))
        if reserved!=(0x3ffe0000,0x3ffe0440) or symbols.get_symbol_by_name("reserved_region_rom_app_data"):
            raise ValueError("Native ROM/single-core reservation differs")
        verify_trampoline(elf,symbols,(source/"disassembly.txt").read_text(),"bench_startup_entry",
            [state["st_value"],0x3ffe0440,0x3ffe3f20,0xa5a5a5a5,0x42535031],"call_start_cpu0")
        if readback is not None:
            from audit_esp32_resources import physical_intervals
            for name, path in (("boot-readback-entry.S", source / "observer/boot-readback-entry.S"),
                               ("boot-readback.inc", source / "boot-readback.inc")):
                if path.read_bytes() != (folder / name).read_bytes():
                    raise ValueError("Unreviewed pre-paint boot readback source")
            snapshot = symbols.get_symbol_by_name("bench_boot_handoff")[0]
            section = elf.get_section(snapshot["st_shndx"])
            if snapshot["st_size"] != 64 or section["sh_type"] != "SHT_NOBITS" or not section.name.startswith(".noinit") or \
                    not (snapshot["st_value"] + 64 <= bss[0] or snapshot["st_value"] >= bss[1]):
                raise ValueError("Boot readback is overwritten by native BSS clear")
            # Loaded application segments must not overwrite the inherited state or marked stack.
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_LOAD" or not segment["p_memsz"]:
                    continue
                for left, right in physical_intervals(segment["p_paddr"], segment["p_memsz"]):
                    for low, high in ((readback, readback + 40), (0x3ffe0440, 0x3ffe3f20)):
                        if left < high and low < right:
                            raise ValueError("Application load clobbers inherited boot evidence")
            verify_trampoline(elf, symbols, (source / "disassembly.txt").read_text(), entry_name,
                [snapshot["st_value"], readback, 0x3ffe0440, 0x3ffe3f20, 0x424c5331, 0xa5a5a5a5, 0x42485231],
                "bench_startup_entry")
    handoff = json.loads((source / "build.json").read_text()).get("startup_heap_handoff", False)
    edges = [("main_task", "__wrap_heap_caps_enable_nonos_stack_heaps")]
    edges += ([("__wrap_heap_caps_enable_nonos_stack_heaps", "bench_startup_heap_handoff"),
               ("bench_startup_heap_handoff", "heap_caps_enable_nonos_stack_heaps")] if handoff else
              [("__wrap_heap_caps_enable_nonos_stack_heaps", "heap_caps_enable_nonos_stack_heaps")])
    edges.append(("__wrap_tm_thread_sleep", "bench_startup_stack_report"))
    return {"application_startup_stack_coverage":True,
        **({"boot_readback_state_address": readback, "boot_readback_snapshot_bytes": 64} if readback is not None else {}),
        "startup_stack_observer":{
        "entry_address":entry["st_value"],"original_entry_address":original["st_value"],
        "state_address":state["st_value"],"state_bytes":40,"lower_bound":0x3ffe0440,
        "entry_sp_upper_bound":0x3ffe3f20,"unpainted_guard_bytes":64,"resolution_bytes":4,
        "official_sources":[{"url":"https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/"+n,"sha256":h} for n,h in SOURCES.items()],
        "machine_calls":calls(source,edges)}}


def heap_handoff(lines, events, pools):
    from run_esp32_tm_ram_lifetimes import replay_events
    pattern = re.compile(r"FREERTOS_BOOT_HEAP before_event=(\d+) after_event=(\d+) before_occupied=(\d+) after_occupied=(\d+) before_peak=(\d+) after_peak=(\d+) before_pools=(\d+) after_pools=(\d+) count=(\d+)")
    markers = [(i, pattern.fullmatch(line)) for i, line in enumerate(lines)
               if line.startswith("FREERTOS_BOOT_HEAP ")]
    if len(markers) != 1 or markers[0][1] is None:
        raise ValueError("Missing or repeated startup-heap handoff")
    at, match = markers[0]
    before, after, before_used, after_used, before_peak, after_peak, before_pools, after_pools, count = map(int, match.groups())
    if count != 1 or not 0 < before < after <= len(events) or after_pools != before_pools + 1 or \
            after_pools > len(pools) or at + 1 >= len(lines) or not lines[at + 1].startswith("FREERTOS_BOOT_STACK "):
        raise ValueError("Startup-heap handoff boundary differs")
    added = events[before:after]
    pool = pools[before_pools]
    if added != [(before, 0, before_pools, 0x3ffe0440, pool[3])] or \
            pool[0:2] != (0x3ffe0440, 0x40000000 - 0x3ffe0440):
        raise ValueError("Native deferred-region registration differs")
    phases = []
    for cursor, used, peak, pool_count in ((before, before_used, before_peak, before_pools),
                                         (after, after_used, after_peak, after_pools)):
        replay = replay_events(events[:cursor], pools, require_terminal=False)
        if replay["occupied"] != used or replay["peak"] != peak or replay["kinds"].get(0) != pool_count:
            raise ValueError("Handoff counters disagree with allocation-event history")
        phases.append({"event_cursor": cursor, "occupied_bytes": used,
                       "allocated_peak_through_boundary_bytes": peak, "registered_pools": pool_count})
    if after_used - before_used != pool[3]:
        raise ValueError("Deferred heap capacity was counted as allocated memory")
    return {"before_release": phases[0], "after_release": phases[1],
        "released_region_start": pool[0], "released_region_capacity_bytes": pool[1],
        "new_allocator_metadata_bytes": pool[3], "whole_live_ram_peak_bytes": None,
        "scope": "Native application-startup stack release and allocator registration; capacity is not used RAM and stack/heap maxima are not added."}


def observations(lines,proof,live_tasks=None):
    found=[(i,m) for i,s in enumerate(lines) if (m:=re.fullmatch(
        r"FREERTOS_BOOT_STACK low=(\d+) entry_sp=(\d+) paint_end=(\d+) painted=(\d+) verified=(\d+) handoff_sp=(\d+) spare=(\d+) touched=(\d+) guard=(\d+) handoffs=(\d+)",s))]
    if len(found)!=1 or sum(s.startswith("FREERTOS_BOOT_STACK ") for s in lines)!=1:
        raise ValueError("Startup watermark missing or repeated")
    at,match=found[0]
    low,entry,end,painted,verified,handoff,spare,touched,guard,count=map(int,match.groups())
    p=proof["startup_stack_observer"]
    if low!=p["lower_bound"] or not low+guard<entry<=p["entry_sp_upper_bound"] or entry%16 or \
            end!=entry-guard or guard!=64 or painted!=verified or painted!=end-low or \
            painted<=0 or spare%4 or touched%4 or spare+touched!=painted or not 0<=spare<=painted or \
            low<=handoff<0x40000000 or handoff%16 or count!=1 or \
            at+1>=len(lines) or not lines[at+1].startswith("FREERTOS_STACK irq_address="):
        raise ValueError("Startup paint, handoff, bounds or watermark arithmetic differs")
    if live_tasks is not None:
        main=[t for t in live_tasks if t[5]==2]
        if len(main)!=1 or not main[0][1]<=handoff<main[0][1]+main[0][2]:
            raise ValueError("Handoff did not execute inside the original main-task allocation")
    return {"application_entry_sp":entry,"painted_start":low,"painted_end":end,
        "initial_painted_and_verified_bytes":painted,"handoff_main_task_sp":handoff,
        "spare_pattern_bytes":spare,"touched_watermark_bytes":touched,"unpainted_guard_bytes":guard,
        "resolution_bytes":4,"observed_before_native_heap_registration":True,
        "scope":"application entry to startup-heap handoff; no bootloader/ROM-before-entry, untouched frames or simultaneous-live peak",
        "full_live_ram_peak_bytes":None}
