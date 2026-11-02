#!/usr/bin/env python3
"""Reconcile retained native RAM ownership without creating a RAM score."""
import argparse
import importlib
import json
from pathlib import Path
import re
from elftools.elf.elffile import ELFFile
from audit_esp32_ram_census import region_accounting
from audit_esp32_resources import static_footprint, physical_intervals, union_bytes, RAM
from replay_esp32_followup import replay
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT/"artifacts/reports"
SPECS = (
    ("FreeRTOS","freertos_stack_coverage","esp32-freertos-stack-coverage-v1","esp32-freertos-stack-coverage-b1-v1"),
    ("Zephyr","zephyr_ram_lifetimes","esp32-zephyr-lifetimes-v4","esp32-zephyr-lifetimes-b1-v1"),
    ("RIOT","riot_stack_coverage","esp32-riot-stack-coverage-v1","esp32-riot-stack-coverage-b1-v1"),
    ("AliOS-Rhino","rhino_stack_coverage","esp32-rhino-stack-coverage-v1","esp32-rhino-stack-coverage-b1-v2"),
    ("NuttX","nuttx_heap_events","esp32-nuttx-retained-owners-v1","esp32-nuttx-retained-owners-b1-v1"),
)


def allocation_total(sections,regions,inside_static,heap_peak):
    region_accounting(sections,regions,inside_static)
    static = static_bytes(sections)
    if heap_peak<0 or heap_peak>sum(n for _,n in regions):
        raise ValueError("Native heap peak outside managed capacity")
    return static+(0 if inside_static else heap_peak)


def static_bytes(sections):
    from audit_esp32_resources import physical_intervals,union_bytes
    return union_bytes([part for s in sections for part in physical_intervals(int(s["address"],16),s["bytes"])])


def address_coverage(sections,regions,control=(),exclusions=()):
    """Partition the existing auditor's physical address universe, not live RAM."""
    def physical(start,size):
        if type(start) is not int or type(size) is not int or start<0 or size<=0:
            raise ValueError("Invalid address-coverage address/size")
        return physical_intervals(start,size)
    def merged(spans):
        result=[]
        for left,right in sorted(spans):
            if right<=left:
                raise ValueError("Empty/reversed address-coverage interval")
            if result and left<=result[-1][1]:
                result[-1]=(result[-1][0],max(result[-1][1],right))
            else:
                result.append((left,right))
        return result
    domain=merged(p for start,end in RAM for p in physical_intervals(start,end-start))
    groups={"static":merged(p for s in sections for p in physical(int(s["address"],16),s["bytes"])),
            "native_heap":merged(p for start,size in regions for p in physical(start,size)),
            "allocator_control":merged(p for start,size in control for p in physical(start,size)),
            "native_exclusion":merged(p for start,size in exclusions for p in physical(start,size))}
    if any(not any(a<=lo<hi<=b for a,b in domain) for spans in groups.values() for lo,hi in spans):
        raise ValueError("Address-coverage record outside the existing physical RAM universe")
    segments=[]
    for start,end in domain:
        cuts=sorted({start,end}|{x for spans in groups.values() for pair in spans for x in pair if start<x<end})
        for left,right in zip(cuts,cuts[1:]):
            owners=[name for name,spans in groups.items() if any(a<=left<right<=b for a,b in spans)]
            if segments and segments[-1]["end"]==left and segments[-1]["owners"]==owners:
                segments[-1]["end"]=right
                segments[-1]["bytes"]+=right-left
            else:
                segments.append({"start":left,"end":right,"bytes":right-left,"owners":owners})
    if sum(s["bytes"] for s in segments)!=union_bytes(domain):
        raise ValueError("Physical address-coverage partition does not close")
    total=lambda predicate:sum(s["bytes"] for s in segments if predicate(s["owners"]))
    return {"physical_address_universe_bytes":union_bytes(domain),
        "static_sram_bytes":total(lambda o:"static" in o),
        "native_heap_capacity_bytes_not_occupancy":total(lambda o:"native_heap" in o),
        "heap_capacity_already_in_static_bytes":total(lambda o:"static" in o and "native_heap" in o),
        "allocator_control_outside_static_and_heaps_bytes":total(lambda o:"allocator_control" in o and
            "static" not in o and "native_heap" not in o),
        "outside_static_and_native_allocator_bytes":total(lambda o:not set(o)&{"static","native_heap","allocator_control"}),
        "native_exclusion_bytes":total(lambda o:"native_exclusion" in o),
        "unclassified_address_bytes_not_free_or_used":total(lambda o:not o),"segments":segments}


def message_coverage(windows=None):
    from audit_esp32_message_startup import current_windows
    from audit_esp32_zephyr_thread import read_raw_capture
    from run_esp32_tm_ram_lifetimes import POOL
    cells=[]
    for cell in (current_windows() if windows is None else windows)["cells"]:
        source,capture=ROOT/cell["build"],ROOT/cell["capture"]
        saved=json.loads((capture/"audit.json").read_text())
        sections=static_footprint(source/"application.elf")["ram_sections"]
        controls=[]
        excluded=[]
        if cell["os"]=="FreeRTOS":
            observed=[[(int(m[1]),int(m[2])) for row in read_raw_capture(capture/"captures",i)
                if (m:=POOL.fullmatch(row["line"]))] for i in range(1,6)]
            if not observed[0] or any(r!=observed[0] for r in observed):
                raise ValueError("Five-reset native heap address coverage differs")
            regions=observed[0]
            with (source/"application.elf").open("rb") as stream:
                elf=ELFFile(stream)
                symbols=elf.get_section_by_name(".symtab")
                from audit_esp32_hartstone_ram_riot import symbol_bytes
                for name in ("reserved_region_cpu0_cache","reserved_region_rom_data","reserved_region_rom_pro_data",
                             "reserved_region_rtc_reserved_data"):
                    values=symbol_bytes(elf,symbols,name,8)
                    start,end=[int.from_bytes(values[i:i+4],"little") for i in (0,4)]
                    if end<=start:
                        raise ValueError("Compiled native exclusion is empty/reversed")
                    excluded.append({"symbol":name,"start":start,"bytes":end-start})
        elif cell["os"]=="Zephyr":
            regions=[saved["build"]["reservations"]["kheap__system_heap"]]
        else:
            observed=[r["native_heap_regions"] for r in saved["runs"]]
            if len(observed)!=5 or any(r!=observed[0] for r in observed):
                raise ValueError("Five-reset NuttX native heap address coverage differs")
            regions=observed[0]
            controls=[nuttx_context(source,regions)]
        coverage=address_coverage(sections,regions,controls,[(r["start"],r["bytes"]) for r in excluded])
        if coverage["static_sram_bytes"]!=cell["static_sram_bytes"]:
            raise ValueError("Physical inventory differs from measured-image static footprint")
        cells.append({"os":cell["os"],"build":cell["build"],"capture":cell["capture"],
            "elf_sha256":sha(source/"application.elf"),"campaign_sha256":cell["campaign_sha256"],
            "native_heap_regions":[list(r) for r in regions],"allocator_controls":controls,
            "native_exclusions":excluded,"coverage":coverage})
    return {"audit":"pass","cells":cells,"reused_workload_resets":15,"new_board_resets":0,
        "new_metric_created":False,"old_data_modified":False,"ranking_eligible":False,
        "scope":"address ownership of the current three measured message/startup images; capacity is not live occupancy",
        "limits":["physical address universe is the existing image auditor's RAM ranges, not an available-heap claim",
            "unclassified ranges are neither declared free nor assumed occupied",
            "native exclusions are source-bound reservations, not measured ROM/cache occupancy",
            "startup handoff can change ownership over time; this union does not establish a simultaneous live peak",
            "marked stack writes do not account for unwritten reserved frames or before-entry execution"],
        "whole_ram_status":"正在测，未加入评分","whole_live_ram_peak_bytes":None}


def tick_coverage(controlled_nuttx=False):
    """Reconcile the three frozen tick images, retaining every uncovered boundary."""
    cells=[];observations=[]
    for system,module,build_name,capture_name in (
            ('FreeRTOS','run_esp32_tm_ram_lifetimes','esp32-freertos-message-tick-stacks-v1','esp32-freertos-message-tick-stacks-b1-v1'),
            ('Zephyr','run_esp32_zephyr_message_lifetimes','esp32-zephyr-message-tick-stacks-v3','esp32-zephyr-message-tick-stacks-b1-v1'),
            ('NuttX','run_esp32_nuttx_message_lifetimes',
                'esp32-nuttx-message-tick-control-v1' if controlled_nuttx else 'esp32-nuttx-message-tick-stacks-v2',
                'esp32-nuttx-message-tick-control-census-b1-v1' if controlled_nuttx else 'esp32-nuttx-message-tick-stacks-b1-v2')):
        source,capture=REPORTS/build_name,REPORTS/capture_name
        result=json.loads(json.dumps(importlib.import_module(module).audit(capture,source)))
        if result!=json.loads((capture/'audit.json').read_text()) or result['independent_resets']!=5:
            raise ValueError('Current native-tick memory image or reset evidence differs')
        cells.append({'os':system,'build':source.relative_to(ROOT).as_posix(),
            'capture':capture.relative_to(ROOT).as_posix(),'campaign_sha256':sha(capture/'campaign.json'),
            'static_sram_bytes':result['build']['static_sram_bytes']})
        spans=[r['native_tick_stack_snapshots'] for r in result['runs']]
        if any(s['exact_peak_established'] or s['new_ram_bytes_to_add'] for s in spans):
            raise ValueError('Sampling acquired a whole-RAM score or duplicate stack bytes')
        observations.append({'os':system,'independent_resets':5,'reused_resets':result.get('reused_resets',0),
            'samples':[s['samples'] for s in spans],
            'maximum_sampled_stack_reserved_span_bytes':[s['maximum_sampled_stack_reserved_span_bytes'] for s in spans],
            'added_stack_bytes':0,'scope':'sampled context reservations including observer, not continuous live peaks'})
    result=message_coverage({'cells':cells})
    result.update(scope='physical address ownership of three native-tick message images; sampled contexts do not close whole-lifetime live RAM',
        tick_observations=observations)
    return result


def nuttx_context(source,regions):
    with (source/"application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbol = elf.get_section_by_name(".symtab").get_symbol_by_name("_sheap")[0]
        start = (symbol["st_value"]+7)&~7
    size = regions[0][0]-start
    if size!=368:
        raise ValueError("Native NuttX heap-control prefix differs")
    body = re.search(r"^[0-9a-f]+ <bench_ram_heap_init>:\n(.*?)(?=\n\n|\Z)",
                     (source/"disassembly.txt").read_text(),re.M|re.S)
    if body is None or not re.search(r"\bmovi\s+a8, 0x170\b",body[1]):
        raise ValueError("Actually compiled native heap-control counter initialization differs")
    return [start,size]


def message_startup_scope():
    from run_esp32_nuttx_message_lifetimes import audit as message_audit
    from audit_esp32_freertos_ram_lifetimes import calls
    source=REPORTS/"esp32-nuttx-message-identities-v1"
    capture=REPORTS/"esp32-nuttx-message-identities-b1-v1"
    result=message_audit(capture,source)
    if json.loads(json.dumps(result))!=json.loads((capture/"audit.json").read_text()):
        raise ValueError("Address lifecycle evidence changed")
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        stack=symbols.get_symbol_by_name("g_idlestack")[0]
        entry=symbols.get_symbol_by_name("__start")[0]
        start,size=stack["st_value"],stack["st_size"]
        if elf["e_entry"]!=entry["st_value"] or size!=3072:
            raise ValueError("Boot entry or known idle reservation differs")
    text=(source/"disassembly.txt").read_text()
    body=re.search(r"^[0-9a-f]+ <__start>:\n(.*?)(?=\n\n|\Z)",text,re.M|re.S)
    switch=re.search(r"\bl32r\s+a8,.*\("+format(start+size,"x")+r" <[^>]+>\)\n[^\n]*\bor\s+a1, a8, a8",body[1]) if body else None
    if body is None or not re.search(r"^.*\bentry\s+a1, 32$",body[1].splitlines()[0]) or switch is None or \
            re.search(r"\bcall(?:x)?\d+\b",body[1][:switch.start()]):
        raise ValueError("Compiled inherited-frame/known-stack transition differs")
    source_start=(source/"native-source/arch/xtensa/src/esp32/esp32_start.c").read_text()
    if "sp = (uint32_t)g_idlestack + IDLETHREAD_STACKSIZE;" not in source_start or \
            "CONFIG_ARCH_INTERRUPTSTACK=0" not in (source/"config").read_text().splitlines():
        raise ValueError("Startup stack source or ordinary IRQ configuration differs")
    sections=static_footprint(source/"application.elf")["ram_sections"]
    if not any(s["type"]=="SHT_NOBITS" and int(s["address"],16)<=start and
               start+size<=int(s["address"],16)+s["bytes"] for s in sections):
        raise ValueError("Known boot/idle stack is outside counted static SRAM")
    machine=calls(source,[("__start","nx_start"),("nx_start","up_allocate_heap"),
        ("nx_start","umm_initialize"),("umm_initialize","mm_initialize"),
        ("mm_initialize","bench_ram_heap_init")],require_iram=False)
    return {"audit":"pass","source":"artifacts/reports/"+source.name,"evidence":"artifacts/reports/"+capture.name,
        "build_manifest_sha256":sha(source/"build.json"),"campaign_sha256":sha(capture/"campaign.json"),
        "elf_sha256":sha(source/"application.elf"),"entry_address":entry["st_value"],
        "inherited_sp_entry_frame_bytes":32,"entry_sp_value_measured":False,
        "known_boot_idle_stack":{"start":start,"reserved_bytes":size,"already_in_static_sram":True},
        "machine_calls":machine,"separate_ordinary_irq_stack":False,
        "reused_workload_resets":5,"new_board_resets":0,"new_metric_created":False,
        "scope":"compiled startup/allocator boundary evidence, not an observed pre-allocator or live-stack peak",
        "remaining":["inherited SP and bootloader/ROM memory before the known-stack switch",
            "actual simultaneous stack depths, including ordinary IRQ on task stacks",
            "unmanaged/ROM-owned memory and observer-inclusive versus uninstrumented accounting"],
        "whole_ram_status":"正在测，未加入评分","full_live_ram_peak_bytes":None}


def observer_inputs(text):
    """Read allocated input sections, excluding discarded and cross-reference lists."""
    marker="Linker script and memory map\n"
    if text.count(marker)!=1:
        raise ValueError("GNU map memory-layout section missing/ambiguous")
    text=text.split(marker,1)[1].split("Cross Reference Table",1)[0]
    pending=None
    for line in text.splitlines():
        first=re.fullmatch(r" (\.\S+)(?:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+))?",line)
        continuation=re.fullmatch(r"\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+)",line)
        if first:
            name, address, size, member=first.groups()
            pending=name if address is None else None
            if address is None: continue
        elif pending and continuation:
            name=pending
            address,size,member=continuation.groups()
            pending=None
        else:
            pending=None
            continue
        if re.search(r"\((?:census\.c|startup-entry\.S)[^)]*\.(?:o|obj)\)$",member):
            yield {"input_section":name,"address":int(address,16),"bytes":int(size,16)}


def observer_ownership():
    from audit_esp32_message_startup import current_windows
    windows=current_windows()
    cells=[]
    for cell in windows["cells"]:
        source=ROOT/cell["build"]
        footprint=static_footprint(source/"application.elf")
        if footprint["static_sram_bytes"]!=cell["static_sram_bytes"]:
            raise ValueError("Current observer physical footprint differs")
        manifest=json.loads((source/"build.json").read_text())
        if sha(source/"application.map")!=manifest["files"]["application.map"]:
            raise ValueError("Map is not bound to the measured build")
        objects=[]
        with (source/"application.elf").open("rb") as stream:
            elf=ELFFile(stream)
            allocated=[s for s in elf.iter_sections() if s["sh_flags"]&2 and s["sh_size"]]
            symbols=[s for s in elf.get_section_by_name(".symtab").iter_symbols()
                if s["st_info"]["type"]=="STT_OBJECT" and s["st_size"] and isinstance(s["st_shndx"],int)]
            for row in observer_inputs((source/"application.map").read_text()):
                start,size=row["address"],row["bytes"]
                if not size or not any(a<=start and start+size<=b for a,b in RAM): continue
                # Merged strings have pre-merge map sizes and shared addresses.
                if row["input_section"].startswith((".rodata", ".srodata")): continue
                parents=[s for s in allocated if s["sh_addr"]<=start and start+size<=s["sh_addr"]+s["sh_size"]]
                if len(parents)!=1:
                    raise ValueError("Observer input section is not contained in one allocated ELF section")
                parent=parents[0]
                objects.append({**row,"elf_section":parent.name,
                    "kind":"ram_code_and_literals" if parent["sh_flags"]&4 else "ram_data",
                    "object_symbols":[s.name for s in symbols if start<=s["st_value"] and
                        s["st_value"]+s["st_size"]<=start+size]})
        spans=[p for r in objects for p in physical_intervals(r["address"],r["bytes"])]
        if not objects or union_bytes(spans)!=sum(r["bytes"] for r in objects):
            raise ValueError("Observer input inventory missing or physically overlapping")
        data=[r for r in objects if r["kind"]=="ram_data"]
        code=[r for r in objects if r["kind"]=="ram_code_and_literals"]
        # A complete object symbol must be inside its recorded compiler input section.
        with (source/"application.elf").open("rb") as stream:
            symbols=ELFFile(stream).get_section_by_name(".symtab")
            state={"FreeRTOS":"bench_startup_state","Zephyr":"bench_z_startup_state","NuttX":"bench_nuttx_startup"}[cell["os"]]
            record=symbols.get_symbol_by_name(state)[0]
            if sum(record.name in r["object_symbols"] for r in data)!=1:
                raise ValueError("Pre-BSS startup state ownership missing/duplicated")
        baseline={"FreeRTOS":("tm-freertos-native-aligned-v1/message_processing","iotosbench_tm.elf"),
            "Zephyr":("zephyr-gcc13-align/message_processing","zephyr.elf"),
            "NuttX":("tm-nuttx-native-aligned-v1/message_processing","nuttx")}[cell["os"]]
        baseline_path=REPORTS/baseline[0]/baseline[1]
        baseline_bytes=static_footprint(baseline_path)["static_sram_bytes"]
        direct=union_bytes(spans)
        cells.append({"os":cell["os"],"build":cell["build"],"elf_sha256":sha(source/"application.elf"),
            "map_sha256":sha(source/"application.map"),"baseline_elf_sha256":sha(baseline_path),
            "static_sram_bytes":footprint["static_sram_bytes"],"baseline_static_sram_bytes":baseline_bytes,
            "whole_image_static_delta_bytes":footprint["static_sram_bytes"]-baseline_bytes,
            "direct_observer_input_bytes":direct,"direct_observer_data_bytes":sum(r["bytes"] for r in data),
            "direct_observer_ram_code_and_literals_bytes":sum(r["bytes"] for r in code),
            "other_linked_change_and_alignment_bytes":footprint["static_sram_bytes"]-baseline_bytes-direct,
            "input_sections":objects,"subtracted_from_published_ram_bytes":0})
    return {"audit":"pass","cells":cells,"new_board_resets":0,"new_metric_created":False,
        "scope":"measured-image static ownership decomposition; direct compiler input sections, not uninstrumented runtime inference",
        "limits":["whole-image delta also includes native hook changes, library selection, relaxation and alignment",
            "read-only input sections are excluded because merged-string map sizes do not establish unique ownership",
            "direct input-section ownership is not the complete causal cost of instrumentation",
            "subtracting identified storage does not reconstruct uninstrumented allocation/stack peaks"],
        "whole_ram_status":"正在测，未加入评分","whole_live_ram_peak_bytes":None,"ranking_eligible":False}


def audit():
    cells = []
    for os,module,source_name,capture_name in SPECS:
        if os=="Zephyr" and (REPORTS/"esp32-zephyr-stack-coverage-b1-v1/audit.json").exists():
            module,source_name,capture_name = "zephyr_stack_coverage","esp32-zephyr-stack-coverage-v1","esp32-zephyr-stack-coverage-b1-v1"
        source,capture = REPORTS/source_name,REPORTS/capture_name
        result = importlib.import_module("audit_esp32_"+module).audit(capture,source)
        if json.loads(json.dumps(result))!=json.loads((capture/"audit.json").read_text()):
            raise ValueError("Saved native lifecycle audit differs: "+os)
        campaign = json.loads((capture/"campaign.json").read_text())
        if campaign["board_mac"]!="34:98:7a:a2:85:28" or campaign["independent_resets"]!=3:
            raise ValueError("Wrong board or incomplete resource cohort")
        footprint = static_footprint(source/"application.elf")
        proof = result["build"]
        separate = replay(capture)["cells"][0]
        values,workers,extra_control = [],[],None
        for run in result["runs"]:
            inside = os=="Zephyr"
            peak = run["allocated_heap_peak_bytes"] if os in ("FreeRTOS","NuttX") else run["heap_native_peak_bytes"]
            if os=="FreeRTOS":
                regions = [r[:2] for r in run["tasks"]["pool_records"]]
            elif os=="Zephyr":
                regions = [proof["static_reservations"]["kheap__system_heap"]]
            elif os in ("RIOT","AliOS-Rhino"):
                regions = proof["heap_regions"]
            else:
                regions = run["stack_ownership"]["native_heap_regions"]
                context = nuttx_context(source,regions)
                extra_control = context[1]
                regions = [*regions,context]
            total = allocation_total(footprint["ram_sections"],regions,inside,peak)
            expected = run.get("observed_software_allocation_bytes",run.get("static_plus_native_heap_peak_bytes",run.get("allocated_software_ram_bytes",total)))
            if total!=expected:
                raise ValueError("Scoped static/allocator total differs: "+os)
            original = run["original_series"] if os=="NuttX" else run["original_ph4"]
            workers.append(original["first_loss_step"]+5)
            values.append({"static_sram_bytes":footprint["static_sram_bytes"],"native_heap_peak_bytes":peak,
                "native_heap_regions":[list(r) for r in regions],"heap_fully_inside_static":inside,
                "heap_peak_added_bytes":0 if inside else peak,"observed_software_allocation_bytes":total})
        independent_peaks = separate["values"] if os in ("FreeRTOS","NuttX") else separate["native_heap_peaks"]
        if independent_peaks != [r["native_heap_peak_bytes"] for r in values]:
            raise ValueError("Independent native heap replay differs: "+os)
        config = (source/"config").read_text()
        tick = (0 if os=="RIOT" else 100000 if os=="Zephyr" else
                1000000//int(re.search(r"^CONFIG_USEC_PER_TICK=(\d+)$",config,re.M)[1]) if os=="NuttX" else
                int(re.search(r"^CONFIG_FREERTOS_HZ=(\d+)$",config,re.M)[1]) if os=="FreeRTOS" else 100)
        cells.append({"os":os,"board_mac":campaign["board_mac"],"source":"artifacts/reports/"+source_name,
            "evidence":"artifacts/reports/"+capture_name,"elf_sha256":sha(source/"application.elf"),"config_sha256":sha(source/"config"),
            "independent_resets":3,"clock_hz":240000000,"cores":1,"tick_hz":tick,
            "tickless":os in ("Zephyr","RIOT") or "CONFIG_SCHED_TICKLESS=y" in config.splitlines(),
            "maximum_workers_per_reset":workers,"runs":values,
            "native_heap_control_bytes_already_in_peak":extra_control,
            "stack_watermarks_added_bytes":0,"scope":"instrumented original PH4 static physical SRAM and native allocated heaps, not exact live bytes",
            "comparison_eligible":False,"full_live_ram_peak_bytes":None})
    return {"audit":"pass","board":"B1","cells":cells,"new_board_resets":0,"reused_workload_resets":15,
        "new_metric_created":False,"historical_records_modified":False,"full_live_ram_ranking_eligible":False,
        "whole_ram_status":"正在测，未加入评分",
        "remaining":["same original workload scale and clock/tick profile for a cross-OS RAM comparison",
            "simultaneous live-stack evidence and pre-allocator/unmanaged memory scope",
            "observer-inclusive versus uninstrumented RAM boundary"],
        "checks":["physical aliases counted once","native regions disjoint or wholly inside ELF static storage",
            "native heap control and dynamically allocated stacks counted once","historical stack watermarks never added",
            "primary source/image/lifetime audit and independent raw-byte replay"]}


if __name__=="__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--message-startup",action="store_true")
    parser.add_argument("--observer-ownership",action="store_true")
    parser.add_argument("--message-coverage",action="store_true")
    parser.add_argument('--tick-coverage',action='store_true')
    parser.add_argument('--controlled-tick-coverage',action='store_true')
    args = parser.parse_args()
    result = tick_coverage(True) if args.controlled_tick_coverage else tick_coverage() if args.tick_coverage else message_coverage() if args.message_coverage else observer_ownership() if args.observer_ownership else \
        message_startup_scope() if args.message_startup else audit()
    if args.output:
        args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(result,indent=2,ensure_ascii=False))
