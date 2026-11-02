#!/usr/bin/env python3
"""Bind RIOT native stack canaries to the unchanged original PH4 lifecycle."""
import argparse
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from audit_esp32_riot_ram_lifetimes import build as base_build, audit as base_audit, provenance
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_zephyr_ram_lifetimes import fields
from audit_esp32_zephyr_thread import read_raw_capture


def build(source):
    if json.loads((source/"build.json").read_text()).get("native_stack_coverage") is not True:
        raise ValueError("Missing native stack coverage declaration")
    proof = base_build(source)
    with (source/"application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        start,end = [symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("port_IntStack","port_IntStackTop")]
        if end-start != 2048 or start%4 or not any(
                s["sh_addr"] <= start < end <= s["sh_addr"]+s["sh_size"] and s["sh_flags"]&3 == 3
                for s in elf.iter_sections()):
            raise ValueError("Original native IRQ stack reservation/section differs")
    extra = calls(source,required=[("system_startup_cpu0","__wrap_thread_isr_stack_init"),
        ("__wrap_thread_isr_stack_init","thread_isr_stack_init"),
        ("bench_r_idle","bench_r_idle_stack_report"),
        ("bench_r_idle_stack_report","measure_stack_free_internal"),
        ("bench_r_irq_report","measure_stack_free_internal")],require_iram=False)
    return {**proof,"interrupt_stack":{"address":start,"reserved_bytes":end-start},
        "stack_extension_calls":extra,"coverage":"native address-canary touch watermarks; not simultaneous live bytes or NMI/debug/ROM coverage"}


def observations(lines,proof,validation=False):
    irq = [fields(s,1) for s in lines if s.startswith("RIOT_STACK irq_address=")]
    idle = [fields(s,1) for s in lines if s.startswith("RIOT_STACK idle_pid=")]
    if len(irq)!=1 or len(idle)!=(not validation) or sum(s.startswith("RIOT_STACK ") for s in lines)!=len(irq)+len(idle):
        raise ValueError("Missing, repeated or unknown native stack coverage")
    r = irq[0]; start = proof["interrupt_stack"]["address"]; size = proof["interrupt_stack"]["reserved_bytes"]
    if set(r)!={"irq_address","reserved","zero_verified","painted","boot_sp","nesting","spare","touched"} or \
            (r["irq_address"],r["reserved"],r["zero_verified"],r["painted"],r["nesting"])!=(start,size,size,size,0) or \
            start<=r["boot_sp"]<start+size or not 0<r["spare"]<size or r["touched"]!=size-r["spare"]:
        raise ValueError("Native IRQ early-context/paint/bounds/watermark differs")
    at = next(i for i,s in enumerate(lines) if s.startswith("RIOT_STACK irq_address="))
    tail = ["RIOT_RAM END"] if validation else ["RIOT_RAM final invalid=0","RIOT_RAM END"]
    if lines[at+1:]!=tail:
        raise ValueError("Native stack report terminal boundary differs")
    if idle:
        r = idle[0]
        records = [fields(s,2) for s in lines if s.startswith("RIOT_RAM thread ")]
        match = [s for s in records if s["role"]==2]
        if len(match)!=1:
            raise ValueError("Missing retained native idle task")
        t = match[0]; aligned = (t["stack"]+3)&~3
        if set(r)!={"idle_pid","tcb","stack","start","reserved","scan_bytes","spare","touched_in_span","main_exited","nesting"} or \
                (r["idle_pid"],r["tcb"],r["stack"],r["reserved"])!=(t["pid"],t["tcb"],t["stack"],t["reserved"]) or \
                [r["stack"],r["reserved"]]!=proof["static_reservations"]["idle_stack"] or \
                r["start"]!=aligned or r["scan_bytes"]!=t["tcb"]-aligned or not 0<r["spare"]<r["scan_bytes"] or \
                r["touched_in_span"]!=r["scan_bytes"]-r["spare"] or r["main_exited"]!=1 or r["nesting"] or \
                lines[at-1] != next(s for s in lines if s.startswith("RIOT_STACK idle_pid=")) or \
                not any(s.startswith("RIOT_RAM phase=main-exited ") for s in lines[:at-1]):
            raise ValueError("Current native idle stack bounds/lifecycle differ")
    return {"ordinary_irq_stack":irq[0],"current_idle_stack":idle[0] if idle else None,
        "already_in_static_sram":True,"exact_simultaneous_live_bytes":False,"nmi_debug_rom_covered":False}


def audit(directory,source):
    result = base_audit(directory,source)
    proof = build(source)
    check = observations([r["line"] for r in read_raw_capture(directory/"validation",1)],proof,True)
    runs = [observations([r["line"] for r in read_raw_capture(directory/"captures",i)],proof) for i in (1,2,3)]
    return {**result,"native_stack_build":proof,"native_stack_validation":check,"native_stack_runs":runs,
        "whole_live_ram_peak_bytes":None,"full_live_ram_ranking_eligible":False,"ranking_eligible":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--verify-upstream",action="store_true")
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    if args.verify_upstream:
        provenance(args.source)
    result = audit(args.capture,args.source) if args.capture else build(args.source)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
