#!/usr/bin/env python3
"""Audit native Zephyr startup fill and current-idle/IRQ touch watermarks."""
import argparse
import json
from pathlib import Path
from audit_esp32_zephyr_ram_lifetimes import build as base_build,audit as base_audit,provenance,fields
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_zephyr_thread import read_raw_capture


def build(source):
    if json.loads((source/"build.json").read_text()).get("native_stack_coverage") is not True:
        raise ValueError("Missing native stack coverage declaration")
    proof = base_build(source)
    extra = calls(source,required=[("z_cstart","bench_z_stack_begin"),("bench_z_idle","bench_z_stack_report"),
        ("bench_z_stack_report","z_stack_space_get"),("bench_z_stack_report","z_impl_k_thread_stack_space_get")],require_iram=False)
    return {**proof,"native_stack_calls":extra,"native_stack_coverage":True,
        "coverage":"Zephyr native 0xaa stack touch watermarks; not simultaneous live bytes or NMI/debug/ROM coverage"}


def observations(lines,proof,validation=False):
    parse = lambda prefix:[fields(s,1) for s in lines if s.startswith(prefix)]
    irq,idle = parse("ZEPHYR_STACK irq_address="),parse("ZEPHYR_STACK idle_tcb=")
    if len(irq)!=1 or len(idle)!=(not validation) or sum(s.startswith("ZEPHYR_STACK ") for s in lines)!=len(irq)+len(idle):
        raise ValueError("Native stack inventory incomplete or repeated")
    r = irq[0]; start,size = proof["static_reservations"]["z_interrupt_stacks"]
    if set(r)!={"irq_address","reserved","initial_verified","boot_sp","spare","touched","nesting"} or \
            (r["irq_address"],r["reserved"],r["initial_verified"],r["nesting"])!=(start,size,size,0) or \
            start<=r["boot_sp"]<start+size or not 0<r["spare"]<size or r["touched"]!=size-r["spare"]:
        raise ValueError("Native initial fill/context/range or IRQ watermark differs")
    at = next(i for i,s in enumerate(lines) if s.startswith("ZEPHYR_STACK irq_address="))
    if lines[at+1:] != (["ZEPHYR_RAM END"] if validation else ["ZEPHYR_RAM final invalid=0","ZEPHYR_RAM END"]):
        raise ValueError("Native watermark completion boundary differs")
    if idle:
        r = idle[0]
        matches = [fields(s,2) for s in lines if s.startswith("ZEPHYR_RAM stack ") and fields(s,2).get("role")==2]
        if len(matches)!=1:
            raise ValueError("Missing original retained idle thread")
        t = matches[0]
        if set(r)!={"idle_tcb","stack","start","reserved","span","spare","touched","main_exited","nesting"} or \
                [r["stack"],r["reserved"]]!=proof["static_reservations"]["z_idle_stacks"] or \
                r["idle_tcb"]!=proof["static_reservations"]["z_idle_threads"][0] or \
                (r["idle_tcb"],r["stack"],r["start"],r["reserved"],r["span"]) != tuple(t[k] for k in ("tcb","stack","start","reserved","span")) or \
                not 0<r["spare"]<r["span"] or r["touched"]!=r["span"]-r["spare"] or \
                (r["main_exited"],r["nesting"])!=(1,0) or not lines[at-1].startswith("ZEPHYR_STACK idle_tcb=") or \
                not any(s.startswith("ZEPHYR_RAM phase=main-exited ") for s in lines[:at-1]):
            raise ValueError("Current native idle bounds/lifecycle/watermark differs")
    return {"ordinary_irq_stack":irq[0],"current_idle_stack":idle[0] if idle else None,
        "already_in_static_sram":True,"exact_simultaneous_live_bytes":False,"nmi_debug_rom_covered":False}


def audit(directory,source):
    result = base_audit(directory,source)
    proof = build(source)
    if json.loads((directory/"stack-build-proof.json").read_text())!=proof:
        raise ValueError("Collected native stack qualification differs")
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
