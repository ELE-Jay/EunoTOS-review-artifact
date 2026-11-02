#!/usr/bin/env python3
"""Audit ordinary-IRQ watermarks without upgrading them to whole-system live RAM."""
import argparse
import json
from pathlib import Path
import re
from audit_esp32_freertos_ram_lifetimes import build as base_build, audit as base_audit, calls, ROOT
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha


def vector_binding(source):
    from elftools.elf.elffile import ELFFile
    from audit_esp32_zephyr_syskernel_sema import literal_word
    text=(source/"disassembly.txt").read_text()
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        irq=symbols.get_symbol_by_name("port_IntStack")[0]
        def body(name):
            found=re.search(r"^([0-9a-f]+) <"+re.escape(name)+r">:\n(.*?)(?=\n\n|\Z)",text,re.M|re.S)
            symbol=symbols.get_symbol_by_name(name)[0]
            if found is None or int(found[1],16)!=symbol["st_value"]:
                raise ValueError("Native IRQ body/ELF symbol differs: "+name)
            section=elf.get_section(symbol["st_shndx"])
            rows=[]
            for address,encoding,instruction in re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.+)$",found[2],re.M):
                pc,value=int(address,16),int(encoding,16)
                offset=pc-section["sh_addr"]
                if section.data()[offset:offset+len(encoding)//2]!=value.to_bytes(len(encoding)//2,"little"):
                    raise ValueError("Native IRQ instruction differs from ELF bytes")
                rows.append((pc,encoding,instruction))
            return rows
        first,enter=body("_xt_lowint1"),body("_frxt_int_enter")
        reserve=[r for r in first if re.fullmatch(r"addmi\s+a1, a1, 0xffffff00",r[2])]
        adjust=[r for r in first if re.fullmatch(r"addi\s+a1, a1, 64",r[2])]
        calls=[r for r in first if re.fullmatch(r"call0\s+[0-9a-f]+ <_frxt_int_enter>",r[2])]
        if len(reserve)!=1 or len(adjust)!=1 or len(calls)!=1 or not reserve[0][0]<adjust[0][0]<calls[0][0]:
            raise ValueError("Interrupted task-stack frame is not reserved before native entry")
        pc,encoding,_=calls[0]
        word=int(encoding,16)
        displacement=word>>6
        if displacement&(1<<17): displacement-=1<<18
        if word&0x3f!=5 or (pc&~3)+4+4*displacement!=symbols.get_symbol_by_name("_frxt_int_enter")[0]["st_value"]:
            raise ValueError("IRQ entry call target differs from actual encoding")
        loads=[r for r in enter if re.match(r"l32r\s+a1,",r[2])]
        stride=[r for r in enter if re.fullmatch(r"movi\s+a2, 0x600",r[2])]
        if len(loads)!=len(stride) or len(loads)!=1 or irq["st_size"]!=1536:
            raise ValueError("Native IRQ stack switch/stride differs")
        pc,encoding,instruction=loads[0]
        top=literal_word(elf,f"{pc:x}: {encoding} {instruction}",1)
        if top!=irq["st_value"]+irq["st_size"] or not loads[0][0]<stride[0][0]:
            raise ValueError("Native IRQ switch does not load the linked stack top")
        if not any(re.fullmatch(r"add\.n\s+a1, a1, a2",r[2]) and r[0]>stride[0][0] for r in enter):
            raise ValueError("Native per-core IRQ stack offset missing")
    return {"audit":"pass","elf_sha256":sha(source/"application.elf"),
        "build_manifest_sha256":sha(source/"build.json"),"new_board_resets":0,
        "interrupt_stack":{"address":irq["st_value"],"reserved_bytes":irq["st_size"]},
        "ordinary_level1_entry_address":first[0][0],"native_stack_switch_address":loads[0][0],
        "native_cpu0_irq_stack_top":top,"interrupted_task_frame_reserved_bytes":192,
        "frame_already_on_interrupted_task_stack":True,"additional_ram_bytes_to_add":0,
        "scope":"compiled ordinary level-1 entry/switch binding; written-canary extent is not the complete IRQ live-frame peak"}


def build(source):
    manifest = json.loads((source/"build.json").read_text())
    if manifest.get("ordinary_irq_stack_coverage") is not True:
        raise ValueError("No declared ordinary-IRQ stack extension")
    proof = base_build(source)
    reference = ROOT/"artifacts/reports/riot-yield-freertos-v1/native-source/components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S"
    portasm = source/"native-source/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S"
    if portasm.read_bytes() != reference.read_bytes():
        raise ValueError("Native ordinary-IRQ vector source differs from retained pinned SDK")
    extra = calls(source,required=[("vTaskStartScheduler","__wrap_xPortStartScheduler"),
                                  ("__wrap_xPortStartScheduler","xPortStartScheduler"),
                                  ("__wrap_vTaskDelay","bench_irq_stack_report")])
    return {**proof,"stack_extension_calls":extra,"ordinary_irq_vector_sha256":sha(portasm),
        "coverage":"A5 touch watermark from before first scheduler dispatch through controller report; not NMI/debug/ROM or exact simultaneous live bytes"}


def observations(lines,proof,terminal_prefix=None):
    records = [tuple(map(int,m.groups())) for line in lines if (m := re.fullmatch(
        r"FREERTOS_STACK irq_address=(\d+) reserved=(\d+) painted=(\d+) boot_sp=(\d+) scheduler=1 nesting=0 spare=(\d+) touched=(\d+)",line))]
    if len(records) != 1 or sum(s.startswith("FREERTOS_STACK ") for s in lines) != 1:
        raise ValueError("Missing or repeated native IRQ stack coverage")
    address,reserved,painted,boot_sp,spare,touched = records[0]
    if address != proof["interrupt_stack"]["address"] or reserved != proof["interrupt_stack"]["reserved_bytes"] or \
            painted != reserved or address <= boot_sp < address+reserved or not 0 < spare < reserved or \
            touched != reserved-spare:
        raise ValueError("IRQ paint, native range, early context or watermark differs")
    irq_at = next(i for i,s in enumerate(lines) if s.startswith("FREERTOS_STACK "))
    endings=[i for i,s in enumerate(lines) if s.startswith(terminal_prefix)] if terminal_prefix else [
        i for i,s in enumerate(lines) if s=="FREERTOS_RAM END"]
    if endings != [irq_at+1]:
        raise ValueError("IRQ watermark is outside original observer terminal boundary")
    return {"address":address,"reserved_bytes":reserved,"painted_bytes":painted,
        "boot_stack_pointer":boot_sp,"spare_pattern_bytes":spare,"touched_watermark_bytes":touched,
        "already_in_static_sram":True,"exact_simultaneous_live_bytes":False,"nmi_debug_rom_covered":False}


def audit(directory,source):
    result = base_audit(directory,source)
    proof = build(source)
    check = observations([r["line"] for r in read_raw_capture(directory/"validation",1)],proof)
    runs = [observations([r["line"] for r in read_raw_capture(directory/"captures",i)],proof) for i in (1,2,3)]
    return {**result,"ordinary_irq_stack_build":proof,"ordinary_irq_validation":check,
        "ordinary_irq_stack_runs":runs,"whole_live_ram_peak_bytes":None,
        "full_live_ram_ranking_eligible":False,"ranking_eligible":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--message-vector-only",action="store_true")
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    result = vector_binding(args.source) if args.message_vector_only else audit(args.capture,args.source) if args.capture else build(args.source)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
