#!/usr/bin/env python3
"""Retain native task/IRQ stack-switch observations without using their stacks."""
import argparse
import json
from pathlib import Path
import re
import shutil
import sys

from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "firmware/bsp/esp32/resource_census/native_asm_stacks"
PORTASM = "FreeRTOS-Kernel/portable/xtensa/portasm.S"
NATIVE_TRACE = b'''
#ifndef __ASSEMBLER__
#define traceTASK_SWITCHED_IN() do { \\
    _Static_assert(__builtin_offsetof(TCB_t, pxTopOfStack) == 0, "Native TCB SP offset"); \\
} while (0)
#endif
'''


def patch_portasm(text):
    from build_esp32_tm_ram_lifetimes import replace_once
    def hook(i):
        return '\n    .global bench_native_site_%d\nbench_native_site_%d:\n    movi a8, %d\n    call0 bench_native_sp_note\n' % (i, i, i)
    text = replace_once(text, "    call0   _xt_context_save\n", "    call0   _xt_context_save\n" + hook(1))
    text = replace_once(text, ".Lnested:\n1:\n", ".Lnested:\n1:\n" + hook(2))
    text = replace_once(text, "_frxt_int_exit:\n", "_frxt_int_exit:\n" + hook(3))
    anchor = "    l32i    a1,  a2, TOPOFSTACK_OFFS    /* SP = pxCurrentTCBs->pxTopOfStack */\n"
    text = replace_once(text, anchor, anchor + hook(4) + "    getcoreid a4\n")
    anchor = "    s32i    a3,  a2, 0\n\n    /* Determine the type of stack frame. */"
    return replace_once(text, anchor, "    s32i    a3,  a2, 0\n" + hook(5) + "\n    /* Determine the type of stack frame. */")


def observer_source(text, extension):
    from build_esp32_tm_ram_lifetimes import replace_once
    declarations = "\n".join("static void bench_native_%s(%s);" % (n, a) for n, a in (
        ("created", "unsigned"), ("disable", "unsigned"), ("retire", "unsigned"), ("start", "void"), ("stop", "void"), ("report", "void")))
    text = replace_once(text, "struct walk_totals {", declarations + "\n\nstruct walk_totals {")
    text = replace_once(text, "            if (tasks[i].role == 1) controller = tcb;",
        "            if (tasks[i].role == 1) controller = tcb;\n            bench_native_created(i);")
    for flag in ("stack_free", "tcb_free"):
        text = replace_once(text, "                    tasks[i].%s = 1;" % flag,
            "                    tasks[i].%s = 1;\n                    bench_native_disable(i);" % flag)
    if text.count("tasks[i].tcb = NULL;") != 2:
        raise ValueError("Native retirement anchors differ")
    text = text.replace("tasks[i].tcb = NULL;", "bench_native_retire(i); tasks[i].tcb = NULL;")
    if 'static void bench_boundary_start(void);' in text:
        text = replace_once(text, 'bench_boundary_start(); validate(); bench_boundary_stop(); bench_boundary_report(); return;',
            'bench_native_start(); bench_boundary_start(); validate(); bench_boundary_stop(); bench_native_stop(); bench_boundary_report(); bench_native_report(); return;')
        text = replace_once(text, '    bench_boundary_start();\n    report("application-entry");',
            '    bench_native_start();\n    bench_boundary_start();\n    report("application-entry");')
    else:
        text = replace_once(text, 'if (strcmp(command, "validate") == 0) { validate(); return; }',
            'if (strcmp(command, "validate") == 0) { bench_native_start(); validate(); bench_native_stop(); bench_native_report(); return; }')
        text = replace_once(text, '    report("application-entry");', '    bench_native_start();\n    report("application-entry");')
    text = replace_once(text, '        report("message-end");', '        bench_native_stop();\n        report("message-end");')
    text = replace_once(text, '        task_report();', '        task_report();\n        bench_native_report();')
    return text + "\n" + extension


def native_build_proof(source):
    from elftools.elf.elffile import ELFFile
    manifest = json.loads((source/'build.json').read_text())
    threshold = manifest.get('single_threshold_guards', False)
    for name in ("native-entry.S", "native-state.h"):
        expected = (EXTENSION / name).read_bytes()
        if threshold and name == 'native-entry.S':
            from guard_esp32_sp_threshold import native_source
            expected = native_source(expected.decode()).encode()
        if (source / "observer" / name).read_bytes() != expected:
            raise ValueError("Compiled native stack observer source differs")
    combined=json.loads((source/'build.json').read_text()).get('compiler_boundary_stack_trace',False)
    for command in json.loads((source / "compile_commands.json").read_text()):
        if not combined and any("instrument-functions" in flag for flag in command["command"].split()):
            raise ValueError("Native-only candidate unexpectedly profiles C functions")
    with (source / "application.elf").open("rb") as f:
        elf = ELFFile(f)
        table = elf.get_section_by_name(".symtab")
        names = ("bench_native_sp_note", "bench_native_state", "bench_native_slots", "bench_native_peak_slots") + tuple(
            "bench_native_site_%d" % i for i in range(1, 6))
        symbols = {n: table.get_symbol_by_name(n)[0] for n in names}
        sections = [(s["sh_addr"], s.data()) for s in elf.iter_sections() if s["sh_type"] == "SHT_PROGBITS"]
    instructions = []
    for line in (source / "disassembly.txt").read_text().splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)", line)
        if m:
            instructions.append((int(m[1], 16), int(m[2], 16), m[3], m[4]))
    s = symbols["bench_native_sp_note"]
    body = [row for row in instructions if s["st_value"] <= row[0] < s["st_value"] + s["st_size"]]
    if not body or not 0x40080000 <= s["st_value"] < 0x400c0000 or \
            [symbols[n]["st_size"] for n in names[1:4]] != [72, 544, 544]:
        raise ValueError("Native stack observer layout differs")
    operations = [(op, args) for _, _, op, args in body]
    if threshold:
        from measure_esp32_message_boundaries import reachable_leaf
        operations = reachable_leaf(source, s)
    for op, args in operations:
        operands = [a.strip() for a in args.split(",")]
        if op.startswith(("call", "entry", "s32e")) or op.startswith("retw") or \
                (operands[0] in ("a0", "a1", "a12", "a13", "a14", "a15") and not op.startswith(("s", "b"))) or \
                (op.startswith(("s32i", "s16i", "s8i")) and len(operands) > 1 and operands[1] == "a1"):
            raise ValueError("Native observer consumes a live frame or clobbers a preserved register")
    if not any(op == "rsil" and args == "a11, 7" for op, args in operations) or \
            not any(op == "wsr.ps" and args == "a11" for op, args in operations) or \
            (not any(op in ('ret', 'ret.n') for op, _ in operations) if threshold else body[-1][2] not in ('ret', 'ret.n')):
        raise ValueError("Native observer PS or call0 return differs")
    returns = {}
    for i in range(1, 6):
        start = symbols["bench_native_site_%d" % i]["st_value"]
        end = min([start + 16] + [symbols["bench_native_site_%d" % n]["st_value"] for n in range(1,6)
                                if symbols["bench_native_site_%d" % n]["st_value"] > start])
        calls = [row for row in instructions if start <= row[0] < end and row[2] == "call0" and
                 row[3].split()[0] == format(s["st_value"], "x")]
        if len(calls) != 1 or not any(start <= pc < calls[0][0] and op in ("movi", "movi.n") and
                args == "a8, %d" % i for pc, encoded, op, args in instructions):
            raise ValueError("Native transition hook is not linked: %d" % i)
        pc, encoded, op, args = calls[0]
        offset = encoded >> 6
        if offset & (1 << 17): offset -= 1 << 18
        raw = next(data[pc-a:pc-a+3] for a, data in sections if a <= pc < a + len(data))
        if encoded & 0x3f != 5 or (pc & ~3) + 4 + 4 * offset != s["st_value"] or raw != encoded.to_bytes(3, "little"):
            raise ValueError("Native call0 instruction does not match ELF bytes")
        returns[str(i)] = pc + 3
    return {"scope":"five reviewed native task/IRQ SP boundaries; not continuous C/ROM coverage",
        **({'compiled_with_boundary_observer':True} if combined else {}),
        "handler_address":s["st_value"], "handler_bytes":s["st_size"], "handler_stackless":True,
        "scratch_registers":"a2-a11 at reviewed dead-register sites", "return_pcs":returns,
        "whole_live_ram_peak_bytes":None, "ranking_eligible":False}


def observations(lines, events, proof):
    summaries, records = [], []
    for line in lines:
        if line.startswith(("NATIVE_SP total=", "NATIVE_SP slot ")):
            slot = line.startswith("NATIVE_SP slot ")
            pairs = [p.split("=") for p in line.split()[2 if slot else 1:]]
            if any(len(p) != 2 or not p[1].isdigit() for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
                raise ValueError("Malformed native SP record")
            (records if slot else summaries).append({k:int(v) for k,v in pairs})
    if len(summaries) != 1 or lines.count("NATIVE_SP END") != 1 or \
            lines.count("NATIVE_SP ARM domain=reviewed-native-task-irq-transitions observer=stackless") != 1:
        raise ValueError("Incomplete native transition interval")
    s = summaries[0]
    if set(s) != {"total", "unknown", "bad", "invalid", "joint_peak", "peak_pc", "peak_site", "peak_event", "peak_heap", "peak_irq", "generations", "retired", "live_mask", *('site%d'%i for i in range(1,6))} or \
            any(s[k] for k in ("unknown", "bad", "invalid")) or not all(s['site%d'%i] > 0 for i in range(1,6)) or \
            sum(s['site%d'%i] for i in range(1,6)) != s["total"] or not s["site1"] == s["site2"] == s["site3"] or s["site4"] > s["site3"]:
        raise ValueError("Native transition counts, pairs or coverage differ")
    if len({(r["kind"],r["index"]) for r in records}) != len(records):
        raise ValueError("Duplicate native context")
    for r in records:
        if set(r) != {"kind", "index", "low", "high", "generation", "tcb", "samples", "minimum", "last", "min_pc"} or \
                r["kind"] not in (0,1,2) or not 0x3ffae000 <= r["low"] <= r["minimum"] <= r["last"] <= r["high"] < 0x40000000:
            raise ValueError("Native context bounds differ")
    live, dead, peak = ([r for r in records if r["kind"] == k] for k in range(3))
    if sum(r["samples"] for r in live+dead) != s["total"] or len(dead) != s["retired"] or \
            sorted(r["generation"] for r in live+dead if r["generation"]) != list(range(1,s["generations"]+1)) or \
            sum(1<<r["index"] for r in live if r["index"] < 16) != s["live_mask"] or \
            len([r for r in live if r["index"]==16 and r["samples"]>0 and r["high"]-r["low"]==1536]) != 1:
        raise ValueError("Native task generations, live mask or observations lost")
    if s["peak_irq"] not in (0,1) or any(r["index"]==16 for r in peak) != bool(s["peak_irq"]) or \
            sum(r["high"]-r["last"] for r in peak) != s["joint_peak"] or \
            proof["return_pcs"].get(str(s["peak_site"])) != s["peak_pc"] or not 0<s["peak_event"]<=len(events) or \
            sum(e[4] for e in events[:s["peak_event"]] if e[1]<5) != s["peak_heap"]:
        raise ValueError("Native peak context, machine site or allocation prefix differs")
    return {"summary":s,"contexts":records,"whole_live_ram_peak_bytes":None,"ranking_eligible":False}


def build(root, workspace, output, boot_source, combined=False, inline_guards=False, stack_entry_guards=False, single_threshold_guards=False):
    from build_esp32_tm_ram_lifetimes import build as build_application
    from measure_esp32_boot_handoff_ram import paired_boot, build_proof
    root, workspace, output, boot_source = (p.resolve() for p in (root, workspace, output, boot_source))
    address, boot = paired_boot(boot_source)
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    build_application(root, workspace, output, observer, observer.parent/"freertos_message_tail.c",
        irq_coverage=True,startup_coverage=True,lifecycle_validation=True,compact=True,
        startup_handoff=True,peak_context=True,boot_readback_state=address,native_sp=True,
        boundary_stacks=combined,boundary_header_exclusion=combined,boundary_fast_pruning=combined,
        boundary_inline_guards=inline_guards, stack_entry_guards=stack_entry_guards, single_threshold_guards=single_threshold_guards)
    shutil.copytree(boot_source,output/"paired-bootloader")
    shutil.copyfile(boot_source/"bootloader.bin",output/"bootloader.bin")
    shutil.copyfile(__file__,output/"paired-builder.py")
    manifest=json.loads((output/"build.json").read_text())
    manifest.update(paired_bootloader_sha256=boot["bootloader_sha256"],application_rebuilt=True)
    manifest["files"]={p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file() and p!=output/"build.json"}
    (output/"build.json").write_text(json.dumps(manifest,indent=2)+'\n')
    return build_proof(output)


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('build','build-audit','audit'))
    p.add_argument('--root',type=Path,default=Path.home()/'esp32-pilot')
    for name in ('workspace','source','boot-source','campaign'):p.add_argument('--'+name,type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--combined',action='store_true')
    p.add_argument('--inline-guards',action='store_true')
    p.add_argument('--stack-entry-guards',action='store_true')
    p.add_argument('--single-threshold-guards',action='store_true')
    a=p.parse_args()
    if sys.platform!='linux':p.error('Evidence-dependent work runs on leon')
    if a.mode=='build':result=build(a.root,a.workspace,a.output,a.boot_source,a.combined,a.inline_guards,a.stack_entry_guards,a.single_threshold_guards)
    elif a.mode=='build-audit':
        from measure_esp32_boot_handoff_ram import build_proof
        result=build_proof(a.source)
    else:
        from measure_esp32_boot_handoff_ram import audit
        result=audit(a.campaign,a.source)
    target=a.output/'paired-build-proof.json' if a.mode=='build' else a.output
    target.write_text(json.dumps(result,indent=2)+'\n')
