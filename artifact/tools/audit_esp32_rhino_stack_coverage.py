#!/usr/bin/env python3
"""Audit native watermarks for deleted startup, current idle and ordinary IRQ stacks."""
import argparse
import json
from pathlib import Path
import re
from elftools.elf.elffile import ELFFile
from audit_esp32_rhino_ram_lifetimes import build as native_build, audit as native_audit, validation as native_validation
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_zephyr_ram_lifetimes import fields
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_zephyr_syskernel_sema import literal_word
from run_esp32_followup import sha
from audit_esp32_followup import envelope, verified
from audit_esp32_riot_original import check_manifest
from collect_esp32_rhino_stack_control import collector_source, FUNCTIONS, NORETURN


def build(folder):
    metadata = json.loads((folder / "build.json").read_text())
    if metadata.get("native_stack_coverage") is not True or "--wrap=krhino_task_dyn_del" not in (folder / "link.opts").read_text():
        raise ValueError("Native pre-deletion extension not linked")
    proof = native_build(folder)
    check_manifest(folder,"stack-control.sha256")
    if {s.split(maxsplit=1)[1] for s in (folder/"stack-control.sha256").read_text().splitlines()} != {
            "application.elf","image.sha256","stack-control-flow.txt","executed-stack-control.py"} or \
            (folder/"executed-stack-control.py").read_text() != collector_source(Path(__file__).with_name("collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Stack branch-aware decoder binding differs")
    machine = calls(folder, require_iram=False, required=[
        ("espos_task_del", "__wrap_krhino_task_dyn_del"),
        ("__wrap_krhino_task_dyn_del", "krhino_task_stack_min_free"),
        ("__wrap_krhino_task_dyn_del", "krhino_task_dyn_del")])
    if max(int(s,16) for s in machine[1]["instructions"]) >= min(int(s,16) for s in machine[2]["instructions"]):
        raise ValueError("Native watermark read does not precede the native deletion call")
    with (folder / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((folder/"stack-control-flow.txt").read_text(),"RHINO STACK CONTROL",elf,symbols,set(FUNCTIONS),noreturn=NORETURN)
        loaded = {}
        for name in ("bench_h_heap_ready", "__wrap_krhino_idle_hook"):
            function = symbols.get_symbol_by_name(name)[0]
            values = set()
            for row in control[name].values():
                match = re.match(r"([0-9a-f]+):\s+([0-9a-f]{6})\s+l32r\s+a(\d+),", row)
                if match and function["st_value"] <= int(match[1],16) < function["st_value"] + function["st_size"]:
                    section = elf.get_section(function["st_shndx"])
                    offset = int(match[1],16)-section["sh_addr"]
                    if section.data()[offset:offset+3] != int(match[2],16).to_bytes(3,"little"):
                        raise ValueError("IRQ stack/pattern literal instruction differs from ELF bytes")
                    values.add(literal_word(elf," ".join(row.split()),int(match[3])))
            loaded[name] = values
        start = symbols.get_symbol_by_name("port_IntStack")[0]["st_value"]
        for name in ("bench_h_heap_ready", "__wrap_krhino_idle_hook"):
            if not {start, 0xa5a5a5a5} <= loaded[name]:
                raise ValueError("Actual IRQ stack/pattern load absent: " + name)
        for name in ("g_sys_stat", "krhino_sys_run", "krhino_sys_nest"):
            if symbols.get_symbol_by_name(name)[0]["st_value"] not in loaded["bench_h_heap_ready"]:
                raise ValueError("Pre-scheduler IRQ initialization guard absent")
    return {**proof, "build_manifest_sha256":sha(folder / "build.json"), "native_stack_coverage":True,
        "stack_extension_machine_calls":machine, "ordinary_irq_stack_reserved_bytes":1536,
        "boundary":"Native zero-fill task watermarks and A5 ordinary-IRQ touched watermark, observer-inclusive; not simultaneous live-byte peak or NMI/debug/ROM stack coverage"}


def coverage(lines, proof):
    parsed = lambda prefix: [fields(s,2) for s in lines if s.startswith(prefix)]
    starts, retired, idles, irqs, finals = [parsed("RHINO_STACK " + name + " ") for name in ("begin","retired","idle","irq","final")]
    tasks = parsed("RHINO_RAM thread ")
    native_final = parsed("RHINO_RAM final ")
    if any(len(rows) != 1 for rows in (starts,idles,irqs,finals,native_final)) or not tasks:
        raise ValueError("Stack coverage inventory incomplete")
    start, idle, irq, final = starts[0],idles[0],irqs[0],finals[0]
    if start != {"stopped":1,"running":0,"nesting":0,"irq_start":proof["interrupt_stack"]["start"],
            "irq_bytes":1536,"pattern":0xa5a5a5a5,"initialized_words":384} or final["invalid"]:
        raise ValueError("IRQ paint was not witnessed before first scheduler use")
    deleted = {t["id"]:t for t in tasks if t["deleted"]}
    if not retired or len(retired) != len(deleted) or {r["id"] for r in retired} != set(deleted) or final["retired"] != len(deleted):
        raise ValueError("Deleted generations lack pre-overwrite stack watermarks")
    for row in retired:
        task = deleted[row["id"]]
        if row["tcb"] != task["tcb"] or row["reserved"] != task["reserved"] or not task["stack_freed"] or not task["tcb_freed"] or \
                (row["before_native_delete"],row["stack_freed"],row["tcb_freed"]) != (1,1,1) or \
                not 0 < row["spare"] <= row["reserved"]-4 or row["spare"] % 4:
            raise ValueError("Deleted native stack has no bounded pre-delete read and actual frees")
    matches = [t for t in tasks if t["id"] == idle["id"] and t["role"] == 2 and t["present"]]
    if len(matches) != 1 or idle["tcb"] != native_final[0]["idle"] or idle["tcb"] != matches[0]["tcb"] or \
            idle["reserved"] != proof["static_idle_stack"]["reserved_bytes"] or idle["current"] != 1 or \
            not 0 < idle["spare"] <= idle["reserved"]-4 or idle["spare"] % 4:
        raise ValueError("Current original idle stack watermark missing or exhausted")
    if irq["reserved"] != 1536 or irq["nesting"] or not 0 < irq["spare"] < 1536 or irq["spare"] % 4 or \
            irq["touched_watermark"] != 1536-irq["spare"] or lines[-1] != "RHINO_RAM END":
        raise ValueError("Ordinary IRQ watermark/completion differs")
    for row in (*retired, idle):
        row["reserved_minus_spare_bytes"] = row["reserved"]-row["spare"]
    return {"deleted_stacks":retired, "current_idle_stack":idle, "ordinary_irq_stack":irq,
        "pre_scheduler_irq_initialization":start, "all_deleted_generations_covered":True,
        "whole_live_ram_peak_bytes":None, "ranking_eligible":False}


def validation(folder, proof):
    native_validation(folder, proof)
    return coverage([r["line"] for r in read_raw_capture(folder,1)], proof)


def audit(folder, source):
    result = native_audit(folder, source)
    proof = build(source)
    if json.loads((folder/"stack-build-proof.json").read_text()) != proof:
        raise ValueError("Collected stack source qualification differs")
    result["stack_coverage_build"] = proof
    result["stack_coverage_validation"] = validation(folder / "validation", proof)
    for index, run in enumerate(result["runs"],1):
        run["stack_coverage"] = coverage([r["line"] for r in read_raw_capture(folder / "captures",index)], proof)
    result["scope"] += "; pre-native-deletion, current-idle and pre-scheduler-painted ordinary-IRQ watermarks; no sum of historical stack peaks"
    return result


def incomplete(folder, source):
    campaign = envelope(folder,allow_incomplete=True)
    if campaign["status"] != "incomplete" or campaign["kind"] != "rhino-ram" or campaign["board_mac"] != "34:98:7a:a2:85:28" or \
            list((folder/"captures").glob("reset*.raw")):
        raise ValueError("Refused pre-workload capture was promoted or already contains PH4 resets")
    if any(sha(p) != sha(source/p.name) for p in (folder/"build").iterdir()):
        raise ValueError("Validation-only image differs")
    verified(folder/"captures",folder/"build",campaign["board_mac"],logs=("identity.log","flash.log","verify-before.log"))
    proof = build(source)
    checked = validation(folder/"validation",proof)
    return {"audit":"pass","diagnostic_only":True,"completed_workload_resets":0,
        "validation_only_boots":1,"stack_coverage_validation":checked,"original_flash_restored":True,
        "ranking_eligible":False,"source_manifest_sha256":sha(source/"build.json"),
        "scope":"Validation image passed; host source-audit gate stopped before any original PH4 workload"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--incomplete", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = (incomplete(args.capture,args.source) if args.incomplete else audit(args.capture,args.source)) if args.capture else build(args.source)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
