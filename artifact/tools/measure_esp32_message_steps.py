#!/usr/bin/env python3
"""Observe continuous context SPs during the original message workload on leon."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal
import sys

from run_esp32_followup import Board, monotonic_interval, read_raw_capture, sha, verified

ROOT = Path(__file__).resolve().parents[1]
MAC = "34:98:7a:a2:85:28"
EXTENSION = ROOT / "firmware/bsp/esp32/resource_census/continuous_step_stacks"


def step_source(text, extension):
    from build_esp32_tm_ram_lifetimes import replace_once
    declarations = "\n".join("static void bench_step_%s(%s);" % (n, a) for n, a in
        (("created", "unsigned"), ("retire", "unsigned"), ("start", "void"), ("stop", "void"), ("report", "void")))
    text = replace_once(text, "struct walk_totals {", declarations + "\n\nstruct walk_totals {")
    text = replace_once(text, "            if (tasks[i].role == 1) controller = tcb;",
        "            if (tasks[i].role == 1) controller = tcb;\n            bench_step_created(i);")
    if text.count("tasks[i].tcb = NULL;") != 2:
        raise ValueError("Native static/dynamic retirement anchors differ")
    text = text.replace("tasks[i].tcb = NULL;", "bench_step_retire(i); tasks[i].tcb = NULL;")
    text = replace_once(text, 'if (strcmp(command, "validate") == 0) { validate(); return; }',
        'if (strcmp(command, "validate") == 0) { bench_step_start(); validate(); bench_step_stop(); bench_step_report(); return; }')
    text = replace_once(text, '    report("application-entry");', '    bench_step_start();\n    report("application-entry");')
    text = replace_once(text, '        report("message-end");', '        bench_step_stop();\n        report("message-end");')
    text = replace_once(text, '        task_report();', '        task_report();\n        bench_step_report();')
    return text + "\n" + extension


def step_build_proof(source):
    from elftools.elf.elffile import ELFFile
    for name in ("step-stacks.inc", "step-entry.S", "step-state.h"):
        if (source / "continuous-step-source" / name).read_bytes() != (EXTENSION / name).read_bytes():
            raise ValueError("Unreviewed continuous step source")
    for name in ("step-entry.S", "step-state.h"):
        if (source / "observer" / name).read_bytes() != (EXTENSION / name).read_bytes():
            raise ValueError("Compiled continuous assembly/header differs")
    with (source / "application.elf").open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        names = ("xt_debugexception", "bench_step_debug_handler", "_DebugExceptionVector", "bench_step_state", "bench_step_slots", "bench_step_peak_slots", "_WindowOverflow4", "_Level2Vector", "_xt_context_save")
        symbols = {n: table.get_symbol_by_name(n)[0] for n in names}
    handler = symbols["xt_debugexception"]
    sizes = (symbols["bench_step_state"]["st_size"], symbols["bench_step_slots"]["st_size"], symbols["bench_step_peak_slots"]["st_size"])
    if handler["st_info"]["bind"] != "STB_GLOBAL" or handler["st_value"] != symbols["bench_step_debug_handler"]["st_value"] or \
            not 0x40080000 <= handler["st_value"] < 0x400c0000 or sizes != (88, 544, 544):
        raise ValueError("Continuous debug handler/state layout differs")
    instructions = []
    for line in (source / "disassembly.txt").read_text().splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)\s*(.*)", line)
        if m:
            instructions.append((int(m[1], 16), m[2], m[3]))
    context = symbols["_xt_context_save"]["st_value"]
    offsets = {pc - context: (op, args) for pc, op, args in instructions if context <= pc < context + 0xa0}
    if symbols["_Level2Vector"]["st_value"] - symbols["_WindowOverflow4"]["st_value"] != 0x180 or \
            any(offsets.get(offset) != expected for offset, expected in {
                0x64: ("addmi", "a1, a1, 0x100"), 0x67: ("addi", "a1, a1, -64"),
                0x6d: ("rotw", "3"), 0x73: ("rotw", "3"), 0x79: ("rotw", "3"),
                0x7f: ("rotw", "3"), 0x85: ("rotw", "4"),
                0x88: ("addmi", "a1, a1, 0xffffff00"), 0x8b: ("addi", "a1, a1, 64")}.items()):
        raise ValueError("Pinned window spill reconstruction does not match actual native instructions")
    body = [(op, args) for pc, op, args in instructions if handler["st_value"] <= pc < handler["st_value"] + handler["st_size"]]
    vector = [(op, args) for pc, op, args in instructions if symbols["_DebugExceptionVector"]["st_value"] <= pc < symbols["_DebugExceptionVector"]["st_value"] + 8]
    if not any(op == "j" and any("<" + name + ">" in args for name in ("xt_debugexception", "bench_step_debug_handler")) for op, args in vector) or not any(op == "rfi" and args == "6" for op, args in body):
        raise ValueError("Continuous debug vector/return is not installed")
    for op, args in body:
        operands = [x.strip() for x in args.split(",")]
        if op.startswith(("call", "entry", "ret", "s32e")) or \
                (operands[0] == "a1" and not op.startswith(("s", "b"))) or \
                (op.startswith(("s32i", "s16i", "s8i")) and len(operands) > 1 and operands[1] == "a1"):
            raise ValueError("Continuous observer consumes the interrupted stack")
    return {"handler_address": handler["st_value"], "handler_bytes": handler["st_size"],
        "handler_stackless": True, "task_slots": 16, "ordinary_irq_slots": 1, "retired_capacity": 32,
        "instruction_budget": 1200000000, "ordinary_interrupts_masked": False,
        "window_sp_reconstruction": "pinned-xtensa-context-and-window-vectors-v1"}


def build(root, workspace, output, boot_source):
    from build_esp32_tm_ram_lifetimes import build as build_application
    from measure_esp32_boot_handoff_ram import paired_boot, build_proof
    address, proof = paired_boot(boot_source)
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    build_application(root, workspace, output, observer, observer.parent / "freertos_message_tail.c",
        irq_coverage=True, startup_coverage=True, lifecycle_validation=True, compact=True,
        startup_handoff=True, peak_context=True, boot_readback_state=address, step_stacks=True)
    shutil.copytree(boot_source, output / "paired-bootloader")
    shutil.copyfile(boot_source / "bootloader.bin", output / "bootloader.bin")
    shutil.copyfile(__file__, output / "paired-builder.py")
    manifest = json.loads((output / "build.json").read_text())
    manifest.update(paired_bootloader_sha256=proof["bootloader_sha256"], application_rebuilt=True)
    manifest["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file() and p != output / "build.json"}
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return build_proof(output)


def step_observations(lines):
    summary, records = [], []
    for line in lines:
        if line.startswith("STEP_RAM total=") or line.startswith("STEP_RAM slot "):
            prefix = "STEP_RAM slot " if line.startswith("STEP_RAM slot ") else "STEP_RAM "
            fields = line[len(prefix):].split()
            pairs = [s.split("=") for s in fields]
            if any(len(p) != 2 or not p[1].isdigit() for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
                raise ValueError("Malformed continuous SP record")
            (records if "kind=" in fields[0] else summary).append({k: int(v) for k, v in pairs})
    if len(summary) != 1 or lines.count("STEP_RAM END") != 1 or lines.count("STEP_RAM ARM domain=instruction-boundary ordinary_irqs=enabled") != 1:
        raise ValueError("Continuous SP interval incomplete")
    s = summary[0]
    fields = {"total", "unknown", "bad", "invalid", "limit", "unknown_min", "unknown_max", "unknown_pc", "joint_peak", "peak_pc", "peak_irq", "peak_event", "retired", "generations"}
    if set(s) not in (fields, fields | {"reconstructed"}) or not 0 <= s.get("reconstructed", 0) <= s["total"]:
        raise ValueError("Continuous SP schema differs")
    if any(s[k] for k in ("bad", "invalid", "limit")) or not 0 < s["total"] < 1200000000:
        raise ValueError("Continuous trace was invalid or exhausted its budget")
    if len({(r["kind"], r["index"]) for r in records}) != len(records):
        raise ValueError("Duplicate continuous context")
    for r in records:
        if set(r) != {"kind", "index", "low", "high", "generation", "tcb", "samples", "minimum", "last", "min_pc"} or \
                r["kind"] not in (0, 1, 2) or not 0x3ffae000 <= r["low"] <= r["minimum"] <= r["last"] <= r["high"] < 0x40000000:
            raise ValueError("Continuous SP context bounds differ")
    current = [r for r in records if r["kind"] == 0]
    retired = [r for r in records if r["kind"] == 1]
    peak = [r for r in records if r["kind"] == 2]
    if len(retired) != s["retired"] or sum(r["samples"] for r in current + retired) + s["unknown"] != s["total"] or \
            len([r for r in current if r["index"] == 16 and r["samples"] > 0 and r["high"] - r["low"] == 1536]) != 1 or \
            sorted(r["generation"] for r in current + retired if r["generation"]) != list(range(1, s["generations"] + 1)):
        raise ValueError("Continuous samples/generations are not conserved")
    if s["peak_irq"] not in (0, 1) or sum(r["high"] - r["last"] for r in peak if r["index"] != 16 or s["peak_irq"]) != s["joint_peak"]:
        raise ValueError("Same-instant context span sum differs")
    return {"summary": s, "contexts": records, "unclassified_sp_observations": s["unknown"],
        "whole_live_ram_peak_bytes": None}


def reusable_validation(previous, source, proof, require_current_epoch=False):
    from audit_esp32_followup import envelope
    from run_esp32_tm_ram_lifetimes import read_run
    state = envelope(previous, allow_incomplete=True)
    plan = json.loads((previous / "plan.json").read_text())
    if state["mode"] != "message-continuous-step-stacks" or state["board_mac"] != MAC or \
            state["separate_validation_resets"] != 1 or plan["build_manifest_sha256"] != sha(source / "build.json"):
        raise ValueError("Validation reuse requires the same restored observer image")
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
        if sha(previous / "build" / name) != sha(source / name):
            raise ValueError("Reused validation image differs")
    verified(previous / "captures", previous / "build", MAC)
    verified(previous / "validation", previous / "build", MAC, logs=("verify-run1.log",))
    rows = read_raw_capture(previous / "validation", 1)
    if require_current_epoch and rows[0]["host_boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise ValueError("Reused validation is from another monotonic clock epoch")
    result = {"native": read_run(previous / "validation", 1, proof["application"], validation=True),
        "steps": step_observations([r["line"] for r in rows])}
    if result["steps"]["unclassified_sp_observations"] or json.loads(json.dumps(result)) != json.loads((previous / "validation/result1.json").read_text()):
        raise ValueError("Reused validation is incomplete or changed")
    return result


def collect(root, source, output, port, reuse_validation=None):
    from measure_esp32_boot_handoff_ram import build_proof
    from run_esp32_tm_ram_lifetimes import read_run
    proof = build_proof(source)
    reused = reusable_validation(reuse_validation, source, proof, require_current_epoch=True) if reuse_validation else None
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build_dir, captures, validation = output / "build", output / "captures", output / "validation"
        for p in (build_dir, captures, validation): p.mkdir()
        for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
            shutil.copyfile(source / name, build_dir / name)
        for name, original in (("runner.py", Path(__file__)), ("board-helper.py", ROOT / "tools/run_esp32_followup.py"),
                              ("capture_esp32_uart.py", root / "capture_esp32_uart.py")):
            shutil.copyfile(original, output / name)
        if reused:
            shutil.copytree(reuse_validation, output / "reused-validation-source")
            shutil.copytree(reuse_validation / "validation", validation, dirs_exist_ok=True)
        plan = {"resets": 5, "separate_validation_resets": 1, "seconds": 150, "validation_seconds": 30,
            "board_mac": MAC, "build_manifest_sha256": sha(source / "build.json"), "step": proof["application"]["step_observer"],
            "scope": "continuous instruction-boundary SPs from app workload entry through original third report; early boot remains separate",
            "chronology": "host-boot-scoped-monotonic-ns-v1",
            **({"reused_validation": True, "reused_campaign_sha256": sha(reuse_validation / "campaign.json")} if reused else {})}
        (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        state = {"mode": "message-continuous-step-stacks", "status": "incomplete", "board_mac": MAC,
            "independent_resets": 0, "separate_validation_resets": int(reused is not None), "started_utc": datetime.now(timezone.utc).isoformat(),
            **({"reused_validation_resets": 1} if reused else {}),
            "original_flash_restored": False, "old_cohort_modified": False, "energy_measured": False, "external_independent_replication": False}
        board = Board(root, output, MAC, port)
        try:
            board.backup()
            try:
                pairs = board.flash(captures, build_dir)
                try:
                    schedule = ([] if reused else [(validation, 1, True)]) + [(captures, i, False) for i in range(1, 6)]
                    for folder, index, finite in schedule:
                        board.capture(folder, index, 30 if finite else 150, stop="STEP_RAM END" if finite else "TM_RAM END", send="validate" if finite else None, monotonic_clock=True)
                        board.verify(pairs, folder / ("verify-run%d.log" % index))
                        native = read_run(folder, index, proof["application"], validation=finite)
                        step = step_observations([r["line"] for r in read_raw_capture(folder, index)])
                        (folder / ("result%d.json" % index)).write_text(json.dumps({"native": native, "steps": step}, indent=2) + "\n")
                        if step["unclassified_sp_observations"]:
                            raise ValueError("Unclassified SP range retained; stop before repeating an incomplete observer")
                        state["separate_validation_resets" if finite else "independent_resets"] += 1
                        print("Continuous SP", "validation" if finite else index, step["summary"], flush=True)
                    state["status"] = "collection_complete_audit_pending"
                finally:
                    board.verify(pairs, captures / "verify-after.log")
            finally:
                board.restore()
                state["original_flash_restored"] = True
        finally:
            state["completed_utc"] = datetime.now(timezone.utc).isoformat()
            state["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}
            (output / "campaign.json").write_text(json.dumps(state, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "collect"))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--boot-source", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--reuse-validation", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    if sys.platform != "linux": parser.error("Build and collect on leon only")
    if args.mode == "build":
        result = build(args.root, args.workspace, args.output, args.boot_source)
        (args.output / "paired-build-proof.json").write_text(json.dumps(result, indent=2) + "\n")
    else:
        def interrupted(signum, frame):
            signal.alarm(0)
            raise InterruptedError("Continuous stack collection interrupted; restoring original Flash")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(1200)
        try:
            collect(args.root, args.source, args.output, args.port, args.reuse_validation)
        finally:
            signal.alarm(0)
