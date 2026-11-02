#!/usr/bin/env python3
"""Build and audit compiler-boundary SP observations; full live RAM remains open."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "firmware/bsp/esp32/resource_census/function_boundary_stacks/boundary-stacks.inc"


def reachable_leaf(source, symbol):
    """Resynchronize at branch targets: linear Xtensa disassembly can decode padding as calls."""
    command = json.loads(next((source / "inline-assembly").glob("*/transform.json")).read_text())["compiler_command"][0]
    objdump = command.removesuffix("gcc") + "objdump"
    start, end = symbol["st_value"], symbol["st_value"] + symbol["st_size"]
    pending, visited, cache = [start], {}, {}
    while pending:
        pc = pending.pop()
        if pc in visited or pc == end:
            continue
        if not start <= pc < end or len(visited) > 2048:
            raise ValueError("Leaf observation control flow escapes its function")
        if pc not in cache:
            result = subprocess.check_output([objdump, "-d", "--start-address=" + hex(pc),
                "--stop-address=" + hex(min(pc + 3, end)), str(source / "application.elf")]).decode()
            for line in result.splitlines():
                m = re.fullmatch(r"\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)", line)
                if m and int(m[1], 16) == pc:
                    cache[int(m[1], 16)] = len(m[2]) // 2, m[3], m[4].split(" <")[0]
        if pc not in cache:
            raise ValueError("Cannot decode reachable leaf instruction")
        size, op, args = cache[pc]
        visited[pc] = op, args
        if op.startswith("ret"):
            continue
        if op.startswith("call") or op in ("jx", "ill", ".byte"):
            raise ValueError("Reachable leaf calls, indirect branches or undecodable bytes at %x: %s %s" % (pc, op, args))
        if op == "j" or op.startswith(("b", "loop")):
            pending.append(int(args.split(", ")[-1], 16))
        if op != "j":
            pending.append(pc + size)
    return list(visited.values())


def boundary_source(text, extension, fast_pruning=False):
    from build_esp32_tm_ram_lifetimes import replace_once
    declarations = "\n".join("static void bench_boundary_%s(%s);" % (n, a) for n, a in
        (("created", "unsigned"), ("retire", "unsigned"), ("start", "void"), ("stop", "void"), ("report", "void")))
    declarations += "\nvoid bench_boundary_sample(void *, void *);"
    text = replace_once(text, "struct walk_totals {", declarations + "\n\nstruct walk_totals {")
    text = replace_once(text, "            if (tasks[i].role == 1) controller = tcb;",
        "            if (tasks[i].role == 1) controller = tcb;\n            bench_boundary_created(i);")
    if text.count("tasks[i].tcb = NULL;") != 2:
        raise ValueError("Native retirement anchors differ")
    text = text.replace("tasks[i].tcb = NULL;", "bench_boundary_retire(i); tasks[i].tcb = NULL;")
    start, end = text.index("void bench_tlsf_delta("), text.index("void bench_heap_check(")
    text = text[:start] + replace_once(text[start:end], "    portEXIT_CRITICAL(&lock);",
        "    bench_boundary_sample(NULL, NULL);\n    portEXIT_CRITICAL(&lock);") + text[end:]
    text = replace_once(text, 'if (strcmp(command, "validate") == 0) { validate(); return; }',
        'if (strcmp(command, "validate") == 0) { bench_boundary_start(); validate(); bench_boundary_stop(); bench_boundary_report(); return; }')
    text = replace_once(text, '    report("application-entry");', '    bench_boundary_start();\n    report("application-entry");')
    text = replace_once(text, '        report("message-end");', '        bench_boundary_stop();\n        report("message-end");')
    text = replace_once(text, '        task_report();', '        task_report();\n        bench_boundary_report();')
    if fast_pruning:
        text = replace_once(text, "static unsigned trace_count;",
            "static unsigned trace_count;\nextern volatile uint32_t bench_boundary_fast_state[3];")
        text = replace_once(text, "    trace[trace_count].kind = kind;",
            "    bench_boundary_fast_state[1] = 0;\n    trace[trace_count].kind = kind;")
        extension = replace_once(extension, "static DRAM_ATTR volatile uint32_t boundary_enabled, boundary_epoch;",
            "DRAM_ATTR volatile uint32_t boundary_enabled, boundary_epoch;\nDRAM_ATTR volatile uint32_t bench_boundary_fast_state[3];")
        extension = replace_once(extension, "    boundary_epoch++;",
            "    bench_boundary_fast_state[1] = 0;\n    boundary_epoch++;")
        extension = replace_once(extension, "bench_boundary_sample(void *function, void *callsite)",
            "bench_boundary_slow_sample(void *function, void *callsite, uint32_t fast_sp)")
        extension = replace_once(extension, '    __asm__ volatile("memw\\nwsr %0, ps\\nrsync" :: "a"(ps) : "memory");',
            '    bench_boundary_fast_state[0] = fast_sp;\n'
            '    bench_boundary_fast_state[1] = current < 17 ? boundary_slots[current].high : 0;\n'
            '    __asm__ volatile("memw\\nwsr %0, ps\\nrsync" :: "a"(ps) : "memory");')
        for name in ("enter", "exit"):
            extension = replace_once(extension,
                'void __cyg_profile_func_' + name + '(void *, void *) __attribute__((alias("bench_boundary_sample"), no_instrument_function));', '')
        extension = extension.replace("    boundary_cached_event = UINT32_MAX;",
            "    boundary_cached_event = UINT32_MAX;\n    bench_boundary_fast_state[1] = 0;")
        extension = replace_once(extension, '    puts("BOUNDARY_RAM END");',
            '    printf("BOUNDARY_RAM fast_skipped=%lu\\n", (unsigned long)bench_boundary_fast_state[2]);\n'
            '    puts("BOUNDARY_RAM END");')
    return text + "\n" + extension


def boundary_build_proof(source):
    from build_esp32_tm_ram_lifetimes import BOUNDARY_TRACE, BOUNDARY_CMAKE
    from audit_esp32_freertos_ram_lifetimes import calls
    from elftools.elf.elffile import ELFFile
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    excluded = json.loads((source / "build.json").read_text()).get("compiler_boundary_header_exclusion", False)
    fast = json.loads((source / "build.json").read_text()).get("compiler_boundary_fast_pruning", False)
    inline = json.loads((source / "build.json").read_text()).get("compiler_boundary_inline_guards", False)
    entry = json.loads((source / "build.json").read_text()).get("compiler_stack_entry_guards", False)
    if type(excluded) is not bool:
        raise ValueError("Invalid compiler-boundary header filtering declaration")
    cmake = BOUNDARY_CMAKE.replace('-finstrument-functions>', '-finstrument-functions;-finstrument-functions-exclude-file-list=.h>') if excluded else BOUNDARY_CMAKE
    if (source / "boundary-stacks.inc").read_bytes() != EXTENSION.read_bytes() or \
            (source / "native-source/freertos/config/include/freertos/bench_task_trace.h").read_bytes() != \
            (observer / "bench_task_trace.h").read_bytes() + BOUNDARY_TRACE or \
            not (source / "observer/app/CMakeLists.txt").read_text().endswith('\nendforeach()\n' if entry else cmake):
        raise ValueError("Compiler-boundary source or native switch hook differs")
    selected = {name: 0 for name in ("main", "freertos", "heap")}
    for row in json.loads((source / "compile_commands.json").read_text()):
        name = next((n for n in selected if "CMakeFiles/__idf_" + n + ".dir/" in row["command"]), None)
        expected = name is not None and Path(row["file"]).suffix == ".c"
        if ("-finstrument-functions" in row["command"].split()) != (expected and not entry):
            raise ValueError("Instrumentation crosses the selected C component boundary: " + row["file"])
        if ("-finstrument-functions-exclude-file-list=.h" in row["command"].split()) != (expected and excluded and not entry):
            raise ValueError("Compiler-boundary header filtering differs: " + row["file"])
        if expected:
            selected[name] += 1
    if not all(selected.values()):
        raise ValueError("Missing compiler instrumentation component")
    if entry:
        from guard_esp32_stack_entries import DYNAMIC, dynamic_source
        dynamic_calls = []
        for name in DYNAMIC:
            patched = source / 'dynamic-stack-sources' / name
            original = patched.with_suffix(patched.suffix + '.original')
            if patched.read_text() != dynamic_source(name, original.read_text()):
                raise ValueError('Dynamic allocation observation patch differs')
        dynamic_calls = [('heap_caps_init', 'bench_boundary_sample'),
                         ('soc_get_available_memory_regions', 'bench_boundary_sample')]
        from audit_esp32_freertos_ram_lifetimes import calls as dynamic_proof
        witnesses = dynamic_proof(source, dynamic_calls, require_iram=False)
        # Each function has two explicit VLA calls plus its new ENTRY guard call.
        if any(len(row['instructions']) != 3 for row in witnesses):
            raise ValueError('Four explicit dynamic stack samples are not linked')
    calls(source, [("vTaskSwitchContext", "bench_boundary_switched"),
        ("bench_tlsf_delta", "bench_boundary_sample")], require_iram=False)
    names = ("bench_boundary_sample", "__cyg_profile_func_enter", "__cyg_profile_func_exit", "bench_boundary_switched") + ((
        "bench_boundary_slow_sample", "bench_boundary_slow_entry", "bench_boundary_fast_return", "bench_boundary_fast_state") if fast else ())
    with (source / "application.elf").open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        symbols = {n: table.get_symbol_by_name(n)[0] for n in names}
    sampler = symbols["bench_boundary_sample"]
    address, size = sampler["st_value"], sampler["st_size"]
    if not 0x40080000 <= address < 0x400c0000 or any(symbols[n]["st_value"] != address for n in names[1:3]):
        raise ValueError("Profile hooks are not aliases of the IRAM sampler")
    instructions = []
    for line in (source / "disassembly.txt").read_text().splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)\s*(.*)", line)
        if m:
            instructions.append((int(m[1], 16), m[2], m[3]))
    body = [(op, args) for pc, op, args in instructions if address <= pc < address + size]
    entries = [args for op, args in body if op == "entry"]
    call_ops = [(op, args) for op, args in body if op.startswith("call")]
    if len(entries) != 1 or not entries[0].startswith("a1, ") or len(call_ops) != int(fast):
        raise ValueError("Sampler frame or call structure differs")
    if fast:
        assembly = EXTENSION.with_name("boundary-fast-entry.S")
        if (source / "observer/boundary-fast-entry.S").read_bytes() != assembly.read_bytes():
            raise ValueError("Fast pruning assembly differs")
        slow = symbols["bench_boundary_slow_sample"]
        slow_body = [(op, args) for pc, op, args in instructions if slow["st_value"] <= pc < slow["st_value"] + slow["st_size"]]
        if inline:
            slow_body = reachable_leaf(source, slow)
        if call_ops[0][1].split()[0] != format(slow["st_value"], "x") or any(op.startswith("call") for op, _ in slow_body):
            raise ValueError("Fast entry does not call the leaf observation path")
        slow_entries = [args for op, args in slow_body if op == "entry"]
        if len(slow_entries) != 1:
            raise ValueError("Slow observation frame differs")
        branch = format(symbols["bench_boundary_slow_entry"]["st_value"], "x")
        finish = format(symbols["bench_boundary_fast_return"]["st_value"], "x")
        if symbols["bench_boundary_fast_state"]["st_size"] != 12 or \
                [(op, args.split(" <")[0]) for op, args in body if op == "bltu"] != [
                    ("bltu", "a5, a1, " + branch), ("bltu", "a1, a5, " + branch)] or \
                not any(op in ("beqz", "beqz.n") and args.split(" <")[0] == "a4, " + finish for op, args in body) or \
                not any(op == "wsr.ps" and args == "a7" for op, args in body) or \
                not any(op in ("mov", "mov.n") and args == "a12, a1" or
                        op == "or" and args == "a12, a1, a1" for op, args in body):
            raise ValueError("Fast pruning bounds, SP argument or PS restore differs")
    if not any(op == "rsil" and args.endswith(", 7") for op, args in body) or not any(op == "wsr.ps" for op, _ in body):
        raise ValueError("Sampler does not preserve interrupt masking")
    # Address comparisons survive objdump's arbitrary choice among alias names.
    verified = []
    with (source / "application.elf").open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        for name in ("xQueueGenericSend", "xQueueReceive", "xTaskIncrementTick", "tm_message_processing_thread_0_entry"):
            candidates = table.get_symbol_by_name(name)
            if not candidates:
                raise ValueError("Missing original instrumented path: " + name)
            s = candidates[0]
            if not any(s["st_value"] <= pc < s["st_value"] + s["st_size"] and op.startswith("call") and
                    args.split()[0] == format(address, "x") for pc, op, args in instructions):
                raise ValueError("Original path does not call the sampler: " + name)
            verified.append(name)
    return {"scope": "selected C function boundaries and native allocation commits; not continuous coverage",
        **({"inline_guards": __import__('guard_esp32_boundary_calls').audit_build(source)} if inline else {}),
        **({"header_definitions_excluded": True} if excluded else {}),
        **({"same_epoch_depth_pruning": True, "slow_frame_bytes": int(slow_entries[0].split(", ")[1], 0)} if fast else {}),
        "selected_c_translation_units": selected, "sampler_address": address, "sampler_bytes": size,
        "sampler_frame_bytes": int(entries[0].split(", ")[1], 0), "sampler_calls": len(call_ops),
        "original_paths_verified": verified, "observer_included": True,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


def observations(lines, events=None, fast_pruning=None, inline_guards=False):
    summaries, records = [], []
    for line in lines:
        if line.startswith("BOUNDARY_RAM total=") or line.startswith("BOUNDARY_RAM slot "):
            prefix = "BOUNDARY_RAM slot " if line.startswith("BOUNDARY_RAM slot ") else "BOUNDARY_RAM "
            fields = line[len(prefix):].split()
            if any(not re.fullmatch(r"[a-z_]+=\d+", f) for f in fields):
                raise ValueError("Malformed boundary record")
            pairs = [f.split("=") for f in fields]
            if len({k for k, v in pairs}) != len(pairs):
                raise ValueError("Repeated boundary field")
            (records if prefix.endswith("slot ") else summaries).append({k: int(v) for k, v in pairs})
    if len(summaries) != 1 or lines.count("BOUNDARY_RAM END") != 1 or \
            lines.count("BOUNDARY_RAM ARM domain=function-boundary-plus-allocation observer=included") != 1:
        raise ValueError("Boundary observation interval is incomplete")
    s = summaries[0]
    if set(s) != {"total", "unknown", "bad", "invalid", "refreshes", "switches", "joint_peak", "peak_event", "peak_heap", "peak_irq", "retired", "generations"} or \
            not 0 < s["total"] < 2**32 or any(s[k] for k in ("unknown", "bad", "invalid")) or \
            not 0 < s["refreshes"] <= s["total"] or s["peak_irq"] not in (0, 1):
        raise ValueError("Invalid or unclassified boundary observations")
    if len({(r["kind"], r["index"]) for r in records}) != len(records):
        raise ValueError("Duplicate boundary context")
    for r in records:
        if set(r) != {"kind", "index", "low", "high", "generation", "tcb", "samples", "minimum", "last", "min_pc"} or \
                r["kind"] not in (0, 1, 2) or not 0x3ffae000 <= r["low"] <= r["minimum"] <= r["last"] <= r["high"] < 0x40000000:
            raise ValueError("Boundary context bounds differ")
    current = [r for r in records if r["kind"] == 0]
    retired = [r for r in records if r["kind"] == 1]
    peak = [r for r in records if r["kind"] == 2]
    if len(retired) != s["retired"] or sum(r["samples"] for r in current + retired) != s["total"] or \
            sorted(r["generation"] for r in current + retired if r["generation"]) != list(range(1, s["generations"] + 1)) or \
            len([r for r in current if r["index"] == 16 and r["samples"] > 0 and r["high"] - r["low"] == 1536]) != 1:
        raise ValueError("Boundary samples, IRQ coverage or task generations differ")
    if sum(r["high"] - r["last"] for r in peak) != s["joint_peak"]:
        raise ValueError("Same-instant boundary context sum differs")
    if events is not None and (not 0 < s["peak_event"] <= len(events) or
            sum(e[4] for e in events[:s["peak_event"]] if e[1] < 5) != s["peak_heap"]):
        raise ValueError("Boundary peak does not match its native allocation prefix")
    extra = {}
    skipped = [line for line in lines if line.startswith("BOUNDARY_RAM fast_skipped=")]
    if skipped:
        if len(skipped) != 1 or not re.fullmatch(r"BOUNDARY_RAM fast_skipped=\d+", skipped[0]):
            raise ValueError("Invalid fast pruning count")
        extra["fast_skipped"] = int(skipped[0].split("=")[1])
    if fast_pruning is not None and (bool(skipped) != fast_pruning or fast_pruning and not inline_guards and not extra["fast_skipped"]):
        raise ValueError("Pruning record does not match the measured firmware")
    return {"summary": s, "contexts": records, **extra, "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


def build(root, workspace, output, boot_source, exclude_header_inline=False, fast_pruning=False):
    from build_esp32_tm_ram_lifetimes import build as build_application
    from measure_esp32_boot_handoff_ram import paired_boot, build_proof
    root, workspace, output, boot_source = (p.resolve() for p in (root, workspace, output, boot_source))
    address, proof = paired_boot(boot_source)
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    build_application(root, workspace, output, observer, observer.parent / "freertos_message_tail.c",
        irq_coverage=True, startup_coverage=True, lifecycle_validation=True, compact=True,
        startup_handoff=True, peak_context=True, boot_readback_state=address, boundary_stacks=True,
        boundary_header_exclusion=exclude_header_inline, boundary_fast_pruning=fast_pruning)
    shutil.copytree(boot_source, output / "paired-bootloader")
    shutil.copyfile(boot_source / "bootloader.bin", output / "bootloader.bin")
    shutil.copyfile(__file__, output / "paired-builder.py")
    manifest = json.loads((output / "build.json").read_text())
    manifest.update(paired_bootloader_sha256=proof["bootloader_sha256"], application_rebuilt=True)
    manifest["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file() and p != output / "build.json"}
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return build_proof(output)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("build", "build-audit", "audit"))
    p.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    for name in ("workspace", "boot-source", "source", "campaign"):
        p.add_argument("--" + name, type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--exclude-header-inline", action="store_true")
    p.add_argument("--fast-pruning", action="store_true")
    a = p.parse_args()
    if sys.platform != "linux": p.error("Evidence-dependent work runs on leon")
    if a.mode == "build":
        result = build(a.root, a.workspace, a.output, a.boot_source, a.exclude_header_inline, a.fast_pruning)
    elif a.mode == "build-audit":
        from measure_esp32_boot_handoff_ram import build_proof
        result = build_proof(a.source)
    else:
        from measure_esp32_boot_handoff_ram import audit
        result = audit(a.campaign, a.source)
    target = a.output / "paired-build-proof.json" if a.mode == "build" else a.output
    target.write_text(json.dumps(result, indent=2) + "\n")
