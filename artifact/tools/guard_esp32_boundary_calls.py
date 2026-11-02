#!/usr/bin/env python3
"""Guard existing windowed-ABI profiling calls without adding another frame."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


CALL = re.compile(r"\s*call8\s+__cyg_profile_func_(enter|exit)\s*$")


def guarded_assembly(text, identity):
    lines, sites = [], []
    for line in text.splitlines(keepends=True):
        match = CALL.fullmatch(line.rstrip("\n"))
        if not match:
            if "__cyg_profile_func_" in line and not line.lstrip().startswith((".extern", ".string", ".ascii", ".asciz")):
                raise ValueError("Unsupported profiling-call lowering: " + line.strip())
            lines.append(line)
            continue
        name = "bench_inline_guard_%s_%d" % (identity, len(sites))
        # a8/a9 are caller-clobbered by the existing call8, outside its a10/a11 arguments.
        # The saved lower bound is the sampler SP, 32 bytes below this call-site SP.
        lines.append("\t.global %s\n%s:\n" % (name, name) +
            "\trsil a8, 7\n"
            "\tmovi a9, bench_boundary_fast_state\n"
            "\tl32i a9, a9, 4\n"
            "\tbltu a9, a1, 1f\n"
            "\tmovi a9, bench_boundary_fast_state\n"
            "\tl32i a9, a9, 0\n"
            "\taddi a9, a9, 32\n"
            "\tbgeu a1, a9, 2f\n1:\n"
            "\twsr a8, ps\n\trsync\n" + line + "\tj 3f\n2:\n"
            "\twsr a8, ps\n\trsync\n3:\n")
        sites.append({"symbol": name, "kind": match[1]})
    return "".join(lines), sites


def observer_source(text):
    from build_esp32_tm_ram_lifetimes import replace_once
    text = replace_once(text, "extern volatile uint32_t bench_boundary_fast_state[3];",
        "extern volatile uint32_t bench_boundary_fast_state[3];\nextern volatile uint32_t boundary_enabled;\n"
        "static unsigned bench_boundary_control_off;")
    text = replace_once(text, "DRAM_ATTR volatile uint32_t bench_boundary_fast_state[3];",
        "DRAM_ATTR volatile uint32_t bench_boundary_fast_state[3] = {0, UINT32_MAX, 0};")
    text = text.replace("    bench_boundary_fast_state[1] = 0;",
        "    bench_boundary_fast_state[1] = boundary_enabled ? 0 : UINT32_MAX;")
    text = replace_once(text, "static void bench_boundary_start(void)\n{",
        "static void bench_boundary_start(void)\n{\n"
        "    if (bench_boundary_control_off) return;\n"
        "    bench_boundary_fast_state[1] = 0;")
    text = replace_once(text, "    boundary_enabled = 0;",
        "    boundary_enabled = 0;\n"
        "    bench_boundary_fast_state[0] = 0;\n"
        "    bench_boundary_fast_state[1] = UINT32_MAX;")
    text = replace_once(text, "    if (count) { invalid++; puts(\"TM_RAM invalid-command\"); return; }",
        "    if (strcmp(command, \"guard-off\") == 0) {\n"
        "        bench_boundary_control_off = 1; count = 0;\n"
        "        puts(\"BOUNDARY_INLINE mode=off native_heap_and_sp=on\");\n"
        "    } else if (strcmp(command, \"guard-on\") == 0 || !count) {\n"
        "        count = 0; puts(\"BOUNDARY_INLINE mode=on native_heap_and_sp=on\");\n"
        "    }\n"
        "    if (count) { invalid++; puts(\"TM_RAM invalid-command\"); return; }")
    return text


def launch(evidence, args):
    if "-finstrument-functions" not in args or "-c" not in args:
        return subprocess.call(args)
    if "-S" in args or "-x" in args:
        raise ValueError("Unexpected compile mode")
    out_index = args.index("-o") + 1
    source = Path(args[args.index("-c") + 1]).resolve()
    identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    folder = evidence / identity
    folder.mkdir(parents=True, exist_ok=False)
    original, guarded = folder / "original.s", folder / "guarded.s"
    first = list(args)
    first[first.index("-c")] = "-S"
    first[out_index] = str(original)
    subprocess.run(first, check=True)
    generated, sites = guarded_assembly(original.read_text(), identity)
    guarded.write_text(generated)
    second = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in ("-MF", "-MT", "-MQ"):
            skip = True
            continue
        if arg not in ("-MD", "-MMD"):
            second.append(str(guarded) if arg == str(source) else arg)
    subprocess.run(second, check=True)
    (folder / "transform.json").write_text(json.dumps({
        "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "object": str(Path(args[out_index]).resolve()), "compiler_command": args,
        "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "guarded_sha256": hashlib.sha256(guarded.read_bytes()).hexdigest(), "sites": sites,
    }, indent=2) + "\n")
    return 0


def audit_build(source):
    from elftools.elf.elffile import ELFFile
    from run_esp32_followup import sha
    ast = __import__('ast')
    def compiler_ast(path):
        tree = ast.parse(path.read_text())
        tree.body = [n for n in tree.body if not isinstance(n, ast.FunctionDef) or n.name != 'audit_build']
        return ast.dump(tree, include_attributes=False)
    if compiler_ast(source / Path(__file__).name) != compiler_ast(Path(__file__)):
        raise ValueError("Inline guard compiler launcher differs")
    records, linked = [], []
    instructions = []
    for line in (source / "disassembly.txt").read_text().splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)", line)
        if m:
            instructions.append((int(m[1], 16), len(m[2]) // 2, m[3], m[4].split(" <")[0]))
    with (source / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".symtab")
        state = table.get_symbol_by_name("bench_boundary_fast_state")[0]["st_value"]
        sampler = table.get_symbol_by_name("bench_boundary_sample")[0]["st_value"]
        sections = [(s["sh_addr"], s.data()) for s in elf.iter_sections() if s["sh_type"] == "SHT_PROGBITS"]
        def literal(address):
            data = next(d[address-a:address-a+4] for a, d in sections if a <= address < a + len(d))
            return int.from_bytes(data, "little")
        def bytes_at(address, size):
            return next(d[address-a:address-a+size] for a, d in sections if a <= address and address + size <= a + len(d))
        for folder in sorted((source / "inline-assembly").iterdir()):
            record = json.loads((folder / "transform.json").read_text())
            before, after = folder / "original.s", folder / "guarded.s"
            threshold = record.get('transform_kind') == 'stack-entry-threshold'
            entry = threshold or record.get('transform_kind') == 'stack-entry'
            if entry:
                from guard_esp32_stack_entries import guarded_assembly as entry_assembly
                if threshold:
                    from guard_esp32_sp_threshold import guarded_assembly as entry_assembly
                    module = Path(__file__).with_name('guard_esp32_sp_threshold.py')
                    if (source / module.name).read_bytes() != module.read_bytes():
                        raise ValueError('Threshold transform source differs')
                expected, sites = entry_assembly(before.read_text(), folder.name)
                for module in ('guard_esp32_stack_entries.py', 'inspect_esp32_stack_entry_coverage.py'):
                    if (source / module).read_bytes() != Path(__file__).with_name(module).read_bytes():
                        raise ValueError('Entry compiler transform source differs')
            else:
                expected, sites = guarded_assembly(before.read_text(), folder.name)
            if sha(before) != record["original_sha256"] or sha(after) != record["guarded_sha256"] or \
                    after.read_text() != expected or record["sites"] != sites:
                raise ValueError("Inline assembly transform differs")
            records.append({"source_sha256": record["source_sha256"], "sites": len(sites)})
            for site in sites:
                symbols = table.get_symbol_by_name(site["symbol"])
                if not symbols:
                    continue  # Linker garbage collection of unused original functions.
                pc = symbols[0]["st_value"]
                if entry:
                    function = table.get_symbol_by_name(site['function'])[0]
                    encoded_entry = int.from_bytes(bytes_at(function['st_value'], 3), 'little')
                    if pc != function['st_value'] + 3 or encoded_entry & 63 != 54 or \
                            ((encoded_entry >> 12) & 4095) * 8 != site['frame_bytes']:
                        raise ValueError('Guard does not immediately follow its actual ENTRY')
                if threshold:
                    from guard_esp32_sp_threshold import audit_site
                    audit_site(site, function, pc, instructions, literal, table)
                    linked.append(site['symbol'])
                    continue
                body = [i for i in instructions if pc <= i[0] < pc + 96]
                def is_nop(row):
                    return row[2] in ("nop", "nop.n") or row[2:] == ("or", "a1, a1, a1")
                decoded = [row for row in body if not is_nop(row)]
                if len(decoded) < 14:
                    raise ValueError("Incomplete linked inline guard")
                ops = [(op, args) for _, _, op, args in decoded]
                if ops[0] != ("rsil", "a8, 7"):
                    raise ValueError("Inline bounds read is not interrupt-atomic")
                for n in (1, 4):
                    if ops[n][0] != "l32r" or not ops[n][1].startswith("a9, ") or \
                            literal(int(ops[n][1].split(", ")[1], 16)) != state:
                        raise ValueError("Inline guard loads a different state")
                if ops[2] not in (("l32i.n", "a9, a9, 4"), ("l32i", "a9, a9, 4")):
                    raise ValueError("Inline upper-bound load differs")
                if ops[5] not in (("l32i.n", "a9, a9, 0"), ("l32i", "a9, a9, 0")) or \
                        ops[6] != ("addi", "a9, a9, 32") or ops[3][0] != "bltu" or ops[7][0] != "bgeu" or \
                        ops[3][1] != "a9, a1, %x" % decoded[8][0] or \
                        ops[8:10] != [("wsr.ps", "a8"), ("rsync", "")]:
                    raise ValueError("Inline frame correction/branch differs")
                skip = int(ops[7][1].split(", ")[-1], 16)
                if not ops[7][1].startswith("a1, a9, "):
                    raise ValueError("Inline lower-bound register differs")
                path = [i for i in decoded[10:] if i[0] < skip]
                # Anything after the unconditional jump is unreachable alignment padding.
                jumps = [n for n, row in enumerate(path) if row[2] == 'j']
                if jumps:
                    path = path[:jumps[0] + 1]
                if not path or path[-1][2] != "j":
                    raise ValueError("Sample path does not skip the second PS restore")
                finish = int(path[-1][3], 16)
                call = path[:-1]
                if entry:
                    if len(call) < 3 or call[0][2] != 'l32r' or not call[0][3].startswith('a10, ') or \
                            literal(int(call[0][3].split(', ')[1], 16)) != function['st_value'] or \
                            call[1][2:] not in (('movi', 'a11, 0'), ('movi.n', 'a11, 0')):
                        raise ValueError('Entry sampler argument setup differs')
                    call = call[2:]
                if len(call) == 1 and call[0][2] == "call8":
                    target = int(call[0][3], 16)
                elif len(call) == 2 and call[0][2] == "l32r" and call[1][2] == "callx8":
                    register, address = call[0][3].split(", ")
                    if register != call[1][3]:
                        raise ValueError("Long call register differs")
                    target = literal(int(address, 16))
                else:
                    raise ValueError("Inline guarded call changes ABI")
                # Decode the branch target's actual bytes, not a linear decoder's alignment.
                if target != sampler or finish != skip + 6 or bytes_at(skip, 6) != bytes.fromhex('80e613102000'):
                    raise ValueError("Inline skip target/sampler or raw PS restore differs: " + site['symbol'])
                linked.append(site["symbol"])
    if len(records) != 26 or not linked:
        raise ValueError("Selected compiler-boundary translation units differ")
    return {"selected_c_translation_units": len(records), "assembly_profile_sites": sum(r["sites"] for r in records),
        **({'actual_stack_entries': True, 'compiler_function_profiling': False} if entry else {}),
        "linked_guard_sites": len(linked), "abi": ("call8; a8 scratch; aligned single-word threshold, native/heap invalidation" if threshold else
            "existing call8; a8/a9 caller-clobbered scratch; atomic PS-preserving bounds check"),
        "sampler_frame_correction_bytes": 32, "added_stack_frames": 0,
        "inline_skips_counted": False, "control": "same image, guard-off leaves native heap/SP observers on",
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    a = parser.parse_args()
    sys.exit(launch(a.evidence.resolve(), a.command))
