#!/usr/bin/env python3
"""Replay the minimal native-vector correction and its paired board energy."""
import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_alios_tm import audit_case, ROOT
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_zephyr_isr import rhino_vector_dispatch
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_powerz import audit as power_audit
from audit_esp32_tm_energy import check_native_workload, paired_energy

CASES = ("interrupt_processing", "interrupt_preemption_processing")
NATIVE = ("kernel/rhino/k_sys.c", "platform/mcu/esp32/espos/platform/rhino/espos_scheduler.c")


def archived_tool_matches(path, source):
    if source == "build_esp32_alios_tm.sh":
        # The GCC5 acquisitions predate the optional GCC13 toolchain override.
        return digest(path) == "c1bea6355315e539d0ff112d559a2e1937391e10344292c8d00a9990f8c70f75"
    return path.read_bytes() == (ROOT / "tools" / source).read_bytes()


def native_calls(directory, case, *, observe_allocators=False, legacy_ablation=False, gcc13_blocks=False):
    text = (directory / "disassembly.txt").read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")

        def calls(source):
            symbol = max(symbols.get_symbol_by_name(source), key=lambda row: row["st_size"])
            body = re.search(r"^" + format(symbol["st_value"], "x") + r" <" + source + r">:\n(.*?)(?=\n\n|\Z)", text, re.M | re.S)
            if not body or not symbol["st_size"]:
                raise ValueError("native IRQ body absent")
            section = elf.get_section(symbol["st_shndx"])
            data, base = section.data(), section["sh_addr"]
            body_text = body[1]
            if gcc13_blocks and source == "krhino_intrpt_exit":
                # Resume objdump at the real BNE destination, not alignment padding.
                extra = (directory / "irq-exit-branch.txt").read_text()
                anchors = re.findall(r"^([0-9a-f]+) <krhino_intrpt_exit\+0x([0-9a-f]+)>:$", extra, re.M)
                if len(anchors) != 1:
                    raise ValueError("Missing unique GCC13 exit branch block")
                anchor, offset = (int(v, 16) for v in anchors[0])
                branches = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+bne\s+a8, a10, " +
                                      format(anchor, "x") + r" <krhino_intrpt_exit\+0x[0-9a-f]+>$", body[1], re.M)
                if len(branches) != 1 or anchor != symbol["st_value"] + offset:
                    raise ValueError("GCC13 block is not the original branch destination")
                pc, encoding = (int(v, 16) for v in branches[0])
                displacement = encoding >> 16
                displacement -= 256 if displacement & 128 else 0
                if encoding & 0xffff != 0x98a7 or pc + 4 + displacement != anchor or \
                        data[pc - base:pc - base + 3] != encoding.to_bytes(3, "little"):
                    raise ValueError("GCC13 branch bytes/target differ")
                position = anchor
                instructions = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{4}(?:[0-9a-f]{2})?)\s+(.+)$", extra, re.M)
                if len(instructions) != 4 or not re.fullmatch(r"call8\s+[0-9a-f]+ <cpu_intrpt_switch>", instructions[-1][2]):
                    raise ValueError("GCC13 block does not end in the native deferred switch")
                for address, encoded, _ in instructions:
                    chunk = bytes.fromhex(encoded)[::-1]
                    if int(address, 16) != position or data[position - base:position - base + len(chunk)] != chunk:
                        raise ValueError("GCC13 block instruction bytes/coverage differ")
                    position += len(chunk)
                if position > symbol["st_value"] + symbol["st_size"]:
                    raise ValueError("GCC13 branch block escapes function")
                body_text += "\n" + extra
            targets = []
            seen = set()
            for address, encoding, destination, name in re.findall(
                    r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <(\w+)>$", body_text, re.M):
                address, value = int(address, 16), int(encoding, 16)
                if address in seen:
                    continue
                seen.add(address)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if not symbol["st_value"] <= address < symbol["st_value"] + symbol["st_size"] or \
                        data[address - base:address - base + 3] != bytes.fromhex(encoding)[::-1] or value & 0x3f != 0x25 or \
                        (address & ~3) + 4 + offset * 4 != int(destination, 16) or \
                        int(destination, 16) != symbols.get_symbol_by_name(name)[0]["st_value"]:
                    raise ValueError("native IRQ call bytes/encoded target differ")
                targets.append(name)
            return targets

        handler = "tm_interrupt_handler" if case == CASES[0] else "tm_interrupt_preemption_handler"
        targets = calls("software_isr")
        expected = 1 if legacy_ablation else 0
        if targets.count(handler) != 1 or any(targets.count(name) != expected for name in
                ("krhino_intrpt_enter", "krhino_intrpt_exit")):
            raise ValueError("ISR handler or declared duplicate kernel nesting differs")
        for source, target in (("espos_isr_enter", "krhino_intrpt_enter"),
                               ("espos_isr_exit", "krhino_intrpt_exit"), ("krhino_intrpt_exit", "cpu_intrpt_switch")):
            if calls(source).count(target) != 1:
                raise ValueError("native vector kernel entry/exit/deferred switch incomplete")
        allocator_calls = {}
        if observe_allocators:
            for source in ("k_mm_alloc", "k_mm_free", "k_mm_realloc"):
                count = calls(source).count("bench_ram_observe")
                if not count:
                    raise ValueError("native allocator commit observer absent from encoded calls")
                allocator_calls[source] = count
    result = {"callback": handler, "native_vector_indirect_calls":
              rhino_vector_dispatch(directory, allow_literal_annotation=gcc13_blocks)}
    if legacy_ablation:
        result["legacy_duplicate_nesting_ablation_not_qualified_performance"] = True
    if observe_allocators:
        result["allocator_commit_observer_calls"] = allocator_calls
    if gcc13_blocks:
        result["byte_verified_branch_block_sha256"] = digest(directory / "irq-exit-branch.txt")
    return result


def audit(directory, verify_upstream=False):
    directory = directory.resolve()
    previous_end, cells = None, []
    for case in CASES:
        folder = directory / case
        for name in ("native-irq.sha256", "capture.sha256"):
            check_manifest(folder, name)
        native_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (folder / "native-irq.sha256").read_text().splitlines()}
        if native_names != {"application.elf", "image.sha256", "build-irq-script.sh", *("native-source/" + name for name in NATIVE)}:
            raise ValueError("native IRQ source/image/build binding incomplete")
        required = {"image.sha256", "flash.log", "runner.sh", "capture_esp32_powerz.py", "seal_esp32_power_supply.py",
                    "operator-setup.json", *(f"reset{i}.jsonl" for i in (1, 2, 3)),
                    *(f"power-reset{i}/capture/{name}" for i in (1, 2, 3) for name in
                      ("metadata.json", "power.csv", "meter.jsonl", "uart.jsonl", "supply-evidence.json", "operator-setup.json"))}
        names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (folder / "capture.sha256").read_text().splitlines()}
        if not required <= names:
            raise ValueError("corrected IRQ acquisition coverage incomplete")
        for archived, source in (("build-irq-script.sh", "build_esp32_alios_tm_irq.sh"),
                                  ("build_esp32_alios_tm.sh", "build_esp32_alios_tm.sh"),
                                  ("runner.sh", "run_esp32_alios_tm_irq.sh"),
                                  ("capture_esp32_powerz.py", "capture_esp32_powerz.py"),
                                  ("seal_esp32_power_supply.py", "seal_esp32_power_supply.py")):
            if not archived_tool_matches(folder / archived, source):
                raise ValueError("corrected IRQ build/acquisition changed")
        proof_path = folder / "official-native-source.json"
        if verify_upstream:
            proof = []
            for name in NATIVE:
                with urlopen(UPSTREAM + name, timeout=30) as response:
                    sha = hashlib.sha256(response.read()).hexdigest()
                if sha != digest(folder / "native-source" / name):
                    raise ValueError("native vector wrapper/kernel file not the pinned official source")
                proof.append({"path": name, "url": UPSTREAM + name, "sha256": sha})
            proof_path.write_text(json.dumps(proof, indent=2) + "\n")
        proof = json.loads(proof_path.read_text())
        if len(proof) != len(NATIVE) or {row["path"] for row in proof} != set(NATIVE) or any(
                row["url"] != UPSTREAM + row["path"] or row["sha256"] != digest(folder / "native-source" / row["path"])
                for row in proof):
            raise ValueError("native source provenance differs")
        commands = [shlex.split(line) for line in (folder / "build.log").read_text().replace("\\\n", " ").splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
        for name in NATIVE:
            selected = [args for args in commands if name in args]
            if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
                raise ValueError("native vector wrapper/kernel compilation differs")
        cell = audit_case(folder, case, irq_vector_corrected=True)
        audit_elf_image(folder / "application.elf", folder / "application.bin")
        cell["actual_native_calls"] = native_calls(folder, case)
        cell["hardware_tick_divisors"] = hardware_tick_divisors(folder, 100)
        cell["energy_runs"] = []
        for index in (1, 2, 3):
            capture = folder / f"power-reset{index}/capture"
            if (capture / "uart.jsonl").read_bytes() != (folder / f"reset{index}.jsonl").read_bytes() or \
                    (capture / "operator-setup.json").read_bytes() != (folder / "operator-setup.json").read_bytes():
                raise ValueError("copied workload/supply record differs from actual paired capture")
            check_native_workload(capture, "AliOS-Rhino", case)
            result = power_audit(capture, tm_os="AliOS-Rhino", tm_case=case,
                                 whole_board_evidence=capture / "supply-evidence.json", image_source=folder)
            metadata = json.loads((capture / "metadata.json").read_text())
            start = datetime.fromisoformat(metadata["started_utc"])
            if previous_end is not None and start <= previous_end:
                raise ValueError("corrected IRQ independent power captures overlap")
            previous_end = start + timedelta(seconds=metadata["duration_actual_s"])
            result.update(paired_energy(result), reset=index, started_utc=metadata["started_utc"])
            cell["energy_runs"].append(result)
        for key in ("steady_average_power_w", "energy_per_original_count_uj", "original_counts_per_s"):
            cell["median_" + key] = statistics.median(row[key] for row in cell["energy_runs"])
        cells.append(cell)
    return {"audit": "pass", "benchmark": "Thread-Metric original two IRQ cases; native vector correction",
            "independent_resets": 6, "cells": cells, "original_test_body_unchanged": True,
            "adapter_change": "remove duplicate kernel enter/exit; existing native vector performs nesting",
            "ranking_eligible": False, "replacement_of_old_matrix": False,
            "boundary": "original 30-second totals and paired board-input energy; 240 MHz/one core/native 100-Hz FIFO/GCC5; reporting/adapter costs retained; signed instrument data with prior operator-confirmed path and fixed direction; uncalibrated, no cross-OS or before/after energy ranking; static footprint audited, corrected workload runtime RAM peak still unmeasured"}


def render_table(result):
    if result.get("audit") != "pass" or result.get("independent_resets") != 6 or \
            tuple(row["case"] for row in result.get("cells", [])) != CASES:
        raise ValueError("cannot render an incomplete or unaudited corrected IRQ pair")
    rows = ["| Corrected Rhino original IRQ case | Original first-window totals (three boots) | Board input median W | Median energy per original count, uJ | Installed Flash B | Static physical SRAM B |",
            "| --- | --- | --- | --- | --- | --- |"]
    for row in result["cells"]:
        rows.append("| " + row["case"] + " | " + " / ".join(map(str, row["first_window_values"])) +
                    f" | {row['median_steady_average_power_w']:.6f} | {row['median_energy_per_original_count_uj']:.6f} | {row['installed_flash_bytes']} | {row['static_sram_bytes']} |")
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
