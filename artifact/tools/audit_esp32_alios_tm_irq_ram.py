#!/usr/bin/env python3
"""Replay separate native RAM observations for the corrected Rhino IRQ pair."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex

from audit_esp32_alios_tm import audit_case, ROOT
from audit_esp32_alios_tm_irq import CASES, NATIVE, native_calls, archived_tool_matches
from audit_esp32_ram_census import audit_census
from audit_esp32_resources import audit_elf_image
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_thread import read_raw_capture

NATIVE_SHA256 = {
    NATIVE[0]: "54832be1c042d9dcc5ebc0ab04a5c01e91892236e15dfb20c227bc9f143a5593",
    NATIVE[1]: "138ca7d75019cb469fd7939c09e123976f3009aa5ef12035d2f645440f538f36",
}


def check_allocator_source(folder):
    source = (folder / "alios-k_mm.c").read_bytes()
    prefix, marker, tail = source.partition(b"#if BENCH_RAM\n")
    hook, closing, suffix = tail.partition(b"#endif\n\n")
    if not marker or not closing or b"#if BENCH_RAM\n" in tail or \
            b"bench_ram_observe(head);" not in hook:
        raise ValueError("native allocator observer insertion differs")
    # The retained observer source omits one trailing blank line of upstream.
    original = (prefix + suffix).rstrip(b"\n") + b"\n\n"
    sha = hashlib.sha256(original).hexdigest()
    if sha != "eabff1b7db1f9b802a5c4cb656047b7e534283aa1d88c95cef6f47428f120fc3":
        raise ValueError("native allocator changed outside the observation macro")
    return {"url": UPSTREAM + "kernel/rhino/k_mm.c", "official_sha256": sha,
            "difference": "observer macro insertion and trailing blank-line normalization"}


def audit(directory):
    directory = directory.resolve()
    previous_end, cells = None, []
    for case in CASES:
        folder = directory / case
        for name in ("native-irq.sha256", "capture.sha256"):
            check_manifest(folder, name)
        native_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in
                        (folder / "native-irq.sha256").read_text().splitlines()}
        if native_names != {"application.elf", "image.sha256", "build-irq-ram-script.sh",
                            *("native-source/" + name for name in NATIVE)}:
            raise ValueError("corrected IRQ RAM native source/image binding incomplete")
        names = {line.split(maxsplit=1)[1].removeprefix("./") for line in
                 (folder / "capture.sha256").read_text().splitlines()}
        required = {"image.sha256", "native-irq.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
                    *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))}
        if not required <= names:
            raise ValueError("corrected IRQ RAM acquisition binding incomplete")
        for archived, source in (("build-irq-ram-script.sh", "build_esp32_alios_tm_irq_ram.sh"),
                                  ("build_esp32_alios_tm.sh", "build_esp32_alios_tm.sh"),
                                  ("runner.sh", "run_esp32_alios_tm_irq_ram.sh"),
                                  ("capture_esp32_uart.py", "capture_esp32_uart.py")):
            if not archived_tool_matches(folder / archived, source):
                raise ValueError("corrected IRQ RAM build/acquisition source differs")
        proof = json.loads((folder / "official-native-source.json").read_text())
        if len(proof) != len(NATIVE) or {row["path"] for row in proof} != set(NATIVE) or any(
                row["url"] != UPSTREAM + row["path"] or
                row["sha256"] != NATIVE_SHA256[row["path"]] or
                row["sha256"] != digest(folder / "native-source" / row["path"]) for row in proof):
            raise ValueError("corrected IRQ RAM pinned native source provenance differs")
        commands = [shlex.split(line) for line in (folder / "build.log").read_text().replace("\\\n", " ").splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
        for name in (*NATIVE, "app/example/thread_metric/census.c", "kernel/rhino/k_mm.c"):
            selected = [args for args in commands if name in args]
            if len(selected) != 1 or "-DBENCH_RAM=1" not in selected[0] or \
                    [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
                raise ValueError("corrected IRQ RAM native allocator/vector/observer compilation differs")
        cell = audit_census(folder, "AliOS-Rhino", case, irq_vector_corrected=True)
        original = audit_case(folder, case, irq_vector_corrected=True)
        if original["elf_sha256"] != cell["elf_sha256"]:
            raise ValueError("original execution and native RAM image differ")
        audit_elf_image(folder / "application.elf", folder / "application.bin")
        cell["actual_native_calls"] = native_calls(folder, case, observe_allocators=True)
        cell["native_allocator_source"] = check_allocator_source(folder)
        cell["hardware_tick_divisors"] = hardware_tick_divisors(folder, 100)
        for index in (1, 2, 3):
            rows = read_raw_capture(folder, index)
            start, end = (datetime.fromisoformat(rows[position]["utc"]) for position in (0, -1))
            if previous_end is not None and start <= previous_end:
                raise ValueError("corrected IRQ RAM independent boot captures overlap")
            previous_end = end
            cell["runs"][index - 1]["raw_sha256"] = digest(folder / f"reset{index}.raw")
        cell["instrumented_original_first_window_values"] = original["first_window_values"]
        cells.append(cell)
    return {"audit": "pass", "benchmark": "Thread-Metric original corrected Rhino IRQ pair: native RAM observation",
            "independent_resets": 6, "cells": cells, "original_test_body_unchanged": True,
            "observer_unchanged": True, "ranking_eligible": False, "replacement_of_old_matrix": False,
            "uninstrumented_firmware_peak_eligible": False, "performance_or_energy_score_eligible": False,
            "boundary": "separate instrumented images; unchanged native allocator commit observer and original 30/60/90-second reports; 240 MHz/one core/native 100-Hz FIFO/GCC5; static physical SRAM union plus simultaneous occupied native heaps; benchmark entry through snapshot before 90-second report; excludes earlier startup, Hartstone and allocator-internal transient peaks; does not measure the uninstrumented performance/energy image RAM peak"}


def render_table(result):
    if result.get("audit") != "pass" or result.get("independent_resets") != 6 or \
            tuple(row["original_case"] for row in result.get("cells", [])) != CASES:
        raise ValueError("cannot render an incomplete corrected IRQ RAM pair")
    rows = ["| Corrected Rhino original IRQ RAM observation | Whole-software RAM peaks B (three boots) | Simultaneous native heap peak B | Static physical SRAM B | Installed Flash B |",
            "| --- | --- | --- | --- | --- |"]
    for cell in result["cells"]:
        peaks = [cell["static_sram_bytes"] + run["dynamic_heap_peak_bytes"] for run in cell["runs"]]
        heaps = [run["dynamic_heap_peak_bytes"] for run in cell["runs"]]
        rows.append("| Corrected IRQ RAM / " + cell["original_case"] + " | " + " / ".join(map(str, peaks)) + " | " +
                    " / ".join(map(str, heaps)) + f" | {cell['static_sram_bytes']} | {cell['installed_flash_bytes']} |")
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
