#!/usr/bin/env python3
"""Replay source-preserving IRAM controls; diagnostics are not qualified scores."""
import argparse
import json
from pathlib import Path
import re
import shlex
import urllib.request

from elftools.elf.elffile import ELFFile
from audit_esp32_rhealstone import ROOT, SOURCE, CASES, audit as original_audit, audit_capture
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_elf_image, image_length, static_footprint
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_rhealstone_iram_control import functions, collector_source
from collect_esp32_rhealstone_irq_control import NORETURN

DIRECTORY = ROOT / "artifacts/reports/rhealstone-freertos-iram-v1"
BUILD = ROOT / "firmware/bsp/esp32/rhealstone/freertos_iram"
REVISION = "acb78c0c8c76f4ae12c60b729948e541c1e3930c"
ORIGINAL = {name + ".c": "testsuites/rhealstone/rh" + name + "/" + name + ".c" for name in CASES}
ORIGINAL.update({"timesys.h": "testsuites/tmtests/include/timesys.h", "btimer.h": "cpukit/include/rtems/btimer.h"})
NATIVE = ("tasks.c", "queue.c", "list.c", "portable/xtensa/port.c", "portable/xtensa/portasm.S")


def verify_official(directory, sources=None):
    proof = []
    for name, path in (ORIGINAL if sources is None else sources).items():
        url = "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + path
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.read() != (SOURCE / name).read_bytes():
                raise ValueError("fixed original source differs: " + name)
        proof.append({"name": name, "url": url, "sha256": digest(SOURCE / name)})
    (directory / "original-source-proof.json").write_text(json.dumps(proof, indent=2) + "\n")


def audit_case(directory, *, calibrated=False):
    case = directory.name
    reference = ROOT / "artifacts/reports/rhealstone-v2/freertos" / case
    old = original_audit(reference)
    if calibrated:
        check_manifest(directory, "image.sha256")
        result = dict(old)
        result["captures"] = [audit_capture(directory / f"reset{i}.jsonl", case) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(result["captures"], result["captures"][1:])):
            raise ValueError("calibrated reset intervals overlap")
        result["raw_original_cycles"] = [row["raw_original_cycles"] for row in result["captures"]]
        result["measurement_eligible"] = all(row["measurement_eligible"] for row in result["captures"])
        result["binary_sha256"] = digest(directory / "rhealstone.bin")
        build_recipe = ROOT / "firmware/bsp/esp32/rhealstone/freertos_calibrated"
        for saved, current in (("port.c", build_recipe / "port.c"), ("native_rhealstone_port.h", reference / "port.c")):
            if (directory / saved).read_bytes() != current.read_bytes():
                raise ValueError("calibrated timer/native adapter differs")
        timer = ROOT / "firmware/bsp/esp32/rhealstone/calibrated_timer"
        for path in timer.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "calibrated_timer" / path.relative_to(timer)).read_bytes():
                raise ValueError("calibrated timer service differs")
        for name in ("tmck-task1.c", "system.h", "btimer.h"):
            if (directory / name).read_bytes() != (SOURCE / name).read_bytes():
                raise ValueError("original calibration/interface source differs")
        base_include = ROOT / "firmware/bsp/esp32/rhealstone/include"
        for path in base_include.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "include" / path.relative_to(base_include)).read_bytes():
                raise ValueError("original API mapping differs")
    else:
        result = original_audit(directory)
        build_recipe = BUILD
        if (directory / "port.c").read_bytes() != (reference / "port.c").read_bytes():
            raise ValueError("placement changed native adapter")
    for name in ("config", "FreeRTOSConfig.h", "compiler.txt", case + ".c", "timesys.h"):
        if (directory / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError("placement control changed original source/native profile: " + name)
    for path in build_recipe.rglob("*"):
        if path.is_file() and path.name != "port.c" and path.read_bytes() != (directory / "build-files" / path.relative_to(build_recipe)).read_bytes():
            raise ValueError("placement build recipe differs")
    builder = "build_esp32_rhealstone_freertos_" + ("calibrated" if calibrated else "iram") + ".sh"
    for saved, current in ((builder, ROOT / "tools" / builder),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone.sh"), ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("placement build/acquisition differs")
    for name in ("capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    expected = {"rhealstone.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}
    if {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != expected:
        raise ValueError("placement control supplement coverage differs")
    if calibrated:
        from collect_esp32_rhealstone_calibrated_control import collector_source as collect, EXTRA
    else:
        collect, EXTRA = collector_source, ()
    generated = collect((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(),
                                 case, (SOURCE / (case + ".c")).read_text())
    if (directory / "collect-irq-control.py").read_text() != generated:
        raise ValueError("placement control collector differs")
    proof = {row["path"]: row for row in json.loads((ROOT / "artifacts/reports/zephyr-isr-freertos-v1/official-native-source.json").read_text())}
    for name in NATIVE:
        path = "components/freertos/FreeRTOS-Kernel/" + name
        if proof[path]["url"] != "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/" + path or \
                digest(directory / "native-source" / name) != proof[path]["sha256"]:
            raise ValueError("fixed official native source differs: " + name)
    commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    application = "rhealstone/freertos_calibrated/port.c" if calibrated else "rhealstone/freertos/port.c"
    required = [application, "rhealstone-original/" + case + ".c", *["FreeRTOS-Kernel/" + n for n in NATIVE]]
    if calibrated:
        required.append("rhealstone-original/tmck-task1.c")
    for name in required:
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("actual original/native compilation differs: " + name)
        if calibrated:
            definitions = {arg for arg in selected[0] if arg.startswith("-D") and arg.split("=", 1)[0] in
                           ("-DInit", "-DTask_1", "-Drtems_test_name", "-DTask_name")}
            wanted = {"-DInit=tmck_Init", "-DTask_1=tmck_Task_1", "-Drtems_test_name=tmck_test_name", "-DTask_name=tmck_Task_name"}
            if definitions != (wanted if name.endswith("tmck-task1.c") else set()) or any(
                    arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION")) for arg in selected[0]):
                raise ValueError("original tmck defaults/namespaced source differ")
    audit_elf_image(directory / "rhealstone.elf", directory / "rhealstone.bin")
    image_length((directory / "bootloader.bin").read_bytes())
    if not (directory / "partition-table.bin").read_bytes().startswith(b"\xaa\x50"):
        raise ValueError("invalid partition table")
    with (directory / "rhealstone.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        names = set(functions((SOURCE / (case + ".c")).read_text()) + EXTRA)
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
                                    elf, symbols, names, noreturn=NORETURN)
        addresses = {}
        for name in names:
            symbol = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
            section = elf.get_section(symbol["st_shndx"])
            if section.name != ".iram0.text" or not 0x40080000 <= symbol["st_value"] < symbol["st_value"] + symbol["st_size"] <= 0x400A0000:
                raise ValueError("original/native adapter function is not actually in IRAM: " + name)
            addresses[name] = hex(symbol["st_value"])
        for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if sum("rsr.ccount" in row for row in control[name].values()) != 1:
                raise ValueError("native raw timestamp changed")
        checked = 0
        # Decode actual direct calls, not just objdump's printed destination.
        for name, rows in control.items():
            for row in rows.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([^>]+)>", row)
                if not match:
                    continue
                address, encoding, printed = (int(x, 16) for x in match.groups()[:3])
                target = match[4]
                candidates = symbols.get_symbol_by_name(target)
                if not candidates:
                    raise ValueError("encoded call lacks native symbol: " + target)
                destination = max(candidates, key=lambda item: item["st_size"])["st_value"]
                offset = encoding >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or printed != destination:
                    raise ValueError("encoded original/native call target differs")
                checked += 1
        if checked < len(names):
            raise ValueError("original/native call coverage incomplete")
        if calibrated:
            for caller, target, count in (("rh_begin", "legacy_rh_begin", 1), ("rh_begin", "rh_timer_check", 2),
                    ("rh_timer_check", "check_read_timer", 1), ("check_read_timer", "benchmark_timer_initialize", 1),
                    ("check_read_timer", "benchmark_timer_read", 1), ("rh_end", "legacy_rh_end", 1)):
                if sum(bool(re.fullmatch(r"[0-9a-f]+: [0-9a-f]{6} call8\s+[0-9a-f]+ <" + target + ">", row))
                       for row in control[caller].values()) != count:
                    raise ValueError("actual original calibration/timer call path differs")
    for index in (1, 2, 3):
        rows = read_raw_capture(directory, index)
        lines = [row["line"] for row in rows]
        if sum("2nd stage bootloader" in line for line in lines) != 1 or \
                sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or \
                sum("Single core mode" in line for line in lines) != 1 or \
                not any("ELF file SHA256:  " + digest(directory / "rhealstone.elf")[:9] + "..." in line for line in lines):
            raise ValueError("placement boot/native clock/image fingerprint differs")
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or \
            written != [((directory / name).stat().st_size, offset) for name, offset in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("rhealstone.bin", 0x10000))]:
        raise ValueError("actual board/verified flash image sizes differ")
    result.update({"original_test_body_unchanged": True, "native_adapter_unchanged": not calibrated,
        "placement": "original application and unchanged adapter text/literals in IRAM; constants in DRAM",
        "native_profile_unchanged": True, "native_source_files": len(NATIVE), "actual_compiled_units_checked": len(required),
        "reachable_functions": len(names), "encoded_direct_calls_checked": checked, "iram_function_addresses": addresses,
        "elf_bin_all_initialized_sections_bound": True, "original_arithmetic_positive": result["measurement_eligible"],
        "measurement_eligible": False, "ranking_eligible": False,
        "reference_original_cycles": old["raw_original_cycles"], "reference_timer_reads_cycles": [r["timer_reads_cycles"] for r in old["captures"]],
        "reference_binary_sha256": old["binary_sha256"],
        "measurement_reason": "placement diagnostic; raw CCOUNT adapter has not restored the original calibrated benchmark_timer_read contract",
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partition-table.bin", "rhealstone.bin")),
        "static_footprint": static_footprint(directory / "rhealstone.elf")})
    for capture in result["captures"]:
        capture["original_arithmetic_positive"] = capture["measurement_eligible"]
        capture["measurement_eligible"] = False
        capture["measurement_reason"] = result["measurement_reason"]
    result["median_us"] = result["range_us"] = None
    return result


def audit(directory=DIRECTORY):
    proof = {row["name"]: row for row in json.loads((directory / "original-source-proof.json").read_text())}
    if set(proof) != set(ORIGINAL):
        raise ValueError("original source proof coverage differs")
    for name, path in ORIGINAL.items():
        if proof[name]["url"] != "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + path or \
                proof[name]["sha256"] != digest(SOURCE / name):
            raise ValueError("fixed original source proof differs")
    contract = (SOURCE / "btimer.h").read_text()
    if "with the average overhead\n *          removed" not in contract or "benchmark_timer_disable_subtracting_average_overhead" not in contract:
        raise ValueError("original timer contract missing")
    cells = [audit_case(directory / "freertos" / case) for case in CASES]
    captures = sorted([capture for cell in cells for capture in cell["captures"]], key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("placement independent boot captures overlap")
    return {"audit": "pass", "scope": "same-OS original-program placement diagnostic", "independent_boots": 15,
        "original_source_files": len(ORIGINAL), "original_timer_contract_url": proof["btimer.h"]["url"],
        "original_timer_contract_sha256": proof["btimer.h"]["sha256"], "cells": cells,
        "ranking_eligible": False, "composite_score": None,
        "original_timer_overhead_contract_restored": False,
        "boundary": "positive output alone is not a valid calibrated latency; no clamping, changed original formula or cross-OS score"}


def render_table(result):
    return "\n".join(["| Original Rhealstone / FreeRTOS | Prior Flash-placement cycles | IRAM-control cycles (three boots) |",
        "| --- | --- | --- |", *["| " + row["case"] + " | " + " / ".join(map(str, row["reference_original_cycles"])) +
        " | " + " / ".join(map(str, row["raw_original_cycles"])) + " |" for row in result["cells"]]])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-official", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_official:
        verify_official(args.directory)
    result = audit(args.directory)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
