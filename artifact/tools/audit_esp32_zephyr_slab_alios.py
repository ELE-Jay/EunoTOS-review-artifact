#!/usr/bin/env python3
"""Replay original fixed-block operations and native Rhino critical-section paths."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_elf_image
from audit_esp32_zephyr_slab import ROOT, REFERENCE, ORIGINALS, TAGS, capture
from audit_esp32_zephyr_thread import read_control_rows
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_rhealstone_alios import UPSTREAM
from collect_esp32_zephyr_slab_alios_control import FUNCTIONS, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_alios"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_riot"
DIRECTORY = ROOT / "artifacts/reports/zephyr-slab-alios-v1"
NATIVE = ("kernel/rhino/k_mm_blk.c", "kernel/rhino/include/k_mm_blk.h", "kernel/rhino/k_task.c",
          "kernel/rhino/k_time.c", "kernel/rhino/k_sys.c", "kernel/rhino/include/k_sys.h",
          "kernel/rhino/include/k_default_config.h", "platform/arch/xtensa/lx6/xtensa_init.c",
          "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h")
SOURCES = {**ORIGINALS, **{"native-source/" + name: UPSTREAM + name for name in NATIVE},
           "rhino-portasm-pinned.S": UPSTREAM + "platform/arch/xtensa/lx6/portasm.S"}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full-suite entry remains linked")
        control = read_control_rows((directory / "slab-control-flow.txt").read_text(), "SLAB CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=("fail",))
        calls, placements, critical = {}, {}, {}
        native_functions = {"krhino_mblk_pool_init", "krhino_mblk_alloc", "krhino_mblk_free", "krhino_sys_tick_get", "krhino_task_sleep"}
        for name, rows in control.items():
            section = elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"]).name
            if section != (".iram0.text" if name in native_functions else ".flash.text"):
                raise ValueError("native fixed-block placement changed")
            placements[name] = section
            for row in rows.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <(\w+)>", row)
                if not match:
                    continue
                address, value, target, callee = int(match[1], 16), int(match[2], 16), int(match[3], 16), match[4]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != destination or target != destination:
                    raise ValueError("original/native fixed-block call label differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        for caller, callee, count in (("run_original", "mem_slab_test", 1), ("run_original", "krhino_mblk_pool_init", 1),
                ("controller_entry", "run_original", 1), ("application_start", "krhino_task_create", 1),
                ("mem_slab_test", "k_mem_slab_alloc", 1), ("mem_slab_test", "k_mem_slab_free", 1),
                ("mem_slab_test", "begin_test", 2), ("mem_slab_test", "TIME_STAMP_DELTA_GET", 4),
                ("mem_slab_test", "check_result", 2), ("begin_test", "krhino_task_sleep", 1),
                ("begin_test", "k_uptime_delta", 1), ("check_result", "k_uptime_delta", 1),
                ("check_result", "native_slab_mean", 1), ("k_uptime_delta", "krhino_sys_tick_get", 1),
                ("k_mem_slab_alloc", "krhino_mblk_alloc", 1), ("k_mem_slab_free", "krhino_mblk_free", 1)):
            if calls.get((caller, callee), 0) != count:
                raise ValueError(("original/native fixed-block call count differs", caller, callee))
        for name, count in (("run_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original calibration/endpoints are not encoded CCOUNT reads")
        for name in ("krhino_mblk_alloc", "krhino_mblk_free", "krhino_sys_tick_get"):
            rows = list(control[name].values())
            rsil = [row for row in rows if " rsil" in row]
            literal = [re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+a8, ([0-9a-f]+) <[^>]+>", row)
                       for row in rows]
            literal = [m for m in literal if m]
            if len(rsil) != 1 or rsil[0].split(" ", 2)[2] != "rsil\ta10, 3" or int(rsil[0].split()[1], 16) != 0x0063a0 or \
                    len(literal) != 1 or sum("callx8\ta8" in row for row in rows) != 1:
                raise ValueError("native fixed-block interrupt protection/restore path differs")
            address, encoding, pool = int(literal[0][1], 16), int(literal[0][2], 16), int(literal[0][3], 16)
            offset = encoding >> 8
            if offset & 0x8000:
                offset -= 0x10000
            if encoding & 0xff != 0x81 or (address + 3 & ~3) + 4 * offset != pool:
                raise ValueError("native critical-section restore literal label differs from actual encoding")
            sections = [section for section in elf.iter_sections() if section["sh_type"] != "SHT_NOBITS" and
                        section["sh_addr"] <= pool and pool + 4 <= section["sh_addr"] + section["sh_size"]]
            if len(sections) != 1:
                raise ValueError("native restore target literal not bound to ELF")
            section = sections[0]
            target = int.from_bytes(section.data()[pool - section["sh_addr"]:pool - section["sh_addr"] + 4], "little")
            rom = symbols.get_symbol_by_name("_xtos_set_intlevel")[0]
            if rom["st_shndx"] != "SHN_ABS" or target != rom["st_value"] or target != 0x4000bfdc:
                raise ValueError("native critical-section restore is not linked ROM target")
            critical[name] = {"saved_interrupt_level": 3, "rom_restore_target": target, "rom_code_not_rebuilt": True}
        text = "\n".join(control["mem_slab_test"].values())
        if len(re.findall(r"\bblt\s+", text)) != 2 or not all(re.search(pattern, text) for pattern in (
                r"l32i\.n\s+a5, a4, 20", r"l32i\.n\s+a4, a4, 16", r"sub\s+a4, a5, a4")):
            raise ValueError("original two loops/native remaining-block check absent")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("my_slab_storage", "slab_array")}
        if sizes != {"my_slab_storage": 8000, "slab_array": 4000} or symbols.get_symbol_by_name("my_slab_storage")[0]["st_value"] % 4:
            raise ValueError("original pool/pointer storage capacity or alignment differs")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
            "critical_sections": critical, "original_storage_sizes": sizes, "original_timestamp_reads_retained": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    for manifest in ("image.sha256", "capture.sha256", "slab-control.sha256"):
        check_manifest(directory, manifest)
    image_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}
    capture_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    control_names = {line.split(maxsplit=1)[1] for line in (directory / "slab-control.sha256").read_text().splitlines()}
    required = {"application.elf", "application.bin", "application.map", "bootloader.bin", "partitions.bin", "link.opts",
                "config", "sdkconfig.h", "k_config.h", "compiler.txt", "configure.log", "build.log", "build-script.sh",
                "port.c", "original_stats.c", "aos.mk", "Config.in", "examples-Config.in", "symbols.txt", "disassembly.txt",
                "rhino-port-pinned.c", "rhino-vectors-pinned.S", *SOURCES}
    if not required <= image_names or not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
            *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= capture_names or control_names != {
                "application.elf", "image.sha256", "capture.sha256", "slab-control-flow.txt", "collect-slab-control.py",
                "collect-slab-alios-control.py", "collector-base.py"}:
        raise ValueError("native original/source/image/acquisition/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("native fixed-block file differs from original official revision", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {row["path"] for row in proof} != set(SOURCES) or any(
            row["url"] != SOURCES[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("fixed-block original/native provenance differs")
    for name in ("mem_slab.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original fixed-block body/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*")
                 if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(name), ROOT / "tools" / local) for name, local in (
        ("build-script.sh", "build_esp32_zephyr_slab_alios.sh"), ("runner.sh", "run_esp32_zephyr_slab_alios.sh"),
        ("collector-base.py", "collect_esp32_zephyr_slab_control.py"),
        ("collect-slab-alios-control.py", "collect_esp32_zephyr_slab_alios_control.py"), ("capture_esp32_uart.py", "capture_esp32_uart.py"))]
    board = ROOT / "firmware/bsp/esp32/alios_board"
    bindings += [(Path(name), board / path) for name, path in (
        ("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"),
        ("k_config.h", "esp32bench/k_config.h"), ("sdkconfig.h", "esp32bench/sdkconfig.h"))]
    for archived, source in bindings:
        if (directory / archived).read_bytes() != source.read_bytes():
            raise ValueError(("reviewed native fixed-block adapter/config/recipe changed", str(archived)))
    if (directory / "collect-slab-control.py").read_text() != collector_source((directory / "collector-base.py").read_text()):
        raise ValueError("generated native fixed-block collector differs from fixed source")
    if "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native Rhino compiler changed")
    config = (directory / "config").read_text().splitlines()
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="zephyr_slab"', 'AOS_APP_ZEPHYR_SLAB=y'} <= set(config):
        raise ValueError("native Rhino application selection differs")
    for name, value in (("RHINO_CONFIG_CPU_NUM", 1), ("RHINO_CONFIG_MM_BLK", 1), ("RHINO_CONFIG_SCHED_RR", 0)):
        if not re.search(r"^#define " + name + r"\s+" + str(value) + "$", (directory / "k_config.h").read_text(), re.M):
            raise ValueError("native fixed-block/scheduler profile differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    units = ("app/example/zephyr_slab/port.c", "app/example/zephyr_slab/original_stats.c",
             *(name for name in NATIVE if name.endswith(".c")), "platform/arch/xtensa/lx6/port.c",
             "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for name in units:
        selected = [args for args in commands if any(a == name or a.endswith("/" + name) for a in args if not a.startswith("-"))]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0] or \
                any(a.startswith("-DNUMBER_OF_LOOPS") or a.startswith("-DMEM_SLAB") for a in selected[0]):
            raise ValueError(("actual native fixed-block compiler/tick/count differs", name))
        if name.endswith(".c") and ([a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                not {"-DAOS_NO_WIFI", "-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(selected[0])):
            raise ValueError(("native fixed-block optimization/WiFi/original count branch differs", name))
    divisors = hardware_tick_divisors(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    control = machine_paths(directory)
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native fixed-block installed image/board binding differs")
    captures = [capture(directory, index, "alios") for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent native fixed-block boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original fixed-block subset", "os": "AliOS-Rhino",
            "metric_count": 2, "resets": 3, "iterations": 1000, "block_bytes": 8, "blocks": 1000, "alignment": 4,
            "original_files": 5, "native_source_files": 10, "actual_compiled_units_checked": len(units),
            "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
            "captures": captures, "machine_paths": control, "hardware_tick_divisors": divisors,
            "clock_mhz": 240, "cores": 1, "compiler": "5.2.0", "tick_hz": 1,
            "native_pool_concurrency_protection": True, "original_one_native_tick_preparation_preserved": True,
            "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
            "boundary": "single-caller original immediate 1000-block allocation/free and means; native Rhino block-pool interrupt protection/status adapters included; one native tick preparation and original elapsed guard retained; no measured blocking/concurrent pool scenario, full-suite or cross-OS rank; linked ROM/SDK not source rebuilt"}


def render_table(result):
    return "\n".join(["| Original sys_kernel fixed-block subset / OS | Allocate means, ns (three boots) | Free means, ns (three boots) |",
        "| --- | --- | --- |", "| Original fixed-block port / AliOS-Rhino | " + " | ".join(
            " / ".join(map(str, result["metrics"][tag]["means_ns"])) for tag in TAGS) + " |"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
