#!/usr/bin/env python3
"""Replay original fixed-block loops on the pinned native NuttX memory pool."""
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
from collect_esp32_zephyr_slab_nuttx_control import FUNCTIONS, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_nuttx"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_riot"
DIRECTORY = ROOT / "artifacts/reports/zephyr-slab-nuttx-v1"
NATIVE = ("mm/mempool/mempool.c", "include/nuttx/mm/mempool.h", "include/nuttx/spinlock.h",
          "include/nuttx/queue.h", "sched/clock/clock_systime_ticks.c", "sched/signal/sig_usleep.c",
          "arch/xtensa/include/irq.h", "arch/xtensa/include/lx6/irq.h",
          "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/esp32/esp32_clockconfig.c")
SOURCES = {**ORIGINALS, **{"native-source/" + name:
    "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/" + name for name in NATIVE}}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full-suite entry remains linked")
        control = read_control_rows((directory / "slab-control-flow.txt").read_text(), "SLAB CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=("fail",))

        def data_at(address, size):
            selected = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                        s["sh_addr"] <= address and address + size <= s["sh_addr"] + s["sh_size"]]
            if len(selected) != 1:
                raise ValueError("native fixed-block data not uniquely bound to ELF")
            section = selected[0]
            return section.data()[address - section["sh_addr"]:address - section["sh_addr"] + size]

        def literal(row, register):
            m = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+a" + str(register) + r", ([0-9a-f]+) <.*", row)
            if not m:
                raise ValueError("native fixed-block literal instruction absent")
            address, encoding, pool = map(lambda x: int(x, 16), m.groups())
            offset = encoding >> 8
            if offset & 0x8000:
                offset -= 0x10000
            if encoding & 0xff != 1 + (register << 4) or ((address + 3) & ~3) + 4 * offset != pool:
                raise ValueError("native fixed-block literal label differs from actual encoding")
            return int.from_bytes(data_at(pool, 4), "little")

        calls, placements, protection = {}, {}, {}
        for name, rows in control.items():
            section = elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"]).name
            if section != ".flash.text":
                raise ValueError("native NuttX fixed-block placement differs")
            placements[name] = section
            for row in rows.values():
                m = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                address, value, target, callee = int(m[1], 16), int(m[2], 16), int(m[3], 16), m[4]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != destination or target != destination:
                    raise ValueError("original/native fixed-block call label differs from encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        for caller, callee, count in (("zephyr_slab_main", "run_original", 1), ("run_original", "mem_slab_test", 1),
                ("run_original", "mempool_init", 1), ("run_original", "check_pool", 2), ("check_pool", "mempool_info", 1),
                ("mem_slab_test", "k_mem_slab_alloc", 1), ("mem_slab_test", "mempool_free", 1),
                ("mem_slab_test", "begin_test", 2), ("mem_slab_test", "TIME_STAMP_DELTA_GET", 4),
                ("mem_slab_test", "check_result", 2), ("begin_test", "nxsig_usleep", 1),
                ("begin_test", "k_uptime_delta", 1), ("check_result", "k_uptime_delta", 1),
                ("check_result", "native_slab_mean", 1), ("k_mem_slab_alloc", "mempool_alloc", 1),
                ("nxsig_usleep", "nxsig_nanosleep", 1), ("esp32_timerisr", "nxsched_process_timer", 1)):
            if calls.get((caller, callee), 0) != count:
                raise ValueError(("original/native fixed-block call count differs", caller, callee))
        for name, count in (("run_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original calibration/endpoints are not encoded CCOUNT reads")
        for name, saved in (("mempool_alloc", 2), ("mempool_free", 1), ("mempool_info", 1)):
            rows = list(control[name].values())
            saves = [row for row in rows if " rsil" in row]
            restores = [row for row in rows if " wsr.ps" in row]
            if len(saves) != saved or not restores:
                raise ValueError("native pool interrupt save/restore absent")
            for row in saves + restores:
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) (rsil|wsr\.ps)\s+a(\d+)(, 2)?", row)
                if not m or bool(m[4]) != (m[2] == "rsil") or int(m[1], 16) != \
                        (0x006200 if m[2] == "rsil" else 0x13e600) + (int(m[3]) << 4):
                    raise ValueError("native pool interrupt instruction label differs from encoding")
            protection[name] = {"saved_interrupt_level": 2, "compiled_save_sites": len(saves),
                                "compiled_restore_sites": len(restores)}
        body = "\n".join(control["mem_slab_test"].values())
        if len(re.findall(r"\bblt\s+", body)) != 2 or "f588 l32i.n\ta8, a5, 60" not in body:
            raise ValueError("original loops/native remaining-block check absent")
        pool = symbols.get_symbol_by_name("my_slab")[0]
        initial = data_at(pool["st_value"], pool["st_size"])
        word = lambda offset: int.from_bytes(initial[offset:offset + 4], "little")
        storage = symbols.get_symbol_by_name("my_slab_storage")[0]
        if pool["st_size"] != 96 or [word(i) for i in (0, 4, 8, 12, 20, 24, 28, 92)] != [
                8, 8004, 0, 0, storage["st_value"], symbols.get_symbol_by_name("native_slab_storage")[0]["st_value"],
                symbols.get_symbol_by_name("native_slab_storage_free")[0]["st_value"], 1000] or initial[16] != 0:
            raise ValueError("native static pool capacity/policy/callback binding differs")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("my_slab_storage", "slab_array")}
        if sizes != {"my_slab_storage": 8004, "slab_array": 4000} or storage["st_value"] % 4:
            raise ValueError("original payload/native metadata storage capacity or alignment differs")
        init = list(control["up_timer_initialize"].values())
        timer = list(control["esp32_timerisr"].values())
        if literal(next(row for row in init if "l32r\ta9," in row), 9) != 240000000 or \
                literal(next(row for row in init if "l32r\ta8," in row), 8) != symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"] or \
                literal(next(row for row in timer if "l32r\ta8," in row), 8) != symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"] or \
                not {"006892 s32i\ta9, a8, 0", "13f080 wsr.ccompare0\ta8"} <= {r.split(": ")[1] for r in init} or \
                not {"03f060 rsr.ccompare0\ta6", "13f080 wsr.ccompare0\ta8"} <= {r.split(": ")[1] for r in timer}:
            raise ValueError("native hardware 1-Hz timer initialization/ISR differs")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
            "interrupt_protection": protection, "original_storage_sizes": sizes, "native_metadata_bytes": 4,
            "hardware_tick_divisor": 240000000, "original_timestamp_reads_retained": True,
            "native_free_adapter_inlined": True, "rom_arithmetic_not_source_rebuilt": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "slab-control.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    required = {"application.elf", "application.bin", "application.map", "bootloader.bin", "partitions.bin",
        "config", "native-profile-config", "compiler.txt", "build.log", "configure.log", "context.log", "clean.log",
        "native-distclean.log", "version-metadata", "version-header.h", "build-script.sh", "port.c", "original_stats.c",
        "Makefile", "Make.defs", "Kconfig", "symbols.txt", "disassembly.txt", *SOURCES}
    if not required <= inventories["image.sha256"] or not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
            *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["slab-control.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "slab-control-flow.txt",
                "collect-slab-control.py", "collect-slab-nuttx-control.py", "collector-base.py"}:
        raise ValueError("native original/source/image/acquisition/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("native file differs from original official revision", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {row["path"] for row in proof} != set(SOURCES) or any(
            row["url"] != SOURCES[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("native fixed-block provenance differs")
    for name in ("mem_slab.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original fixed-block body/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(name), ROOT / "tools" / local) for name, local in (
        ("build-script.sh", "build_esp32_zephyr_slab_nuttx.sh"), ("runner.sh", "run_esp32_zephyr_slab_nuttx.sh"),
        ("collector-base.py", "collect_esp32_zephyr_slab_control.py"),
        ("collect-slab-nuttx-control.py", "collect_esp32_zephyr_slab_nuttx_control.py"), ("capture_esp32_uart.py", "capture_esp32_uart.py"))]
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-slab-control.py").read_text() != collector_source((directory / "collector-base.py").read_text()):
        raise ValueError("reviewed native adapter/build/capture/control binding differs")
    config = (directory / "config").read_text().splitlines()
    expected = {"CONFIG_EXAMPLES_ZEPHYR_SLAB=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_USEC_PER_TICK=1000000",
        "CONFIG_RR_INTERVAL=0", "CONFIG_MM_BACKTRACE=-1", "# CONFIG_MM_KASAN is not set", 'CONFIG_INIT_ENTRYPOINT="nsh_main"'}
    if not expected <= set(config) or any(line in config for line in ("CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y")) or \
            "13.2.0" not in (directory / "compiler.txt").read_text() or "12.2.1" not in (directory / "version-header.h").read_text():
        raise ValueError("native scheduler/allocator/compiler/version profile differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if line.startswith("xtensa-esp32-elf-gcc -c ")]
    units = ("mempool/mempool.c", "clock/clock_systime_ticks.c", "signal/sig_usleep.c", "chip/esp32_timerisr.c", "chip/esp32_clockconfig.c",
             "original_stats.c", "port.c")
    for name in units:
        selected = [args for args in commands if name in args and
                    (name not in ("port.c", "original_stats.c") or any("/examples/zephyr_slab/" in arg for arg in args))]
        if len(selected) != 1 or [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith("-DNUMBER_OF_LOOPS") or a.startswith("-DMEM_SLAB") for a in selected[0]):
            raise ValueError(("actual native fixed-block compilation/count differs", name))
        if name in ("port.c", "original_stats.c") and not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(selected[0]):
            raise ValueError("original count or timing branch differs")
    control = machine_paths(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native fixed-block installed image/board binding differs")
    captures = [capture(directory, index, "nuttx") for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent native fixed-block boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original fixed-block subset", "os": "NuttX",
        "metric_count": 2, "resets": 3, "iterations": 1000, "block_bytes": 8, "blocks": 1000, "alignment": 4,
        "original_files": 5, "native_source_files": len(NATIVE), "actual_compiled_units_checked": len(units),
        "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
        "captures": captures, "machine_paths": control, "clock_mhz": 240, "cores": 1, "compiler": "13.2.0", "tick_hz": 1,
        "other_configured_builtins": sorted(line.split("=", 1)[0] for line in config if line.startswith("CONFIG_EXAMPLES_") and line.endswith("=y") and line != "CONFIG_EXAMPLES_ZEPHYR_SLAB=y"),
        "native_pool_concurrency_protection": True, "original_tick_phase_synchronization_preserved": False,
        "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
        "boundary": "single-caller original immediate allocation/free of 1000 eight-byte blocks; native static backing includes four-byte metadata, expansion/interrupt pool/wait disabled, native interrupt protection/status adapter included; native one-second sleep request rounds through NuttX tick scheduling, not Zephyr phase synchronization; original coarse elapsed guard retained; other configured NSH builtins not executed; no full-suite, blocking/concurrent equivalence, new-image RAM/energy or cross-OS rank; ROM arithmetic not source rebuilt"}


def render_table(result):
    return "\n".join(["| Original sys_kernel fixed-block subset / OS | Allocate means, ns (three boots) | Free means, ns (three boots) |",
        "| --- | --- | --- |", "| Original fixed-block port / NuttX | " + " | ".join(
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
