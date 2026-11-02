#!/usr/bin/env python3
"""Replay the original sys_kernel fixed-block subset through native RIOT memarray."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_slab_control import FUNCTIONS

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_riot"
REFERENCE = ROOT / "artifacts/reports/zephyr-original-v1/sys_kernel"
DIRECTORY = ROOT / "artifacts/reports/zephyr-slab-riot-v3"
ZEPHYR = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/"
ORIGINALS = {"source/" + name: ZEPHYR + "tests/benchmarks/sys_kernel/src/" + name
             for name in ("mem_slab.c", "syskernel.c", "syskernel.h")}
ORIGINALS.update({"include/zephyr/" + name: ZEPHYR + "subsys/testsuite/include/zephyr/" + name
                  for name in ("timestamp.h", "test_asm_inline_gcc.h")})
NATIVE = ("sys/include/memarray.h", "sys/memarray/memarray.c")
SOURCES = {**ORIGINALS, **{"native-source/" + name: RIOT_UPSTREAM + name for name in NATIVE}}
TAGS = ("Memslab #1", "Memslab #2")
BEGIN = "SLAB PORT BEGIN RIOT Zephyr-3.7.0-subset count=1000 bytes=8 align=4 clock=240 cores=1 tick=native-tickless"


def capture(directory, index, os="riot"):
    if os not in ("riot", "alios", "nuttx"):
        raise ValueError("unsupported native fixed-block port")
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    if os == "riot":
        begin = BEGIN
        native_boot = lines.count("main(): This is RIOT! (Version: 2024.10-devel)") == 1 and \
            lines.count("Single core mode") == 1 and lines.count("Pro cpu up.") == 1
    elif os == "alios":
        begin = BEGIN.replace(" RIOT ", " AliOS-Rhino ").replace("tick=native-tickless", "tick=1")
        native_boot = lines.count("Welcome to AliOS Things") == 1 and lines.count("bootload image") == 1 and \
            lines.count("SLAB NATIVE TICK divisor=240000000") == 1
    else:
        begin = BEGIN.replace(" RIOT ", " NuttX ").replace("tick=native-tickless", "tick=1")
        native_boot = lines.count("NuttShell (NSH) NuttX-12.2.1") == 1 and \
            lines.count("SLAB NATIVE VERSION NuttX 12.2.1") == 1 and \
            lines.count("SLAB NATIVE POOL payload=8000 metadata=4 capacity=1000 block=8 expand=0 wait=0") == 1
    if lines.count(begin) != 1 or lines[-1] != "SLAB PORT END" or lines.count("SLAB PORT END") != 1 or \
            lines.count("SLAB POOL FINAL available=1000") != 1 or sum("rst:0x" in line for line in lines) != 1 or \
            not native_boot or any(re.search(
                r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("original slab reset/profile/end/correctness differs")
    result = original_syskernel_cases(lines, TAGS, "SLAB")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
            "uart_sha256": digest(directory / f"reset{index}.jsonl"),
            "raw_sha256": digest(directory / f"reset{index}.raw")}


def original_syskernel_cases(lines, tags, prefix):
    """Replay the unchanged case grammar, coarse guard and integer mean formula."""
    values, current, successful = {}, None, False
    for line in lines:
        if line.startswith("TEST CASE: "):
            if current is not None or line[11:] not in tags or line[11:] in values:
                raise ValueError("duplicate/unfinished original slab case")
            current, successful = line[11:], False
        elif line == "TEST RESULT: SUCCESSFUL":
            if current is None or successful:
                raise ValueError("unbound original slab success")
            successful = True
        elif m := re.fullmatch(r"DETAILS: Average time for 1 iteration: (\d+) nSec", line):
            if not successful or current in values:
                raise ValueError("unbound original mean")
            values[current] = int(m[1])
        elif line == "END TEST CASE":
            if current not in values or not successful:
                raise ValueError("incomplete original slab case")
            current = None
    inputs = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        prefix + r" ORIGINAL INPUT cycles=(\d+) count=(\d+) tm_off=(\d+)", line))]
    uptime = [int(m[1]) for line in lines if (m := re.fullmatch(prefix + r" UPTIME elapsed_ms=(\d+)", line))]
    preparation = uptime[::2]
    if tuple(values) != tags or current is not None or len(inputs) != len(tags) or len(uptime) != 2 * len(tags) or \
            not preparation or preparation[0] < 1000 or preparation != sorted(preparation) or any(t >= 1000 for t in uptime[1::2]) or \
            len({row[2] for row in inputs}) != 1 or any(
                count != 1000 or not 0 < cycles < 2**32 or not 0 < overhead < 2**32 or
                values[tag] != cycles * 1000 // 240 // count for tag, (cycles, count, overhead) in zip(tags, inputs)):
        raise ValueError("original slab count/calibration/guard/mean formula differs")
    if lines.index(prefix + " ORIGINAL INPUT cycles=" + str(inputs[0][0]) + " count=1000 tm_off=" + str(inputs[0][2])) < \
            max(i for i, line in enumerate(lines) if line == "END TEST CASE"):
        raise ValueError("observation UART entered original timed windows")
    return {"means_ns": values,
            "original_inputs": [dict(zip(("adjusted_cycles", "iterations", "tm_off_cycles"), row)) for row in inputs],
            "native_uptime_deltas_ms": uptime}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full-suite entry remains linked")
        control = read_control_rows((directory / "slab-control-flow.txt").read_text(), "SLAB CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=("fail",))
        calls = {}
        for name, rows in control.items():
            if elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"]).name != ".flash.text":
                raise ValueError("native slab placement changed")
            text = "\n".join(rows.values())
            for address, encoding, target, callee in re.findall(
                    r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <(\w+)>$", text, re.M):
                value, address = int(encoding, 16), int(address, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(target, 16) != destination:
                    raise ValueError("native slab call target differs from actual ELF encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        for caller, callee, count in (("main", "mem_slab_test", 1), ("main", "memarray_init", 1),
                ("mem_slab_test", "k_mem_slab_alloc", 1), ("mem_slab_test", "begin_test", 2),
                ("mem_slab_test", "TIME_STAMP_DELTA_GET", 4), ("mem_slab_test", "check_result", 2),
                ("mem_slab_test", "k_mem_slab_num_used_get", 1), ("begin_test", "ztimer_sleep", 1),
                ("begin_test", "k_uptime_delta", 1), ("check_result", "k_uptime_delta", 1),
                ("check_result", "native_slab_mean", 1), ("memarray_init", "memarray_extend", 1),
                ("k_mem_slab_num_used_get", "memarray_available", 1)):
            if calls.get((caller, callee), 0) != count:
                raise ValueError(("original/native slab call count differs", caller, callee))
        for name, count in (("main", 2), ("TIME_STAMP_DELTA_GET", 1)):
            rows = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(rows) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in rows):
                raise ValueError("original calibration/endpoints are not encoded CCOUNT reads")
        # Native memarray_free is inlined: four byte copies then the pool-head store.
        free_body = "\n".join(control["mem_slab_test"][a] for a in sorted(control["mem_slab_test"]))
        if any(len(re.findall(r"\b" + opcode + r"\s+", free_body)) != 4 for opcode in ("l8ui", "s8i")) or \
                not re.search(r"s32i\.n\s+a3, a5, 0", free_body) or \
                len(re.findall(r"\bblt\s+", free_body)) != 2:
            raise ValueError("native inlined free-list updates/original loops absent")
        free_ops = re.findall(r"^[0-9a-f]+: ([0-9a-f]{6}) (l8ui|s8i)\s+a(\d+), a(\d+), (\d+)$", free_body, re.M)
        if len(free_ops) != 8:
            raise ValueError("native inlined free-list byte copies incomplete")
        for encoding, opcode, register, base, offset in free_ops:
            value = int(encoding, 16)
            if value & 0xf00f != (0x0002 if opcode == "l8ui" else 0x4002) or \
                    (value >> 4 & 15, value >> 8 & 15, value >> 16) != tuple(map(int, (register, base, offset))):
                raise ValueError("native free-list instruction label differs from encoding")
        if [(int(base), int(offset)) for _, opcode, _, base, offset in free_ops if opcode == "s8i"] != \
                [(3, 0), (3, 1), (3, 2), (3, 3)]:
            raise ValueError("native free-list four-byte copy offsets differ")
        sizes = {name: max(symbols.get_symbol_by_name(name), key=lambda s: s["st_size"])["st_size"]
                 for name in ("my_slab_storage", "slab_array")}
        if sizes != {"my_slab_storage": 8000, "slab_array": 4000} or \
                symbols.get_symbol_by_name("my_slab_storage")[0]["st_value"] % 4:
            raise ValueError("original fixed-block capacity/alignment differs")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()),
            "native_free_inlined_and_loop_retained": True, "original_storage_sizes": sizes,
            "original_timestamp_reads_retained": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    for manifest in ("image.sha256", "capture.sha256", "slab-control.sha256"):
        check_manifest(directory, manifest)
    control_names = {line.split(maxsplit=1)[1] for line in (directory / "slab-control.sha256").read_text().splitlines()}
    if control_names != {"application.elf", "image.sha256", "capture.sha256", "slab-control-flow.txt", "collect-slab-control.py"}:
        raise ValueError("slab machine-path inventory incomplete")
    required = {"application.elf", "application.bin", "application.map", "bootloader.bin", "partitions.bin",
                "config", "compiler.txt", "build.log", "build-script.sh", "port.c", "original_stats.c",
                "Makefile", "symbols.txt", "disassembly.txt", *SOURCES}
    image_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}
    capture_names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not required <= image_names or not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
            *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= capture_names:
        raise ValueError("slab source/image/acquisition inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("slab source is not pinned original/native file", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {row["path"] for row in proof} != set(SOURCES) or any(
            row["url"] != SOURCES[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("original/native slab provenance differs")
    for name in ("mem_slab.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original benchmark differs from native Zephyr source")
    for file in PORT.rglob("*"):
        if file.is_file() and file.read_bytes() != (directory / file.relative_to(PORT)).read_bytes():
            raise ValueError("reviewed native slab compatibility wrapper changed")
    for name, local in (("build-script.sh", "build_esp32_zephyr_slab_riot.sh"), ("runner.sh", "run_esp32_zephyr_slab_riot.sh"),
                         ("collect-slab-control.py", "collect_esp32_zephyr_slab_control.py"), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
        if (directory / name).read_bytes() != (ROOT / "tools" / local).read_bytes():
            raise ValueError("native slab build/capture/control recipe changed")
    if "12.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native RIOT compiler changed")
    config = (directory / "config").read_text()
    for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                        ("THREAD_PRIORITY_MAIN", 10), ("MODULE_MEMARRAY", 1), ("MODULE_ZTIMER_USEC", 1)):
        if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
            raise ValueError("native fixed-pool/core/clock/tickless configuration changed")
    if "MODULE_SCHED_ROUND_ROBIN" in config:
        raise ValueError("native RIOT scheduling profile changed")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    for name in ("/app/port.c", "/app/original_stats.c", "/sys/memarray/memarray.c"):
        selected = [args for args in commands if any(not a.startswith("-") and a.endswith(name) for a in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or \
                [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320", "-DTHREAD_PRIORITY_MAIN=10"} <= set(selected[0]) or any(
                    a.startswith("-DNUMBER_OF_LOOPS") or a.startswith("-DMEM_SLAB") for a in selected[0]):
            raise ValueError("actual original/native slab compilation differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    control = machine_paths(directory)
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("slab installed image/board binding differs")
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent slab boots overlap")
    excluded = []
    for version in (1, 2):
        attempt = ROOT / "artifacts/reports" / f"zephyr-slab-riot-v{version}"
        if (attempt / "flash.log").exists() or list(attempt.glob("reset*.jsonl")):
            raise ValueError("excluded slab build acquired unreported board captures")
        if version == 1:
            if (attempt / "application.elf").exists() or "-Werror=sign-compare" not in (attempt / "build.log").read_text():
                raise ValueError("original warning-only build failure differs")
        else:
            check_manifest(attempt, "image.sha256")
        excluded.append({"cohort": attempt.name, "board_boots": 0, "build_log_sha256": digest(attempt / "build.log"),
                         "reason": "original sign/format warnings under native Werror" if version == 1 else
                         "build-only reuse of prior native objects; replaced by clean-build v3 before measurement"})
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original fixed-block subset", "os": "RIOT",
            "metric_count": 2, "resets": 3, "iterations": 1000, "block_bytes": 8, "blocks": 1000, "alignment": 4,
            "original_files": 5, "native_source_files": 2, "actual_compiled_units_checked": 3,
            "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
            "captures": captures, "machine_paths": control, "excluded_build_attempts": excluded,
            "clock_mhz": 240, "cores": 1, "compiler": "12.2.0",
            "tick_hz": None, "native_pool_concurrency_protection": False, "original_tick_phase_synchronization_preserved": False,
            "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
            "boundary": "single-caller original immediate 1000-block allocation/free and original arithmetic means; native memarray, inlined free and allocation adapter costs retained; one-second native tickless sleep, not Zephyr tick-phase synchronization; no blocking/concurrent slab claim or cross-OS rank"}


def render_table(result):
    return "\n".join(["| Original sys_kernel fixed-block subset / OS | Allocate means, ns (three boots) | Free means, ns (three boots) |",
        "| --- | --- | --- |", "| Original fixed-block port / RIOT | " + " | ".join(
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
