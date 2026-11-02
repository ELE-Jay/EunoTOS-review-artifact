#!/usr/bin/env python3
"""Audit the unchanged RIOT yield program on FreeRTOS; builds are not scores."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_flash
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_riot_yield_freertos_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-yield-freertos-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_yield_pingpong"
REFERENCE = ROOT / "artifacts/reports/zephyr-yield-freertos-v1"
IDF_UPSTREAM = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/"
NATIVE = tuple("components/freertos/" + name for name in (
    "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/list.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
    "FreeRTOS-Kernel/portable/xtensa/portasm.S", "FreeRTOS-Kernel/portable/xtensa/include/freertos/portmacro.h",
    "esp_additions/freertos_tasks_c_additions.h")) + (
    "components/esp_timer/src/esp_timer.c", "components/esp_timer/src/esp_timer_impl_lac.c",
    "components/esp_timer/src/esp_timer_impl_common.c", "components/esp_timer/include/esp_timer.h")
BEGIN = ("RIOT YIELD PORT BEGIN FreeRTOS original=dd06b372 duration_us=1000000 "
         "clock=240 cores=1 tick=1 priority=14 stack=3584 timer=ISR")


def native_assembler_control(elf, symbols, disassembly, names=("vPortYield", "_frxt_dispatch")):
    control = {}
    for name in names:
        symbol = symbols.get_symbol_by_name(name)[0]
        match = re.search(r"^" + format(symbol["st_value"], "x") + " <" + name + r">:\n(.*?)(?=\n\n|\Z)",
                          disassembly, re.M | re.S)
        if not match or symbol["st_size"] != 0:
            raise ValueError("native assembler entry missing")
        rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", match[1], re.M)
        section = elf.get_section(symbol["st_shndx"])
        position = symbol["st_value"]
        next_entry = min(s["st_value"] for s in symbols.iter_symbols()
                         if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == symbol["st_shndx"]
                         and s["st_value"] > position)
        body = {}
        for address, encoding, instruction in rows:
            address = int(address, 16)
            raw = bytes.fromhex(encoding)[::-1]
            offset = address - section["sh_addr"]
            if address != position or address + len(raw) > next_entry or section.data()[offset:offset + len(raw)] != raw:
                raise ValueError("native assembler bytes/bounds differ")
            body[address] = f"{address:x}: {encoding} {instruction}"
            position += len(raw)
        if not body:
            raise ValueError("empty native assembler body")
        control[name] = body
    return control


def machine(directory):
    check_manifest(directory, "yield-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "yield-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "yield-control-flow.txt", "executed-yield-control.py"}:
        raise ValueError("yield machine manifest coverage differs")
    recipe = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text())
    if (directory / "executed-yield-control.py").read_text() != recipe:
        raise ValueError("yield control recipe differs")
    calls = Counter()
    disassembly = (directory / "disassembly.txt").read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "yield-control-flow.txt").read_text(), "RIOT YIELD CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=("fail", "abort"))
        # These assembler entries intentionally have zero-sized ELF symbols.
        control.update(native_assembler_control(elf, symbols, disassembly))
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call(0|4|8)\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                value, window, target = int(match[1], 16), int(match[2]), int(match[3], 16)
                delta = value >> 6
                if delta & (1 << 17):
                    delta -= 1 << 18
                if value & 0x3f != 0x05 + window * 4 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(match[4]) or []):
                    raise ValueError("original/native encoded call target differs")
                calls[name, match[4]] += 1
        for caller, callee, count in (("riot_original_main", "thread_create", 1),
                ("riot_original_main", "xtimer_set", 1), ("riot_original_main", "vPortYield", 1),
                ("_second_thread", "vPortYield", 1), ("vPortYield", "_frxt_dispatch", 1),
                ("_frxt_dispatch", "vTaskSwitchContext", 1),
                ("thread_create", "xTaskCreateStaticPinnedToCore", 1),
                ("xtimer_set", "esp_timer_create", 1), ("xtimer_set", "esp_timer_start_once", 1),
                ("timer_alarm_handler", "timer_process_alarm", 1), ("app_main", "riot_original_main", 1),
                ("app_main", "vTaskDelete", 1), ("app_main", "esp_timer_delete", 1)):
            if calls[caller, callee] != count:
                raise ValueError(("original/native call missing", caller, callee))
        def has_literal(name, target):
            return any(literal_word(elf, row, int(match[1])) == target for row in control[name].values()
                       if (match := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                               ("thread_create", "peer_entry"), ("_timer_callback", "_flag")):
            if not has_literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("original peer/stop callback or flag binding differs")
        for name, patterns in (("riot_original_main", (r"addi\.n\s+a7, a7, 1$", r"quou\s+a11, a11, a7$")),
                ("xtimer_set", (r"movi\.n\s+a10, 1$", r"s32i\.n\s+a10, a1, 8$",
                                r"s32i\.n\s+a9, a1, 0$", r"s32i\.n\s+a8, a1, 4$")),
                ("timer_process_alarm", (r"l32i\.n\s+a6, a7, 16$", r"l32i\.n\s+a7, a7, 20$", r"callx8\s+a6$")),
                ("timer_alarm_handler", (r"movi\.n\s+a10, 1$",))):
            if any(not any(re.search(pattern, row) for row in control[name].values()) for pattern in patterns):
                raise ValueError("original counter/formula or direct ISR dispatch operand differs: " + name)
        start = symbols.get_symbol_by_name("_stack")[0]
        if start["st_size"] != 3584:
            raise ValueError("original nominal peer stack changed")
        ordered = [next(a for a, row in control["app_main"].items() if re.search(r" <" + n + ">$", row))
                   for n in ("riot_original_main", "vTaskDelete", "esp_timer_delete")]
        if ordered != sorted(ordered):
            raise ValueError("cleanup entered original window")
    return {"reachable_c_functions_checked": len(FUNCTIONS), "native_assembler_bodies_checked": 2,
            "encoded_direct_calls_checked": sum(calls.values()), "original_peer_stack_bytes": 3584,
            "original_peer_stack_address": hex(start["st_value"]), "direct_isr_callback_binding_checked": True,
            "original_count_increment_and_division_checked": True, "cleanup_after_original_return_checked": True}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]) for row in rows]
    if sum("Project name:     riot_yield_pingpong_port" in line for line in lines) != 1 or sum(
            "ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "..." in line for line in lines) != 1:
        raise ValueError("original yield boot is not bound to the built firmware")
    if sum("rst:0x" in line for line in lines) != 1 or lines.count(BEGIN) != 1 or \
            lines.count("main starting") != 1 or lines.count("RIOT YIELD PORT END") != 1 or \
            lines[-1] != "RIOT YIELD PORT END" or any(re.search(
                r"RIOT YIELD PORT FAIL|Guru Meditation|panic|assert failed|Exception", line, re.I) for line in lines):
        raise ValueError("incomplete or failed independent original yield boot")
    results = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retired = [(i, re.fullmatch(r"RIOT YIELD PORT RETIRE before=(\d+) after=(\d+)", line))
               for i, line in enumerate(lines) if line.startswith("RIOT YIELD PORT RETIRE")]
    if len(results) != 1 or len(retired) != 1 or not retired[0][1]:
        raise ValueError("missing original result or native retirement")
    i, result = results[0]
    r, match = retired[0]
    if type(result["result"]) is not int or result["result"] <= 0 or result["ticks"] != 240000000 // result["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < r < len(lines) - 1 or \
            match[1] != match[2] or int(match[1]) < 2 or rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("original one-second count/formula/retirement mismatch")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
            "original_count": result["result"], "original_ticks": result["ticks"],
            "registry_before": int(match[1]), "registry_after": int(match[2]),
            "uart_sha256": digest(directory / f"reset{index}.jsonl"),
            "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    expected = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/main.c",
                "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/README.md"}
    expected.update({"native-source/" + n: IDF_UPSTREAM + n for n in NATIVE})
    required = set(expected) | {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config",
        "reference-config", "FreeRTOSConfig.h", "compile_commands.json", "compiler.txt", "disassembly.txt", "build-script.sh",
        "port.c", "CMakeLists.txt", "main/CMakeLists.txt", *(p.relative_to(PORT).as_posix()
                                                           for p in (PORT / "include").rglob("*.h"))}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./")
                        for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native image inventory coverage differs")
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(expected.items())]
    if verify_upstream:
        import hashlib
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("original/native source differs from fixed upstream: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("fixed original/native source proof differs")
    for relative in ("port.c", "CMakeLists.txt", "main/CMakeLists.txt", *(p.relative_to(PORT).as_posix()
                          for p in (PORT / "include").rglob("*.h"))):
        if (directory / relative).read_bytes() != (PORT / relative).read_bytes():
            raise ValueError("audited adapter differs from current owned source")
    if (directory / "build-script.sh").read_bytes() != (ROOT / "tools/build_esp32_riot_yield_freertos.sh").read_bytes() or \
            (directory / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (REFERENCE / "FreeRTOSConfig.h").read_bytes():
        raise ValueError("build recipe or pinned native profile differs")
    def config(path):
        return dict(re.findall(r"^(CONFIG_\w+)=(.*)$", path.read_text(), re.M))
    baseline, actual = config(directory / "reference-config"), config(directory / "config")
    if {k: (baseline.get(k), actual.get(k)) for k in baseline.keys() | actual.keys()
            if baseline.get(k) != actual.get(k)} != {"CONFIG_ESP_TIMER_SUPPORTS_ISR_DISPATCH_METHOD": (None, "y")}:
        raise ValueError("native execution profile changed beyond ISR dispatch")
    if actual.get("CONFIG_FREERTOS_HZ") != "1" or actual.get("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ") != "240" or \
            actual.get("CONFIG_FREERTOS_UNICORE") != "y" or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("clock/core/tick/compiler profile differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("original.c", "riot-yield-pingpong/app-freertos-v1/port.c", *(n for n in NATIVE if n.endswith((".c", ".S"))))
    for unit in units:
        suffix = unit.removeprefix("components/freertos/")
        matches = [row for row in commands if row["file"].endswith("/" + suffix)]
        if len(matches) != 1:
            raise ValueError("missing/duplicate actual compile unit: " + unit)
        args = shlex.split(matches[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or "-c" not in args or \
                [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_yield")) for a in args) or \
                (unit == "original.c" and "-Dmain=riot_original_main" not in args):
            raise ValueError("original/native compiler/options/window override differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    control = machine(directory)
    captures = []
    if full:
        check_manifest(directory, "capture.sha256")
        expected_capture = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
            "flash.log", "board-check.log", "image-check.log", "runner.sh", "capture_esp32_uart.py", "image.sha256",
            "yield-control.sha256", "official-source.json"}
        if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected_capture:
            raise ValueError("independent yield capture manifest coverage differs")
        audit_flash(directory, "flash.log", 3)
        if (directory / "runner.sh").read_bytes() != (ROOT / "tools/run_esp32_riot_yield_freertos.sh").read_bytes() or \
                (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes():
            raise ValueError("board runner or raw UART recorder differs")
        captures = [capture(directory, index) for index in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("independent original boots overlap")
    elif (directory / "capture.sha256").exists() or list(directory.glob("reset*.jsonl")):
        raise ValueError("build-only audit cannot silently ignore board captures")
    return {"benchmark": "RIOT thread_yield_pingpong original program / native FreeRTOS adapter",
            "os": "FreeRTOS", "built": True, "measured": full, "board_boots": len(captures),
            "measurement_eligible": full, "ranking_eligible": False, "new_metric_created": False,
            "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
            "official_native_files_checked": len(NATIVE), "actual_compiled_units_checked": len(units),
            "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
            "native_equal_worker_priority": 14, "timeslicing": False, "stop_callback_dispatch": "native hardware timer ISR",
            "machine_control": control, "captures": captures, "energy_measured": False,
            "runtime_ram_peak_measured": False, "application_elf_sha256": digest(directory / "application.elf"),
            "application_bin_sha256": digest(directory / "application.bin"),
            "prepared_capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_yield_freertos.sh"),
            "prepared_raw_uart_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"),
            "boundary": "Original main-thread yield count and nominal ticks/count, not isolated latency. "
                "RIOT GCC12/tickless versus SDK GCC13/1-Hz; native TCB, stack ownership, code placement, "
                "timer dispatch and background differ. IRQ deadline precision requires real captures; no rank. "
                "Post-window timer deletion is deferred by the SDK; no whole-heap retirement claim."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
