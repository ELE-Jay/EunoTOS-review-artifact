#!/usr/bin/env python3
"""Replay the unchanged RIOT yield program on Zephyr; builds are not scores."""
import argparse
from collections import Counter
import hashlib
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
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_rhealstone_irq_zephyr import HAL
from collect_esp32_riot_yield_zephyr_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-yield-zephyr-v3"
PORT = ROOT / "firmware/bsp/esp32/riot_yield_pingpong/zephyr"
SHARED = PORT.parent / "include"
UPSTREAM = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/"
NATIVE = ("kernel/thread.c", "kernel/sched.c", "kernel/thread_monitor.c", "kernel/init.c",
    "arch/xtensa/core/thread.c", "arch/xtensa/core/xtensa_intgen.tmpl", "include/zephyr/arch/xtensa/thread_stack.h",
    "include/zephyr/kernel/thread_stack.h", "drivers/counter/counter_esp32_tmr.c", "include/zephyr/drivers/counter.h",
    "drivers/interrupt_controller/intc_esp32.c", "drivers/timer/xtensa_sys_timer.c")
HAL_FILES = ("components/hal/timer_hal.c", "components/hal/esp32/include/hal/timer_ll.h", "components/esp_hw_support/esp_clk.c")
BEGIN = ("RIOT YIELD PORT BEGIN Zephyr original=dd06b372 duration_us=1000000 clock=240 cores=1 "
         "tick=1 priority=7 stack=3584 timer=ISR channel=2 resolution_us=1")


def symbol_data(elf, symbols, name):
    found = symbols.get_symbol_by_name(name)
    if not found or len(found) != 1:
        raise ValueError("missing/ambiguous native symbol: " + name)
    symbol = found[0]
    section = elf.get_section(symbol["st_shndx"])
    start = symbol["st_value"] - section["sh_addr"]
    return section.data()[start:start + symbol["st_size"]], symbol["st_value"]


def counter_device_control(directory, elf, symbols, control):
    header = (directory / "device-tree.h").read_text()
    ordinal = re.search(r"^#define DT_N_S_soc_S_counter_3ff60000_ORD (\d+)$", header, re.M)
    if not ordinal: raise ValueError("selected native TIMER2 ordinal missing")
    device, device_address = symbol_data(elf, symbols, "__device_dts_ord_" + ordinal[1])
    config, config_address = symbol_data(elf, symbols, "counter_config_0")
    api, api_address = symbol_data(elf, symbols, "counter_api")
    literals = [literal_word(elf, row, int(match[1])) for row in control["xtimer_set"].values()
                if (match := re.search(r"l32r\s+a(\d+),", row))]
    if len(device) != 20 or int.from_bytes(device[4:8], "little") != config_address or \
            int.from_bytes(device[8:12], "little") != api_address or device_address not in literals:
        raise ValueError("native device/config/counter-API object chain differs")
    words = [int.from_bytes(config[i:i + 4], "little") for i in range(0, len(config), 4)]
    if words != [0xffffffff, 1000000, 0x101, 0, 1, 0, 1, 0, 0, 80, 1, 0, 18]:
        raise ValueError("native TIMER2 frequency/prescaler/group/IRQ or one-shot configuration differs")
    for offset, target in ((0, "counter_esp32_start"), (4, "counter_esp32_stop"), (8, "counter_esp32_get_value"),
                           (16, "counter_esp32_set_alarm"), (20, "counter_esp32_cancel_alarm")):
        if int.from_bytes(api[offset:offset + 4], "little") != symbols.get_symbol_by_name(target)[0]["st_value"]:
            raise ValueError("native counter indirect operation table differs")


def machine(directory):
    check_manifest(directory, "yield-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "yield-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "yield-control-flow.txt", "executed-yield-control.py"} or \
            (directory / "executed-yield-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Zephyr original/native control recipe binding differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        for name in FUNCTIONS:
            if len(symbols.get_symbol_by_name(name) or []) != 1:
                raise ValueError("ambiguous native callback/controller function: " + name)
        control = read_control_rows((directory / "yield-control-flow.txt").read_text(), "RIOT YIELD CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match: continue
                value, target = int(match[1], 16), int(match[2], 16)
                delta = value >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("Zephyr native/original encoded call differs")
                calls[name, match[3]] += 1
        for caller, callee, count in (("riot_original_main", "thread_create", 1), ("riot_original_main", "xtimer_set", 1),
                ("riot_original_main", "z_impl_k_yield", 1), ("_second_thread", "z_impl_k_yield", 1),
                ("thread_create", "z_impl_k_thread_create", 1), ("z_impl_k_thread_create", "z_setup_new_thread", 1),
                ("z_setup_new_thread", "arch_new_thread", 1), ("main", "riot_original_main", 1),
                ("main", "z_impl_k_thread_abort", 1), ("main", "z_impl_k_thread_join", 1),
                ("main", "k_thread_foreach", 2), ("counter_esp32_isr", "counter_esp32_cancel_alarm", 1),
                ("counter_esp32_isr", "counter_esp32_get_value", 1), ("counter_esp32_init", "esp_intr_alloc", 1),
                ("counter_esp32_init", "timer_hal_init", 1)):
            if calls[caller, callee] != count:
                raise ValueError(("Zephyr original/native operation missing", caller, callee))
        def has_literal(name, target):
            return any(literal_word(elf, row, int(match[1])) == target for row in control[name].values()
                       if (match := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"), ("xtimer_set", "alarm_expired"),
                ("alarm_expired", "stop_callback"), ("counter_esp32_init", "counter_esp32_isr")):
            if not has_literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("Zephyr peer/original stop/counter callback binding differs")
        required = {"riot_original_main": (r"addi\.n\s+a7, a7, 1$", r"quou\s+a11, a11, a7$"),
            "thread_create": (r"movi\.n\s+a13, -16$", r"addi\.n\s+a11, a2, 15$", r"and\s+a11, a11, a13$",
                              r"and\s+a12, a12, a13$", r"sub\s+a12, a12, a11$", r"movi\s+a9, 7$"),
            "alarm_expired": (r"movi\.n\s+a10, 0$", r"callx8\s+a8$"),
            "counter_esp32_isr": (r"l32i\s+a7, a2, 16$", r"l32i\.n\s+a8, a7, 0$", r"callx8\s+a8$"),
            "xtimer_set": (r"l32i\.n\s+a8, a3, 16$", r"s32i\.n\s+a8, a1, 8$", r"s32i\.n\s+a8, a1, 12$")}
        for name, patterns in required.items():
            if any(not any(re.search(pattern, row) for row in control[name].values()) for pattern in patterns):
                raise ValueError("Zephyr original counter/alignment/ABI/relative-alarm operand differs: " + name)
        counter_device_control(directory, elf, symbols, control)
        if not has_literal("sys_clock_driver_init", 240000000) or not any(
                "13f080 wsr.ccompare0\ta8" in row for row in control["sys_clock_driver_init"].values()):
            raise ValueError("Zephyr native one-Hz CPU tick differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584:
            raise ValueError("original nominal stack changed")
        begin, end = (stack["st_value"] + 15) & ~15, (stack["st_value"] + 3584) & ~15
        if not stack["st_value"] <= begin < end <= stack["st_value"] + 3584 or end - begin < 3554:
            raise ValueError("native aligned stack escapes original storage")
        ordered = [next(a for a, row in control["main"].items() if re.search(r" <" + name + ">$", row))
                   for name in ("riot_original_main", "z_impl_k_thread_abort", "z_impl_k_thread_join")]
        if ordered != sorted(ordered): raise ValueError("Zephyr cleanup entered original window")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
            "native_counter_frequency_hz": 1000000, "native_counter_irq_source": 18, "native_hardware_tick_hz": 1,
            "original_stack_bytes": 3584, "original_stack_address": hex(stack["st_value"]),
            "aligned_peer_storage_bytes": end - begin, "aligned_peer_storage_address": hex(begin),
            "peer_alignment_inside_original_buffer": True, "original_stop_callback_via_native_abi_bridge": True,
            "native_device_operation_table_checked": True, "cleanup_after_original_return_checked": True}


def capture(directory, index, aligned_bytes):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    required = (BEGIN, "*** Booting Zephyr OS build 3.7.0 ***", "RIOT YIELD PORT END",
                f"RIOT YIELD NATIVE STACK nominal=3584 aligned={aligned_bytes}", "RIOT YIELD NATIVE TIMER irq_reserved_until_reset=1")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(line) != 1 for line in required) or \
            lines.count("main starting") != 1 or lines[-1] != "RIOT YIELD PORT END" or \
            any(re.search(r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout", line, re.I) for line in lines):
        raise ValueError("Zephyr independent original yield boot/profile/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retire = [(i, re.fullmatch(r"RIOT YIELD PORT RETIRE before=(\d+) after=(\d+)", line))
              for i, line in enumerate(lines) if line.startswith("RIOT YIELD PORT RETIRE")]
    if len(found) != 1 or len(retire) != 1 or not retire[0][1]:
        raise ValueError("Zephyr original count/retirement missing")
    i, value = found[0]
    r, match = retire[0]
    if not 1 <= value["result"] <= 0xffffffff or value["ticks"] != 240000000 // value["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < r < len(lines) - 1 or \
            int(match[1]) < 2 or match[1] != match[2] or rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Zephyr original one-second formula/retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
            "original_ticks": value["ticks"], "registry_before": int(match[1]), "registry_after": int(match[2]),
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/main.c",
               "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/README.md",
               **{"native-source/" + n: UPSTREAM + n for n in NATIVE}, "west.yml": UPSTREAM + "west.yml",
               **{"native-source/hal/" + n: "https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL + "/" + n
                  for n in HAL_FILES}}
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native Zephyr source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("Zephyr original/native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_yield_zephyr.sh")]
    if any((directory / name).read_bytes() != path.read_bytes() for name, path in files):
        raise ValueError("current Zephyr original adapter/recipe differs")
    required = set(sources) | {"application.elf", "application.bin", "config", "compiler.txt", "compile_commands.json",
        "device-tree.dts", "device-tree.h", "disassembly.txt", *(str(name) for name, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("Zephyr original/native image inventory coverage differs")
    config = (directory / "config").read_text().splitlines()
    if not {"CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_SYS_CLOCK_TICKS_PER_SEC=1", "CONFIG_MAIN_THREAD_PRIORITY=7",
            "CONFIG_MAIN_STACK_SIZE=3584", "CONFIG_INIT_STACKS=y", "CONFIG_THREAD_MONITOR=y", "CONFIG_MP_MAX_NUM_CPUS=1",
            "CONFIG_COUNTER_TMR_ESP32=y", "# CONFIG_COUNTER_TMR_RTC_ESP32 is not set", "# CONFIG_COUNTER_RTC_ESP32 is not set",
            "# CONFIG_TIMESLICING is not set", "CONFIG_SIZE_OPTIMIZATIONS=y"} <= set(config) or any(
            x in config for x in ("CONFIG_USERSPACE=y", "CONFIG_SMP=y", "CONFIG_THREAD_STACK_MEM_MAPPED=y")) or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("Zephyr native profile/selected-counter driver differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("port.c", "original.c", *(n for n in NATIVE if n.endswith(".c")), *("hal/" + n for n in HAL_FILES if n.endswith(".c")))
    for n in units:
        suffix = n.removeprefix("hal/")
        selected = [row for row in commands if row["file"].endswith("/" + suffix) and (n != "port.c" or "/app-zephyr-v3/" in row["file"])]
        if len(selected) != 1: raise ValueError("missing/duplicate Zephyr compile unit: " + n)
        args = shlex.split(selected[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_yield")) for a in args) or (n == "original.c" and "-Dmain=riot_original_main" not in args):
            raise ValueError("Zephyr actual original/native compiler/window override differs")
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    failed = directory.with_name("riot-yield-zephyr-v1")
    check_manifest(failed, "failed-build.sha256")
    if "'_IONBF' undeclared" not in (failed / "build.log").read_text() or (failed / "application.bin").exists() or any(failed.glob("reset*")):
        raise ValueError("failed initial Zephyr compile promoted to a board result")
    diagnostic = directory.with_name("riot-yield-zephyr-v2")
    check_manifest(diagnostic, "image.sha256")
    if "CONFIG_COUNTER_TMR_RTC_ESP32=y" not in (diagnostic / "config").read_text() or any(diagnostic.glob("reset*")) or (diagnostic / "flash.log").exists():
        raise ValueError("unused-counter diagnostic promoted to a measured result")
    captures = []
    if full:
        check_manifest(directory, "capture.sha256")
        expected_capture = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
            "flash.log", "board-check.log", "image-check.log", "runner.sh", "capture_esp32_uart.py", "image.sha256",
            "yield-control.sha256", "official-source.json"}
        if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected_capture:
            raise ValueError("Zephyr original capture inventory coverage differs")
        audit_flash(directory, "flash.log", 1)
        for archive, source in (("runner.sh", "run_esp32_riot_yield_zephyr.sh"), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
            if (directory / archive).read_bytes() != (ROOT / "tools" / source).read_bytes():
                raise ValueError("Zephyr original runner/raw recorder binding differs")
        captures = [capture(directory, i, control["aligned_peer_storage_bytes"]) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("Zephyr original yield boots overlap")
    elif (directory / "capture.sha256").exists() or list(directory.glob("reset*.jsonl")):
        raise ValueError("Zephyr build-only replay cannot ignore board captures")
    return {"benchmark": "RIOT thread_yield_pingpong original program / native Zephyr adapter", "os": "Zephyr",
            "built": True, "measured": full, "measurement_eligible": full, "board_boots": len(captures), "ranking_eligible": False,
            "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
            "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
            "native_equal_worker_priority": 7, "official_native_files_checked": len(NATIVE) + len(HAL_FILES),
            "actual_compiled_units_checked": len(units), "machine_control": control, "captures": captures,
            "energy_measured": False, "runtime_ram_peak_measured": False, "application_elf_sha256": digest(directory / "application.elf"),
            "application_bin_sha256": digest(directory / "application.bin"), "excluded_compile_failure_board_boots": 0,
            "excluded_unused_rtc_driver_diagnostic_board_boots": 0,
            "prepared_capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_yield_zephyr.sh"),
            "boundary": "Original nominal one-second yield count/ticks formula, not isolated latency. Equal native preemptive priorities; "
                "selected TIMER2/1-MHz relative hardware alarm and explicit four-argument ABI bridge; no software tick timer. "
                "Kernel-only aligned slice of original3584B byte buffer, INIT_STACKS/monitor, native TLS and TCB ownership retained. "
                "Driver allocation failure is not returned by native init; actual IRQ/correctness needs real captures. "
                "Counter is stopped after original return but IRQ/device reservation persists until reset. No general heap cleanup, RAM/energy or rank from a build."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output: args.output.write_text(text)
    else: print(text, end="")
