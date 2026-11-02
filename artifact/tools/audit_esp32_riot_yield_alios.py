#!/usr/bin/env python3
"""Audit the unchanged RIOT yield program on Rhino; cross-builds are not scores."""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT, audit_flash
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_zephyr_isr import irq_archive_member, rhino_vector_dispatch
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_syskernel_sema_alios import elf_bytes
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from collect_esp32_riot_yield_alios_control import FUNCTIONS, NORETURN, INDIRECT_ADDRESS, INDIRECT_TARGETS, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-yield-alios-v2"
PORT = ROOT / "firmware/bsp/esp32/riot_yield_pingpong/alios"
SHARED = PORT.parent / "include"
NATIVE = ("kernel/rhino/k_task.c", "kernel/rhino/k_sched.c", "kernel/rhino/k_tick.c", "kernel/rhino/k_sys.c",
    "kernel/rhino/k_obj.c", "platform/mcu/esp32/aos/hook_impl.c", "kernel/rhino/include/k_task.h", "kernel/rhino/include/k_sched.h",
    "platform/arch/xtensa/lx6/xtensa_init.c", "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h",
    "platform/mcu/esp32/espos/platform/rhino/espos_scheduler.c",
    "platform/mcu/esp32/bsp/include/driver/include/driver/timer.h",
    "platform/mcu/esp32/bsp/include/soc/esp32/include/soc/timer_group_struct.h",
    "platform/mcu/esp32/bsp/include/soc/esp32/include/soc/timer_group_reg.h")
LIBRARIES = ("libdriver.a", "libesp32.a", "libsoc.a")
BEGIN = ("RIOT YIELD PORT BEGIN AliOS-Rhino original=dd06b372 duration_us=1000000 clock=240 cores=1 "
         "tick=1 priority=10 stack=3584 timer=ISR channel=2 resolution_us=1")


def machine(directory):
    check_manifest(directory, "yield-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "yield-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "yield-control-flow.txt", "executed-yield-control.py"} or \
            (directory / "executed-yield-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Rhino original/native control recipe binding differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        literal = elf_bytes(elf, 0x4008089c, 4)
        table = int.from_bytes(literal, "little")
        targets = tuple(int.from_bytes(elf_bytes(elf, table + 4 * i, 4), "little") for i in range(6))
        if targets != INDIRECT_TARGETS:
            raise ValueError("native deletion jump table differs")
        control = read_control_rows((directory / "yield-control-flow.txt").read_text(), "RIOT YIELD CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=NORETURN,
            indirect_targets={("krhino_task_del", INDIRECT_ADDRESS): set(targets)})
        if literal_word(elf, control["krhino_task_del"][0x40085324], 8) != table:
            raise ValueError("native deletion dispatch table pointer differs")
        for name, rows in control.items():
            for address, row in rows.items():
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m: continue
                value, target = int(m[1], 16), int(m[2], 16)
                delta = value >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(m[3]) or []):
                    raise ValueError("Rhino native/original encoded call differs")
                calls[name, m[3]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "xtimer_set", 1),
            ("riot_original_main", "krhino_task_yield", 1), ("_second_thread", "krhino_task_yield", 1),
            ("thread_create", "krhino_task_create", 1), ("krhino_task_create", "task_create$part$0", 1),
            ("task_create$part$0", "cpu_task_stack_init", 1), ("krhino_task_yield", "ready_list_head_to_tail", 1),
            ("controller_entry", "riot_original_main", 1), ("controller_entry", "krhino_task_del", 1),
            ("controller_entry", "esp_intr_free", 1), ("controller_entry", "registry_count", 2),
            ("xtimer_set", "timer_init", 1), ("xtimer_set", "timer_set_counter_value", 1),
            ("xtimer_set", "timer_set_alarm_value", 1), ("xtimer_set", "timer_isr_register", 1),
            ("xtimer_set", "timer_enable_intr", 1), ("xtimer_set", "timer_start", 1),
            ("timer_isr_register", "esp_intr_alloc_intrstatus", 1),
            ("espos_isr_enter", "krhino_intrpt_enter", 1), ("espos_isr_exit", "krhino_intrpt_exit", 1))
        if any(calls[a, b] != n for a, b, n in expected):
            raise ValueError("Rhino original/native operation missing")
        def has_literal(name, target):
            return any(literal_word(elf, row, int(m[1])) == target for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"), ("xtimer_set", "alarm_expired"),
                ("alarm_expired", "stop_callback")):
            if not has_literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("Rhino original peer/stop/native callback binding differs")
        patterns = {"riot_original_main": (r"addi\.n\s+a\d+, a\d+, 1$", r"quou\s+"),
            "thread_create": (r"movi\.n\s+a9, -16$", r"addi\.n\s+a3, a8, 15$", r"and\s+a3, a3, a9$",
                              r"and\s+a8, a8, a9$", r"sub\s+a8, a8, a3$", r"srli\s+a8, a8, 2$"),
            "alarm_expired": (r"callx8\s+a8$", r"movi\.n\s+a10, 0$")}
        for name, required in patterns.items():
            if any(not any(re.search(p, row) for row in control[name].values()) for p in required):
                raise ValueError("original loop/formula/ABI/bounded stack operand differs: " + name)
        configuration = literal_word(elf, control["xtimer_set"][0x400d615f], 11)
        if elf_bytes(elf, configuration, 20) != b"".join(n.to_bytes(4, "little") for n in (1, 0, 1, 0, 80)) or \
                not all(has_literal("xtimer_set", n) for n in (80000000, 1000000, (-1000000) & 0xffffffff, 0x3ff60000)) or \
                literal_word(elf, control["timer_isr_register"][0x400d3cd6], 12) != 0x3ff600a0 or \
                "2e0c movi.n\ta14, 2" not in "\n".join(control["xtimer_set"].values()) or \
                "12c382 addi\ta8, a3, 18" not in "\n".join(control["timer_isr_register"].values()):
            raise ValueError("native TIMER2 APB/prescaler/one-shot/level1/status/source configuration differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584:
            raise ValueError("original nominal stack changed")
        begin, end = (stack["st_value"] + 15) & ~15, (stack["st_value"] + 3584) & ~15
        if not stack["st_value"] <= begin < end <= stack["st_value"] + 3584 or end - begin < 3554:
            raise ValueError("native peer alignment escapes original buffer")
        ordered = [next(a for a, row in control["controller_entry"].items() if re.search(r" <" + name + r">$", row))
                   for name in ("riot_original_main", "timer_get_counter_value", "esp_intr_free", "krhino_task_del")]
        if ordered != sorted(ordered): raise ValueError("Rhino retirement entered original window")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
        "native_deletion_jump_table_targets": list(targets), "original_stack_bytes": 3584,
        "original_stack_address": hex(stack["st_value"]), "aligned_peer_storage_bytes": end - begin,
        "peer_alignment_inside_original_buffer": True, "native_equal_priority_yield_checked": True,
        "native_counter_frequency_hz": 1000000, "native_counter_irq_source": 18,
        "native_counter_configuration_checked": True,
        "original_stop_callback_via_native_abi_bridge": True, "cleanup_after_original_return_checked": True}


def capture(directory, index, aligned_bytes):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    required = (BEGIN, "Welcome to AliOS Things", "load image", "RIOT YIELD PORT END",
                f"RIOT YIELD NATIVE STACK nominal=3584 aligned={aligned_bytes}")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(line) != 1 for line in required) or \
            lines.count("main starting") != 1 or lines[-1] != "RIOT YIELD PORT END" or \
            any(re.search(r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", line, re.I) for line in lines):
        raise ValueError("Rhino independent original yield boot/profile/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retire = [(i, re.fullmatch(r"RIOT YIELD PORT RETIRE before=(\d+) after=(\d+)", line))
              for i, line in enumerate(lines) if line.startswith("RIOT YIELD PORT RETIRE")]
    timer = [(i, re.fullmatch(r"RIOT YIELD NATIVE TIMER counter_us=(\d+) alarm_count=1 irq_released=1", line))
             for i, line in enumerate(lines) if line.startswith("RIOT YIELD NATIVE TIMER")]
    if len(found) != 1 or len(retire) != 1 or not retire[0][1] or len(timer) != 1 or not timer[0][1]:
        raise ValueError("Rhino original count/retirement/timer missing")
    i, value = found[0]
    r, match = retire[0]
    if not 1 <= value["result"] <= 0xffffffff or value["ticks"] != 240000000 // value["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < timer[0][0] < r < len(lines) - 1 or \
            int(timer[0][1][1]) < 1000000 or int(match[1]) < 2 or match[1] != match[2] or \
            rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Rhino original one-second formula/native timer/retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "registry_before": int(match[1]), "registry_after": int(match[2]),
        "native_counter_us": int(timer[0][1][1]), "uart_sha256": digest(directory / f"reset{index}.jsonl"),
        "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "archive-recovery.sha256")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/README.md",
        **{"native-source/" + n: UPSTREAM + n for n in NATIVE},
        "rhino-portasm-pinned.S": UPSTREAM + "platform/arch/xtensa/lx6/portasm.S",
        **{"native-libraries/" + n: UPSTREAM + "platform/mcu/esp32/lib/" + n for n in LIBRARIES}}
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native Rhino source/archive differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("Rhino original/native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_yield_alios.sh")]
    if any((directory / name).read_bytes() != path.read_bytes() for name, path in files):
        raise ValueError("current Rhino original adapter/recipe differs")
    board = ROOT / "firmware/bsp/esp32/alios_board"
    for saved, source in (("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"),
                          ("sdkconfig.h", "esp32bench/sdkconfig.h"), ("k_config.h", "esp32bench/k_config.h")):
        if (directory / saved).read_bytes() != (board / source).read_bytes():
            raise ValueError("Rhino native board/IRQ/configuration adapter differs")
    required = set(sources) | {"application.elf", "application.bin", "application.map", "config", "compiler.txt",
        "bootloader.bin", "partitions.bin", "link.opts", "build.log", "disassembly.txt", *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("Rhino original/native image inventory coverage differs")
    config = set((directory / "config").read_text().splitlines())
    if not {'AOS_BUILD_APP="riot_yield"', 'AOS_BUILD_BOARD="esp32bench"', 'AOS_APP_RIOT_YIELD=y'} <= config or \
            "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("Rhino native app/target/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    units = ("app/example/riot_yield/port.c", "app/example/riot_yield/original.c",
        *(n for n in NATIVE if n.endswith(".c")), "platform/arch/xtensa/lx6/port.c",
        "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for n in units:
        selected = [args for args in commands if n in args]
        if len(selected) != 1 or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_yield")) for a in selected[0]) or \
                (not n.endswith(".S") and [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"]) or \
                (n.endswith("original.c") and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("Rhino actual original/native compile/window override differs: " + n)
    control = machine(directory)
    divisors = hardware_tick_divisors(directory)
    vector = rhino_vector_dispatch(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    map_text, link = (directory / "application.map").read_text(), (directory / "link.opts").read_text()
    for library, member, names in (("libdriver.a", "timer.o", tuple(n for n in FUNCTIONS if n.startswith("timer_"))),
                                  ("libesp32.a", "intr_alloc.o", ("esp_intr_alloc_intrstatus", "esp_intr_free"))):
        if "platform/mcu/esp32/lib/" + library not in link:
            raise ValueError("native SDK library not linked")
        member_data = irq_archive_member(directory / "native-libraries" / library, member.encode())
        with io.BytesIO(member_data) as stream:
            native = ELFFile(stream)
            for name in names:
                source = native.get_section_by_name(".text." + name)
                if source is None or not re.search(r"\.text\." + name + r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*" +
                        re.escape(library + "(" + member + ")"), map_text):
                    raise ValueError("native SDK member/function linkage differs: " + name)
    failed = directory.with_name("riot-yield-alios-v1")
    check_manifest(failed, "failed-build.sha256")
    if "error: expected ')' before 'PRIu32'" not in (failed / "build.log").read_text() or \
            "has no member named 'int_ena_timers'" not in (failed / "build.log").read_text() or \
            (failed / "application.bin").exists() or any(failed.glob("reset*")):
        raise ValueError("failed initial Rhino compile promoted to a board result")
    captures = []
    if full:
        check_manifest(directory, "capture.sha256")
        expected = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
            "flash.log", "board-check.log", "image-check.log", "runner.sh", "capture_esp32_uart.py", "image.sha256",
            "yield-control.sha256", "official-source.json"}
        if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected:
            raise ValueError("Rhino original capture inventory coverage differs")
        audit_flash(directory, "flash.log", 3)
        for saved, source in (("runner.sh", "run_esp32_riot_yield_alios.sh"), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
            if (directory / saved).read_bytes() != (ROOT / "tools" / source).read_bytes():
                raise ValueError("Rhino original runner/raw recorder binding differs")
        captures = [capture(directory, i, control["aligned_peer_storage_bytes"]) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("Rhino original yield boots overlap")
    elif (directory / "capture.sha256").exists() or list(directory.glob("reset*.jsonl")):
        raise ValueError("Rhino build-only replay cannot ignore board captures")
    return {"benchmark": "RIOT thread_yield_pingpong original program / native Rhino adapter", "os": "AliOS-Rhino",
        "built": True, "measured": full, "measurement_eligible": full, "board_boots": len(captures), "ranking_eligible": False,
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 5.2.0", "optimization": "Os",
        "native_equal_worker_priority": 10, "official_native_files_checked": len(NATIVE) + 1,
        "official_sdk_archives_checked": len(LIBRARIES), "actual_compiled_units_checked": len(units), "machine_control": control,
        "native_hardware_tick_divisors": divisors, "native_irq_vector_dispatch": vector, "captures": captures,
        "energy_measured": False, "runtime_ram_peak_measured": False,
        "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
        "excluded_compile_failure_board_boots": 0,
        "boundary": "unchanged original one-second RIOT count/ticks formula, not isolated yield latency; native equal-priority FIFO tasks, static original peer buffer with in-buffer alignment and native zero coloring/guard/frame, native group1/timer0 APB one-shot and level1 ABI bridge; SDK drivers are pinned official precompiled archives, not rebuilt from source; controller/IRQ checks and cleanup outside original window; existing background/timer tasks remain; registry/IRQ retirement does not prove full heap or peripheral reclamation; GCC5/1-Hz differs from other cohorts, no cross-OS rank or new-image RAM/energy result"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.directory, args.verify_upstream, args.full)
    text = json.dumps(result, indent=2) + "\n"
    if args.output: args.output.write_text(text)
    else: print(text, end="")


if __name__ == "__main__":
    main()
