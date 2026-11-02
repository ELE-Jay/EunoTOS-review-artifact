#!/usr/bin/env python3
"""Audit an unchanged RIOT flags program on native Zephyr; builds are not scores."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_report import ROOT
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_riot_yield_zephyr import NATIVE as YIELD_NATIVE, HAL_FILES, UPSTREAM, HAL, symbol_data, counter_device_control
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_riot_flags_alios import capture_envelope
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_syskernel_sema_alios import elf_bytes
from collect_esp32_riot_flags_zephyr_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-flags-zephyr-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_thread_flags_pingpong/zephyr"
SHARED = PORT.parent.parent / "riot_yield_pingpong/include"
NATIVE = YIELD_NATIVE + ("kernel/events.c", "include/zephyr/kernel.h", "include/zephyr/kernel/thread.h",
                        "kernel/include/wait_q.h", "kernel/include/ksched.h")
BEGIN = ("RIOT FLAGS PORT BEGIN Zephyr original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
         "controller=7 peer=6 stack=3584 timer=ISR channel=2 resolution_us=1 flags=16 object=native-event")


def machine(directory):
    check_manifest(directory, "flags-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "flags-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "flags-control-flow.txt", "executed-flags-control.py"} or \
            (directory / "executed-flags-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Zephyr flags native-control recipe differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(len(symbols.get_symbol_by_name(n) or []) != 1 for n in FUNCTIONS):
            raise ValueError("ambiguous native event/controller/counter function")
        control = read_control_rows((directory / "flags-control-flow.txt").read_text(), "RIOT FLAGS CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        for name, rows in control.items():
            for address, row in rows.items():
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m: continue
                value, target = int(m[1], 16), int(m[2], 16)
                delta = value >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(m[3]) or []):
                    raise ValueError("native/original encoded call differs")
                calls[name, m[3]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "thread_get", 1),
            ("riot_original_main", "thread_flags_set", 1), ("riot_original_main", "xtimer_set", 1),
            ("_second_thread", "thread_flags_wait_any", 1), ("thread_create", "z_impl_k_event_init", 1),
            ("thread_create", "z_impl_k_thread_create", 1), ("z_impl_k_thread_create", "z_setup_new_thread", 1),
            ("z_setup_new_thread", "arch_new_thread", 1), ("thread_flags_set", "z_impl_k_event_post", 1),
            ("thread_flags_wait_any", "z_impl_k_event_wait", 1), ("thread_flags_wait_any", "z_impl_k_event_clear", 1),
            ("z_impl_k_event_post", "k_event_post_internal", 1), ("z_impl_k_event_clear", "k_event_post_internal", 1),
            ("z_impl_k_event_wait", "k_event_wait_internal", 1), ("k_event_post_internal", "z_sched_waitq_walk", 1),
            ("k_event_post_internal", "z_sched_wake_thread", 1), ("k_event_post_internal", "z_reschedule", 1),
            ("k_event_wait_internal", "z_pend_curr", 1), ("main", "riot_original_main", 1),
            ("main", "k_thread_state_str", 1), ("main", "z_impl_k_thread_abort", 1),
            ("main", "z_impl_k_thread_join", 1), ("main", "k_thread_foreach", 2),
            ("counter_esp32_isr", "counter_esp32_cancel_alarm", 1), ("counter_esp32_isr", "counter_esp32_get_value", 1),
            ("counter_esp32_init", "esp_intr_alloc", 1), ("counter_esp32_init", "timer_hal_init", 1))
        if any(calls[a, b] != n for a, b, n in expected): raise ValueError("native original event operation missing")
        def literal(name, target):
            return any(literal_word(elf, row, int(m[1])) == target for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"), ("thread_create", "peer_flags"),
                ("thread_flags_set", "peer_flags"), ("thread_flags_wait_any", "peer_flags"),
                ("k_event_post_internal", "event_walk_op"), ("xtimer_set", "alarm_expired"),
                ("alarm_expired", "stop_callback"), ("counter_esp32_init", "counter_esp32_isr")):
            if not literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("native object/peer/event/counter callback differs")
        patterns = {
            "riot_original_main": (r"addi\.n\s+a7, a7, 1$", r"quou\s+a11, a11, a7$"),
            "thread_create": (r"movi\.n\s+a12, -16$", r"addi\.n\s+a6, a2, 15$", r"and\s+a6, a6, a12$",
                              r"and\s+a8, a8, a12$", r"sub\s+a8, a8, a6$", r"movi\.n\s+a8, 6$"),
            "thread_flags_set": (r"movi\s+a11, 1$",),
            "thread_flags_wait_any": (r"movi\.n\s+a12, 0$", r"movi\.n\s+a14, -1$", r"movi\.n\s+a15, -1$",
                                      r"mov\.n\s+a11, a2$", r"extui\s+a2, a10, 0, 16$", r"extui\s+a8, a8, 16, 16$"),
            "_second_thread": (r"movi\.n\s+a10, -1$", r"extui\s+a10, a10, 16, 16$"),
            "z_impl_k_event_post": (r"mov\.n\s+a12, a3$",),
            "z_impl_k_event_clear": (r"mov\.n\s+a12, a3$", r"movi\.n\s+a11, 0$"),
            "z_impl_k_event_wait": (r"add\.n\s+a12, a12, a12$",),
            "k_event_post_internal": (r"xor\s+a3, a6, a3$", r"and\s+a4, a3, a4$", r"xor\s+a6, a6, a4$",
                                      r"s32i\.n\s+a6, a5, 8$"),
            "k_event_wait_internal": (r"and\s+a9, a8, a2$", r"extui\s+a12, a4, 0, 1$", r"s32i\s+a2, a3, 68$"),
            "alarm_expired": (r"movi\.n\s+a10, 0$", r"callx8\s+a8$"),
            "counter_esp32_isr": (r"l32i\s+a7, a2, 16$", r"l32i\.n\s+a8, a7, 0$", r"callx8\s+a8$"),
            "xtimer_set": (r"l32i\.n\s+a8, a3, 16$", r"s32i\.n\s+a8, a1, 8$", r"s32i\.n\s+a8, a1, 12$")}
        for name, required in patterns.items():
            if any(not any(re.search(p, row) for row in control[name].values()) for p in required):
                raise ValueError("native flags/stack/ABI/relative-alarm operand differs: " + name)
        def ordered(name, targets):
            return [next(a for a, row in control[name].items() if re.search(r" <" + re.escape(t) + r">$", row)) for t in targets]
        for name, targets in (("thread_create", ("z_impl_k_event_init", "z_impl_k_thread_create")),
                ("thread_flags_wait_any", ("z_impl_k_event_wait", "z_impl_k_event_clear")),
                ("main", ("riot_original_main", "k_thread_state_str", "z_impl_k_thread_abort", "z_impl_k_thread_join"))):
            positions = ordered(name, targets)
            if positions != sorted(positions): raise ValueError("native initialize/wait-clear/retirement order differs")
        state, _ = symbol_data(elf, symbols, "state_string$0")
        pointer, length = int.from_bytes(state[8:12], "little"), int.from_bytes(state[12:16], "little")
        if len(state) != 64 or length != 7 or elf_bytes(elf, pointer, 8) != b"pending\0":
            raise ValueError("native pending-state table differs")
        counter_device_control(directory, elf, symbols, control)
        if not literal("sys_clock_driver_init", 240000000) or not any(
                "13f080 wsr.ccompare0\ta8" in row for row in control["sys_clock_driver_init"].values()):
            raise ValueError("native one-Hz CPU tick differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584: raise ValueError("original nominal stack changed")
        begin, end = (stack["st_value"] + 15) & ~15, (stack["st_value"] + 3584) & ~15
        if not stack["st_value"] <= begin < end <= stack["st_value"] + 3584 or end - begin < 3554:
            raise ValueError("native aligned stack escapes original storage")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
        "native_or_post_any_wait_no_reset_then_atomic_clear_checked": True,
        "native_wait_wake_reschedule_calls_checked": True, "original_stack_bytes": 3584,
        "original_stack_address": hex(stack["st_value"]), "aligned_peer_storage_bytes": end - begin,
        "native_counter_frequency_hz": 1000000, "native_counter_irq_source": 18, "native_hardware_tick_hz": 1,
        "native_device_operation_table_checked": True, "native_pending_state_table_checked": True,
        "scope": "selected C bodies/direct calls and device/pending tables, not whole-program or assembly context-switch coverage"}


def capture(directory, index, aligned_bytes):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    required = (BEGIN, "*** Booting Zephyr OS build 3.7.0 ***", "main starting", "RIOT FLAGS PORT END",
                "RIOT FLAGS NATIVE FINAL peer_blocked=1 flags=0",
                f"RIOT FLAGS NATIVE STACK nominal=3584 aligned={aligned_bytes}",
                "RIOT FLAGS NATIVE TIMER alarm_count=1 isr=1 irq_reserved_until_reset=1")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RIOT FLAGS PORT END" or any(re.search(
                r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", line, re.I) for line in lines):
        raise ValueError("Zephyr original flags boot/profile/final-state/timer/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retires = [(i, re.fullmatch(r"RIOT FLAGS PORT RETIRE before=(\d+) after=(\d+)", line))
               for i, line in enumerate(lines) if line.startswith("RIOT FLAGS PORT RETIRE")]
    if len(found) != 1 or len(retires) != 1 or not retires[0][1]:
        raise ValueError("Zephyr original flag count/retirement missing")
    index_result, value = found[0]
    index_retire, retire = retires[0]
    order = (lines.index(BEGIN), lines.index("main starting"), index_result, lines.index(required[4]),
             index_retire, lines.index(required[5]), lines.index(required[6]), len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= value["result"] <= 0xffffffff or \
            value["ticks"] != 240000000 // value["result"] or int(retire[1]) < 2 or retire[1] != retire[2] or \
            rows[index_result]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Zephyr original flag formula/window/registry retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "registry_before": int(retire[1]), "registry_after": int(retire[2]),
        "final_peer_blocked": True, "final_pending_flags": 0, "native_alarm_count": 1, "native_alarm_isr_context": True,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    if not full and (any(directory.glob("reset*")) or any((directory / n).exists() for n in ("flash.log", "capture.sha256"))):
        raise ValueError("build-only flags audit cannot ignore board captures")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/README.md",
        **{"original-semantics/" + n: RIOT_UPSTREAM + n for n in ("core/thread_flags.c", "core/include/thread_flags.h")},
        **{"native-source/" + n: UPSTREAM + n for n in NATIVE}, "west.yml": UPSTREAM + "west.yml",
        **{"native-source/hal/" + n: "https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL + "/" + n for n in HAL_FILES}}
    proof = [{"path": n, "url": url, "sha256": digest(directory / n)} for n, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof: raise ValueError("native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_flags_zephyr.sh")]
    if any((directory / n).read_bytes() != p.read_bytes() for n, p in files): raise ValueError("current adapter/recipe differs")
    required = set(sources) | {"application.elf", "application.bin", "config", "compiler.txt", "compile_commands.json",
        "device-tree.dts", "device-tree.h", "disassembly.txt", *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native image inventory coverage differs")
    config = (directory / "config").read_text()
    if "CONFIG_EVENTS=y" not in config.splitlines() or config.replace("CONFIG_EVENTS=y", "# CONFIG_EVENTS is not set") != \
            (ROOT / "artifacts/reports/riot-yield-zephyr-v3/config").read_text() or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native reference profile/events/compiler differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("port.c", "original.c", *(n for n in NATIVE if n.endswith(".c")), *("hal/" + n for n in HAL_FILES if n.endswith(".c")))
    for n in units:
        suffix = n.removeprefix("hal/")
        selected = [row for row in commands if row["file"].endswith("/" + suffix) and
                    (n != "port.c" or "/app-zephyr-v1/" in row["file"])]
        if len(selected) != 1: raise ValueError("missing/duplicate native compile unit: " + n)
        args = shlex.split(selected[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_flags")) for a in args) or \
                (n == "original.c" and "-Dmain=riot_original_main" not in args): raise ValueError("actual native compiler/window override differs")
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    captures, verification = [], []
    if full:
        verification = capture_envelope(directory, "run_esp32_riot_flags_zephyr.sh", ((0x1000, "application.bin"),))
        captures = [capture(directory, i, control["aligned_peer_storage_bytes"]) for i in (1, 2, 3)]
        if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
               for a, b in zip(captures, captures[1:])) or len({c["registry_before"] for c in captures}) != 1:
            raise ValueError("independent original flags boots overlap or change registry profile")
    return {"benchmark": "RIOT thread_flags_pingpong original program / native Zephyr adapter", "os": "Zephyr",
        "built": True, "measured": full, "measurement_eligible": full, "board_boots": len(captures), "ranking_eligible": False,
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
        "native_controller_priority": 7, "native_peer_priority": 6, "official_native_files_checked": len(NATIVE) + len(HAL_FILES),
        "official_riot_semantics_reference_files_checked": 2, "actual_compiled_units_checked": len(units), "machine_control": control,
        "energy_measured": False, "runtime_ram_peak_measured": False, "capture_pipeline_prepared": True,
        "physical_positive_validation_complete": full, "captures": captures,
        "capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_flags_zephyr.sh"),
        "capture_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"),
        "verified_installed_images_before_after": verification,
        "flash_verification_scope": "esptool4.8.1 device MD5 checks whole merged input at0x1000 after CLI-header adjustment/4-byte padding; input SHA256 is not returned device SHA256",
        "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
        "image_manifest_sha256": digest(directory / "image.sha256"), "source_proof_sha256": digest(directory / "official-source.json"),
        "scope": "native dedicated32-bit event, lower16-bit subset, sole higher-priority peer, mask0x1 non-ISR setter/all16 ANY wait then clear on return; not general per-thread/reserved/multiple-waiter/ISR-set flags",
        "count_semantics": "original main-thread flag-set calls, not independently observed wakes/context switches or isolated latency",
        "missing": ([] if full else ["positive real ISR/flag/preemption/retirement validation"]) +
                   ["matched compiler/tick/background/stack/object conditions for ranking"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output: args.output.write_text(value)
    else: print(value, end="")
