#!/usr/bin/env python3
"""Audit the RIOT original message program on Zephyr; builds are not measurements."""
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
from audit_esp32_riot_yield_zephyr import NATIVE as YIELD_NATIVE, HAL_FILES, UPSTREAM, HAL, counter_device_control, symbol_data
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_syskernel_sema_alios import elf_bytes
from audit_esp32_riot_flags_alios import capture_envelope
from audit_esp32_iperf_original import ANSI
from collect_esp32_riot_msg_zephyr_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-msg-zephyr-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_msg_pingpong"
YIELD = PORT.parent / "riot_yield_pingpong"
NATIVE = YIELD_NATIVE + ("kernel/msg_q.c", "include/zephyr/kernel.h", "include/zephyr/kernel/thread.h",
                        "kernel/include/wait_q.h", "kernel/include/ksched.h")
BEGIN = ("RIOT MSG PORT BEGIN Zephyr original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
         "controller=7 peer=6 stack=3584 timer=ISR channel=2 resolution_us=1 message_bytes=8 queue_slots=1 logical_sender=0")


def machine(directory):
    check_manifest(directory, "msg-control.sha256")
    names = {line.split(maxsplit=1)[1] for line in (directory / "msg-control.sha256").read_text().splitlines()}
    if names != {"application.elf", "image.sha256", "msg-control-flow.txt", "executed-msg-control.py"} or \
            (directory / "executed-msg-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("message machine-control recipe differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(len(symbols.get_symbol_by_name(n) or []) != 1 for n in FUNCTIONS):
            raise ValueError("ambiguous original/native message function")
        control = read_control_rows((directory / "msg-control-flow.txt").read_text(), "RIOT MSG CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        for caller, rows in control.items():
            for address, row in rows.items():
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                word, target = int(m[1], 16), int(m[2], 16)
                delta = word >> 6
                if delta & (1 << 17):
                    delta -= 1 << 18
                if word & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(m[3]) or []):
                    raise ValueError("original/native encoded call differs")
                calls[caller, m[3]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "xtimer_set", 1),
            ("riot_original_main", "msg_send", 1), ("_second_thread", "msg_receive", 1),
            ("thread_create", "k_msgq_init", 1), ("thread_create", "z_impl_k_thread_create", 1),
            ("z_impl_k_thread_create", "z_setup_new_thread", 1), ("z_setup_new_thread", "arch_new_thread", 1),
            ("msg_send", "z_impl_k_msgq_put", 1), ("msg_receive", "z_impl_k_msgq_get", 1),
            ("z_impl_k_msgq_put", "z_unpend_first_thread", 1), ("z_impl_k_msgq_put", "z_ready_thread", 1),
            ("z_impl_k_msgq_put", "z_reschedule", 1), ("z_impl_k_msgq_get", "z_pend_curr", 1),
            ("main", "riot_original_main", 1), ("main", "k_thread_state_str", 1),
            ("main", "z_impl_k_thread_abort", 1), ("main", "z_impl_k_thread_join", 1),
            ("main", "k_msgq_cleanup", 1), ("main", "k_thread_foreach", 2),
            ("alarm_expired", "k_is_in_isr", 1), ("counter_esp32_init", "esp_intr_alloc", 1))
        if any(calls[a, b] != n for a, b, n in expected):
            raise ValueError("original/native message call missing")

        def literal(caller, target):
            value = symbols.get_symbol_by_name(target)[0]["st_value"]
            return any(literal_word(elf, row, int(m[1])) == value for row in control[caller].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))

        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("thread_create", "peer_entry"), ("thread_create", "messages"), ("thread_create", "message_storage"),
                ("msg_send", "messages"), ("msg_receive", "messages"), ("msg_receive", "peer"),
                ("xtimer_set", "alarm_expired"), ("xtimer_set", "stop_argument"),
                ("alarm_expired", "stop_argument"), ("alarm_expired", "stop_callback")):
            if not literal(caller, target):
                raise ValueError("original/native object or callback binding differs")
        patterns = {
            "riot_original_main": (r"addi\s+a6, a6, 1$", r"quou\s+a11, a11, a6$", r"s32c1i\s+a8, a1, 32$"),
            "_timer_callback": (r"s8i\s+a8, a2, 0$", r"movi\.n\s+a8, 0$"),
            "thread_create": (r"movi\.n\s+a13, 1$", r"movi\.n\s+a12, 8$", r"movi\.n\s+a8, 6$"),
            "msg_send": (r"movi\s+a12, -1$", r"movi\s+a13, -1$", r"s16i\s+a8, a2, 0$"),
            "msg_receive": (r"movi\s+a12, -1$", r"movi\.n\s+a13, -1$"),
            "alarm_expired": (r"l32i\.n\s+a10, a9, 0$", r"callx8\s+a8$"),
            "xtimer_set": (r"l32i\.n\s+a8, a2, 4$", r"s32i\.n\s+a8, a9, 0$"),
        }
        for name, required in patterns.items():
            if any(not any(re.search(p, row) for row in control[name].values()) for p in required):
                raise ValueError("original counter/message/priority/timeout/timer operand differs: " + name)
        for caller, targets in (("thread_create", ("k_msgq_init", "z_impl_k_thread_create")),
                ("main", ("riot_original_main", "k_thread_state_str", "z_impl_k_thread_abort",
                          "z_impl_k_thread_join", "k_msgq_cleanup"))):
            positions = [next(a for a, row in control[caller].items() if row.endswith("<" + n + ">")) for n in targets]
            if positions != sorted(positions):
                raise ValueError("native object initialization/retirement order differs")
        counter_device_control(directory, elf, symbols, control)
        state, _ = symbol_data(elf, symbols, "state_string$0")
        pointer, length = int.from_bytes(state[8:12], "little"), int.from_bytes(state[12:16], "little")
        if len(state) != 64 or length != 7 or elf_bytes(elf, pointer, 8) != b"pending\0":
            raise ValueError("native pending-state table differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        begin, end = (stack["st_value"] + 15) & ~15, (stack["st_value"] + 3584) & ~15
        if stack["st_size"] != 3584 or not stack["st_value"] <= begin < end <= stack["st_value"] + 3584 or end - begin < 3554:
            raise ValueError("native aligned stack escapes original storage")
        if symbols.get_symbol_by_name("message_storage")[0]["st_size"] != 8:
            raise ValueError("native single-slot message storage differs")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
            "original_stack_bytes": 3584, "aligned_peer_storage_bytes": end - begin,
            "native_counter_frequency_hz": 1000000, "native_counter_irq_source": 18,
            "original_atomic_stop_and_nominal_division_checked": True,
            "native_queue_init_before_peer_and_postwindow_cleanup_checked": True,
            "native_pending_state_table_checked": True,
            "scope": "selected C bodies, direct calls and counter device table; not whole-program or assembly context-switch proof"}


def capture(directory, index, aligned_bytes):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    boot = "*** Booting Zephyr OS build 3.7.0 ***"
    final = "RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 alarm_count=1 isr=1"
    stack = f"RIOT MSG NATIVE STACK nominal=3584 aligned={aligned_bytes}"
    timer = "RIOT MSG NATIVE TIMER irq_reserved_until_reset=1"
    required = (boot, BEGIN, "main starting", final, stack, timer, "RIOT MSG PORT END")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(s) != 1 for s in required) or \
            lines[-1] != required[-1] or any(re.search(
                r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", line, re.I) for line in lines):
        raise ValueError("Zephyr original message boot/profile/queue/ISR/completion differs")
    results = [(i, json.loads(s)) for i, s in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', s)]
    retires = [(i, re.fullmatch(r"RIOT MSG PORT RETIRE before=(\d+) after=(\d+)", s))
               for i, s in enumerate(lines) if s.startswith("RIOT MSG PORT RETIRE")]
    if len(results) != 1 or sum(s.startswith('{ "result"') for s in lines) != 1 or len(retires) != 1 or not retires[0][1]:
        raise ValueError("original message result/retirement missing or duplicated")
    i, value = results[0]
    r, retire = retires[0]
    reset = next(i for i, s in enumerate(lines) if s.startswith("rst:0x"))
    order = (reset, lines.index(boot), lines.index(BEGIN), lines.index("main starting"), i,
             lines.index(final), r, lines.index(stack), lines.index(timer), len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= value["result"] <= 0xffffffff or \
            value["ticks"] != 240000000 // value["result"] or int(retire[1]) < 2 or retire[1] != retire[2] or \
            rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("original message formula/window/registry retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
            "original_count": value["result"], "original_ticks": value["ticks"],
            "registry_before": int(retire[1]), "registry_after": int(retire[2]),
            "final_peer_blocked": True, "final_queued_messages": 0, "native_alarm_count": 1,
            "native_alarm_isr_context": True, "uart_sha256": digest(directory / f"reset{index}.jsonl"),
            "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    if not full and (any(directory.glob("reset*")) or any((directory / n).exists() for n in ("flash.log", "capture.sha256"))):
        raise ValueError("build-only message audit cannot ignore board captures")
    check_manifest(directory, "image.sha256")
    sources = {"source/" + n: RIOT_UPSTREAM + "tests/bench/msg_pingpong/" + n for n in ("main.c", "README.md")}
    sources.update({"original-semantics/" + n: RIOT_UPSTREAM + n for n in ("core/msg.c", "core/include/msg.h", "core/include/sched.h")})
    sources.update({"native-source/" + n: UPSTREAM + n for n in NATIVE})
    sources.update({"native-source/hal/" + n: "https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL + "/" + n for n in HAL_FILES})
    sources["west.yml"] = UPSTREAM + "west.yml"
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("official source proof differs")
    files = [(p.relative_to(PORT / "zephyr"), p) for p in (PORT / "zephyr").rglob("*") if p.is_file()]
    files += [(Path("include") / n, PORT / "include" / n) for n in ("msg.h", "xtimer.h")]
    files += [(Path("include/clk.h"), YIELD / "include/clk.h"),
              (Path("include/macros/units.h"), YIELD / "zephyr/include/macros/units.h")]
    files += [(Path(n), YIELD / "zephyr" / n) for n in ("prj.conf", "app.overlay")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_msg_zephyr.sh"),
              (Path("reference-config"), ROOT / "artifacts/reports/riot-yield-zephyr-v3/config")]
    if any((directory / n).read_bytes() != p.read_bytes() for n, p in files):
        raise ValueError("current adapter/build recipe/reference differs")
    required = set(sources) | {"application.elf", "application.bin", "config", "compiler.txt", "compile_commands.json",
        "device-tree.dts", "device-tree.h", "disassembly.txt", *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native image inventory incomplete")
    if (directory / "config").read_bytes() != (directory / "reference-config").read_bytes() or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native execution profile/compiler differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("port.c", "original.c", *(n for n in NATIVE if n.endswith(".c")), *("hal/" + n for n in HAL_FILES if n.endswith(".c")))
    for n in units:
        selected = [r for r in commands if r["file"].endswith("/" + n.removeprefix("hal/")) and
                    (n != "port.c" or "/riot-msg-pingpong/app-zephyr-v1/" in r["file"])]
        if len(selected) != 1:
            raise ValueError("missing/duplicate actual compile unit: " + n)
        args = shlex.split(selected[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dmsg_send", "-Dmsg_receive")) for a in args) or \
                (n == "original.c" and "-Dmain=riot_original_main" not in args):
            raise ValueError("actual original/native compiler or workload override differs")
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    captures, verification = [], []
    if full:
        verification = capture_envelope(directory, "run_esp32_riot_msg_zephyr.sh", ((0x1000, "application.bin"),), "msg")
        device = (directory / "device-check.log").read_text().splitlines()
        if device.count("ID_USB_DRIVER=ch341") != 1 or "ID_TYPE=audio" in device or any(
                s.startswith("ID_MODEL=USB_MIDI") for s in device):
            raise ValueError("original message serial driver/audio-MIDI descriptor differs")
        captures = [capture(directory, i, control["aligned_peer_storage_bytes"]) for i in (1, 2, 3)]
        if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
               for a, b in zip(captures, captures[1:])) or len({c["registry_before"] for c in captures}) != 1:
            raise ValueError("independent original message boots overlap or change registry profile")
    return {"benchmark": "RIOT msg_pingpong original program / native Zephyr adapter", "os": "Zephyr",
        "built": True, "measured": full, "board_boots": len(captures), "measurement_eligible": full, "ranking_eligible": False,
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
        "native_controller_priority": 7, "native_peer_priority": 6, "message_bytes": 8, "queue_slots": 1,
        "official_native_files_checked": len(NATIVE) + len(HAL_FILES), "official_riot_semantics_reference_files_checked": 3,
        "actual_compiled_units_checked": len(units), "machine_control": control,
        "energy_measured": False, "runtime_ram_peak_measured": False, "capture_pipeline_prepared": True,
        "physical_positive_validation_complete": full, "payload_correctness_validated": False,
        "captures": captures, "verified_installed_images_before_after": verification,
        "capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_msg_zephyr.sh"),
        "capture_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"),
        "flash_verification_scope": "esptool4.8.1 device MD5 checks merged input at0x1000 after header adjustment/4-byte padding; not device SHA256",
        "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
        "boundary": "Original main-thread send count and nominal cycles/count, not isolated latency. Native Zephyr one-slot "
            "8-byte message queue can directly copy to a waiting receiver; the higher-priority sole receiver is intended to "
            "re-pend before sender continues. That exact fast-path selection is not established by final-state checks or a dynamic trace. "
            "Not a general RIOT PID-addressed unbuffered API, not FreeRTOS two-copy semantics; original opaque uninitialized "
            "user fields are not content-integrity evidence. Fixed 240MHz/one-core/GCC13/1Hz, original nominal3584B stack aligned "
            "within its buffer, TIMER2 1MHz callback/atomic-flag bridge. IRQ/device reservation persists until reset. "
            "Full capture auditing and safe three-reset acquisition are implemented; physical positive validation and "
            "matched-condition qualification remain pending for build-only results. Final queue state is checked, but "
            "not each original send's delivery or dynamic native fast-path selection."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
