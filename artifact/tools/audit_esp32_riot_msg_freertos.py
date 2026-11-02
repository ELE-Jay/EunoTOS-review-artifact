#!/usr/bin/env python3
"""Audit unchanged RIOT one-way message loops; cross-builds are not scores."""
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
from audit_esp32_riot_flags_freertos import NATIVE as FLAGS_NATIVE
from audit_esp32_riot_yield_freertos import IDF_UPSTREAM, native_assembler_control
from audit_esp32_riot_flags_alios import capture_envelope
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_riot_msg_freertos_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-msg-freertos-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_msg_pingpong"
SHARED = PORT.parent / "riot_yield_pingpong/include"
NATIVE = FLAGS_NATIVE + ("components/freertos/FreeRTOS-Kernel/queue.c",
    "components/freertos/FreeRTOS-Kernel/include/freertos/queue.h", "components/newlib/stdatomic.c")
RIOT_SEMANTICS = ("core/msg.c", "core/include/msg.h", "core/include/sched.h")
BEGIN = ("RIOT MSG PORT BEGIN FreeRTOS original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
         "controller=14 peer=15 stack=3584 timer=ISR message_bytes=8 queue_slots=1 logical_sender=0")


def machine(directory):
    check_manifest(directory, "msg-control.sha256")
    if {n.split(maxsplit=1)[1] for n in (directory / "msg-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "msg-control-flow.txt", "executed-msg-control.py"} or \
            (directory / "executed-msg-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("original message control recipe/inventory differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(len(symbols.get_symbol_by_name(n) or []) != 1 for n in FUNCTIONS):
            raise ValueError("ambiguous original/native message function")
        control = read_control_rows((directory / "msg-control-flow.txt").read_text(), "RIOT MSG CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        control.update(native_assembler_control(elf, symbols, (directory / "disassembly.txt").read_text(),
                                               ("vPortYield", "_frxt_dispatch", "_frxt_setup_switch")))
        for name, rows in control.items():
            for address, row in rows.items():
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call(0|4|8)\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m: continue
                value, window, target = int(m[1], 16), int(m[2]), int(m[3], 16)
                delta = value >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if value & 0x3f != 0x05 + window * 4 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(m[4]) or []):
                    raise ValueError("original/native message encoded call differs")
                calls[name, m[4]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "xtimer_set", 1),
            ("riot_original_main", "msg_send", 1), ("_second_thread", "msg_receive", 1),
            ("thread_create", "xQueueGenericCreateStatic", 1), ("thread_create", "xTaskCreateStaticPinnedToCore", 1),
            ("msg_send", "xQueueGenericSend", 1), ("msg_receive", "xQueueReceive", 1),
            ("xQueueGenericCreateStatic", "xQueueGenericReset", 1),
            ("xQueueGenericSend", "prvCopyDataToQueue", 1), ("xQueueReceive", "prvCopyDataFromQueue", 1),
            ("xQueueGenericSend", "xTaskRemoveFromEventList", 1), ("xQueueReceive", "xTaskRemoveFromEventList", 1),
            ("xQueueGenericSend", "vTaskPlaceOnEventList", 1), ("xQueueReceive", "vTaskPlaceOnEventList", 1),
            ("xQueueGenericSend", "esp_crosscore_int_send_yield", 2), ("xQueueReceive", "esp_crosscore_int_send_yield", 2),
            ("esp_crosscore_int_send_yield", "esp_crosscore_int_send", 1), ("esp_crosscore_isr", "_frxt_setup_switch", 1),
            ("esp_crosscore_int_init", "esp_intr_alloc", 1), ("_frxt_dispatch", "vTaskSwitchContext", 1),
            ("xtimer_set", "esp_timer_create", 1), ("xtimer_set", "esp_timer_start_once", 1),
            ("timer_alarm_handler", "timer_process_alarm", 1), ("alarm_expired", "xPortInIsrContext", 1),
            ("app_main", "riot_original_main", 1), ("app_main", "eTaskGetState", 1),
            ("app_main", "uxQueueMessagesWaiting", 1), ("app_main", "vTaskDelete", 1),
            ("app_main", "vQueueDelete", 1), ("app_main", "esp_timer_delete", 1), ("app_main", "uxTaskGetNumberOfTasks", 2))
        for a, b, n in expected:
            if calls[a, b] != n: raise ValueError(("original/native message operation missing", a, b))
        def literal(name, value):
            return any(literal_word(elf, row, int(m[1])) == value for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("thread_create", "peer_entry"), ("thread_create", "queue_storage"), ("thread_create", "queue_control"),
                ("xtimer_set", "alarm_expired"), ("xtimer_set", "stop_callback"), ("alarm_expired", "stop_callback"),
                ("msg_send", "messages"), ("msg_receive", "messages"), ("esp_crosscore_int_init", "esp_crosscore_isr")):
            if not literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("original message object/peer/callback binding differs")
        required = {
            "riot_original_main": ("20c182 addi\ta8, a1, 32", "7189 s32i.n\ta8, a1, 28",
                "130cb0 wsr.scompare1\ta11", "08e182 s32c1i\ta8, a1, 32", "661b addi.n\ta6, a6, 1", "c2bb60 quou\ta11, a11, a6"),
            "_timer_callback": ("080c movi.n\ta8, 0", "004282 s8i\ta8, a2, 0"),
            "thread_create": ("8b0c movi.n\ta11, 8", "1a0c movi.n\ta10, 1", "0e0c movi.n\ta14, 0",
                              "fe0c movi.n\ta14, 15", "11cc70 slli\ta12, a12, 9"),
            "msg_send": ("005282 s16i\ta8, a2, 0", "0d0c movi.n\ta13, 0", "fc7c movi.n\ta12, -1"),
            "msg_receive": ("fc7c movi.n\ta12, -1",),
            "xQueueGenericCreateStatic": ("0f6282 s32i\ta8, a2, 60", "106232 s32i\ta3, a2, 64"),
            "xtimer_set": ("1298 l32i.n\ta9, a2, 4", "1199 s32i.n\ta9, a1, 4", "1a0c movi.n\ta10, 1", "21a9 s32i.n\ta10, a1, 8"),
            "alarm_expired": ("02ad mov.n\ta10, a2", "0008e0 callx8\ta8"),
            "timer_process_alarm": ("l32i.n\ta6, a7, 16", "l32i.n\ta7, a7, 20", "callx8\ta6"),
            "esp_crosscore_int_init": ("8a1c movi.n\ta10, 24", "00a4b2 movi\ta11, 0x400"),
            "esp_crosscore_isr": ("026707 bbci\ta7, 0,",)}
        for name, instructions in required.items():
            if any(i not in "\n".join(control[name].values()) for i in instructions):
                raise ValueError("original message layout/atomic flag/queue/timer/preemption operand differs: " + name)
        if sum("08e182 s32c1i\ta8, a1, 32" in r for r in control["riot_original_main"].values()) != 2:
            raise ValueError("original initial and loop atomic exchanges differ")
        for name in ("esp_crosscore_int_send", "esp_crosscore_isr"):
            if not literal(name, 0x3ff000dc): raise ValueError("native scheduling IRQ register differs")
        for name, targets in (("thread_create", ("xQueueGenericCreateStatic", "xTaskCreateStaticPinnedToCore")),
                ("app_main", ("riot_original_main", "eTaskGetState", "uxQueueMessagesWaiting", "vTaskDelete", "vQueueDelete", "esp_timer_delete"))):
            positions = [next(a for a, r in control[name].items() if re.search(r" <" + re.escape(t) + r">$", r)) for t in targets]
            if positions != sorted(positions): raise ValueError("original queue initialization or retirement order differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584 or symbols.get_symbol_by_name("queue_storage")[0]["st_size"] != 8:
            raise ValueError("original stack or native queue storage size changed")
    return {"reachable_c_functions_checked": len(FUNCTIONS), "native_assembler_bodies_checked": 3,
        "encoded_direct_calls_checked": sum(calls.values()), "original_peer_stack_bytes": 3584,
        "original_message_bytes": 8, "native_queue_slots": 1, "native_copy_send_receive_checked": True,
        "original_inline_atomic_exchange_and_isr_clear_checked": True, "original_timer_argument_forwarded": True,
        "native_scheduling_irq_source": 24, "native_scheduling_irq_register": "0x3ff000dc",
        "cleanup_after_original_return_checked": True,
        "scope": "selected C bodies/calls and three assembler entries; not whole-program or general rendezvous/payload correctness validation"}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    required = (BEGIN, "main starting", "RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 alarm_count=1 isr=1", "RIOT MSG PORT END")
    if sum("Project name:     riot_msg_pingpong_port" in n for n in lines) != 1 or \
            sum("ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "..." in n for n in lines) != 1 or \
            sum("rst:0x" in n for n in lines) != 1 or any(lines.count(n) != 1 for n in required) or \
            lines[-1] != required[-1] or any(re.search(r"PORT FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog", n, re.I) for n in lines):
        raise ValueError("original message boot/image/profile/final-state/ISR/completion differs")
    values = [(i, json.loads(n)) for i, n in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', n)]
    retires = [(i, re.fullmatch(r"RIOT MSG PORT RETIRE before=(\d+) after=(\d+)", n)) for i, n in enumerate(lines) if n.startswith("RIOT MSG PORT RETIRE")]
    if len(values) != 1 or len(retires) != 1 or not retires[0][1]: raise ValueError("original message count/retirement missing")
    i, value = values[0]
    r, retire = retires[0]
    if not 1 <= value["result"] <= 0xffffffff or value["ticks"] != 240000000 // value["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < lines.index(required[2]) < r < len(lines) - 1 or \
            int(retire[1]) < 2 or retire[1] != retire[2] or rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < .95:
        raise ValueError("original message one-second formula/window/registry retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "registry_before": int(retire[1]), "registry_after": int(retire[2]),
        "final_peer_blocked": True, "final_queued_messages": 0, "native_alarm_count": 1, "native_alarm_isr_context": True,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "archive-recovery.sha256")
    if {n.split(maxsplit=1)[1] for n in (directory / "archive-recovery.sha256").read_text().splitlines()} != {
            "application.elf", "application.bin", "build.log"} or \
            (directory / "completed-build-script.sh").read_text().split("for name in core/msg.c", 1)[0] != \
            (ROOT / "tools/build_esp32_riot_msg_freertos.sh").read_text().split("for name in core/msg.c", 1)[0]:
        raise ValueError("archive-only recovery changed compiled images/recipe")
    if not full and (any(directory.glob("reset*")) or any((directory / n).exists() for n in ("capture.sha256", "flash.log"))):
        raise ValueError("build-only message audit cannot ignore board captures")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/msg_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/msg_pingpong/README.md",
        **{"original-semantics/" + n: RIOT_UPSTREAM + n for n in RIOT_SEMANTICS},
        **{"native-source/" + n: IDF_UPSTREAM + n for n in NATIVE}}
    proof = [{"path": n, "url": url, "sha256": digest(directory / n)} for n, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]: raise ValueError("fixed original/native message source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof: raise ValueError("original/native message source proof differs")
    files = [(Path(n), PORT / n) for n in ("port.c", "CMakeLists.txt", "main/CMakeLists.txt",
                                          "include/thread.h", "include/msg.h", "include/xtimer.h")]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_msg_freertos.sh")]
    if any((directory / n).read_bytes() != p.read_bytes() for n, p in files): raise ValueError("current original message adapter/recipe differs")
    required = set(sources) | {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config",
        "reference-config", "FreeRTOSConfig.h", "compiler.txt", "compile_commands.json", "disassembly.txt", "build.log",
        "completed-build-script.sh", "archive-recovery.sha256", *(str(n) for n, _ in files)}
    if not required <= {n.split(maxsplit=1)[1].removeprefix("./") for n in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native message image inventory coverage differs")
    reference = ROOT / "artifacts/reports/riot-flags-freertos-v1"
    config = lambda p: dict(re.findall(r"^(CONFIG_\w+)=(.*)$", p.read_text(), re.M))
    if (directory / "reference-config").read_bytes() != (reference / "config").read_bytes() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (reference / "FreeRTOSConfig.h").read_bytes() or \
            config(directory / "config") != config(directory / "reference-config") or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native message reference profile/compiler differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("original.c", "riot-msg-pingpong/app-freertos-v1/port.c", *(n for n in NATIVE if n.endswith((".c", ".S"))))
    for unit in units:
        suffix = unit.removeprefix("components/freertos/")
        selected = [row for row in commands if row["file"].endswith("/" + suffix)]
        if len(selected) != 1: raise ValueError("missing/duplicate original/native message compile unit: " + unit)
        args = shlex.split(selected[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dmsg_", "-Datomic_flag")) for a in args) or \
                (unit == "original.c" and "-Dmain=riot_original_main" not in args):
            raise ValueError("original/native message compilation or loop override differs")
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    captures, verification = [], []
    if full:
        verification = capture_envelope(directory, "run_esp32_riot_msg_freertos.sh", control_prefix="msg")
        captures = [capture(directory, i) for i in (1, 2, 3)]
        if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])) or \
                len({c["registry_before"] for c in captures}) != 1: raise ValueError("original message independent boots overlap/profile differs")
    return {"benchmark": "RIOT msg_pingpong original program / native FreeRTOS one-slot copy queue adapter", "os": "FreeRTOS",
        "built": True, "measured": full, "measurement_eligible": full, "ranking_eligible": False, "board_boots": len(captures),
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
        "native_controller_priority": 14, "native_peer_priority": 15, "official_native_files_checked": len(NATIVE),
        "official_riot_semantics_reference_files_checked": len(RIOT_SEMANTICS), "actual_compiled_units_checked": len(units),
        "machine_control": control, "captures": captures, "capture_pipeline_prepared": True,
        "physical_positive_validation_complete": full, "energy_measured": False, "runtime_ram_peak_measured": False,
        "native_unbuffered_rendezvous_implemented": False, "payload_correctness_validated": False,
        "capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_msg_freertos.sh"),
        "capture_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"), "verified_installed_images_before_after": verification,
        "flash_verification_scope": "native esptool4.8.1 MD5 before/after all three normalized/padded images; input SHA256 is not returned device SHA256",
        "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
        "image_manifest_sha256": digest(directory / "image.sha256"), "source_proof_sha256": digest(directory / "official-source.json"),
        "count_semantics": "original main-thread msg_send calls, not independently counted deliveries/context switches, isolated latency or request/reply throughput",
        "scope": "sole lower-priority producer/higher-priority receiver, eight-byte original layout, native FIFO depth1/send-to-back/forever, logical IDs0/1; native buffered two-copy queue differs from RIOT direct unbuffered transfer; original uninitialized user fields remain opaque, not a payload-integrity test; native stack/TCB/atomic/cache/background costs retained, deferred idle deletion not whole-heap cleanup",
        "missing": ([] if full else ["positive real ISR/message/preemption/retirement validation"]) +
                   ["matched compiler/tick/background/stack/object conditions and transfer semantics for ranking"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", type=Path, default=DIRECTORY)
    p.add_argument("--verify-upstream", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output: args.output.write_text(result)
    else: print(result, end="")
