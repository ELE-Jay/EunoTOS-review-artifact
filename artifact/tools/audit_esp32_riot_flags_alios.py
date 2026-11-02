#!/usr/bin/env python3
"""Audit a native Rhino cross-build of RIOT's original flags program, not a score."""
import argparse
from collections import Counter
from datetime import datetime
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
from audit_esp32_riot_yield_alios import NATIVE as YIELD_NATIVE, LIBRARIES, UPSTREAM
from audit_esp32_zephyr_isr import irq_archive_member, rhino_vector_dispatch
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_syskernel_sema_alios import elf_bytes
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from collect_esp32_riot_flags_alios_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-flags-alios-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_thread_flags_pingpong/alios"
SHARED = PORT.parent.parent / "riot_yield_pingpong/include"
NATIVE = YIELD_NATIVE + ("kernel/rhino/k_event.c", "kernel/rhino/k_pend.c", "kernel/rhino/include/k_event.h")
BEGIN = ("RIOT FLAGS PORT BEGIN AliOS-Rhino original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
         "controller=10 peer=9 stack=3584 timer=ISR channel=2 resolution_us=1 flags=16 object=native-event")


def machine(directory):
    check_manifest(directory, "flags-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "flags-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "flags-control-flow.txt", "executed-flags-control.py"} or \
            (directory / "executed-flags-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Rhino flags native-control recipe differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
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
                    raise ValueError("Rhino native/original encoded call differs")
                calls[name, m[3]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "thread_get", 1),
            ("riot_original_main", "thread_flags_set", 1), ("riot_original_main", "xtimer_set", 1),
            ("_second_thread", "thread_flags_wait_any", 1), ("thread_flags_set", "krhino_event_set", 1),
            ("thread_flags_wait_any", "krhino_event_get", 1), ("thread_create", "krhino_event_create", 1),
            ("thread_create", "krhino_task_create", 1), ("krhino_task_create", "task_create$part$0", 1),
            ("task_create$part$0", "cpu_task_stack_init", 1), ("krhino_event_set", "pend_task_wakeup", 1),
            ("krhino_event_set", "core_sched", 1), ("krhino_event_get", "pend_to_blk_obj", 1),
            ("krhino_event_get", "core_sched", 1), ("krhino_event_get", "pend_state_end_proc", 1),
            ("controller_entry", "riot_original_main", 1), ("controller_entry", "krhino_task_del", 1),
            ("controller_entry", "krhino_event_del", 1), ("controller_entry", "esp_intr_free", 1),
            ("controller_entry", "registry_count", 4), ("xtimer_set", "timer_init", 1),
            ("xtimer_set", "timer_set_counter_value", 1), ("xtimer_set", "timer_set_alarm_value", 1),
            ("xtimer_set", "timer_isr_register", 1), ("xtimer_set", "timer_enable_intr", 1),
            ("xtimer_set", "timer_start", 1), ("timer_isr_register", "esp_intr_alloc_intrstatus", 1),
            ("espos_isr_enter", "krhino_intrpt_enter", 1), ("espos_isr_exit", "krhino_intrpt_exit", 1))
        if any(calls[a, b] != n for a, b, n in expected): raise ValueError("native original flag operation missing")
        def literal(name, target):
            return any(literal_word(elf, row, int(m[1])) == target for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"), ("thread_create", "peer_flags"),
                ("thread_flags_set", "peer_flags"), ("thread_flags_wait_any", "peer_flags"),
                ("xtimer_set", "alarm_expired"), ("alarm_expired", "stop_callback")):
            if not literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("native original object/callback binding differs")
        patterns = {
            "riot_original_main": (r"addi\.n\s+a2, a2, 1$", r"quou\s+a11, a11, a2$"),
            "thread_flags_set": (r"movi\.n\s+a11, 1$", r"mov\.n\s+a12, a8$", r"movnez\s+a8, a11, a12$"),
            "thread_flags_wait_any": (r"movi\.n\s+a12, 1$", r"mov\.n\s+a11, a2$", r"extui\s+a2, a2, 0, 16$"),
            "krhino_event_set": (r"\bor\s+a3, a3, a7$", r"s32i\.n\s+a3, a2, 24$", r"xor\s+a4, a5, a4$",
                                 r"and\s+a4, a5, a4$", r"s32i\s+a4, a2, 24$"),
            "krhino_event_get": (r"bnone\s+a3, a8,", r"xor\s+a3, a8, a3$", r"and\s+a3, a5, a3$",
                                 r"s32i\.n\s+a3, a2, 24$", r"s32i\s+a3, a11, 116$"),
            "thread_create": (r"movi\.n\s+a8, -16$", r"addi\.n\s+a13, a11, 15$", r"and\s+a4, a13, a8$",
                              r"and\s+a3, a3, a8$", r"sub\s+a3, a3, a4$", r"srli\s+a3, a3, 2$", r"movi\.n\s+a13, 9$"),
            "alarm_expired": (r"callx8\s+a8$", r"movi\.n\s+a10, 0$")}
        for name, required in patterns.items():
            if any(not any(re.search(p, row) for row in control[name].values()) for p in required):
                raise ValueError("native flags/window/ABI/stack operand differs: " + name)
        if not literal("_second_thread", 65535) or not literal("thread_flags_wait_any", 65535) or \
                not literal("thread_flags_wait_any", 0xffffffff):
            raise ValueError("native all16-bit wait/forever operand differs")
        configuration = literal_word(elf, control["xtimer_set"][0x400d62b3], 11)
        if elf_bytes(elf, configuration, 20) != b"".join(n.to_bytes(4, "little") for n in (1, 0, 1, 0, 80)) or \
                not all(literal("xtimer_set", n) for n in (80000000, 1000000, (-1000000) & 0xffffffff, 0x3ff60000)) or \
                literal_word(elf, control["timer_isr_register"][0x400d3cfa], 12) != 0x3ff600a0 or \
                "2e0c movi.n\ta14, 2" not in "\n".join(control["xtimer_set"].values()) or \
                "12c382 addi\ta8, a3, 18" not in "\n".join(control["timer_isr_register"].values()):
            raise ValueError("native TIMER2 APB/prescaler/one-shot/level1/source configuration differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584: raise ValueError("original nominal stack changed")
        begin, end = (stack["st_value"] + 15) & ~15, (stack["st_value"] + 3584) & ~15
        if not stack["st_value"] <= begin < end <= stack["st_value"] + 3584 or end - begin < 3554:
            raise ValueError("native peer alignment escapes original buffer")
        ordered = [next(a for a, row in control["controller_entry"].items() if re.search(r" <" + name + r">$", row))
                   for name in ("riot_original_main", "timer_get_counter_value", "esp_intr_free", "krhino_task_del", "krhino_event_del")]
        if ordered != sorted(ordered): raise ValueError("native retirement entered original window")
        create_order = [next(a for a, row in control["thread_create"].items() if re.search(r" <" + name + r">$", row))
                        for name in ("krhino_event_create", "krhino_task_create")]
        if create_order != sorted(create_order): raise ValueError("higher-priority peer could run before event initialization")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
        "native_or_set_all16_wait_consume_checked": True, "native_block_wake_scheduler_calls_checked": True,
        "original_stack_bytes": 3584, "original_stack_address": hex(stack["st_value"]),
        "aligned_peer_storage_bytes": end - begin, "native_counter_irq_source": 18, "native_counter_frequency_hz": 1000000,
        "native_counter_configuration_checked": True, "original_callback_via_native_abi_bridge": True,
        "cleanup_calls_after_original_return_checked": True,
        "scope": "selected C bodies/direct calls, not whole-program or native deletion implementation coverage"}


def capture(directory, index, aligned_bytes):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    required = (BEGIN, "load image", "Welcome to AliOS Things", "main starting", "RIOT FLAGS PORT END",
                "RIOT FLAGS NATIVE FINAL peer_blocked=1 flags=0 waiters=1",
                f"RIOT FLAGS NATIVE STACK nominal=3584 aligned={aligned_bytes}")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RIOT FLAGS PORT END" or any(re.search(
                r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", line, re.I) for line in lines):
        raise ValueError("Rhino original flag boot/profile/final-state/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    timers = [(i, re.fullmatch(r"RIOT FLAGS NATIVE TIMER counter_us=(\d+) alarm_count=1 irq_released=1", line))
              for i, line in enumerate(lines) if line.startswith("RIOT FLAGS NATIVE TIMER")]
    retires = [(i, re.fullmatch(r"RIOT FLAGS PORT RETIRE tasks_before=(\d+) tasks_after=(\d+) events_before=(\d+) events_after=(\d+)", line))
               for i, line in enumerate(lines) if line.startswith("RIOT FLAGS PORT RETIRE")]
    if len(found) != 1 or len(timers) != 1 or not timers[0][1] or len(retires) != 1 or not retires[0][1]:
        raise ValueError("Rhino original flag count/native timer/retirement missing")
    index_result, value = found[0]
    index_timer, timer = timers[0]
    index_retire, retire = retires[0]
    order = (lines.index(BEGIN), lines.index("main starting"), index_result,
             lines.index(required[5]), lines.index(required[6]), index_timer, index_retire, len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= value["result"] <= 0xffffffff or \
            value["ticks"] != 240000000 // value["result"] or not 1000000 <= int(timer[1]) <= 0xffffffff or \
            int(retire[1]) < 2 or retire[1] != retire[2] or retire[3] != retire[4] or \
            rows[index_result]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Rhino original flag formula/window/timer/registry retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "native_counter_us": int(timer[1]), "final_peer_blocked": True,
        "final_pending_flags": 0, "final_waiters": 1, "tasks_before": int(retire[1]), "tasks_after": int(retire[2]),
        "events_before": int(retire[3]), "events_after": int(retire[4]),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


THREE_IMAGES = ((0x1000, "bootloader.bin"), (0x8000, "partitions.bin"), (0x10000, "application.bin"))


def verify_flash_log(directory, name, port, images=THREE_IMAGES):
    if images not in (THREE_IMAGES, ((0x1000, "application.bin"),)):
        raise ValueError("unsupported retained native Flash layout")
    text = (directory / name).read_text()
    lines = text.splitlines()
    for line in ("esptool.py v4.8.1", "Serial port " + port, "Chip is ESP32-D0WDQ6 (revision v1.1)",
                 "Crystal is 40MHz", "MAC: 84:1f:e8:8f:55:dc"):
        if lines.count(line) != 1: raise ValueError("native flash-verification identity differs")
    if any(re.search(r"FAILED|Fatal error|Traceback|digest mismatch", line, re.I) for line in lines):
        raise ValueError("native flash verification failed")
    found = list(re.finditer(r"^Verifying 0x([0-9a-f]+) \((\d+)\) bytes @ 0x([0-9a-f]+) in flash against (.+)\.\.\.\n"
                            r"-- verify OK \(digest matched\)$", text, re.M))
    if len(found) != len(images) or lines.count("-- verify OK (digest matched)") != len(images):
        raise ValueError("native verified Flash segment coverage missing")
    result = []
    for match, (address, file) in zip(found, images):
        length = ((directory / file).stat().st_size + 3) & ~3
        if int(match[1], 16) != length or int(match[2]) != length or int(match[3], 16) != address or Path(match[4]).name != file:
            raise ValueError("native verified Flash address/length/file differs")
        result.append({"file": file, "address": hex(address), "padded_bytes": length,
                       "input_file_sha256": digest(directory / file)})
    return result


def capture_envelope(directory, runner, images=THREE_IMAGES, control_prefix="flags"):
    if control_prefix not in ("flags", "msg"):
        raise ValueError("unsupported original capture-control prefix")
    check_manifest(directory, "capture.sha256")
    expected = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
        "flash.log", "board-check.log", "device-check.log", "image-check.log", "verify-before.log", "verify-after.log",
        "runner.sh", "capture_esp32_uart.py", "image.sha256", control_prefix + "-control.sha256", "official-source.json"}
    if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected:
        raise ValueError("independent original flags capture inventory differs")
    properties = {}
    for line in (directory / "device-check.log").read_text().splitlines():
        if "=" not in line: continue
        key, value = line.split("=", 1)
        if key in properties: raise ValueError("duplicate original flags USB identity property")
        properties[key] = value
    port = properties.get("DEVNAME", "")
    if not re.fullmatch(r"/dev/ttyUSB\d+", port) or properties.get("ID_VENDOR_ID") != "1a86" or properties.get("ID_MODEL_ID") != "7523":
        raise ValueError("original flags retained USB bridge identity missing")
    board = (directory / "board-check.log").read_text()
    if board.count("Serial port " + port) != 1 or not re.search(r"ESP32-D0WDQ6.*revision v1\.1", board) or \
            board.count("MAC: 84:1f:e8:8f:55:dc") != 1 or re.search(r"Fatal error|Traceback", board, re.I):
        raise ValueError("original flags correct physical board identity missing")
    audit_flash(directory, "flash.log", len(images))
    if (directory / "flash.log").read_text().splitlines().count("Serial port " + port) != 1:
        raise ValueError("original flags flash serial device differs")
    verification = [verify_flash_log(directory, name, port, images) for name in ("verify-before.log", "verify-after.log")]
    if verification[0] != verification[1]: raise ValueError("installed images differ across three resets")
    for saved, source in (("runner.sh", runner), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != (ROOT / "tools" / source).read_bytes():
            raise ValueError("original flags runner/raw recorder differs")
    checked = (directory / "image-check.log").read_text()
    if not all(re.search(r"^(?:\./)?" + re.escape(name) + r": OK$", checked, re.M)
               for name in ("application.elf", "application.bin", "image.sha256", control_prefix + "-control-flow.txt")):
        raise ValueError("original flags preflash image/control checks missing")
    return verification


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "archive-recovery.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "archive-recovery.sha256").read_text().splitlines()} != {
            "application.elf", "application.bin", "build.log"}: raise ValueError("archive-only recovery proof differs")
    prefix = lambda p: p.read_text().split("for name in kernel/rhino/k_task.c", 1)[0]
    if prefix(directory / "completed-build-script.sh") != prefix(ROOT / "tools/build_esp32_riot_flags_alios.sh"):
        raise ValueError("completed compile recipe differs")
    if not full and (any(directory.glob("reset*")) or any((directory / n).exists() for n in ("capture.sha256", "flash.log"))):
        raise ValueError("build-only flags audit cannot ignore board captures")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/README.md",
        **{"original-semantics/" + n: RIOT_UPSTREAM + n for n in ("core/thread_flags.c", "core/include/thread_flags.h")},
        **{"native-source/" + n: UPSTREAM + n for n in NATIVE},
        "rhino-portasm-pinned.S": UPSTREAM + "platform/arch/xtensa/lx6/portasm.S",
        **{"native-libraries/" + n: UPSTREAM + "platform/mcu/esp32/lib/" + n for n in LIBRARIES}}
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native source/archive differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof: raise ValueError("native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_flags_alios.sh")]
    if any((directory / name).read_bytes() != path.read_bytes() for name, path in files): raise ValueError("current adapter/recipe differs")
    board = ROOT / "firmware/bsp/esp32/alios_board"
    for saved, source in (("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"),
                          ("sdkconfig.h", "esp32bench/sdkconfig.h"), ("k_config.h", "esp32bench/k_config.h")):
        if (directory / saved).read_bytes() != (board / source).read_bytes(): raise ValueError("native board/IRQ/configuration differs")
    required = set(sources) | {"application.elf", "application.bin", "application.map", "config", "compiler.txt",
        "bootloader.bin", "partitions.bin", "link.opts", "build.log", "disassembly.txt", "completed-build-script.sh",
        "archive-recovery.sha256", *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native image inventory coverage differs")
    config = (directory / "config").read_text().replace('AOS_BUILD_APP="riot_flags"', 'AOS_BUILD_APP="riot_yield"').replace(
        "AOS_APP_RIOT_FLAGS=y", "AOS_APP_RIOT_YIELD=y")
    if config != (ROOT / "artifacts/reports/riot-yield-alios-v2/config").read_text() or \
            "5.2.0" not in (directory / "compiler.txt").read_text(): raise ValueError("native reference profile/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    units = ("app/example/riot_flags/port.c", "app/example/riot_flags/original.c", *(n for n in NATIVE if n.endswith(".c")),
             "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for n in units:
        selected = [args for args in commands if n in args]
        if len(selected) != 1 or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_flags")) for a in selected[0]) or \
                (not n.endswith(".S") and [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"]) or \
                (n.endswith("original.c") and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("actual original/native compilation differs: " + n)
    control = machine(directory)
    divisors, vector = hardware_tick_divisors(directory), rhino_vector_dispatch(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    map_text, link = (directory / "application.map").read_text(), (directory / "link.opts").read_text()
    for library, member, names in (("libdriver.a", "timer.o", tuple(n for n in FUNCTIONS if n.startswith("timer_"))),
                                  ("libesp32.a", "intr_alloc.o", ("esp_intr_alloc_intrstatus", "esp_intr_free"))):
        if "platform/mcu/esp32/lib/" + library not in link: raise ValueError("official SDK library not linked")
        with io.BytesIO(irq_archive_member(directory / "native-libraries" / library, member.encode())) as stream:
            native = ELFFile(stream)
            for name in names:
                if native.get_section_by_name(".text." + name) is None or not re.search(r"\.text\." + name +
                        r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*" + re.escape(library + "(" + member + ")"), map_text):
                    raise ValueError("official SDK member/function linkage differs: " + name)
    captures, verification = [], []
    if full:
        verification = capture_envelope(directory, "run_esp32_riot_flags_alios.sh")
        checked = (directory / "image-check.log").read_text()
        if not re.search(r"^(?:\./)?build\.log: OK$", checked, re.M):
            raise ValueError("original flags preflash image/control checks missing")
        captures = [capture(directory, i, control["aligned_peer_storage_bytes"]) for i in (1, 2, 3)]
        if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
               for a, b in zip(captures, captures[1:])) or \
                len({(c["tasks_before"], c["events_before"]) for c in captures}) != 1:
            raise ValueError("independent original flag boots overlap or change registry profile")
    return {"benchmark": "RIOT thread_flags_pingpong original program / native Rhino adapter", "os": "AliOS-Rhino",
        "built": True, "measured": full, "measurement_eligible": full, "board_boots": len(captures), "ranking_eligible": False,
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 5.2.0", "optimization": "Os",
        "native_controller_priority": 10, "native_peer_priority": 9, "official_native_files_checked": len(NATIVE) + 1,
        "official_sdk_archives_checked": len(LIBRARIES), "official_riot_reference_files_checked": 2,
        "actual_compiled_units_checked": len(units), "machine_control": control, "hardware_tick_divisors": divisors,
        "native_vector_dispatch": vector, "elf_sha256": digest(directory / "application.elf"),
        "bin_sha256": digest(directory / "application.bin"), "source_proof_sha256": digest(directory / "official-source.json"),
        "image_manifest_sha256": digest(directory / "image.sha256"), "energy_eligible": False, "whole_ram_peak_eligible": False,
        "energy_measured": False, "runtime_ram_peak_measured": False,
        "captures": captures, "capture_pipeline_prepared": True, "physical_positive_validation_complete": full,
        "capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_flags_alios.sh"),
        "capture_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"),
        "verified_installed_images_before_after": verification,
        "flash_verification_scope": "esptool4.8.1 compares device MD5 with CLI-header-adjusted/4-byte-padded input; recorded SHA256 identifies input files, not a returned device SHA256",
        "scope": "native event object dedicated to the sole original peer, not general per-thread flags; only mask0x1 set/all16 wait",
        "consume_timing": "Rhino consumes flags while waking a blocked peer; RIOT clears on resumed wait return",
        "count_semantics": "original main-thread flag-set calls, not independently observed wakes or context switches",
        "missing": ([] if full else ["correct-device physical delivery and three independent resets",
                    "positive runtime priority/flag/block/retirement validation"]) + ["matched compiler/tick/background for ranking"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = audit(args.directory, args.verify_upstream, args.full)
    output = json.dumps(value, indent=2) + "\n"
    if args.output: args.output.write_text(output)
    else: print(output, end="")
