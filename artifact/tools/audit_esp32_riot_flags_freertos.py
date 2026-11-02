#!/usr/bin/env python3
"""Audit unchanged RIOT thread flags on native FreeRTOS; builds are not scores."""
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
from audit_esp32_riot_yield_freertos import NATIVE as YIELD_NATIVE, IDF_UPSTREAM, native_assembler_control
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_riot_flags_freertos_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-flags-freertos-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_thread_flags_pingpong"
SHARED = PORT.parent / "riot_yield_pingpong/include"
REFERENCE = ROOT / "artifacts/reports/riot-yield-freertos-v1"
NATIVE = YIELD_NATIVE + ("components/freertos/FreeRTOS-Kernel/include/freertos/task.h",
                        "components/esp_system/crosscore_int.c", "components/esp_hw_support/intr_alloc.c")
RIOT_SEMANTICS = ("core/thread_flags.c", "core/include/thread_flags.h")
BEGIN = ("RIOT FLAGS PORT BEGIN FreeRTOS original=dd06b372 duration_us=1000000 clock=240 cores=1 "
         "tick=1 controller=14 peer=15 stack=3584 timer=ISR flags=16 index=0")


def machine(directory):
    check_manifest(directory, "flags-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "flags-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "flags-control-flow.txt", "executed-flags-control.py"} or \
            (directory / "executed-flags-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("original flags control recipe/inventory differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "flags-control-flow.txt").read_text(), "RIOT FLAGS CONTROL",
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
                    raise ValueError("original/native flags encoded call differs")
                calls[name, m[4]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "thread_get", 1),
            ("riot_original_main", "xtimer_set", 1), ("riot_original_main", "thread_flags_set", 1),
            ("_second_thread", "thread_flags_wait_any", 1), ("thread_create", "xTaskCreateStaticPinnedToCore", 1),
            ("thread_flags_set", "xTaskGenericNotify", 1), ("thread_flags_wait_any", "xTaskGenericNotifyWait", 1),
            ("xTaskGenericNotify", "esp_crosscore_int_send_yield", 1),
            ("xTaskGenericNotifyWait", "esp_crosscore_int_send_yield", 1),
            ("esp_crosscore_int_send_yield", "esp_crosscore_int_send", 1),
            ("esp_crosscore_isr", "_frxt_setup_switch", 1), ("esp_crosscore_int_init", "esp_intr_alloc", 1),
            ("_frxt_dispatch", "vTaskSwitchContext", 1), ("xtimer_set", "esp_timer_create", 1),
            ("xtimer_set", "esp_timer_start_once", 1), ("timer_alarm_handler", "timer_process_alarm", 1),
            ("app_main", "riot_original_main", 1), ("app_main", "eTaskGetState", 1),
            ("app_main", "ulTaskGenericNotifyValueClear", 1), ("app_main", "vTaskDelete", 1),
            ("app_main", "esp_timer_delete", 1), ("app_main", "uxTaskGetNumberOfTasks", 2))
        if any(calls[a, b] != count for a, b, count in expected):
            raise ValueError("original/native flags operation missing")
        def has_literal(name, target):
            return any(literal_word(elf, row, int(m[1])) == target for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"),
                ("esp_crosscore_int_init", "esp_crosscore_isr"), ("esp_crosscore_int_init", "reason")):
            if not has_literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("original/native flag callback binding differs")
        required = {
            "thread_create": ("fe0c movi.n\ta14, 15", "11cc70 slli\ta12, a12, 9"),
            "thread_flags_set": ("01a0d2 movi\ta13, 1", "01a0c2 movi\ta12, 1", "0b0c movi.n\ta11, 0"),
            "thread_flags_wait_any": ("f4c020 extui\ta12, a2, 0, 16", "00a0b2 movi\ta11, 0",
                                      "0a0c movi.n\ta10, 0", "ffafe2 movi\ta14, -1"),
            "xTaskGenericNotify": ("209940 or\ta9, a9, a4", "526292 s32i\ta9, a2, 0x148"),
            "xTaskGenericNotifyWait": ("104490 and\ta4, a4, a9", "304490 xor\ta4, a4, a9",
                                       "526842 s32i\ta4, a8, 0x148"),
            "esp_crosscore_int_init": ("8a1c movi.n\ta10, 24", "00a4b2 movi\ta11, 0x400"),
            "esp_crosscore_isr": ("026707 bbci\ta7, 0,",),
            "xtimer_set": ("1a0c movi.n\ta10, 1", "21a9 s32i.n\ta10, a1, 8"),
            "app_main": ("0c0c movi.n\ta12, 0", "0b0c movi.n\ta11, 0"),
            "timer_process_alarm": ("callx8\ta6", "l32i.n\ta6, a7, 16", "l32i.n\ta7, a7, 20")}
        for name, instructions in required.items():
            if any(instruction not in "\n".join(control[name].values()) for instruction in instructions):
                raise ValueError("native notification mode/index/consume/preemption/ISR operand differs: " + name)
        for name in ("esp_crosscore_int_send", "esp_crosscore_isr"):
            if not has_literal(name, 0x3ff000dc):
                raise ValueError("native core0 scheduling IRQ register differs")
        original = "\n".join(control["riot_original_main"].values())
        if "01c772 addi\ta7, a7, 1" not in original or "c2bb70 quou\ta11, a11, a7" not in original:
            raise ValueError("original flag-set count/ticks formula absent")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584:
            raise ValueError("original flag peer stack size changed")
        ordered = [next(a for a, row in control["app_main"].items() if re.search(r" <" + name + r">$", row))
                   for name in ("riot_original_main", "eTaskGetState", "ulTaskGenericNotifyValueClear", "vTaskDelete", "esp_timer_delete")]
        if ordered != sorted(ordered): raise ValueError("native final-state observation/retirement entered original window")
    return {"reachable_c_functions_checked": len(FUNCTIONS), "native_assembler_bodies_checked": 3,
        "encoded_direct_calls_checked": sum(calls.values()), "original_peer_stack_bytes": 3584,
        "original_peer_stack_address": hex(stack["st_value"]), "native_notification_index": 0,
        "native_or_setbits_and_wait_consume_checked": True, "native_scheduling_irq_source": 24,
        "native_scheduling_irq_register": "0x3ff000dc", "native_scheduling_irq_callback_checked": True,
        "direct_stop_isr_dispatch_checked": True, "final_observation_and_cleanup_after_original_checked": True}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    if sum("Project name:     riot_flags_pingpong_port" in line for line in lines) != 1 or \
            sum("ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "..." in line for line in lines) != 1:
        raise ValueError("original flags boot not bound to the built firmware")
    required = (BEGIN, "main starting", "RIOT FLAGS NATIVE FINAL peer_blocked=1 flags=0", "RIOT FLAGS PORT END")
    if sum("rst:0x" in line for line in lines) != 1 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RIOT FLAGS PORT END" or any(re.search(
                r"PORT FAIL|Guru Meditation|panic|assert failed|Exception|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("incomplete/failed independent original flags boot")
    values = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retires = [(i, re.fullmatch(r"RIOT FLAGS PORT RETIRE before=(\d+) after=(\d+)", line))
               for i, line in enumerate(lines) if line.startswith("RIOT FLAGS PORT RETIRE")]
    if len(values) != 1 or len(retires) != 1 or not retires[0][1]:
        raise ValueError("original flag count/retirement missing")
    i, value = values[0]
    r, match = retires[0]
    if not 1 <= value["result"] <= 0xffffffff or value["ticks"] != 240000000 // value["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < lines.index(required[2]) < r < len(lines) - 1 or \
            match[1] != match[2] or int(match[1]) < 2 or rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("original one-second flag count/formula/final-state/retirement mismatch")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "registry_before": int(match[1]), "registry_after": int(match[2]),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "archive-recovery.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "archive-recovery.sha256").read_text().splitlines()} != {
            "application.elf", "application.bin", "build.log"}:
        raise ValueError("archive-only recovery lacks exact image/build binding")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/README.md",
        **{"native-source/" + n: IDF_UPSTREAM + n for n in NATIVE},
        **{"original-semantics/" + n: RIOT_UPSTREAM + n for n in RIOT_SEMANTICS}}
    proof = [{"path": p, "url": url, "sha256": digest(directory / p)} for p, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("original/native flag source differs from fixed upstream: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("fixed original/native flag source proof differs")
    relative = ("port.c", "CMakeLists.txt", "main/CMakeLists.txt", *(p.relative_to(PORT).as_posix()
                for p in (PORT / "include").rglob("*.h")))
    files = [(Path(n), PORT / n) for n in relative]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_flags_freertos.sh")]
    if any((directory / name).read_bytes() != p.read_bytes() for name, p in files):
        raise ValueError("current original flags adapter/build recipe differs")
    required = set(sources) | {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config",
        "reference-config", "FreeRTOSConfig.h", "compiler.txt", "compile_commands.json", "disassembly.txt", *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("original/native flags image inventory coverage differs")
    if (directory / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (REFERENCE / "FreeRTOSConfig.h").read_bytes():
        raise ValueError("original flag native reference profile differs")
    def config(path): return dict(re.findall(r"^(CONFIG_\w+)=(.*)$", path.read_text(), re.M))
    actual = config(directory / "config")
    if actual != config(directory / "reference-config") or actual.get("CONFIG_FREERTOS_HZ") != "1" or \
            actual.get("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ") != "240" or actual.get("CONFIG_FREERTOS_UNICORE") != "y" or \
            actual.get("CONFIG_ESP_TIMER_SUPPORTS_ISR_DISPATCH_METHOD") != "y" or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native flag clock/core/tick/timer/compiler profile differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    units = ("original.c", "riot-flags-pingpong/app-freertos-v1/port.c", *(n for n in NATIVE if n.endswith((".c", ".S"))))
    for unit in units:
        suffix = unit.removeprefix("components/freertos/")
        selected = [row for row in commands if row["file"].endswith("/" + suffix)]
        if len(selected) != 1: raise ValueError("missing/duplicate original/native flag compile unit: " + unit)
        args = shlex.split(selected[0]["command"])
        if "esp-13.2.0_20230928" not in args[0] or [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_flags_")) for a in args) or \
                (unit == "original.c" and "-Dmain=riot_original_main" not in args):
            raise ValueError("original/native flag compilation/window override differs")
    if (directory / "completed-build-script.sh").read_text().partition("for name in FreeRTOS")[0] != \
            (directory / "build-script.sh").read_text().partition("for name in FreeRTOS")[0]:
        raise ValueError("archive-only recovery changed original compile recipe")
    if "vPortYieldFromISR" not in (directory / "failed-collect-flags-control.py").read_text():
        raise ValueError("initial non-emitted-helper collector diagnostic missing")
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    captures = []
    if full:
        check_manifest(directory, "capture.sha256")
        expected = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
            "flash.log", "board-check.log", "image-check.log", "runner.sh", "capture_esp32_uart.py", "image.sha256",
            "flags-control.sha256", "official-source.json"}
        if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected:
            raise ValueError("independent original flags capture inventory differs")
        board = (directory / "board-check.log").read_text()
        if not re.search(r"ESP32-D0WDQ6.*revision v1\.1", board) or "MAC: 84:1f:e8:8f:55:dc" not in board:
            raise ValueError("original flags correct physical board identity missing")
        audit_flash(directory, "flash.log", 3)
        for saved, source in (("runner.sh", "run_esp32_riot_flags_freertos.sh"), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
            if (directory / saved).read_bytes() != (ROOT / "tools" / source).read_bytes():
                raise ValueError("original flag capture runner/raw recorder differs")
        captures = [capture(directory, i) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("independent original flag boots overlap")
    elif (directory / "capture.sha256").exists() or (directory / "flash.log").exists() or list(directory.glob("reset*")):
        raise ValueError("build-only original flags audit cannot ignore partial/full board captures")
    return {"benchmark": "RIOT thread_flags_pingpong original program / native FreeRTOS adapter", "os": "FreeRTOS",
        "built": True, "measured": full, "board_boots": len(captures), "measurement_eligible": full, "ranking_eligible": False,
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "official_native_files_checked": len(NATIVE), "original_reference_semantics_files_checked": len(RIOT_SEMANTICS),
        "actual_compiled_units_checked": len(units), "clock_mhz": 240, "cores": 1, "tick_hz": 1,
        "compiler": "GCC 13.2.0", "optimization": "Os", "native_controller_priority": 14, "native_peer_priority": 15,
        "timeslicing": False, "machine_control": control, "captures": captures, "energy_measured": False,
        "runtime_ram_peak_measured": False, "application_elf_sha256": digest(directory / "application.elf"),
        "application_bin_sha256": digest(directory / "application.bin"),
        "boundary": "unchanged original one-second main-thread flag-set count and integer ticks/count, not isolated latency or observed wakeup/context-switch count; native task notification index0 uses OR/setbits and consumes the full original16-bit mask on wait exit, supporting this single high-priority peer/mask0x1/all-mask/non-ISR-set program, not general selective RIOT flag waits or reserved automatic flags; native SW scheduling IRQ and direct hardware-stop ISR retained; wrapper cost, GCC13/1-Hz versus RIOT/GCC12/tickless, TCB/stack ownership/background remain separate; final blocked/empty flags and registry checks are outside original window; SDK timer deletion is deferred, no whole-heap/RAM/energy/rank claim; physical positive validation still pending for build-only result"}


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
