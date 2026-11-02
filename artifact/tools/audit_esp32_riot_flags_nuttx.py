#!/usr/bin/env python3
"""Audit the original RIOT flags program on an unchanged NuttX driver event."""
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
from audit_esp32_riot_yield_nuttx import NATIVE as YIELD_NATIVE, EXTRA, UPSTREAM
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_riot_flags_alios import capture_envelope
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_riot_flags_nuttx_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-flags-nuttx-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_thread_flags_pingpong/nuttx"
SHARED = PORT.parent.parent / "riot_yield_pingpong/include"
NATIVE = tuple(n for n in YIELD_NATIVE if n != "sched/sched/sched_yield.c") + (EXTRA,
    "drivers/modem/alt1250/altmdm_event.c", "drivers/modem/alt1250/altmdm_event.h",
    "libs/libc/semaphore/sem_init.c", "sched/semaphore/sem_setprotocol.c", "sched/semaphore/sem_trywait.c",
    "sched/semaphore/sem_wait.c", "sched/semaphore/sem_post.c", "sched/semaphore/sem_destroy.c",
    "sched/semaphore/sem_timedwait.c", "sched/semaphore/sem_clockwait.c", "sched/sched/sched_gettcb.c",
    "include/nuttx/semaphore.h", "include/nuttx/sched.h")
BEGIN = ("RIOT FLAGS PORT BEGIN NuttX original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
         "controller=150 peer=151 stack=3584 timer=ISR channel=2 resolution_us=1 flags=16 "
         "object=official-driver-event protocol=NONE")


def machine(directory):
    check_manifest(directory, "flags-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "flags-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "flags-control-flow.txt", "executed-flags-control.py"} or \
            (directory / "executed-flags-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("NuttX flags control/source recipe differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(len(symbols.get_symbol_by_name(n) or []) != 1 for n in FUNCTIONS):
            raise ValueError("ambiguous NuttX original/native function")
        control = read_control_rows((directory / "flags-control-flow.txt").read_text(), "RIOT FLAGS CONTROL",
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
                    raise ValueError("NuttX original/native encoded call differs")
                calls[name, match[3]] += 1
        expected = (("riot_original_main", "thread_create", 1), ("riot_original_main", "thread_get", 1),
            ("riot_original_main", "thread_flags_set", 1), ("riot_original_main", "xtimer_set", 1),
            ("_second_thread", "thread_flags_wait_any", 1), ("thread_create", "altmdm_event_init", 1),
            ("thread_create", "nxsem_set_protocol", 1), ("thread_create", "pthread_create", 1),
            ("thread_create", "pthread_attr_setstack", 1), ("pthread_create", "nx_pthread_create", 1),
            ("nx_pthread_create", "up_use_stack", 1), ("up_use_stack", "xtensa_stack_color", 1),
            ("thread_flags_set", "altmdm_event_set", 1), ("thread_flags_wait_any", "altmdm_event_wait", 1),
            ("altmdm_event_init", "nxsem_init", 1), ("altmdm_event_set", "nxsem_post", 1),
            ("altmdm_event_wait", "nxsem_trywait", 1), ("altmdm_event_wait", "nxsem_wait_uninterruptible", 1),
            ("nxsem_wait_uninterruptible", "nxsem_wait", 1), ("altmdm_event_destroy", "nxsem_destroy", 1),
            ("nxsem_post", "nxsched_add_readytorun", 1), ("nxsem_post", "up_switch_context", 1),
            ("xtimer_set", "esp32_oneshot_initialize", 1), ("xtimer_set", "esp32_oneshot_start", 1),
            ("riot_flags_main", "riot_original_main", 1), ("riot_flags_main", "nxsched_get_tcb", 1),
            ("riot_flags_main", "altmdm_event_refer", 1), ("riot_flags_main", "pthread_cancel", 1),
            ("riot_flags_main", "nxsem_get_value", 1),
            ("riot_flags_main", "pthread_join", 1), ("riot_flags_main", "altmdm_event_destroy", 1),
            ("riot_flags_main", "esp32_oneshot_cancel", 1), ("riot_flags_main", "nxsched_foreach", 2),
            ("pthread_cancel", "nxnotify_cancellation", 1))
        for caller, callee, count in expected:
            if calls[caller, callee] != count:
                raise ValueError(("NuttX original/native operation missing", caller, callee))
        def literal(name, target):
            return any(literal_word(elf, row, int(m[1])) == target for row in control[name].values()
                       if (m := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("thread_create", "peer_entry"), ("thread_create", "peer_flags"),
                ("thread_flags_wait_any", "peer_flags"), ("xtimer_set", "alarm_expired"),
                ("alarm_expired", "stop_callback"), ("esp32_oneshot_start", "esp32_oneshot_handler"),
                ("esp32_tim_init", "g_esp32_tim2_priv")):
            if not literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("NuttX original object/peer/timer callback binding differs")
        patterns = {
            "riot_original_main": (r"addi\.n\s+a7, a7, 1$", r"quou\s+a11, a11, a7$"),
            "thread_create": (r"movi\s+a8, 151$", r"movi\.n\s+a11, 0$"),
            "thread_flags_wait_any": (r"movi\s+a12, 1$", r"movi\s+a13, 0$", r"extui\s+a11, a2, 0, 16$",
                                      r"extui\s+a8, a8, 16, 16$", r"extui\s+a2, a10, 0, 16$"),
            "_second_thread": (r"movi\.n\s+a10, -1$", r"extui\s+a10, a10, 16, 16$"),
            "altmdm_event_set": (r"\bor\s+a3, a8, a3$", r"s32i\.n\s+a3, a2, 16$"),
            "altmdm_event_wait": (r"and\s+a2, a9, a3$", r"beqz\.n\s+a4,", r"and\s+a8, a2, a9$",
                                  r"xor\s+a8, a8, a9$", r"s32i\.n\s+a8, a7, 16$"),
            "xtimer_set": (r"movi\s+a11, 2$", r"movi\s+a12, 1$", r"movi\s+a12, 0$"),
            "esp32_oneshot_handler": (r"l32i\.n\s+a9, a4, 8$", r"l32i\.n\s+a10, a4, 12$", r"callx8\s+a9$"),
            "pthread_startup": (r"callx8\s+a2$",),
            "alarm_expired": (r"movi\.n\s+a10, 0$", r"callx8\s+a8$"),
            "riot_flags_main": (r"l8ui\s+a8, a10, 28$", r"bnei\s+a8, 5,", r"l32i\s+a8, a10, 72$",
                                r"bne\s+a8, a6,", r"bnei\s+a8, -1,")}
        for name, required in patterns.items():
            if any(not any(re.search(p, row) for row in control[name].values()) for p in required):
                raise ValueError("NuttX original/event/priority/callback operand differs: " + name)
        def order(name, targets):
            addresses = [next(a for a, row in control[name].items() if re.search(r" <" + re.escape(t) + r">$", row))
                         for t in targets]
            if addresses != sorted(addresses): raise ValueError("NuttX native initialization/retirement order differs")
        order("thread_create", ("altmdm_event_init", "nxsem_set_protocol", "pthread_create"))
        order("riot_flags_main", ("riot_original_main", "nxsched_get_tcb", "pthread_cancel", "pthread_join",
                                  "altmdm_event_destroy", "esp32_oneshot_cancel"))
        ops = symbols.get_symbol_by_name("esp32_tim_ops")[0]
        section = elf.get_section(ops["st_shndx"])
        start = ops["st_value"] - section["sh_addr"]
        for offset, target in ((4, "esp32_tim_stop"), (48, "esp32_tim_setisr"),
                               (56, "esp32_tim_disableint"), (60, "esp32_tim_ackint")):
            if int.from_bytes(section.data()[start + offset:start + offset + 4], "little") != symbols.get_symbol_by_name(target)[0]["st_value"]:
                raise ValueError("NuttX native timer indirect operation table differs")
        private = symbols.get_symbol_by_name("g_esp32_tim2_priv")[0]
        section = elf.get_section(private["st_shndx"])
        start = private["st_value"] - section["sh_addr"]
        data = section.data()[start:start + private["st_size"]]
        if int.from_bytes(data[:4], "little") != ops["st_value"] or int.from_bytes(data[4:8], "little") != 0x3ff60000 or data[21] != 1:
            raise ValueError("NuttX native TIMER2 base/interrupt level differs")
        for name in ("up_timer_initialize", "esp32_timerisr"):
            if not literal(name, symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"]) or \
                    not any("13f080 wsr.ccompare0\ta8" in row for row in control[name].values()):
                raise ValueError("NuttX native hardware tick path differs")
        if not literal("up_timer_initialize", 240000000): raise ValueError("NuttX one-Hz CPU tick divisor differs")
        if not literal("alarm_expired", symbols.get_symbol_by_name("g_current_regs")[0]["st_value"]):
            raise ValueError("NuttX native ISR context check differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584: raise ValueError("original nominal stack changed")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
        "original_stack_bytes": 3584, "original_stack_address": hex(stack["st_value"]),
        "native_stack_coloring_checked": True, "driver_indirect_operations_bound": True,
        "native_counter_frequency_hz": 1000000, "native_timer_interrupt_level": 1, "native_hardware_tick_hz": 1,
        "official_driver_event_body_unchanged": True, "native_signaling_protocol_initialized_before_peer": True,
        "cleanup_after_original_return_checked": True,
        "scope": "selected C bodies/direct calls and timer table; not whole-program or assembly context-switch coverage"}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    required = (BEGIN, "NuttShell (NSH) NuttX-12.2.1", "RIOT FLAGS NATIVE VERSION NuttX 12.2.1", "main starting",
                "RIOT FLAGS NATIVE FINAL peer_blocked=1 flags=0 sem_count=-1",
                "RIOT FLAGS NATIVE TIMER alarm_count=1 isr=1 channel_reserved_until_reset=1", "RIOT FLAGS PORT END")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(n) != 1 for n in required) or \
            lines[-1] != required[-1] or any(re.search(
                r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", n, re.I) for n in lines):
        raise ValueError("NuttX original flags boot/profile/final-state/ISR/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retire = [(i, re.fullmatch(r"RIOT FLAGS PORT RETIRE before=(\d+) after=(\d+)", line))
              for i, line in enumerate(lines) if line.startswith("RIOT FLAGS PORT RETIRE")]
    if len(found) != 1 or len(retire) != 1 or not retire[0][1]: raise ValueError("NuttX original flag count/retirement missing")
    i, result = found[0]
    r, match = retire[0]
    order = (lines.index(required[1]), lines.index(required[2]), lines.index(BEGIN), lines.index("main starting"),
             i, lines.index(required[4]), r, lines.index(required[5]), len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= result["result"] <= 0xffffffff or \
            result["ticks"] != 240000000 // result["result"] or int(match[1]) < 2 or match[1] != match[2] or \
            rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("NuttX original flag formula/window/registry retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": result["result"],
        "original_ticks": result["ticks"], "registry_before": int(match[1]), "registry_after": int(match[2]),
        "final_peer_blocked": True, "final_pending_flags": 0, "final_signaling_semaphore_count": -1,
        "native_alarm_count": 1, "native_alarm_isr_context": True,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    if not full and (any(directory.glob("reset*")) or any((directory / n).exists() for n in ("flash.log", "capture.sha256"))):
        raise ValueError("build-only flags audit cannot ignore board captures")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/main.c",
        "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_flags_pingpong/README.md",
        **{"original-semantics/" + n: RIOT_UPSTREAM + n for n in ("core/thread_flags.c", "core/include/thread_flags.h")},
        **{"native-source/" + n: UPSTREAM + n for n in NATIVE}}
    proof = [{"path": n, "url": url, "sha256": digest(directory / n)} for n, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof: raise ValueError("native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / n, SHARED / n) for n in ("clk.h", "xtimer.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_flags_nuttx.sh")]
    if any((directory / n).read_bytes() != p.read_bytes() for n, p in files) or \
            (directory / "include/altmdm_event.h").read_bytes() != (directory / "native-source/drivers/modem/alt1250/altmdm_event.h").read_bytes():
        raise ValueError("current adapter/recipe/official event header differs")
    required = set(sources) | {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config",
        "reference-config", "version-header.h", "compiler.txt", "build.log", "disassembly.txt", "include/altmdm_event.h",
        *(str(n) for n, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("NuttX flags original/native image inventory coverage differs")
    reference = ROOT / "artifacts/reports/riot-yield-nuttx-v1/config"
    if (directory / "reference-config").read_bytes() != reference.read_bytes(): raise ValueError("native reference config differs")
    baseline = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", reference.read_text(), re.M))
    actual = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", (directory / "config").read_text(), re.M))
    differences = {k: (baseline.get(k), actual.get(k)) for k in baseline.keys() | actual.keys()
                   if k != "CONFIG_BASE_DEFCONFIG" and baseline.get(k) != actual.get(k)}
    if differences != {"CONFIG_EXAMPLES_RIOT_YIELD": ("y", None), "CONFIG_EXAMPLES_RIOT_FLAGS": (None, "y")} or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native profile changed beyond declared original flags app")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc -c ")]
    units = ("original.c", "port.c", *(n for n in NATIVE if n.endswith(".c")))
    for n in units:
        if n in ("original.c", "port.c", "drivers/modem/alt1250/altmdm_event.c"):
            file, scope = n.rsplit("/", 1)[-1], "/apps/examples/riot_flags/"
        elif n.startswith("libs/libc/"): file, scope = n[10:], "/nuttx/libs/libc"
        elif n.startswith("sched/"): file, scope = n[6:], "/nuttx/sched"
        else: file, scope = n.replace("arch/xtensa/src/esp32/", "chip/").replace("arch/xtensa/src/", ""), "/nuttx/arch/xtensa/src"
        selected = [args for args in commands if file in args and any(scope in arg for arg in args)]
        if len(selected) != 1 or [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_flags")) for a in selected[0]) or \
                (n == "original.c" and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("actual original/native compilation differs: " + n)
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    verification, captures = [], []
    if full:
        verification = capture_envelope(directory, "run_esp32_riot_flags_nuttx.sh")
        captures = [capture(directory, i) for i in (1, 2, 3)]
        if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
               for a, b in zip(captures, captures[1:])) or len({c["registry_before"] for c in captures}) != 1:
            raise ValueError("NuttX independent boots overlap or native registry profile differs")
    return {"benchmark": "RIOT thread_flags_pingpong original program / NuttX official driver-event adapter", "os": "NuttX",
        "built": True, "measured": full, "measurement_eligible": full, "ranking_eligible": False, "board_boots": len(captures),
        "new_metric_created": False, "original_test_body_unchanged": True, "original_nominal_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os",
        "native_controller_priority": 150, "native_peer_priority": 151, "official_native_files_checked": len(NATIVE),
        "official_riot_semantics_reference_files_checked": 2, "actual_compiled_units_checked": len(units), "machine_control": control,
        "capture_pipeline_prepared": True, "physical_positive_validation_complete": full, "captures": captures,
        "energy_measured": False, "runtime_ram_peak_measured": False,
        "capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_flags_nuttx.sh"),
        "capture_recorder_sha256": digest(ROOT / "tools/capture_esp32_uart.py"), "verified_installed_images_before_after": verification,
        "flash_verification_scope": "esptool4.8.1 native MD5 checks all three images after CLI-header adjustment/4-byte padding; input SHA256 is not returned device SHA256",
        "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
        "image_manifest_sha256": digest(directory / "image.sha256"), "source_proof_sha256": digest(directory / "official-source.json"),
        "scope": "unchanged official ALT1250 driver-event source reused without modem hardware; native signaling semaphore configured PRIO_NONE before higher-priority peer; sole receiver, mask0x1/all16 ANY-clear subset, not general per-thread/multiple-waiter/ISR flags or a core-kernel event API",
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
