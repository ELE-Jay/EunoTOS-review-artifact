#!/usr/bin/env python3
"""Audit unchanged RIOT yield on NuttX; cross-builds do not become board scores."""
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
from audit_esp32_iperf_original import ANSI
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_riot_yield_nuttx_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/riot-yield-nuttx-v1"
PORT = ROOT / "firmware/bsp/esp32/riot_yield_pingpong/nuttx"
SHARED = PORT.parent / "include"
REFERENCE = ROOT / "artifacts/reports/zephyr-yield-nuttx-v1"
UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
NATIVE = ("arch/xtensa/src/esp32/esp32_oneshot.c", "arch/xtensa/src/esp32/esp32_oneshot.h",
    "arch/xtensa/src/esp32/esp32_tim.c", "arch/xtensa/src/esp32/esp32_tim.h", "arch/xtensa/src/esp32/esp32_irq.c",
    "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/esp32/esp32_clockconfig.c",
    "libs/libc/pthread/pthread_create.c", "libs/libc/pthread/pthread_attr_setstack.c", "sched/pthread/pthread_create.c",
    "sched/pthread/pthread_cancel.c", "sched/pthread/pthread_join.c", "sched/pthread/pthread_completejoin.c",
    "sched/task/task_cancelpt.c", "sched/sched/sched_yield.c", "sched/sched/sched_foreach.c",
    "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_releasestack.c")
EXTRA = "arch/xtensa/src/common/xtensa_checkstack.c"
BEGIN = ("RIOT YIELD PORT BEGIN NuttX original=dd06b372 duration_us=1000000 clock=240 "
         "cores=1 tick=1 priority=150 stack=3584 timer=ISR channel=2 resolution_us=1")


def machine(directory):
    check_manifest(directory, "yield-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "yield-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "yield-control-flow.txt", "executed-yield-control.py",
            "native-yield-source/xtensa_checkstack.c"} or (directory / "executed-yield-control.py").read_text() != \
            collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("NuttX yield control/source supplement binding differs")
    calls = Counter()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "yield-control-flow.txt").read_text(), "RIOT YIELD CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        for name, rows in control.items():
            for address, row in rows.items():
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                value, target = int(match[1], 16), int(match[2], 16)
                delta = value >> 6
                if delta & (1 << 17): delta -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + delta * 4 != target or not any(
                        s["st_value"] == target for s in symbols.get_symbol_by_name(match[3]) or []):
                    raise ValueError("NuttX original/native encoded call differs")
                calls[name, match[3]] += 1
        for caller, callee, count in (("riot_original_main", "thread_create", 1), ("riot_original_main", "xtimer_set", 1),
                ("riot_original_main", "sched_yield", 1), ("_second_thread", "sched_yield", 1),
                ("thread_create", "pthread_create", 1), ("thread_create", "pthread_attr_setstack", 1),
                ("pthread_create", "nx_pthread_create", 1), ("nx_pthread_create", "up_use_stack", 1),
                ("up_use_stack", "xtensa_stack_color", 1), ("xtimer_set", "esp32_oneshot_initialize", 1),
                ("xtimer_set", "esp32_oneshot_start", 1), ("riot_yield_main", "riot_original_main", 1),
                ("riot_yield_main", "pthread_cancel", 1), ("riot_yield_main", "pthread_join", 1),
                ("riot_yield_main", "esp32_oneshot_cancel", 1), ("riot_yield_main", "nxsched_foreach", 2),
                ("pthread_cancel", "nxnotify_cancellation", 1)):
            if calls[caller, callee] != count:
                raise ValueError(("NuttX original/native operation missing", caller, callee))
        def has_literal(name, target):
            return any(literal_word(elf, row, int(match[1])) == target for row in control[name].values()
                       if (match := re.search(r"l32r\s+a(\d+),", row)))
        for caller, target in (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
                ("_timer_callback", "_flag"), ("esp32_oneshot_start", "esp32_oneshot_handler"),
                ("esp32_tim_init", "g_esp32_tim2_priv")):
            if not has_literal(caller, symbols.get_symbol_by_name(target)[0]["st_value"]):
                raise ValueError("NuttX original peer/ISR/timer binding differs")
        patterns = {"riot_original_main": (r"addi\.n\s+a7, a7, 1$", r"quou\s+a11, a11, a7$"),
            "xtimer_set": (r"movi\.n\s+a11, 2$", r"movi\.n\s+a12, 1$", r"l32i\s+a11, a2, 0$", r"movi\s+a12, 0$"),
            "esp32_oneshot_handler": (r"l32i\.n\s+a9, a4, 8$", r"l32i\.n\s+a10, a4, 12$", r"callx8\s+a9$"),
            "pthread_startup": (r"callx8\s+a2$",), "thread_create": (r"movi\s+a8, 150$",)}
        for name, required in patterns.items():
            if any(not any(re.search(pattern, row) for row in control[name].values()) for pattern in required):
                raise ValueError("NuttX counter/formula/callback/timer/priority operand differs: " + name)
        # Bind the initialized driver vtable, not just an indirect call's label.
        ops = symbols.get_symbol_by_name("esp32_tim_ops")[0]
        section = elf.get_section(ops["st_shndx"])
        start = ops["st_value"] - section["sh_addr"]
        for offset, target in ((4, "esp32_tim_stop"), (48, "esp32_tim_setisr"),
                               (56, "esp32_tim_disableint"), (60, "esp32_tim_ackint")):
            if int.from_bytes(section.data()[start + offset:start + offset + 4], "little") != symbols.get_symbol_by_name(target)[0]["st_value"]:
                raise ValueError("native timer indirect operation table differs")
        private = symbols.get_symbol_by_name("g_esp32_tim2_priv")[0]
        section = elf.get_section(private["st_shndx"])
        start = private["st_value"] - section["sh_addr"]
        data = section.data()[start:start + private["st_size"]]
        if int.from_bytes(data[:4], "little") != ops["st_value"] or int.from_bytes(data[4:8], "little") != 0x3ff60000 or data[21] != 1:
            raise ValueError("native timer channel/base/interrupt level differs")
        for name in ("up_timer_initialize", "esp32_timerisr"):
            if not has_literal(name, symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"]) or \
                    not any("13f080 wsr.ccompare0\ta8" in row for row in control[name].values()):
                raise ValueError("native hardware tick path differs")
        if not has_literal("up_timer_initialize", 240000000):
            raise ValueError("native one-Hz tick divisor differs")
        stack = symbols.get_symbol_by_name("_stack")[0]
        if stack["st_size"] != 3584:
            raise ValueError("original nominal stack changed")
        ordered = [next(a for a, row in control["riot_yield_main"].items() if re.search(r" <" + name + ">$", row))
                   for name in ("riot_original_main", "pthread_cancel", "pthread_join", "esp32_oneshot_cancel")]
        if ordered != sorted(ordered):
            raise ValueError("native retirement entered original window")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": sum(calls.values()),
            "native_hardware_tick_hz": 1, "native_timer_channel": 2, "native_timer_resolution_us": 1,
            "native_timer_interrupt_level": 1, "driver_indirect_operations_bound": True,
            "original_peer_stack_bytes": 3584, "native_stack_coloring_checked": True,
            "direct_original_isr_callback_checked": True, "cleanup_after_original_return_checked": True,
            "inlined_nonbenchmark_helpers": ["task_count"]}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    if sum(line.startswith("rst:0x") for line in lines) != 1 or lines.count(BEGIN) != 1 or \
            lines.count("main starting") != 1 or lines.count("NuttShell (NSH) NuttX-12.2.1") != 1 or \
            lines.count("RIOT YIELD NATIVE VERSION NuttX 12.2.1") != 1 or lines.count("RIOT YIELD PORT END") != 1 or \
            lines[-1] != "RIOT YIELD PORT END" or lines.count("RIOT YIELD NATIVE TIMER channel_reserved_until_reset=1") != 1 or \
            any(re.search(r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout", line, re.I) for line in lines):
        raise ValueError("NuttX independent original yield boot/profile/completion differs")
    found = [(i, json.loads(line)) for i, line in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', line)]
    retire = [(i, re.fullmatch(r"RIOT YIELD PORT RETIRE before=(\d+) after=(\d+)", line))
              for i, line in enumerate(lines) if line.startswith("RIOT YIELD PORT RETIRE")]
    if len(found) != 1 or len(retire) != 1 or not retire[0][1]:
        raise ValueError("NuttX original count/retirement missing")
    i, result = found[0]
    r, match = retire[0]
    if not 1 <= result["result"] <= 0xffffffff or result["ticks"] != 240000000 // result["result"] or \
            not lines.index(BEGIN) < lines.index("main starting") < i < r < len(lines) - 1 or \
            int(match[1]) < 2 or match[1] != match[2] or rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("NuttX original one-second formula/retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": result["result"],
            "original_ticks": result["ticks"], "registry_before": int(match[1]), "registry_after": int(match[2]),
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory=DIRECTORY, verify_upstream=False, full=False):
    directory = directory.resolve()
    check_manifest(directory, "image.sha256")
    sources = {"source/main.c": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/main.c",
               "source/README.md": RIOT_UPSTREAM + "tests/bench/thread_yield_pingpong/README.md",
               **{"native-source/" + name: UPSTREAM + name for name in NATIVE},
               "native-yield-source/xtensa_checkstack.c": UPSTREAM + EXTRA}
    proof = [{"path": path, "url": url, "sha256": digest(directory / path)} for path, url in sorted(sources.items())]
    if verify_upstream:
        for row in proof:
            with urlopen(row["url"], timeout=40) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("fixed original/native source differs: " + row["path"])
        (directory / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")
    if json.loads((directory / "official-source.json").read_text()) != proof:
        raise ValueError("NuttX original/native source proof differs")
    files = [(p.relative_to(PORT), p) for p in PORT.rglob("*") if p.is_file()]
    files += [(Path("include") / name, SHARED / name) for name in ("clk.h", "xtimer.h", "macros/units.h")]
    files += [(Path("build-script.sh"), ROOT / "tools/build_esp32_riot_yield_nuttx.sh")]
    required = {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "reference-config",
        "compiler.txt", "build.log", "disassembly.txt", "version-header.h", "source/main.c", "source/README.md",
        *("native-source/" + name for name in NATIVE), *(str(name) for name, _ in files)}
    if not required <= {line.split(maxsplit=1)[1].removeprefix("./")
                        for line in (directory / "image.sha256").read_text().splitlines()}:
        raise ValueError("NuttX original/native image inventory coverage differs")
    if any((directory / archive).read_bytes() != source.read_bytes() for archive, source in files) or \
            (directory / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes():
        raise ValueError("NuttX current adapter/recipe/native reference binding differs")
    baseline = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", (directory / "reference-config").read_text(), re.M))
    actual = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", (directory / "config").read_text(), re.M))
    expected = {"CONFIG_EXAMPLES_ZEPHYR_YIELD": ("y", None), "CONFIG_EXAMPLES_RIOT_YIELD": (None, "y"),
                **{name: (None, "y") for name in ("CONFIG_ESP32_TIMER", "CONFIG_ESP32_TIMER2", "CONFIG_ESP32_ONESHOT", "CONFIG_STACK_COLORATION")}}
    differences = {k: (baseline.get(k), actual.get(k)) for k in baseline.keys() | actual.keys()
                   if k != "CONFIG_BASE_DEFCONFIG" and baseline.get(k) != actual.get(k)}
    if differences != expected or actual.get("CONFIG_USEC_PER_TICK") != "1000000" or actual.get("CONFIG_RR_INTERVAL") != "0" or \
            actual.get("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ") != "240" or actual.get("CONFIG_SMP") == "y" or \
            actual.get("CONFIG_CANCELLATION_POINTS") == "y" or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("NuttX native profile changed beyond declared app/timer/stack-coloring configuration")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc -c ")]
    units = ("original.c", "port.c", *(n for n in NATIVE if n.endswith(".c")), EXTRA)
    for name in units:
        if name in ("original.c", "port.c"): file, scope = name, "/apps/examples/riot_yield/"
        elif name.startswith("libs/libc/"): file, scope = name[10:], "/nuttx/libs/libc"
        elif name.startswith("sched/"): file, scope = name[6:], "/nuttx/sched"
        else: file, scope = name.replace("arch/xtensa/src/esp32/", "chip/").replace("arch/xtensa/src/", ""), "/nuttx/arch/xtensa/src"
        selected = [args for args in commands if file in args and any(scope in arg for arg in args)]
        if len(selected) != 1 or [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dthread_yield")) for a in selected[0]) or \
                (name == "original.c" and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("NuttX actual original/native compilation differs: " + name)
    control = machine(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    captures = []
    if full:
        check_manifest(directory, "capture.sha256")
        expected_capture = {f"reset{i}.{suffix}" for i in (1, 2, 3) for suffix in ("jsonl", "raw")} | {
            "flash.log", "board-check.log", "image-check.log", "runner.sh", "capture_esp32_uart.py", "image.sha256",
            "yield-control.sha256", "official-source.json"}
        if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected_capture:
            raise ValueError("NuttX original capture inventory coverage differs")
        audit_flash(directory, "flash.log", 3)
        for archive, source in (("runner.sh", "run_esp32_riot_yield_nuttx.sh"), ("capture_esp32_uart.py", "capture_esp32_uart.py")):
            if (directory / archive).read_bytes() != (ROOT / "tools" / source).read_bytes():
                raise ValueError("NuttX prepared/used capture tool differs")
        captures = [capture(directory, i) for i in (1, 2, 3)]
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("NuttX original boots overlap")
    elif (directory / "capture.sha256").exists() or list(directory.glob("reset*.jsonl")):
        raise ValueError("NuttX build-only audit cannot silently ignore board captures")
    return {"benchmark": "RIOT thread_yield_pingpong original program / native NuttX adapter", "os": "NuttX",
            "built": True, "measured": full, "measurement_eligible": full, "board_boots": len(captures),
            "ranking_eligible": False, "new_metric_created": False, "original_test_body_unchanged": True,
            "original_nominal_duration_us": 1000000, "clock_mhz": 240, "cores": 1, "tick_hz": 1,
            "compiler": "GCC 13.2.0", "optimization": "Os", "native_equal_worker_priority": 150,
            "official_native_files_checked": len(NATIVE) + 1, "actual_compiled_units_checked": len(units),
            "machine_control": control, "captures": captures, "energy_measured": False, "runtime_ram_peak_measured": False,
            "application_elf_sha256": digest(directory / "application.elf"), "application_bin_sha256": digest(directory / "application.bin"),
            "prepared_capture_runner_sha256": digest(ROOT / "tools/run_esp32_riot_yield_nuttx.sh"),
            "base_defconfig_labels": [baseline["CONFIG_BASE_DEFCONFIG"], actual["CONFIG_BASE_DEFCONFIG"]],
            "boundary": "Original nominal one-second main-thread yield count/ticks formula, not isolated latency. Native FIFO pthreads, "
                "1-us hardware TIMER2/direct IRQ callback, native stack coloring (not RIOT marker pattern), cleanup outside original return. "
                "Reserved timer channel remains until reset; no full peripheral/heap cleanup claim. Native ABI/stack ownership, "
                "tick, compiler, code layout and console/background differ from RIOT/other ports. No board/energy/RAM result from a build."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream, args.full), indent=2) + "\n"
    if args.output: args.output.write_text(result)
    else: print(result, end="")
