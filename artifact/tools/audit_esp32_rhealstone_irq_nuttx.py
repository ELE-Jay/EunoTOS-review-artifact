#!/usr/bin/env python3
"""Replay NuttX's original one-shot IRQ with the native IRQ-ABI bridge retained."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
import struct
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile

from audit_esp32_rhealstone_irq import ROOT, PORT, BASE, OFFICIAL, GUARD, original_formula
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_rhealstone_irq_control import FUNCTIONS, NORETURN as BASE_NORETURN

UPSTREAM = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"
NATIVE = ("arch/xtensa/src/esp32/esp32_irq.c", "arch/xtensa/src/esp32/esp32_irq.h",
    "arch/xtensa/src/esp32/esp32_clockconfig.c", "arch/xtensa/src/esp32/esp32_timerisr.c",
    "arch/xtensa/src/common/xtensa_irqdispatch.c", "arch/xtensa/src/common/xtensa.h",
    "sched/irq/irq_attach.c", "sched/irq/irq_dispatch.c", "sched/task/task_create.c",
    "sched/task/exit.c", "libs/libc/stdlib/lib_exit.c", "sched/sched/sched_getparam.c",
    "sched/sched/sched_getscheduler.c", "sched/sched/sched_lock.c")
EXTRA = ("native_isr", "rhealstone_main")
NORETURN = BASE_NORETURN + ("exit",)
BEGIN = "RHEALSTONE BEGIN RHILATENCY NuttX clock=240 cores=1 tick=100 timer=ccount unit=cycles"
COMPLETE = "RHEALSTONE IRQ COMPLETE actual_irqs=1 detached=1 teardown_called=1 original_iterations=1"


def verify_official(directory):
    rows = []
    for name in NATIVE:
        with urlopen(UPSTREAM + name, timeout=60) as response:
            data = response.read()
        if data != (directory / "native-source" / name).read_bytes():
            raise ValueError(("NuttX fixed official native source differs", name))
        rows.append({"path": name, "url": UPSTREAM + name, "sha256": hashlib.sha256(data).hexdigest()})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "NuttShell (NSH)",
        "RHEALSTONE IRQ SOURCE peripheral=26 requested_level=1 cpu=0 input=1 low_priority=100", COMPLETE, "RHEALSTONE END")
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "RHEALSTONE END" or lines.count("rhealstone") != 1 or \
            any(re.search(r"FAIL|panic|ASSERT|watchdog|Brownout|Error ==> ", line, re.I) for line in lines):
        raise ValueError("NuttX original IRQ reset/command/source/completion differs")
    values = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (-?\d+)", line))]
    trace = [list(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+) value2=(\d+)", line))]
    if len(values) != 1 or len(trace) != 1 or any(not 0 < value < 2**32 for value in trace[0]) or \
            trace[0][2] <= trace[0][1] or values[0] <= 0 or original_formula(trace[0], 1, (2, 1, None)) != values[0]:
        raise ValueError("NuttX original single-shot trace/subtraction differs")
    order = [lines.index(BEGIN), lines.index(required[2]),
        next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: Interrupt Latency - ")),
        lines.index(COMPLETE), next(i for i, line in enumerate(lines) if line.startswith("RHEALSTONE TIMER_READS ")),
        lines.index("RHEALSTONE END")]
    if order != sorted(order):
        raise ValueError("NuttX original IRQ phase order differs")
    return {"original_single_shot_cycles": values[0], "timer_reads_cycles": trace[0], "actual_irqs": 1,
        "original_iterations": 1, "native_irq_detach_succeeded": True, "native_irq_teardown_called": True,
        "start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def excluded_diagnostics(directory, proof):
    previous = ROOT / "artifacts/reports/rhealstone-irq-nuttx-v3"
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(previous, name)
    audit_elf_image(previous / "application.elf", previous / "application.bin")
    current = (directory / "port.c").read_text()
    new = '    printf("RHEALSTONE TIMER_READS count=3 value0=%lu value1=%lu value2=%lu\\nRHEALSTONE END\\n",\n        (unsigned long)reads[0], (unsigned long)reads[1], (unsigned long)reads[2]);'
    if current.count(new) != 1 or (previous / "port.c").read_text() != current.replace(new, "    legacy_rh_end();") or \
            digest(previous / "application.bin") == digest(directory / "application.bin"):
        raise ValueError("NuttX diagnostic-only version change differs")
    old_config = (previous / "config").read_text().splitlines()
    new_config = (directory / "config").read_text().splitlines()
    prefix = "CONFIG_BASE_DEFCONFIG="
    labels = [line for lines in (old_config, new_config) for line in lines if line.startswith(prefix)]
    if len(labels) != 2 or any(not re.fullmatch(r'CONFIG_BASE_DEFCONFIG="esp32-devkitc:nsh(?:-dirty)+"', line) for line in labels) or \
            [line for line in old_config if not line.startswith(prefix)] != [line for line in new_config if not line.startswith(prefix)]:
        raise ValueError("NuttX diagnostic runtime configuration differs")
    for name in ("ported-ilatency.c", "native_rhealstone_port.c"):
        if (previous / name).read_bytes() != (directory / name).read_bytes():
            raise ValueError("NuttX excluded version configuration/measurement body differs")
    for row in proof:
        if digest(previous / "native-source" / row["path"]) != row["sha256"]:
            raise ValueError("NuttX excluded native version differs")
    with (previous / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        read_control_rows((previous / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, elf.get_section_by_name(".symtab"), set(FUNCTIONS + EXTRA), noreturn=NORETURN)
    observations = []
    for index in (1, 2, 3):
        rows = read_raw_capture(previous, index)
        lines = [row["line"] for row in rows]
        result = [int(m[1]) for line in lines if (m := re.fullmatch(r"Rhealstone: Interrupt Latency - (\d+)", line))]
        trace = [list(map(int, m.groups())) for line in lines if (m := re.fullmatch(
            r"RHEALSTONE TIMER_READS count=3 value0=(\d+) value1=(\d+)nsh>  value2=(\d+)\x1b\[K", line))]
        if len(result) != 1 or len(trace) != 1 or lines.count(BEGIN) != 1 or lines.count(COMPLETE) != 1 or \
                original_formula(trace[0], 1, (2, 1, None)) != result[0]:
            raise ValueError("NuttX excluded prompt-interleaving diagnostic differs")
        observations.append({"raw_original_output_cycles": result[0], "timer_reads_cycles": trace[0],
            "raw_sha256": digest(previous / f"reset{index}.raw"), "measurement_eligible": False})
    failed = []
    for version, error in (("v1", "fatal error: xtensa_attr.h: No such file or directory"),
                           ("v2", "undefined reference to `Isr_handler'")):
        path = ROOT / "artifacts/reports" / ("rhealstone-irq-nuttx-" + version)
        if error not in (path / "build.log").read_text() or (path / "flash.log").exists():
            raise ValueError("NuttX failed-build/no-flash record differs")
        failed.append({"version": version, "build_log_sha256": digest(path / "build.log"), "flash_record_exists": False})
    return {"failed_builds": failed, "v3_diagnostic_boots": observations,
        "v3_image_sha256": digest(previous / "application.bin"),
        "configuration_label_difference": labels, "runtime_configuration_unchanged": True,
        "interpretation": "three prompt-interleaved diagnostic boots excluded; after-measurement output and nonruntime dirty build-label changes also change image layout; different first-IRQ outputs have unresolved cache/layout/shell causes, not an OS improvement"}


def audit(directory):
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    for name, (_, sha) in OFFICIAL.items():
        if digest(directory / "source" / name) != sha:
            raise ValueError("original Rhealstone source differs")
    original = (directory / "source/ilatency.c").read_text()
    if original.count(GUARD) != 1 or (directory / "ported-ilatency.c").read_text() != \
            original.replace(GUARD, "    !rh_native_priority_scheduler()"):
        raise ValueError("native guard patch changed original measurement body")
    for saved, current in (("port.c", PORT / "nuttx/port.c"), ("native_rhealstone_port.c", BASE / "nuttx/port.c"),
            ("Makefile", PORT / "nuttx/Makefile"), ("Kconfig", BASE / "nuttx/Kconfig"), ("Make.defs", BASE / "nuttx/Make.defs"),
            ("scheduler-guard.patch", PORT / "scheduler-guard.patch"),
            ("build_esp32_rhealstone_irq_nuttx.sh", ROOT / "tools/build_esp32_rhealstone_irq_nuttx.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_irq_nuttx.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError(("NuttX original IRQ adapter/build/acquisition differs", saved))
    for source in (BASE / "include", PORT / "include"):
        for path in source.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / "include" / path.relative_to(source)).read_bytes():
                raise ValueError("NuttX original IRQ header differs")
    if (directory / "include/timesys.h").read_bytes() != (directory / "source/timesys.h").read_bytes():
        raise ValueError("NuttX original formula include differs")
    collector = (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text().replace(
        'directory = root / "downloads/rhealstone-irq-freertos-v1"', 'directory = root / "downloads/rhealstone-irq-nuttx-v4"')
    collector = collector.replace('NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")',
        'NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail", "exit")')
    collector = collector.replace("for name in FUNCTIONS:", 'for name in FUNCTIONS + ("native_isr", "rhealstone_main"):')
    if (directory / "collect-irq-control.py").read_text() != collector or \
            {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != \
            {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("NuttX original/native control coverage differs")
    proof = json.loads((directory / "official-native-source.json").read_text())
    if len(proof) != len(NATIVE) or {row["path"] for row in proof} != set(NATIVE) or any(
            row["url"] != UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"] for row in proof):
        raise ValueError("NuttX fixed native source differs")
    config = set((directory / "config").read_text().splitlines())
    required = {"CONFIG_BUILD_FLAT=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_USEC_PER_TICK=10000",
        "CONFIG_RR_INTERVAL=0", "CONFIG_PRIORITY_INHERITANCE=y", "CONFIG_SIG_DEFAULT=y",
        "CONFIG_SIG_SIGSTOP_ACTION=y", "CONFIG_EXAMPLES_RHEALSTONE=y"}
    if not required <= config or any(flag + "=y" in config for flag in
            ("CONFIG_SMP", "CONFIG_SCHED_TICKLESS", "CONFIG_EXAMPLES_HARTSTONE")) or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("NuttX actual native scheduler/clock/core/tick/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compiled = ("port.c", "original.c", *(name for name in NATIVE if name.endswith(".c")))
    for name in compiled:
        selected = [args for args in commands if any(Path(arg).name == Path(name).name for arg in args if not arg.startswith("-"))]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("NuttX original/native actual compilation differs", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, set(FUNCTIONS + EXTRA), noreturn=NORETURN)
        for source, target, count in (("Init", "rh_native_priority_scheduler", 1), ("Init", "benchmark_timer_initialize", 2),
                ("Init", "benchmark_timer_read", 2), ("Task_1", "benchmark_timer_initialize", 1),
                ("Task_1", "rh_cause_irq", 1), ("Isr_handler", "benchmark_timer_read", 1), ("Isr_handler", "rh_clear_irq", 1),
                ("rh_install_irq", "esp32_setup_irq", 1), ("rh_install_irq", "irq_attach", 1),
                ("rh_install_irq", "up_enable_irq", 1), ("rh_end", "irq_attach", 1), ("rh_end", "up_disable_irq", 1),
                ("rh_end", "esp32_teardown_irq", 1), ("rtems_task_start", "task_create", 1),
                ("rtems_task_exit", "exit", 1), ("rh_native_priority_scheduler", "esp_clk_cpu_freq", 1),
                ("rh_native_priority_scheduler", "sched_getparam", 1), ("rh_native_priority_scheduler", "sched_getscheduler", 1),
                ("rh_native_priority_scheduler", "sched_lockcount", 1)):
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$",
                "\n".join(control[source].values()), re.M)
            if len(rows) != count:
                raise ValueError(("NuttX original/native encoded call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("NuttX encoded native call differs")
        for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if not any("rsr.ccount" in row for row in control[name].values()):
                raise ValueError("NuttX native CCOUNT instruction differs")
        for source, expected in (("rh_cause_irq", 0x3ff000e4), ("rh_clear_irq", 0x3ff000e4),
                ("Task_1", symbols.get_symbol_by_name("Isr_handler")[0]["st_value"]),
                ("rh_install_irq", symbols.get_symbol_by_name("native_isr")[0]["st_value"]),
                ("rh_install_irq", symbols.get_symbol_by_name("original_handler")[0]["st_value"]),
                ("native_isr", symbols.get_symbol_by_name("original_handler")[0]["st_value"]),
                ("rh_clear_irq", symbols.get_symbol_by_name("g_current_regs")[0]["st_value"]),
                ("rh_native_priority_scheduler", (-240000000) % 2**32)):
            matched = False
            for row in control[source].values():
                m = re.match(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+\w+, ([0-9a-f]+) <", row)
                if not m:
                    continue
                address, code, literal = (int(value, 16) for value in m.groups())
                if code & 0xf != 1 or ((address + 3) & ~3) + ((code >> 8) | -65536) * 4 != literal:
                    raise ValueError("NuttX encoded IRQ literal address differs")
                sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                    s["sh_addr"] <= literal and literal + 4 <= s["sh_addr"] + s["sh_size"]]
                if len(sections) != 1:
                    raise ValueError("NuttX IRQ literal not mapped to ELF")
                matched |= struct.unpack_from("<I", sections[0].data(), literal - sections[0]["sh_addr"])[0] == expected
            if not matched:
                raise ValueError(("NuttX original/native IRQ pointer/register/clock binding missing", source))
        bridge = list(control["native_isr"].values())
        callback = [row for row in bridge if re.search(r"\bcallx8\s+a8$", row)]
        if len(callback) != 1 or not re.search(r": 0008e0 callx8\s+a8$", callback[0]) or \
                not any("l32i.n\ta8, a8, 0" in row for row in bridge) or \
                not any("s32i.n\ta2, a9, 0" in row for row in control["rh_install_irq"].values()) or \
                any(re.search(r"\b(?:b[\w.]+|call8)\b", row) for row in bridge[:bridge.index(callback[0])]):
            raise ValueError("NuttX measured native callback bridge or post-timestamp checks differ")
    footprint = audit_cell(directory, "NuttX", "rhealstone-single-irq", observation=True, recursive_manifest=True)
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("NuttX original IRQ independent resets overlap")
    values = [row["original_single_shot_cycles"] for row in captures]
    diagnostics = excluded_diagnostics(directory, proof)
    return {"audit": "pass", "os": "NuttX", "resets": 3, "metric_count": 1, "original_iterations": 1,
        "original_single_shot_cycles": values, "median_of_three_single_shots_us": statistics.median(values) / 240,
        "original_measurement_body_preserved": True, "native_scheduler_guard_adapted": True,
        "unmodified_official_source": False, "native_source_files": len(NATIVE), "reachable_functions": 17,
        "actual_native_compiled_units_checked": len(compiled), "native_source_identity": proof,
        "native_source_proof_sha256": digest(directory / "official-native-source.json"), "captures": captures, "footprint": footprint,
        "native_irq_source": 26, "native_irq_input": 1, "native_worker_priority": 100,
        "native_irq_abi_bridge_cost_retained": True, "general_irq_cleanup_state_independently_read": False,
        "ranking_eligible": False, "external_gpio_interrupt_entry_measured": False,
        "excluded_failed_build_versions": ["v1", "v2"], "excluded_prompt_interleaving_diagnostic_boots": 3,
        "excluded_version_evidence": diagnostics,
        "boundary": "original one CPU software IRQ per boot, not unused 50000 macro, mean or worst case; RTEMS table guard replaced with actual FIFO/unlocked/Init110/240MHz admission, original worker254 maps to native100, 100Hz/single-core/no round robin; native three-argument IRQ ABI bridge calls the original supplied static handler, pointer loads/call and native dispatch/cache costs retained, all context/count branches after timestamp; source26/level1/input1, successful detach and void teardown execution checked, no private IRQ/free-list state independent read; native NSH remains in profile, measured diagnostic line emitted once after IRQ to avoid interleaving; v1/v2 build failures unflashed, v3 three prompt-interleaved boots diagnostic only; no external GPIO, controlled-cache cross-OS rank or general task/heap cleanup claim"}


def render_table(result):
    if result["audit"] != "pass" or result["resets"] != 3 or result["original_iterations"] != 1:
        raise ValueError("incomplete NuttX original one-shot IRQ cohort")
    return "\n".join(("| Original Rhealstone IRQ port / OS | Original single-shot cycles (three boots) | Approximate single-shot us (three boots) |",
        "| --- | --- | --- |", "| Original IRQ port / NuttX | " + " / ".join(map(str, result["original_single_shot_cycles"])) +
        " | " + " / ".join(f"{value / 240:.3f}" for value in result["original_single_shot_cycles"]) + " |"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-official", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_official:
        verify_official(args.directory)
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
