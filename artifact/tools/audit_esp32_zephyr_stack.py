#!/usr/bin/env python3
"""Replay the unchanged Zephyr bounded-stack kernel cases through native FreeRTOS queues."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_cell, audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_thread import ROOT, REFERENCE, SHARED, NATIVE, UPSTREAM, ZEPHYR_UPSTREAM, read_raw_capture, read_control_rows
from audit_esp32_zephyr_original import LATENCY
from collect_esp32_zephyr_stack_control import FUNCTIONS

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_stack"
BASE = ROOT / "firmware/bsp/esp32/zephyr_latency_yield"
ORIGINALS = ("stack.c", "timing_sc.c", "timing_sc.h", "utils.h")
TAGS = ("stack.push.immediate.kernel", "stack.pop.immediate.kernel",
        "stack.pop.blocking.k_to_k", "stack.push.wake+ctx.k_to_k")
BEGIN = "STACK PORT BEGIN FreeRTOS Zephyr-3.7.0-subset iterations=1000 clock=240 cores=1 tick=1 stack=1792 slots=16 item_bytes=4"


def capture(directory, index, elf_sha):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    if lines.count(BEGIN) != 1 or lines.count("STACK PORT END") != 1 or lines[-1] != "STACK PORT END" or \
            sum(line.startswith("rst:0x") for line in lines) != 1 or \
            sum("2nd stage bootloader" in line for line in lines) != 1 or \
            sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or \
            sum("Single core mode" in line for line in lines) != 1 or \
            sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
            not any("ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines) or \
            any(re.search(r"PORT FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("stack reset/profile/completion/image binding differs")
    self_check = "STACK NATIVE SELF_CHECK capacity=16 item_bytes=4 lifo=16 empty=1 full=1"
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines.count(self_check) != 1 or \
            lines.index(self_check) >= lines.index(BEGIN) or \
            lines.count("STACK NATIVE RETIRE before=3 after=3 pending=0") != 1:
        raise ValueError("native bounded LIFO or registry/drain witness missing")
    overheads = [int(m[1]) for line in lines if
                 (m := re.fullmatch(r"YIELD ORIGINAL TIMESTAMP_OVERHEAD (\d+) cycles", line))]
    if len(overheads) != 1 or not 0 < overheads[0] < 2 ** 32:
        raise ValueError("original stack timestamp calibration differs")
    pending_raw = pending_input = None
    metrics = {}
    for line in lines:
        if match := re.fullmatch(r"YIELD ORIGINAL RAW cycles=(\d+) overhead=(\d+)", line):
            if pending_raw is not None or pending_input is not None:
                raise ValueError("unbound stack calibration record")
            pending_raw = tuple(map(int, match.groups()))
        elif match := re.fullmatch(r"YIELD ORIGINAL INPUT numerator=(\d+) count=(\d+)", line):
            if pending_input is not None:
                raise ValueError("unbound stack mean input")
            pending_input = tuple(map(int, match.groups()))
        elif match := LATENCY.fullmatch(line):
            tag, _, cycles, ns = match.groups()
            if tag not in TAGS or tag in metrics or pending_input is None:
                raise ValueError("original stack metric/input binding differs")
            numerator, count = pending_input
            immediate = tag in TAGS[:2]
            if count != 1000 or not 0 < numerator < 2 ** 32 or \
                    int(cycles) != numerator // count or int(ns) != numerator * 1000 // 240 // count or \
                    (immediate and (pending_raw is None or not 0 < pending_raw[0] < 2 ** 32 or pending_raw[1] != overheads[0] or
                                    pending_raw[0] - pending_raw[1] != numerator)) or \
                    (not immediate and pending_raw is not None):
                raise ValueError("original stack mean/subtraction formula differs")
            metrics[tag] = {"mean_cycles": int(cycles), "mean_ns": int(ns), "numerator": numerator,
                            "iterations": count, "raw_calibration_input": pending_raw,
                            "timestamp_overhead_subtracted": immediate}
            pending_raw = pending_input = None
    if tuple(metrics) != TAGS or pending_raw is not None or pending_input is not None:
        raise ValueError("original stack cases incomplete or reordered")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "metrics": metrics,
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory):
    directory = directory.resolve()
    for name in ("image.sha256", "capture.sha256", "stack-control.sha256"):
        check_manifest(directory, name)
    names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}
    required = {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "compiler.txt",
                "compile_commands.json", "build.log", "port.c", "native_thread_port.c", "build-script.sh",
                "include/zephyr/kernel.h", "include/zephyr/native_thread_kernel.h", "FreeRTOSConfig.h", "disassembly.txt",
                *("source/" + name for name in ORIGINALS), *("native-source/" + name for name in NATIVE["freertos"])}
    if not required <= names:
        raise ValueError("original stack native/source/image binding incomplete")
    names = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
            *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= names:
        raise ValueError("stack acquisition coverage incomplete")
    proof = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in ORIGINALS:
        if proof["src/" + name]["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["src/" + name]["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("published original stack body/statistics changed")
    for archived, expected in (("port.c", PORT / "port.c"), ("include/zephyr/kernel.h", PORT / "include/zephyr/kernel.h"),
                              ("native_thread_port.c", BASE / "port.c"),
                              ("include/zephyr/native_thread_kernel.h", BASE / "include/zephyr/kernel.h"),
                              ("build-script.sh", ROOT / "tools/build_esp32_zephyr_stack_freertos.sh"),
                              ("runner.sh", ROOT / "tools/run_esp32_zephyr_stack_freertos.sh"),
                              ("capture_esp32_uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / archived).read_bytes() != expected.read_bytes():
            raise ValueError("stack native adapter/build/acquisition differs")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                path.read_bytes() != (directory / "include" / path.relative_to(SHARED)).read_bytes():
            raise ValueError("stack shared timing/format adapter differs")
    for path in (PORT / "freertos").rglob("*"):
        if path.is_file() and path.read_bytes() != (directory / "build-files" / path.relative_to(PORT / "freertos")).read_bytes():
            raise ValueError("stack application recipe differs")
    native_proof = json.loads((ROOT / "artifacts/reports/zephyr-yield-freertos-v1/official-native-source.json").read_text())
    if {row["path"] for row in native_proof} != set(NATIVE["freertos"]) or any(
            row["url"] != UPSTREAM["freertos"] + row["path"] or row["sha256"] != digest(directory / "native-source" / row["path"])
            for row in native_proof):
        raise ValueError("stack fixed native kernel differs from verified source")
    config = (directory / "config").read_text()
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y",
            "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000"} <= set(config.splitlines()) or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (ROOT / "artifacts/reports/zephyr-yield-freertos-v1/FreeRTOSConfig.h").read_bytes() or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("stack native clock/core/FIFO/tick/compiler profile differs")
    commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    for name in ("app-freertos/port.c", "app-freertos/stack.c", "app-freertos/timing_sc.c", *NATIVE["freertos"]):
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                (name.startswith("app-") and "-DTHREAD_OS_FREERTOS" not in selected[0]):
            raise ValueError("original stack/native application compilation differs")
    names = {line.split(maxsplit=1)[1] for line in (directory / "stack-control.sha256").read_text().splitlines()}
    if names != {"application.elf", "image.sha256", "capture.sha256", "stack-control-flow.txt", "collect-stack-control.py"} or \
            (directory / "collect-stack-control.py").read_bytes() != (ROOT / "tools/collect_esp32_zephyr_stack_control.py").read_bytes():
        raise ValueError("stack reachable branch supplement/image binding differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(symbols.get_symbol_by_name(name) for name in ("unused_original_yield_app_main", "run_original", "thread_switch_yield")):
            raise ValueError("unused prior workload entry remains in the new stack image")
        control = read_control_rows((directory / "stack-control-flow.txt").read_text(), "STACK CONTROL", elf, symbols, set(FUNCTIONS))

        def calls(source, target, count):
            text = "\n".join(control[source].values())
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$", text, re.M)
            if len(rows) != count:
                raise ValueError(("stack original/native call coverage differs", source, target))
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("stack native call encoded target differs")

        for source, target, count in (("stack_push_pop_thread_entry", "k_stack_push", 1),
                ("stack_push_pop_thread_entry", "k_stack_pop", 1), ("start_thread_entry", "k_stack_push", 1),
                ("alt_thread_entry", "k_stack_pop", 1), ("stack_ops", "timing_cycles_to_ns_avg", 2),
                ("stack_ops", "__wrap_timestamp_overhead_adjustment", 2),
                ("stack_blocking_ops", "timing_cycles_to_ns_avg", 2), ("stack_blocking_ops", "k_thread_create", 2),
                ("k_stack_init", "xQueueGenericCreateStatic", 1), ("k_stack_push", "xQueueGenericSend", 1),
                ("k_stack_pop", "xQueueReceive", 1), ("k_thread_create", "xTaskCreateStaticPinnedToCore", 1),
                ("k_thread_start", "xTaskGenericNotify", 1), ("k_thread_join", "xQueueSemaphoreTake", 1),
                ("k_thread_join", "k_thread_abort", 1), ("k_thread_abort", "vTaskDelete", 1)):
            calls(source, target, count)
        push = "\n".join(control["k_stack_push"].values())
        if not re.search(r"01a0d2\s+movi\s+a13, 1\b", push):
            raise ValueError("native queue push is not the encoded front-insertion operation")
        if "__wrap_timestamp_overhead_adjustment" in "\n".join(control["stack_blocking_ops"].values()):
            raise ValueError("original blocking stack case acquired invented timestamp subtraction")
        disassembly = (directory / "disassembly.txt").read_text()
        body = re.search(r"^[0-9a-f]+ <z_impl_timing_timestamp_get>:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
        if not body or not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body[1]):
            raise ValueError("stack original timestamp does not read native CCOUNT")
    footprint = audit_cell(directory, "FreeRTOS", "zephyr-original-bounded-stack", observation=True, recursive_manifest=True)
    captures = [capture(directory, index, footprint["elf_sha256"]) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("stack independent reset captures overlap")
    return {"audit": "pass", "os": "FreeRTOS", "resets": 3, "metric_count": 4, "original_iterations": 1000,
            "original_test_body_unchanged": True, "native_source_files": 4, "footprint": footprint,
            "captures": captures, "metrics": {tag: {"means_ns": [row["metrics"][tag]["mean_ns"] for row in captures]} for tag in TAGS},
            "ranking_eligible": False, "unmodified_official_native_suite": False, "native_dedicated_k_stack_implementation": False,
            "full_lifo_object_suite_eligible": False, "excluded_initial_configuration": "v1: missing component scope; not compiled or flashed",
            "boundary": "four unchanged original Zephyr bounded-stack kernel cases, 16 four-byte slots, 1000 iterations; only two immediate cases subtract timestamp calibration; native FreeRTOS static queue send-to-front/receive, copying and waiter wake path costs retained, not Zephyr direct waiter delivery or a dedicated FreeRTOS stack object; existing task/format/timing adapter reused; native registry restores 3 to 3 and stack drains; no general heap cleanup, user mode, full native suite or cross-OS rank; 240 MHz/one core/1-Hz/FIFO/GCC13.2/Os/1792-byte workers"}


def render_table(result):
    if result.get("audit") != "pass" or result.get("resets") != 3 or tuple(result.get("metrics", {})) != TAGS:
        raise ValueError("cannot render an incomplete original bounded-stack subset")
    rows = ["| Original Zephyr bounded-stack subset / OS | Original case | Original means, ns (three boots) |", "| --- | --- | --- |"]
    for tag in TAGS:
        rows.append(f"| Original bounded-stack port / FreeRTOS / {tag} | {tag} | " +
                    " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
