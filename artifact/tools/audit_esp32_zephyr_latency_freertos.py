#!/usr/bin/env python3
"""Replay six original Zephyr latency cases through the inspected FreeRTOS adapter."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_original import LATENCY, UPSTREAM

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos"
REFERENCE = ROOT / "artifacts/reports/zephyr-original-v1/latency_measure"
SOURCES = ("sema_test_signal_release.c", "mutex_lock_unlock.c", "timing_sc.c", "timing_sc.h", "utils.h")
TAGS = ("semaphore.give.immediate.kernel", "semaphore.take.immediate.kernel",
        "semaphore.take.blocking.k_to_k", "semaphore.give.wake+ctx.k_to_k",
        "mutex.lock.immediate.recursive.kernel", "mutex.unlock.immediate.recursive.kernel")
INPUT = re.compile(r"LATENCY ORIGINAL INPUT numerator=(\d+) count=(\d+) raw=(\d+) overhead=(\d+)")
BEGIN = "LATENCY PORT BEGIN FreeRTOS Zephyr-3.7.0-subset iterations=1000 clock=240 cores=1 tick=1 stack=1792"


def capture(directory, index, elf_sha, native_os="FreeRTOS"):
    path = directory / f"reset{index}.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    raw = (directory / f"reset{index}.raw").read_bytes()
    position = 0
    for row in rows:
        chunk = raw[position:position + row["raw_bytes"]]
        if row["raw_bytes"] <= 0 or hashlib.sha256(chunk).hexdigest() != row["raw_sha256"] or \
                chunk.decode("utf-8", errors="replace").rstrip("\r\n") != row["line"]:
            raise ValueError("raw UART byte/decoded record binding differs")
        position += row["raw_bytes"]
    if position != len(raw):
        raise ValueError("raw UART coverage incomplete")
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("native capture chronology differs")
    begin = BEGIN.replace("FreeRTOS", native_os)
    stage_valid = sum("2nd stage bootloader" in line for line in lines) == 1
    if native_os == "FreeRTOS":
        boot_valid = sum("main_task: Calling app_main()" in line for line in lines) == 1 and \
            sum("cpu freq: 240000000 Hz" in line for line in lines) == 1 and \
            any("ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines)
    elif native_os == "NuttX":
        boot_valid = lines.count("NuttShell (NSH) NuttX-12.2.1") == 1 and \
            lines.count("LATENCY NATIVE VERSION NuttX 12.2.1") == 1
    elif native_os == "RIOT":
        boot_valid = lines.count("Single core mode") == 1 and \
            lines.count("main(): This is RIOT! (Version: 2024.10-devel)") == 1
        begin = begin.replace("tick=1", "tick=native-tickless")
        stage_valid = lines.count("Pro cpu up.") == 1
    elif native_os == "AliOS-Rhino":
        boot_valid = lines.count("Welcome to AliOS Things") == 1 and \
            sum("Starting scheduler on PRO CPU. no wdt" in line for line in lines) == 1 and \
            lines.count("LATENCY NATIVE TICK divisor=240000000") == 1
        stage_valid = lines.count("bootload image") == 1
    else:
        raise ValueError("unsupported native latency adapter")
    if lines.count(begin) != 1 or lines[-1] != "LATENCY PORT END" or \
            lines.count("LATENCY PORT END") != 1 or sum("rst:0x" in line for line in lines) != 1 or \
            not stage_valid or not boot_valid or \
            any(re.search(r"LATENCY PORT FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("native reset/profile/completion/ELF binding differs")
    overheads = [int(m[1]) for line in lines if (m := re.fullmatch(r"LATENCY ORIGINAL TIMESTAMP_OVERHEAD (\d+) cycles", line))]
    if len(overheads) != 1 or overheads[0] <= 0:
        raise ValueError("original timestamp calibration missing")
    pending, metrics = None, {}
    for line in lines:
        if match := INPUT.fullmatch(line):
            if pending is not None:
                raise ValueError("unbound original average input")
            pending = dict(zip(("numerator", "count", "raw", "overhead"), map(int, match.groups())))
        elif match := LATENCY.fullmatch(line):
            tag, _, cycles, ns = match.groups()
            if pending is None or tag in metrics or tag not in TAGS or pending["count"] != 1000 or pending["overhead"] != overheads[0]:
                raise ValueError("original metric/input/count binding differs")
            corrected = ".blocking." in tag or ".wake+ctx." in tag
            # Mutex lock keeps a local total while the resumed worker publishes unlock.
            expected = pending["raw"] - pending["overhead"] if corrected else pending["numerator"]
            if not corrected and tag != "mutex.lock.immediate.recursive.kernel" and pending["raw"] != expected:
                raise ValueError("original shared timestamp differs from operation total")
            if expected <= 0 or pending["numerator"] != expected or expected >= 2 ** 32 or \
                    int(cycles) != expected // 1000 or int(ns) != expected * 1000 // 240 // 1000:
                raise ValueError("original numerator/overhead/average formula differs or wraps")
            metrics[tag] = {"mean_cycles": int(cycles), "mean_ns": int(ns), "original_input": pending}
            pending = None
    if pending is not None or tuple(metrics) != TAGS:
        raise ValueError("original selected cases incomplete or reordered")
    if metrics[TAGS[-2]]["original_input"]["raw"] != metrics[TAGS[-1]]["original_input"]["numerator"]:
        raise ValueError("original mutex shared timestamp handoff differs")
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "metrics": metrics,
            "uart_sha256": digest(path), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= covered:
        raise ValueError("native acquisition coverage incomplete")
    original = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in SOURCES:
        proof = original["src/" + name]
        if proof["url"] != UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original selected source differs")
    for path in PORT.rglob("*"):
        if path.is_file() and (directory / path.relative_to(PORT)).read_bytes() != path.read_bytes():
            raise ValueError("native adapter differs from inspected implementation")
    config = set((directory / "config").read_text().splitlines())
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y",
            "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000"} <= config or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native compiler/clock/tick/watchdog profile differs")
    header = (directory / "FreeRTOSConfig.h").read_text()
    if not re.search(r"#define configUSE_PREEMPTION\s+1", header) or not re.search(r"#define configUSE_TIME_SLICING\s+0", header):
        raise ValueError("native scheduler profile differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for name in SOURCES[:3]:
        selected = [row for row in commands if Path(row["file"]).name == name]
        if len(selected) != 1 or "/tests/benchmarks/latency_measure/src/" not in selected[0]["file"] or \
                "/zephyr-latency-freertos/include" not in selected[0]["command"]:
            raise ValueError("original timed body not compiled through inspected adapter")
    for name in ("queue.c", "tasks.c"):
        selected = [row for row in commands if Path(row["file"]).name == name]
        if len(selected) != 1 or "/tm-cooperative-no-timeslicing/freertos/FreeRTOS-Kernel/" not in selected[0]["file"] or \
                "/tm-cooperative-no-timeslicing/freertos/config/include" not in selected[0]["command"] or \
                " -Os " not in selected[0]["command"]:
            raise ValueError("native kernel/scheduler override not actually compiled")
    audit_elf_image(directory / "zephyr_latency_port.elf", directory / "zephyr_latency_port.bin")
    with (directory / "zephyr_latency_port.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = {symbol.name: symbol for symbol in elf.get_section_by_name(".symtab").iter_symbols()}
        for name in ("sema_test_signal", "sema_context_switch", "mutex_lock_unlock", "z_impl_timing_timestamp_get",
                     "k_sem_give", "k_sem_take", "k_mutex_lock", "k_mutex_unlock"):
            if name not in symbols or not symbols[name]["st_size"] or symbols[name]["st_shndx"] == "SHN_UNDEF":
                raise ValueError("original/native operation entry not linked")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("zephyr_latency_port.bin", 0x10000))]:
        raise ValueError("native installed image/board binding differs")
    captures = [capture(directory, i, digest(directory / "zephyr_latency_port.elf")) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure semaphore/recursive-mutex subset",
            "os": "FreeRTOS/ESP-IDF 5.2.5", "resets": 3, "original_iterations": 1000, "metric_count": 6,
            "captures": captures, "metrics": metrics, "source_files": 5, "cores": 1, "clock_mhz": 240,
            "tick_hz": 1, "worker_stack_bytes": 1792, "ranking_eligible": False,
            "unmodified_official_native_suite": False,
            "boundary": "original selected bodies/statistics; native counting semaphore, recursive mutex and static-thread adapter costs included; not the full Zephyr suite or a cross-OS kernel-only rank"}


def render_table(result, native_os="FreeRTOS"):
    lines = [f"| {native_os} / original Zephyr latency subset | Original means, ns (three boots) | Median of means, ns |",
             "| --- | --- | --- |"]
    for tag, row in result["metrics"].items():
        lines.append(f"| {native_os} latency port / {tag} | " + " / ".join(map(str, row["means_ns"])) +
                     f" | {row['median_of_three_means_ns']} |")
    return "\n".join(lines)


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
