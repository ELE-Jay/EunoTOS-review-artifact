#!/usr/bin/env python3
"""Audit a minimal ISR-method correction, explicitly not unchanged vendor code."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
from urllib.request import urlopen
from audit_esp32_report import ROOT, audit_flash
from audit_esp32_freertos_original_performance import audit as original_app
from audit_esp32_freertos_original_isr import capture
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_iperf_original import ANSI

ALLOCATOR_URL = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/components/esp_hw_support/intr_alloc.c"


def validate_patch(original, corrected):
    declaration = b"    BaseType_t yield;\n"
    cleanup = b"    esp_intr_free(handle);\n"
    if original.count(declaration) != 2 or original.count(cleanup) != 2:
        raise ValueError("original ISR revision does not match the correction")
    expected = original.replace(declaration, b"    BaseType_t yield = pdFALSE;\n").replace(
        cleanup, cleanup + b"    vSemaphoreDelete(sync);\n    vSemaphoreDelete(end_sema);\n")
    if corrected != expected:
        raise ValueError("source changes exceed initialized yield and post-measurement semaphore cleanup")


def reuse_capture(rows, name, elf_sha):
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [float(row["elapsed_s"]) for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid reuse-control chronology")
    if sum("2nd stage bootloader" in line for line in lines) != 1 or \
            sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
            sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or not any(
            "ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines):
        raise ValueError("reuse control lacks exactly one matching native boot")
    starts = [i for i, line in enumerate(lines) if line.startswith("Running ")]
    ends = [i for i, line in enumerate(lines) if re.fullmatch(r"1 Tests \d+ Failures \d+ Ignored", line)]
    if len(starts) != 3 or len(ends) != 3 or any(re.search(
            r"Guru Meditation|panic|Brownout|:FAIL|Ignoring performance test", line) for line in lines):
        raise ValueError("reuse control requires three complete native calls without reboot/failure")
    checks = []
    for index, (start, end) in enumerate(zip(starts, ends)):
        if start >= end or (index and ends[index - 1] >= start) or \
                lines[start] != "Running " + name + "..." or lines[end] != "1 Tests 0 Failures 0 Ignored":
            raise ValueError("wrong reuse selection or outcome order")
        segment = lines[start:end]
        if sum(line.endswith(":" + name + ":PASS") for line in segment) != 1 or any(
                sum(line.startswith("[Performance][" + label + "]:") for line in segment) != 1
                for label in ("ISR_ENTER_CYCLES", "ISR_EXIT_CYCLES")):
            raise ValueError("reuse call lacks original completion/performance checks")
        native = []
        for line in segment:
            match = re.fullmatch(r"MALLOC_CAP_(8BIT|32BIT): Before (\d+) bytes free, After (\d+) bytes free \(delta (-?\d+)\)", line)
            if match:
                before, after, delta = map(int, match.groups()[1:])
                if after - before != delta or delta != (-16 if index == 0 else 0):
                    raise ValueError("unaccounted initial allocation or repeated memory loss")
                native.append({"capability": match[1], "before_free_bytes": before,
                               "after_free_bytes": after, "delta_free_bytes": delta})
        if [row["capability"] for row in native] != ["8BIT", "32BIT"] or (index and any(
                previous["after_free_bytes"] != current["before_free_bytes"]
                for previous, current in zip(checks[-1], native))):
            raise ValueError("native overlapping-view accounting or consecutive reuse continuity differs")
        checks.append(native)
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "same_boot_calls": 3, "native_heap_checks": checks, "no_repeated_free_memory_loss": True,
            "timing_score_eligible": False,
            "reason": "allocator-reuse control only; original static timing accumulators are not reset between calls"}


def audit(directory, verify_upstream=False):
    baseline = ROOT / "artifacts/reports/freertos-original-performance-v1"
    original_app(baseline)
    check_manifest(directory, "image.sha256")
    source = directory / "source"
    originals = {p.relative_to(baseline / "source"): p for p in (baseline / "source").rglob("*")
                 if p.is_file() and p.name != "dependencies.lock"}
    current = {p.relative_to(source): p for p in source.rglob("*") if p.is_file() and p.name != "dependencies.lock"}
    if set(originals) != set(current):
        raise ValueError("original application file coverage changed")
    changed = Path("performance/test_isr_latency.c")
    for relative, original in originals.items():
        if relative == changed:
            validate_patch(original.read_bytes(), current[relative].read_bytes())
            if current[relative].read_bytes() != (ROOT / "firmware/bsp/esp32/freertos_original_isr/test_isr_latency.c").read_bytes():
                raise ValueError("unreviewed correction")
        elif current[relative].read_bytes() != original.read_bytes():
            raise ValueError(("unrelated source change", str(relative)))
    if (directory / "config").read_bytes() != (baseline / "config").read_bytes() or \
            (directory / "board-defaults").read_bytes() != (baseline / "board-defaults").read_bytes():
        raise ValueError("original clock/tick/core/assertion profile changed")
    if "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native compiler changed")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for name in ("test_isr_latency.c", "test_freertos_main.c"):
        selected = [row for row in commands if Path(row["file"]).name == name]
        if len(selected) != 1 or "freertos-original-performance-source-freertos-original-isr-corrected-v1/" not in selected[0]["file"]:
            raise ValueError("corrected source or unchanged framework not compiled")
    control = directory / "reuse-control-v2"
    allocator = control / "intr_alloc.c"
    provenance = control / "official-source.json"
    if verify_upstream:
        with urlopen(ALLOCATOR_URL, timeout=30) as response:
            upstream = hashlib.sha256(response.read()).hexdigest()
        if digest(allocator) != upstream:
            raise ValueError("native retained-descriptor source differs from the official SDK")
        provenance.write_text(json.dumps({"url": ALLOCATOR_URL, "sha256": upstream}, indent=2) + "\n")
    identity = json.loads(provenance.read_text())
    if identity != {"url": ALLOCATOR_URL, "sha256": digest(allocator)}:
        raise ValueError("native allocator source identity changed")
    native_command = [row for row in commands if Path(row["file"]).name == "intr_alloc.c"]
    if len(native_command) != 1 or not native_command[0]["file"].endswith(
            "/esp-idf-v5.2.5/components/esp_hw_support/intr_alloc.c"):
        raise ValueError("reviewed native allocator was not compiled")
    audit_flash(directory, "flash.log", 3)
    written = re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())
    if [(int(size), int(address, 16)) for size, address in written] != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("freertos_test.bin", 0x10000))]:
        raise ValueError("verified Flash segments do not match the archived image")
    audit_flash(control, "flash.log", 3)
    if [(int(size), int(address, 16)) for size, address in re.findall(
            r"Wrote (\d+) bytes .* at (0x\w+)", (control / "flash.log").read_text())] != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("freertos_test.bin", 0x10000))]:
        raise ValueError("allocator control used a different installed image")
    groups = {}
    reuse = {}
    for case, suffix in (("no-parameter", "no parameter"), ("parameter", "parameter")):
        runs = [capture(directory / case / f"reset{i}.jsonl",
                        "isr latency test vport-yield-from-isr with " + suffix,
                        digest(directory / "freertos_test.elf")) for i in (1, 2, 3)]
        if any(not row["original_unity_pass"] or any(check["delta_free_bytes"] != -16 for check in row["native_heap_checks"])
               for row in runs):
            raise ValueError("corrected assertions or native first-use retained footprint differs")
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(runs, runs[1:])):
            raise ValueError("independent reset windows overlap")
        for row in runs:
            row.update(measurement_eligible=True, reason="reviewed minimal correction; original points/counts/formula and native assertions preserved")
        medians, ranges = {}, {}
        for label in ("ISR_ENTER_CYCLES", "ISR_EXIT_CYCLES"):
            values = [row["original_average_cycles"][label] for row in runs]
            if any(value is None or value <= 0 for value in values):
                raise ValueError("missing positive original average")
            medians[label] = statistics.median(values) / 240
            ranges[label] = [min(values) / 240, max(values) / 240]
        groups[case] = {"resets": 3, "captures": runs, "median_of_original_averages_us": medians,
                        "range_of_original_averages_us": ranges}
        path = control / (case + ".jsonl")
        reuse[case] = reuse_capture([json.loads(line) for line in path.read_text().splitlines()],
                                   "isr latency test vport-yield-from-isr with " + suffix,
                                   digest(directory / "freertos_test.elf"))
        reuse[case]["uart_sha256"] = digest(path)
    if groups["no-parameter"]["captures"][-1]["end_utc"] >= groups["parameter"]["captures"][0]["start_utc"]:
        raise ValueError("case windows overlap")
    if groups["parameter"]["captures"][-1]["end_utc"] >= reuse["no-parameter"]["start_utc"] or \
            reuse["no-parameter"]["end_utc"] >= reuse["parameter"]["start_utc"]:
        raise ValueError("fresh-reset and independent reuse-control windows overlap")
    return {"audit": "pass", "resets": 6, "os": "FreeRTOS/ESP-IDF 5.2.5", "groups": groups,
            "reuse_controls": reuse, "reuse_control_boots": 2, "reuse_control_invocations": 6,
            "native_first_use_retained_bytes": 16, "native_allocator_source": identity,
            "memory_boundary": "native descriptor retained for reuse; overlapping 8BIT/32BIT views are not added; no repeated loss across three calls in either control",
            "source_files": len(originals), "unchanged_source_files": len(originals) - 1,
            "method": "corrected port of the original 10,000-iteration arithmetic-average ISR test",
            "source_change": "two initialized yield locals; delete two semaphores after each measured case",
            "unmodified_official_source": False, "measurement_eligible": True, "ranking_eligible": False,
            "tick_hz": 1000, "clock_mhz": 240, "cores": 1,
            "binary_sha256": digest(directory / "freertos_test.bin"),
            "boundary": "CPU software-interrupt trigger to handler; ISR tail to continuing trigger task; no GPIO or blocked-task-wake measurement",
            "ranking_reason": "native software trigger and original profile; no matching other-OS port yet"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
