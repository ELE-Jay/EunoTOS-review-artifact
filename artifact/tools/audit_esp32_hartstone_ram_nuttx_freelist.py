#!/usr/bin/env python3
"""Keep the new observer unmeasured until three original reference-covering runs exist."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import statistics
from elftools.elf.elffile import ELFFile
from audit_esp32_hartstone_ram_nuttx import build, freelist_machine, FREELIST_DIRECTORY, REFERENCE, ROOT
from audit_esp32_hartstone_series import audit as hartstone
from audit_esp32_ram_census import region_accounting
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_report import audit_flash
from audit_esp32_zephyr_thread import read_raw_capture


def audit(directory=FREELIST_DIRECTORY):
    result = build(directory, freelist=True)
    result["machine_control"] = freelist_machine(directory)
    if list(directory.glob("reset*.jsonl")) or list(directory.glob("pilot-reset*.jsonl")):
        raise ValueError("build-only result cannot silently ignore physical captures")
    return result


def full(directory=FREELIST_DIRECTORY):
    result = build(directory, freelist=True)
    machine = freelist_machine(directory)
    if not (directory / "capture.sha256").is_file():
        raise ValueError("free-chain PH4 has no complete three-reset physical capture manifest")
    check_manifest(directory, "capture.sha256")
    expected = {f"reset{index}.{suffix}" for index in (1, 2, 3) for suffix in ("jsonl", "raw")}
    expected |= {"flash-full.log", "image-check-full.log", "board-check-full.log", "run-script-full.sh", "capture_esp32_uart.py"}
    if {line.split(maxsplit=1)[1] for line in (directory / "capture.sha256").read_text().splitlines()} != expected:
        raise ValueError("free-chain physical manifest coverage differs")
    if (directory / "run-script-full.sh").read_bytes() != (ROOT / "tools/run_esp32_hartstone_ram_nuttx_freelist.sh").read_bytes() or \
            (directory / "capture_esp32_uart.py").read_bytes() != (ROOT / "tools/capture_esp32_uart.py").read_bytes():
        raise ValueError("free-chain physical/raw runner changed")
    board = (directory / "board-check-full.log").read_text()
    if "MAC: 84:1f:e8:8f:55:dc" not in board or not re.search(r"ESP32-D0WDQ6.*revision v1.1", board):
        raise ValueError("free-chain run targets a different board")
    audit_flash(directory, "flash-full.log", 3)
    writes = [(int(size), int(offset, 16)) for size, offset in re.findall(
        r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", (directory / "flash-full.log").read_text())]
    if writes != [((directory / name).stat().st_size, offset) for name, offset in (
            ("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("free-chain flash sizes/offsets differ from the frozen image")
    reference = [hartstone(REFERENCE / f"reset{index}.jsonl", "NuttX", 4, high_resolution=True) for index in (1, 2, 3)]
    return observations(directory, result, machine, reference)


def observations(directory, result, machine, reference):
    """Caller must bind the frozen build, machine checks and physical capture envelope."""
    with (directory / "application.elf").open("rb") as stream:
        heap_start = ELFFile(stream).get_section_by_name(".symtab").get_symbol_by_name("_sheap")[0]["st_value"]
    runs = []
    for index in (1, 2, 3):
        rows = read_raw_capture(directory, index)
        lines = [row["line"] for row in rows]
        if lines.count("NuttShell (NSH)") != 1 or any(re.search(
                r"Guru Meditation|panic|assert failed|Brownout|watchdog|status=FAIL", line, re.I) for line in lines):
            raise ValueError("free-chain capture lacks one healthy independent native boot")
        begin = "BENCH_RAM lifecycle begin os=NuttX family=native-region-heap window=application-through-first-loss clock_hz=240000000"
        if lines.count(begin) != 1 or lines.count("BENCH_RAM observer=native-free-chain endpoint_crosscheck=full-region-walk") != 1:
            raise ValueError("free-chain observer/clock/window admission differs")
        regions = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
            r"BENCH_RAM region start=(\d+) bytes=(\d+)", line))]
        contexts = [tuple(map(int, match.groups())) for line in lines if (match := re.fullmatch(
            r"BENCH_RAM heap-control start=(\d+) bytes=(\d+)", line))]
        if len(regions) != 3 or contexts != [(heap_start, machine["native_heap_control_bytes"])] or \
                regions[0][0] != heap_start + machine["native_heap_control_bytes"]:
            raise ValueError("free-chain heap/control ownership differs")
        capacity = region_accounting(result["static_footprint"]["ram_sections"], regions, False)
        region_accounting(result["static_footprint"]["ram_sections"], regions + contexts, False)
        samples = [(position, match[1], *map(int, match.groups()[1:])) for position, line in enumerate(lines) if (match := re.fullmatch(
            r"BENCH_RAM lifecycle sample phase=(\S+) occupied=(\d+) peak=(\d+) observations=(\d+) invalid=(\d+)", line))]
        if [sample[1] for sample in samples] != ["application-start", "series-return"]:
            raise ValueError("free-chain endpoint samples incomplete")
        previous_peak = previous_count = 0
        for position, phase, occupied, peak, count, invalid in samples:
            if not 0 < occupied <= peak <= capacity or peak < previous_peak or count <= previous_count or invalid:
                raise ValueError("free-chain invalid/regressing/crosscheck-failed heap observation")
            previous_peak, previous_count = peak, count
        original = hartstone(directory / f"reset{index}.jsonl", "NuttX", 4, high_resolution=True)
        terminal = next(position for position, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status="))
        if original["completion"] != "FIRST_LOSS_REACHED" or lines.count("BENCH_RAM lifecycle result=0") != 1 or \
                lines.count("BENCH_RAM lifecycle complete") != 1 or lines[-1] != "BENCH_RAM lifecycle complete" or \
                not lines.index(begin) < samples[0][0] < lines.index("HARTSTONE PH SERIES boot target=ESP32 os=NuttX experiment=4") or \
                not terminal < samples[1][0] < lines.index("BENCH_RAM lifecycle result=0"):
            raise ValueError("free-chain window does not enclose the complete original first-loss series")
        if previous_peak - samples[0][2] < (5 + original["first_loss_step"]) * 4096:
            raise ValueError("free-chain peak cannot contain the actual original worker stacks")
        covered = original["first_loss_step"] >= max(run["first_loss_step"] for run in reference)
        runs.append({"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
            "raw_sha256": digest(directory / f"reset{index}.raw"), "uart_sha256": digest(directory / f"reset{index}.jsonl"),
            "original_series": original, "samples": [sample[1:] for sample in samples],
            "reference_worker_cohort_covered": covered, "native_heap_regions": regions,
            "native_heap_control_context": contexts[0], "observed_software_ram_bytes":
                result["static_footprint"]["static_sram_bytes"] + previous_peak + contexts[0][1]})
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(runs, runs[1:])):
        raise ValueError("free-chain independent reset windows overlap")
    covered = all(run["reference_worker_cohort_covered"] for run in runs)
    result.update(audit="complete-reference-covered-pass" if covered else "short-cohort-diagnostic-pass", measured=True,
        board_boots=3, runs=runs, machine_control=machine, reference_worker_cohort_covered=covered,
        runtime_peak_reportable=covered, median_observed_software_ram_bytes=statistics.median(
            run["observed_software_ram_bytes"] for run in runs) if covered else None,
        reference_original_series=reference, uninstrumented_peak_measured=False, energy_measured=False,
        fewer_observer_cycles_verified_on_board=False, ranking_eligible=False, new_metric_created=False)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=FREELIST_DIRECTORY)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = json.dumps(full(args.directory) if args.full else audit(args.directory), indent=2) + "\n"
    if args.output: args.output.write_text(content)
    else: print(content, end="")
