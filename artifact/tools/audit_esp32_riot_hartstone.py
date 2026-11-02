#!/usr/bin/env python3
"""Bind RIOT native-us first-loss records to the persistent-worker v4 image."""
import argparse
import hashlib
import json
import re
import shlex
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from audit_esp32_hartstone_series import audit
from audit_esp32_report import PH_NATIVE_SCHEDULE_SHA256, audit_image_manifest, audit_flash
from audit_esp32_resources import image_length

ROOT = Path(__file__).resolve().parents[1]
WHETSTONE_SHA = "ff3547d384542f5024af647e62bbb84c69dfefaf9953840df8ff7b4770b38a8f"


def audit_experiment(folder, experiment):
    required = {"application.elf", "application.bin", "bootloader.bin", "partitions.bin",
                "build.log", "compiler.txt", "config.h", "main.c", "Makefile", "workload.c",
                "small_whetstone.c", "small_whetstone.h", "ph_us_schedule.h",
                "thread-arch-pinned.c", "context-pinned.S"}
    audit_image_manifest(folder, required)
    for name in ("main.c", "Makefile", "workload.c"):
        if (folder / name).read_bytes() != (ROOT / "firmware/bsp/esp32/hartstone_riot" / name).read_bytes():
            raise ValueError("unreviewed native persistent-worker source")
    for name, expected in (("small_whetstone.c", WHETSTONE_SHA),
                           ("ph_us_schedule.h", PH_NATIVE_SCHEDULE_SHA256)):
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise ValueError("published workload/shared release schedule changed")
    if "12.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("wrong RIOT toolchain cohort")
    log = (folder / "build.log").read_text()
    if "xtensa-esp32-elf-gcc" not in log:
        reproduction = folder / "reproduction"
        for line in (reproduction / "reproduction.sha256").read_text().splitlines():
            expected, name = line.split(maxsplit=1)
            file = (reproduction / name).resolve()
            if file.parent != reproduction.resolve() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
                raise ValueError("invalid fresh-build reproduction evidence")
        if (reproduction / "application.bin").read_bytes() != (folder / "application.bin").read_bytes():
            raise ValueError("verbose clean build did not reproduce the measured firmware")
        log = (reproduction / "build.log").read_text()
    commands = []
    for line in log.replace("\\\n", " ").splitlines():
        if "xtensa-esp32-elf-gcc" not in line:
            continue
        args = shlex.split(line)
        if "-c" in args and any(Path(arg).name in ("main.c", "workload.c") for arg in args):
            commands.append(args)
    expected = {"-fno-fast-math", "-ffp-contract=off", f"-DPH_EXPERIMENT={experiment}",
                "-DTHREAD_PRIORITY_MAIN=14", "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1"}
    if len(commands) != 2 or any(not expected <= set(args) or
            [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]
                                 for args in commands):
        raise ValueError("native application compiler flags/experiment not witnessed")
    config = (folder / "config.h").read_text()
    if "#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240 1" not in config:
        raise ValueError("wrong native clock configuration")
    image_length((folder / "application.bin").read_bytes())
    image_length((folder / "bootloader.bin").read_bytes())
    audit_flash(folder, "flash-full.log", 3)
    flash = (folder / "flash-full.log").read_text()
    written = [(int(size), int(offset, 16)) for size, offset in
               re.findall(r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", flash)]
    if sorted(written) != sorted([(len((folder / name).read_bytes()), offset) for offset, name in
                                 ((0x1000, "bootloader.bin"), (0x8000, "partitions.bin"),
                                  (0x10000, "application.bin"))]):
        raise ValueError("installed sizes/offsets differ from archived images")
    captures = [folder / f"reset{reset}.jsonl" for reset in (1, 2, 3)]
    runs = [audit(path, "RIOT", experiment, high_resolution=True) for path in captures]
    if any(run["completion"] != "FIRST_LOSS_REACHED" or run["bounded_capture"] for run in runs):
        raise ValueError("a short pilot cannot establish a first-loss threshold")
    previous_end = None
    for path in captures:
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        started = datetime.fromisoformat(raw[0]["utc"]) - timedelta(seconds=raw[0]["elapsed_s"])
        if previous_end is not None and started <= previous_end:
            raise ValueError("independent reset records overlap")
        previous_end = started + timedelta(seconds=raw[-1]["elapsed_s"])
    steps = [run["first_loss_step"] for run in runs]
    return {"status": "PASS", "experiment": experiment, "independent_resets": 3,
            "elf_sha256": hashlib.sha256((folder / "application.elf").read_bytes()).hexdigest(),
            "capture_sha256": [hashlib.sha256(path.read_bytes()).hexdigest() for path in captures],
            "first_loss_steps": steps, "first_loss_step_median": statistics.median(steps),
            "runs": runs, "ranking_eligible": False,
            "comparison_boundary": "GCC12/native tickless/persistent RIOT worker cohort"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--experiment", type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = json.dumps(audit_experiment(args.directory.resolve(), args.experiment), indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
