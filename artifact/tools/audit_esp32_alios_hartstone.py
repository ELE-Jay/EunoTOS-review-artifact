#!/usr/bin/env python3
"""Bind native Rhino Hartstone records to original workload and legacy SDK."""
import argparse
import hashlib
import json
import re
import shlex
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from audit_esp32_hartstone_series import audit
from audit_esp32_report import PH_NATIVE_SCHEDULE_SHA256, audit_flash, audit_image_manifest
from audit_esp32_resources import image_length, static_footprint
from audit_esp32_riot_hartstone import WHETSTONE_SHA
from audit_esp32_alios_tm import check_native_port

ROOT = Path(__file__).resolve().parents[1]


def audit_image(folder, experiment):
    required = {"application.elf", "application.bin", "bootloader.bin", "partitions.bin",
                "build.log", "compiler.txt", "config", "sdkconfig.h", "k_config.h",
                "main.c", "aos.mk", "workload.c", "small_whetstone.c", "small_whetstone.h",
                "ph_us_schedule.h", "rhino-port-pinned.c", "rhino-portasm-pinned.S",
                "xtensa_rtos.h", "espos_time.c", "espos_task.c", "esp_timer.h", "libesp32.a",
                "symbols.txt", "disassembly.txt"}
    audit_image_manifest(folder, required)
    port_profile = check_native_port(folder)
    for name in ("main.c", "aos.mk", "workload.c"):
        if (folder / name).read_bytes() != (ROOT / "firmware/bsp/esp32/hartstone_alios" / name).read_bytes():
            raise ValueError("unreviewed native Hartstone adapter")
    for name, expected in (("small_whetstone.c", WHETSTONE_SHA),
                           ("ph_us_schedule.h", PH_NATIVE_SCHEDULE_SHA256)):
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise ValueError("original workload/release rules changed")
    pinned = ROOT / "artifacts/reports/alios-native-gcc5-v2/basic_processing"
    for name in ("xtensa_rtos.h", "espos_time.c"):
        if (folder / name).read_bytes() != (pinned / name).read_bytes():
            raise ValueError("native FPU/task port or SDK compatibility differs from pinned Rhino")
    board = ROOT / "firmware/bsp/esp32/alios_board/esp32bench"
    for name in ("sdkconfig.h", "k_config.h"):
        if (folder / name).read_bytes() != (board / name).read_bytes():
            raise ValueError("unreviewed native clock/kernel conditions")
    config = (folder / "config").read_text()
    if any(marker not in config for marker in ('AOS_BUILD_BOARD="esp32bench"',
            'AOS_BUILD_APP="hartstone"', 'AOS_COMP_RHINO=y')) or \
            "5.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("wrong native kernel/application/toolchain")
    commands = []
    for line in (folder / "build.log").read_text().replace("\\\n", " ").splitlines():
        if not line.startswith("xtensa-esp32-elf-gcc "):
            continue
        args = shlex.split(line)
        if "-c" in args and any(Path(arg).name in ("main.c", "workload.c") for arg in args):
            commands.append(args)
    expected = {"-fno-fast-math", "-ffp-contract=off", f"-DPH_EXPERIMENT={experiment}"}
    if len(commands) != 2 or any(not expected <= set(args) or
            [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]
                                 for args in commands):
        raise ValueError("original application compilation/experiment not witnessed")
    symbols = (folder / "symbols.txt").read_text()
    for name in ("krhino_task_create", "krhino_sem_take", "esp_timer_start_once",
                 "_xt_coproc_savecs", "_xt_coproc_restorecs", "__ieee754_sqrtf"):
        if not re.search(r"\bT " + re.escape(name) + r"$", symbols, re.M):
            raise ValueError("native timer/task/FPU/library symbol missing")
    for name in ("application.bin", "bootloader.bin"):
        image_length((folder / name).read_bytes())
    result = static_footprint(folder / "application.elf")
    result.update(status="BUILD_ONLY", experiment=experiment,
                  elf_sha256=hashlib.sha256((folder / "application.elf").read_bytes()).hexdigest(),
                  native_port_profile=port_profile, ranking_eligible=False)
    return result


def audit_experiment(folder, experiment, smoke=False):
    result = audit_image(folder, experiment)
    if not smoke and result["native_port_profile"].startswith("historical"):
        raise ValueError("legacy FPU-switch failure image cannot supply a full threshold")
    mode = "smoke" if smoke else "full"
    audit_flash(folder, f"flash-{mode}.log", 3)
    written = [(int(size), int(offset, 16)) for size, offset in re.findall(
        r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", (folder / f"flash-{mode}.log").read_text())]
    if sorted(written) != sorted((len((folder / name).read_bytes()), offset) for offset, name in
                                 ((0x1000, "bootloader.bin"), (0x8000, "partitions.bin"),
                                  (0x10000, "application.bin"))):
        raise ValueError("verified installed sizes/offsets differ from archived firmware")
    captures = ([folder / "smoke-reset1.jsonl"] if smoke else
                [folder / f"reset{index}.jsonl" for index in (1, 2, 3)])
    runs = []
    previous_end = None
    for path in captures:
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        lines = [row["line"] for row in raw]
        conditions = "HARTSTONE conditions cpu_hz=240000000 cores=1 tick_hz=100 scheduler=priority-fifo"
        witnesses = [re.fullmatch(r"HARTSTONE native timer self-check PASS callback_prio=(\d+) worker_prios=30,29,28,27,26", line)
                     for line in lines if line.startswith("HARTSTONE native timer self-check ")]
        if lines.count(conditions) != 1 or len(witnesses) != 1 or not witnesses[0] or int(witnesses[0][1]) >= 26:
            raise ValueError("effective conditions/native timer priority not witnessed")
        started = datetime.fromisoformat(raw[0]["utc"]) - timedelta(seconds=raw[0]["elapsed_s"])
        if previous_end is not None and started <= previous_end:
            raise ValueError("reset captures overlap rather than independently restarting")
        previous_end = started + timedelta(seconds=raw[-1]["elapsed_s"])
        run = audit(path, "AliOS-Rhino", experiment, allow_incomplete=smoke, high_resolution=True)
        if not smoke and (run["completion"] != "FIRST_LOSS_REACHED" or run["bounded_capture"]):
            raise ValueError("incomplete pilot cannot establish a first-loss threshold")
        runs.append(run)
    steps = [run["first_loss_step"] for run in runs]
    result.update(status="PILOT" if smoke else "PASS", independent_resets=len(runs),
                  first_loss_steps=steps,
                  first_loss_step_median=statistics.median(steps) if all(step is not None for step in steps) else None,
                  capture_sha256=[hashlib.sha256(path.read_bytes()).hexdigest() for path in captures],
                  runs=runs, comparison_boundary="legacy GCC5/Rhino/native SDK task-dispatched timer/persistent workers")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--experiment", type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.smoke and args.build_only:
        parser.error("choose smoke capture or build-only evidence, not both")
    folder = args.directory.resolve()
    result = audit_image(folder, args.experiment) if args.build_only else audit_experiment(folder, args.experiment, args.smoke)
    content = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
