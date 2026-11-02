#!/usr/bin/env python3
"""Interleave unchanged native Thread-Metric images with signed POWER-Z capture."""
import argparse
import fcntl
import json
import os
import random
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CASES = (
    "basic_processing", "cooperative_scheduling", "preemptive_scheduling",
    "message_processing", "synchronization_processing", "memory_allocation",
    "interrupt_processing", "interrupt_preemption_processing",
)
OSES = {"freertos": "FreeRTOS", "zephyr": "Zephyr", "nuttx": "NuttX",
        "riot": "RIOT", "alios": "AliOS-Rhino"}
SEED = 20261009


def source_directory(os_name, case):
    if os_name == "freertos":
        return "tm-freertos-native-aligned-v1/" + case
    if os_name == "zephyr":
        return ("tm-irq-cpu2-v1/zephyr/" if case.startswith("interrupt_")
                else "zephyr-gcc13-align/") + case
    if os_name == "nuttx":
        if case.startswith("interrupt_"):
            return "tm-irq-cpu2-v1/nuttx/" + case
        if case == "cooperative_scheduling":
            return "tm-cooperative-native-nuttx-v1"
        if case == "message_processing":
            return "nuttx-message-resource-v2"
        return "tm-nuttx-native-aligned-v1/" + case
    return ("riot-native-gcc12-v3/" if os_name == "riot" else "alios-native-gcc5-v3/") + case


def segments(os_name):
    return {
        "freertos": ((0x1000, "bootloader.bin"), (0x8000, "partition-table.bin"),
                     (0x10000, "iotosbench_tm.bin")),
        "zephyr": ((0x1000, "zephyr.bin"),),
        "nuttx": ((0x1000, "bootloader-esp32.bin"), (0x8000, "partition-table-esp32.bin"),
                  (0x10000, "nuttx.bin")),
        "riot": ((0x1000, "bootloader.bin"), (0x8000, "partitions.bin"), (0x10000, "application.bin")),
        "alios": ((0x1000, "bootloader.bin"), (0x8000, "partitions.bin"), (0x10000, "application.bin")),
    }[os_name]


def make_plan():
    rng, schedule = random.Random(SEED), []
    for reset in (1, 2, 3):
        cases = list(CASES)
        rng.shuffle(cases)
        for case in cases:
            systems = list(OSES)
            rng.shuffle(systems)
            for system in systems:
                schedule.append({"case": case, "system": system, "os": OSES[system],
                                 "reset": reset, "source": source_directory(system, case),
                                 "directory": f"{case}/{system}/reset{reset}"})
    return {"version": 1, "seed": SEED, "capture_seconds": 95,
            "order": "seeded case/OS permutation in each of three rounds; one board",
            "schedule": schedule}


def write_status(output, **fields):
    content = dict(pid=os.getpid(), updated_utc=datetime.now(timezone.utc).isoformat(), **fields)
    temporary = output / ".status.json.tmp"
    temporary.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output / "status.json")


def run(root, output, setup, port):
    statement = json.loads(setup.read_text(encoding="utf-8"))
    verified = datetime.fromisoformat(statement["verified_utc"])
    if verified.utcoffset() is None or verified > datetime.now(timezone.utc):
        raise ValueError("operator confirmation must precede this fresh acquisition")
    output.mkdir(parents=True, exist_ok=False)
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = make_plan()
        (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(setup, output / "operator-setup.json")
        for name in ("run_esp32_tm_energy.py", "audit_esp32_tm_energy.py", "capture_esp32_powerz.py",
                     "audit_esp32_powerz.py", "seal_esp32_power_supply.py"):
            shutil.copyfile(root / name, output / name)
        env = dict(os.environ, PYTHONPATH=":".join(str(root / name) for name in
                   ("powerz-python", "python-nuttx/lib/python3.8/site-packages", "esptool-4.8.1")))
        completed, current = 0, None
        try:
            with (output / "inventory-check.log").open("x") as log:
                for system in OSES:
                    for case in CASES:
                        source = root / "downloads" / source_directory(system, case)
                        print(source, file=log, flush=True)
                        subprocess.run(["sha256sum", "-c", "image.sha256"], cwd=source,
                                       stdout=log, stderr=subprocess.STDOUT, check=True)
            for current in plan["schedule"]:
                write_status(output, status="running", completed_resets=completed,
                             expected_resets=120, current=current)
                source = root / "downloads" / current["source"]
                installation = output / current["directory"]
                installation.mkdir(parents=True, exist_ok=False)
                shutil.copyfile(source / "image.sha256", installation / "image.sha256")
                images = [part for offset, name in segments(current["system"])
                          for part in (hex(offset), str(source / name))]
                print(f"[{completed + 1}/120] {current['os']} {current['case']} reset {current['reset']}", flush=True)
                with (installation / "flash.log").open("x") as log:
                    subprocess.run([sys.executable, "-m", "esptool", "--chip", "esp32",
                                    "--port", port, "--baud", "460800", "write_flash",
                                    "--flash_mode", "dio", "--flash_freq", "40m", "--flash_size",
                                    "2MB" if current["system"] == "freertos" else "4MB", *images],
                                   env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
                capture = installation / "capture"
                command = [sys.executable, str(root / "capture_esp32_powerz.py"), "--seconds", "95",
                           "--port", port, "--output", str(capture)]
                if current["system"] == "nuttx":
                    command += ["--send-line", "iotosbench"]
                subprocess.run(command, env=env, check=True)
                from audit_esp32_tm_energy import check_native_workload
                check_native_workload(capture, current["os"], current["case"])
                with (capture / "packet-workload-audit.json").open("x") as log:
                    subprocess.run([sys.executable, str(root / "audit_esp32_powerz.py"), str(capture),
                                    "--tm-os", current["os"], "--tm-case", current["case"]],
                                   env=env, stdout=log, check=True)
                subprocess.run([sys.executable, str(root / "seal_esp32_power_supply.py"), str(capture),
                                "--setup", str(output / "operator-setup.json")], env=env, check=True)
                completed += 1
            write_status(output, status="capture_complete_requires_independent_audit",
                         completed_resets=completed, expected_resets=120)
        except BaseException as error:
            write_status(output, status="failed_preserved", completed_resets=completed,
                         expected_resets=120, current=current, error=repr(error))
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--port", default="/dev/ttyUSB0")
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    if args.plan_only:
        print(json.dumps(make_plan(), indent=2))
    else:
        if args.output is None or args.setup is None:
            parser.error("fresh --output and prior --setup are required")
        run(args.root.resolve(), args.output.resolve(), args.setup.resolve(), args.port)
