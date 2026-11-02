#!/usr/bin/env python3
"""Observe native second-stage startup without rebuilding the measured application."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess

from run_esp32_followup import Board, sha, read_raw_capture, verified

ROOT = Path(__file__).resolve().parents[1]
MAC = "34:98:7a:a2:85:28"
REFERENCE = "esp32-freertos-peak-context-build-v1"
OBSERVER = Path("firmware/bsp/esp32/resource_census/bootloader_stack")
FIELDS = ("phase", "entry_sp", "low", "paint_end", "painted", "verified", "sp", "spare", "touched", "invalid", "guard", "stages")
PATTERN = re.compile("BOOT_RAM " + " ".join(name + r"=(\d+)" for name in FIELDS))


def observations(lines):
    records = []
    for line in lines:
        if not line.startswith("BOOT_RAM "):
            continue
        match = PATTERN.fullmatch(line)
        if not match:
            raise ValueError("Malformed boot-stage observation")
        records.append(dict(zip(FIELDS, map(int, match.groups()))))
    if len(records) != 2 or [r["phase"] for r in records] != [0, 1]:
        raise ValueError("Missing or repeated boot-stage observation")
    for row in records:
        if row["invalid"] or row["low"] != 0x3ffe0440 or row["guard"] != 64 or row["stages"] != 2 or \
                not row["low"] + 64 < row["entry_sp"] <= 0x3ffe3f20 or row["entry_sp"] % 16 or \
                row["paint_end"] != row["entry_sp"] - 64 or row["painted"] != row["paint_end"] - row["low"] or \
                row["verified"] != row["painted"] or row["spare"] + row["touched"] != row["painted"] or \
                any(row[n] % 4 for n in ("spare", "touched")) or not row["low"] <= row["sp"] < row["entry_sp"]:
            raise ValueError("Invalid boot-stage bounds or observation state")
    if records[1]["touched"] < records[0]["touched"]:
        raise ValueError("Cumulative startup watermark decreased")
    return records


def watchdog_observer(text):
    anchor='void IRAM_ATTR __wrap_bootloader_console_deinit(void)\n{\n    observe(1);'
    if text.count(anchor)!=1:
        raise ValueError('Native loader handoff observer anchor differs')
    return text.replace(anchor,'#include "rhino_watchdog.inc"\n\n'
        'void IRAM_ATTR __wrap_bootloader_console_deinit(void)\n{\n'
        '    rhino_watchdog_handoff();\n    observe(1);')


def build(root, workspace, output, reference, observer,legacy_rtc_wdt_handoff=False):
    if workspace.exists() or output.exists():
        raise ValueError("Refusing to overwrite build/evidence")
    workspace.mkdir(parents=True)
    output.mkdir(parents=True)
    component = workspace / "project/bootloader_components/boot_ram"
    shutil.copytree(observer, component)
    shutil.copytree(observer, output / "observer")
    if legacy_rtc_wdt_handoff:
        for folder in (component,output/'observer'):
            (folder/'observe.c').write_text(watchdog_observer((folder/'observe.c').read_text()))
            cmake_text=(folder/'CMakeLists.txt').read_text()
            (folder/'CMakeLists.txt').write_text(cmake_text.replace(
                'idf_component_register(SRCS "observe.c" "entry.S")',
                'idf_component_register(SRCS "observe.c" "entry.S" PRIV_REQUIRES hal)'))
    shutil.copyfile(reference / "config", output / "config")
    sdk = root / "esp-idf-v5.2.5"
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env = dict(os.environ, IDF_PATH=str(sdk), IDF_TOOLS_PATH=str(root / "idf-tools"),
        IDF_PYTHON_ENV_PATH=str(root / "idf-python-env"),
        ESP_ROM_ELF_DIR=str(root / "idf-tools/tools/esp-rom-elfs/20230320"),
        PATH=":".join(map(str, (gcc, root / "idf-python-env/bin", root / "bin"))) + ":" + os.environ["PATH"])
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    directory = workspace / "build"
    def run(args, name):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    run([cmake, "-G", "Ninja", "-S", str(sdk / "components/bootloader/subproject"), "-B", str(directory),
        "-DSDKCONFIG=" + str(output / "config"), "-DIDF_PATH=" + str(sdk), "-DIDF_TARGET=esp32",
        "-DPROJECT_SOURCE_DIR=" + str(workspace / "project"),
        "-DEXTRA_COMPONENT_DIRS=" + str(sdk / "components/bootloader"),
        "-DPYTHON=" + str(root / "idf-python-env/bin/python"), "-DPYTHON_DEPS_CHECKED=1",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log")
    run([cmake, "--build", str(directory), "--parallel", "2"], "build.log")
    if (output / "config").read_bytes() != (reference / "config").read_bytes():
        raise ValueError("Native configuration changed")
    for name in ("bootloader.elf", "bootloader.bin", "bootloader.map", "compile_commands.json"):
        shutil.copyfile(directory / name, output / name)
    for name in ("application.elf", "application.bin", "partitions.bin"):
        shutil.copyfile(reference / name, output / name)
    for unit in json.loads((output / "compile_commands.json").read_text()):
        source = Path(unit["file"]).resolve()
        if source.is_relative_to(sdk):
            relative = Path("sdk") / source.relative_to(sdk)
        elif source.is_relative_to(workspace):
            relative = Path("work") / source.relative_to(workspace)
        else:
            raise ValueError("Unmapped compiled source: " + str(source))
        destination = output / "source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for name in ("components/bootloader/subproject/main/ld/esp32/bootloader.ld",
                 "components/bootloader/subproject/main/CMakeLists.txt",
                 "components/bootloader/subproject/CMakeLists.txt",
                 "components/bootloader_support/src/bootloader_init.c",
                 "components/bootloader/subproject/main/bootloader_hooks.h"):
        destination = output / "source/sdk" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sdk / name, destination)
    shutil.copytree(directory / "config", output / "native-config")
    if legacy_rtc_wdt_handoff:
        for name in ('components/hal/include/hal/wdt_hal.h','components/hal/include/hal/wdt_types.h',
                'components/hal/esp32/include/hal/rwdt_ll.h','components/hal/esp32/include/hal/mwdt_ll.h',
                'components/soc/esp32/include/soc/rtc_cntl_reg.h',
                'components/soc/esp32/include/soc/rtc_cntl_struct.h'):
            destination=output/'source/sdk'/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(sdk/name,destination)
    shutil.copyfile(__file__, output / "builder.py")
    run([str(gcc / "xtensa-esp32-elf-objdump"), "-d", str(output / "bootloader.elf")], "disassembly.txt")
    result = {"status": "build_pass_not_measured", "reference": REFERENCE,
        "application_rebuilt": False, "application_sha256": sha(reference / "application.bin"),
        "whole_live_ram_peak_measured": False, "ranking_eligible": False,
        **({'legacy_rtc_wdt_handoff':True} if legacy_rtc_wdt_handoff else {}),
        "files": {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}}
    (output / "build.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Boot-stage observer built; original application bytes unchanged", flush=True)


def collect(root, output, source, port):
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build_dir, captures = output / "build", output / "captures"
        build_dir.mkdir()
        captures.mkdir()
        for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
            shutil.copyfile(source / name, build_dir / name)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(Path(__file__).with_name("run_esp32_followup.py"), output / "board-helper.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        (output / "plan.json").write_text(json.dumps({"resets": 5, "seconds": 100, "board_mac": MAC,
            "build_manifest_sha256": sha(source / "build.json"), "application_unchanged": True,
            "scope": "second-stage entry to console-deinit entry; first-stage ROM and final transfer remain outside this observer"}, indent=2) + "\n")
        state = {"mode": "boot-stage-ram", "status": "incomplete", "board_mac": MAC, "independent_resets": 0,
            "started_utc": datetime.now(timezone.utc).isoformat(), "original_flash_restored": False,
            "old_cohort_modified": False, "energy_measured": False, "external_independent_replication": False}
        board = Board(root, output, MAC, port)
        try:
            board.backup()
            try:
                pairs = board.flash(captures, build_dir)
                try:
                    for index in range(1, 6):
                        board.capture(captures, index, 100, stop="TM_RAM END")
                        board.verify(pairs, captures / ("verify-run%d.log" % index))
                        values = observations([r["line"] for r in read_raw_capture(captures, index)])
                        state["independent_resets"] += 1
                        print("Boot-stage reset", index, values, flush=True)
                    state["status"] = "collection_complete_audit_pending"
                finally:
                    board.verify(pairs, captures / "verify-after.log")
            finally:
                board.restore()
                state["original_flash_restored"] = True
        finally:
            state["completed_utc"] = datetime.now(timezone.utc).isoformat()
            state["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}
            (output / "campaign.json").write_text(json.dumps(state, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "collect"))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--observer", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    parser.add_argument('--legacy-rtc-wdt-handoff',action='store_true')
    args = parser.parse_args()
    if args.mode == "build":
        build(args.root, args.workspace, args.output, args.reference, args.observer,args.legacy_rtc_wdt_handoff)
    else:
        def interrupted(signum, frame):
            signal.alarm(0)
            raise RuntimeError("Interrupted; restoring original full Flash")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(1200)
        try:
            collect(args.root, args.output, args.source, args.port)
        finally:
            signal.alarm(0)
