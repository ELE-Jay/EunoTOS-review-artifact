#!/usr/bin/env python3
"""Reconcile the ESP32 summary tables with archived real-board UART evidence."""

import argparse
import hashlib
import json
import re
import shlex
import statistics
from datetime import datetime
from fractions import Fraction
from pathlib import Path

from audit_esp32_hartstone_series import audit as audit_hartstone
from audit_esp32_hartstone_ph0 import audit as audit_ph_baseline
from audit_esp32_tm_basic import audit as audit_tm
from audit_esp32_tm_reboots import require_self_check


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md"
EVIDENCE = ROOT / "artifacts/reports"
OSES = ("FreeRTOS", "Zephyr", "NuttX")
PH_NATIVE_SCHEDULE_SHA256 = "e46e85494dc423bff80582f6b783893f236ff6ea538e55780299171224029374"
TM_SCOPED_RANKING_CASES = (
    "cooperative_scheduling", "preemptive_scheduling", "message_processing",
    "synchronization_processing", "interrupt_processing", "interrupt_preemption_processing",
)

TM = (
    ("basic_processing", "Basic single-thread processing", {
        "FreeRTOS": "tm-freertos-native-aligned-v1/basic_processing/reset*.jsonl",
        "Zephyr": "zephyr-gcc13-align/basic_processing/reset*.jsonl",
        "NuttX": "tm-nuttx-native-aligned-v1/basic_processing/reset*.jsonl"}),
    ("cooperative_scheduling", "Cooperative scheduling", {
        "FreeRTOS": "tm-freertos-native-aligned-v1/cooperative_scheduling/reset*.jsonl",
        "Zephyr": "zephyr-gcc13-align/cooperative_scheduling/reset*.jsonl",
        "NuttX": "tm-cooperative-native-nuttx-v1/reset*.jsonl"}),
    ("preemptive_scheduling", "Preemptive scheduling", {
        os: ("zephyr-gcc13-align/preemptive_scheduling/reset*.jsonl" if os == "Zephyr"
             else "tm-freertos-native-aligned-v1/preemptive_scheduling/reset*.jsonl" if os == "FreeRTOS"
             else "tm-nuttx-native-aligned-v1/preemptive_scheduling/reset*.jsonl") for os in OSES}),
    ("message_processing", "16-byte message processing", {
        os: ("zephyr-gcc13-align/message_processing/reset*.jsonl" if os == "Zephyr"
             else "tm-freertos-native-aligned-v1/message_processing/reset*.jsonl" if os == "FreeRTOS"
             else f"esp32-tm-v2/tm-message-selfcheck-{os.lower()}/reset*.jsonl") for os in OSES}),
    ("synchronization_processing", "Semaphore synchronization", {
        os: ("zephyr-gcc13-align/synchronization_processing/reset*.jsonl" if os == "Zephyr"
             else "tm-freertos-native-aligned-v1/synchronization_processing/reset*.jsonl" if os == "FreeRTOS"
             else f"tm-sync-power-r3-20261005/{os.lower()}/reset*/uart.jsonl") for os in OSES}),
    ("memory_allocation", "128-byte memory allocation", {
        "FreeRTOS": "tm-freertos-native-aligned-v1/memory_allocation/reset*.jsonl",
        "Zephyr": "zephyr-gcc13-align/memory_allocation/reset*.jsonl",
        "NuttX": "tm-nuttx-native-aligned-v1/memory_allocation/reset*.jsonl"}),
    ("interrupt_processing", "Interrupt processing", {
        os: ("tm-freertos-native-aligned-v1/interrupt_processing/reset*.jsonl" if os == "FreeRTOS"
             else f"tm-irq-cpu2-v1/{os.lower()}/interrupt_processing/reset*.jsonl") for os in OSES}),
    ("interrupt_preemption_processing", "Interrupt preemption processing", {
        os: ("tm-freertos-native-aligned-v1/interrupt_preemption_processing/reset*.jsonl" if os == "FreeRTOS"
             else f"tm-irq-cpu2-v1/{os.lower()}/interrupt_preemption_processing/reset*.jsonl") for os in OSES}),
)

PH = (
    (1, "FreeRTOS", "hartstone-ph1-freertos/reset*.jsonl", 3),
    (1, "Zephyr", "hartstone-ph1-zephyr/reset*.jsonl", 3),
    (1, "NuttX", "hartstone-ph1-nuttx-abs/reset*.jsonl", 3),
    (2, "FreeRTOS", "esp32-hartstone-ph2-freertos/reset1-uart.jsonl", 1),
    (2, "Zephyr", "esp32-hartstone-ph2-zephyr/abs-reset1-uart.jsonl", 1),
    (2, "NuttX", "esp32-hartstone-ph2-nuttx/*reset*.jsonl", 3),
    (3, "FreeRTOS", "hartstone-ph3-freertos-full*/reset*.jsonl", 2),
    (3, "Zephyr", "hartstone-ph3-zephyr-full*/reset*.jsonl", 2),
    (3, "NuttX", "hartstone-ph3-nuttx-gcc12/reset*.jsonl", 3),
    (4, "FreeRTOS", "esp32-hartstone-ph4-freertos-extended/*reset*.jsonl", 3),
    (4, "Zephyr", "esp32-hartstone-ph4-zephyr-extended/*reset*.jsonl", 3),
    (4, "NuttX", "esp32-hartstone-ph4-nuttx/*reset*.jsonl", 3),
)

PH_BASELINES = (
    ("Zephyr", "hartstone-zephyr-gcc13-calibration", False, "Zephyr / GCC13 tick baseline"),
    ("NuttX", "hartstone-nuttx-gcc13-calibration", False, "NuttX / GCC13 tick baseline"),
    ("NuttX", "hartstone-nuttx-highres-calibration", True, "NuttX / GCC13 native-us baseline"),
)


def audit_image_manifest(directory, required, *, allow_nested=False):
    directory = directory.resolve()
    checked = set()
    for line in (directory / "image.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        file = (directory / name).resolve()
        contained = file.is_relative_to(directory) if allow_nested else file.parent == directory
        if not contained or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError(f"{directory}: invalid image manifest entry {name}")
        checked.add(file.relative_to(directory).as_posix() if allow_nested else file.name)
    if not required <= checked:
        raise ValueError(f"{directory}: incomplete image manifest")


def audit_freertos_no_timeslicing(directory, require_preemption=None):
    stock = (directory / "FreeRTOSConfig-stock.h").read_text()
    controlled = (directory / "FreeRTOSConfig.h").read_text()
    timeslice = "#define configUSE_TIME_SLICING                       1"
    preemptive = "#define configUSE_PREEMPTION                         1"
    preemption = "1" if preemptive in controlled else "0"
    expected = stock.replace(timeslice, timeslice[:-1] + "0")
    if preemption == "0":
        expected = expected.replace(preemptive, preemptive[:-1] + "0")
    if stock.count(timeslice) != 1 or stock.count(preemptive) != 1 or controlled != expected or \
            (require_preemption is not None and preemption != require_preemption):
        raise ValueError(f"{directory}: scheduler change exceeds the documented configuration control")
    defines = json.loads((directory / "kernel-defines.json").read_text())
    if len(defines) != 3 or {Path(row["source"]).name for row in defines} != {"tasks.c", "queue.c", "timers.c"} or \
            any(row["configUSE_TIME_SLICING"] != "0" or row["configUSE_PREEMPTION"] != preemption
                for row in defines):
        raise ValueError(f"{directory}: effective native scheduler configuration not proven")
    compiled = json.loads((directory / "compile_commands.json").read_text())
    component = "tm-cooperative-no-timeslicing" if preemption == "1" else "tm-cooperative-mode"
    for row in defines:
        if f"/{component}/freertos/FreeRTOS-Kernel/" not in row["source"]:
            raise ValueError(f"{directory}: scheduler preprocessing source mismatch")
        commands = [shlex.split(entry["command"]) for entry in compiled if entry["file"] == row["source"]]
        if len(commands) != 1:
            raise ValueError(f"{directory}: scheduler source lacks a unique compile command")
        command = commands[0]
        if [arg for arg in command if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(f"{directory}: kernel optimization differs from the size-optimized profile")
        output = command.index("-o")
        del command[output:output + 2]
        command.remove("-c")
        command.extend(["-E", "-dM"])
        if command != row["command"]:
            raise ValueError(f"{directory}: macro evidence does not replay the actual kernel command")
    return preemption


def audit_flash(directory, name, segments):
    lines = (directory / name).read_text().splitlines()
    if lines.count("MAC: 84:1f:e8:8f:55:dc") != 1 or \
            lines.count("Chip is ESP32-D0WDQ6 (revision v1.1)") != 1 or \
            lines.count("Crystal is 40MHz") != 1:
        raise ValueError(f"{directory}: flash target does not match the declared ESP32 board")
    if lines.count("Hash of data verified.") != segments:
        raise ValueError(f"{directory}: incomplete verified flash segments")


def audit_zephyr_image(directory, case):
    audit_image_manifest(directory, {"config", "compiler.txt", "compile_commands.json",
                                    "test.c", "port.c", "main.c", "tm_override.h",
                                    "zephyr.elf", "zephyr.bin"})
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_SYS_CLOCK_TICKS_PER_SEC=100",
                    "CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000",
                    "CONFIG_MP_MAX_NUM_CPUS=1", "# CONFIG_SMP is not set",
                    "# CONFIG_TIMESLICING is not set", "CONFIG_SIZE_OPTIMIZATIONS=y"):
        if setting not in config:
            raise ValueError(f"{directory}: missing {setting}")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            '#pragma GCC optimize("O0")' not in (directory / "test.c").read_text():
        raise ValueError(f"{directory}: wrong compiler or original-body optimization")
    producer = b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0"
    if producer not in (directory / "zephyr.elf").read_bytes():
        raise ValueError(f"{directory}: missing ELF compiler evidence")
    audit_flash(directory, "flash.log", 1)
    commands = json.loads((directory / "compile_commands.json").read_text())
    application = [row for row in commands if Path(row["file"]).name in
                   ("main.c", "port.c", "test.c")]
    if {Path(row["file"]).name for row in application} != {"main.c", "port.c", "test.c"}:
        raise ValueError(f"{directory}: missing application compile commands")
    for row in application:
        arguments = shlex.split(row["command"])
        optimizations = [arg for arg in arguments if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        if "esp-13.2.0_20230928" not in arguments[0] or optimizations[-1:] != ["-Os"] or \
                f"-DTM_TEST_{case}=1" not in arguments:
            raise ValueError(f"{directory}: wrong application compiler/flags/test case")


def audit_freertos_memory_image(directory):
    audit_image_manifest(directory, {"sdkconfig", "compiler.txt", "compile_commands.json",
                                    "test.c", "port.c", "main.c", "tm_override.h",
                                    "iotosbench_tm.elf", "iotosbench_tm.bin",
                                    "bootloader.bin", "partition-table.bin", "flash_args"})
    config = (directory / "sdkconfig").read_bytes()
    if hashlib.sha256(config).hexdigest() != \
            "dff62037ee6e0004496fa847f22be71af7ce61009d75ceff233b0784c8206dd2":
        raise ValueError("FreeRTOS memory configuration differs from the aligned cohort")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            '#pragma GCC optimize("O0")' not in (directory / "test.c").read_text():
        raise ValueError("wrong FreeRTOS memory compiler or original-body optimization")
    if b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in \
            (directory / "iotosbench_tm.elf").read_bytes() or \
            (directory / "flash.log").read_text().count("Hash of data verified.") != 3:
        raise ValueError("missing FreeRTOS memory ELF compiler or verified flash segments")
    commands = json.loads((directory / "compile_commands.json").read_text())
    application = [row for row in commands
                   if "/idf-freertos-tm-v2/main/" in row["file"]]
    if len(application) != 3 or {Path(row["file"]).name for row in application} != \
            {"main.c", "port.c", "test.c"}:
        raise ValueError("missing FreeRTOS memory application compile commands")
    for row in application:
        arguments = shlex.split(row["command"])
        optimizations = [arg for arg in arguments if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        if "esp-13.2.0_20230928" not in arguments[0] or optimizations[-1:] != ["-Os"] or \
                "-DTM_TEST_memory_allocation=1" not in arguments:
            raise ValueError("wrong FreeRTOS memory compiler/flags/test case")


def require_memory_pool_metadata(raw):
    require_self_check(raw, "memory")
    marker = "Thread-Metric memory pool family=ESP_IDF_MULTI_HEAP arena_bytes=4096 lock=PORTMUX"
    indices = [index for index, row in enumerate(raw) if row["line"].strip() == marker]
    report = next(index for index, row in enumerate(raw)
                  if row["line"].startswith("**** Thread-Metric"))
    if len(indices) != 1 or indices[0] >= report:
        raise ValueError("missing ordered FreeRTOS private-pool family metadata")


def audit_hartstone_baseline_image(directory, os, high_resolution=False):
    image_name = "zephyr.elf" if os == "Zephyr" else "nuttx"
    required = {"config", "compiler.txt", "build.log", "small_whetstone.c", image_name}
    required |= {"zephyr.bin", "compile_commands.json", "main.c", "math_compat.h",
                 "CMakeLists.txt"} if os == "Zephyr" else \
                {"nuttx.bin", "nuttx.map", "hartstone_main.c", "Makefile", "Kconfig",
                 "bootloader-esp32.bin", "partition-table-esp32.bin"}
    if high_resolution:
        required.add("ph_rt_timer.h")
    audit_image_manifest(directory, required)
    if hashlib.sha256((directory / "small_whetstone.c").read_bytes()).hexdigest() != \
            "ff3547d384542f5024af647e62bbb84c69dfefaf9953840df8ff7b4770b38a8f":
        raise ValueError(f"{directory}: Small_Whetstone body differs from pinned shared source")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in \
            (directory / image_name).read_bytes():
        raise ValueError(f"{directory}: baseline compiler not proven")
    config = (directory / "config").read_text().splitlines()
    settings = ("CONFIG_SYS_CLOCK_TICKS_PER_SEC=1000",
                "CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_MP_MAX_NUM_CPUS=1",
                "# CONFIG_SMP is not set", "# CONFIG_TIMESLICING is not set",
                "CONFIG_FPU=y", "CONFIG_FPU_SHARING=y") if os == "Zephyr" else \
               ("CONFIG_USEC_PER_TICK=1000", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240",
                "CONFIG_ARCH_FPU=y", "CONFIG_LIBM_TOOLCHAIN=y",
                "CONFIG_EXAMPLES_HARTSTONE_PH_EXPERIMENT=0")
    if any(setting not in config for setting in settings) or "CONFIG_SMP=y" in config:
        raise ValueError(f"{directory}: baseline configuration mismatch")
    if os == "NuttX":
        enabled = "CONFIG_ESP32_RT_TIMER=y" in config
        if enabled != high_resolution or (high_resolution and
                "CONFIG_EXAMPLES_HARTSTONE_HIGH_RES=y" not in config):
            raise ValueError(f"{directory}: incorrect native release-timer profile")
        commands = [line for line in (directory / "build.log").read_text().splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc -c ") and
                    any(f"{name}.c -o " in line for name in ("hartstone_main", "small_whetstone"))]
        if len(commands) != 2 or "esp-13.2.0_20230928" not in \
                (directory / "build.log").read_text():
            raise ValueError(f"{directory}: missing baseline compile/library link evidence")
    else:
        rows = json.loads((directory / "compile_commands.json").read_text())
        commands = [row["command"] for row in rows if
                    "/hartstone_zephyr/src/" in row["file"] or
                    Path(row["file"]).name == "small_whetstone.c"]
        if len(commands) != 3 or any("esp-13.2.0_20230928" not in line or
                                    "math_compat.h" not in line for line in commands):
            raise ValueError(f"{directory}: missing Zephyr baseline compile evidence")
    for command in commands:
        args = shlex.split(command)
        optimizations = [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        if optimizations[-1:] != ["-Os"] or not {"-fno-fast-math", "-ffp-contract=off"} <= set(args) or \
                any(arg.startswith("-DPH_EXPERIMENT=") for arg in args):
            raise ValueError(f"{directory}: baseline application flags mismatch")
    if (directory / "flash.log").read_text().count("Hash of data verified.") != \
            (1 if os == "Zephyr" else 3):
        raise ValueError(f"{directory}: missing verified baseline flash segments")


def evidence(pattern, count):
    paths = sorted(EVIDENCE.glob(pattern))
    if len(paths) != count:
        raise ValueError(f"{pattern}: expected {count} captures, found {len(paths)}")
    return paths


def audit_hartstone_native_image(directory, os, experiment, mode, aligned=False, fifo=False,
                                 require_flash=True):
    if fifo and os != "FreeRTOS":
        raise ValueError("the isolated FIFO SDK configuration applies only to FreeRTOS")
    aligned = aligned or fifo
    images = {"FreeRTOS": "iotosbench_esp32_hartstone.elf", "Zephyr": "zephyr.elf", "NuttX": "nuttx"}
    image = images[os]
    required = {"config", "compiler.txt", "build.log", "small_whetstone.c",
                "ph_us_schedule.h", "build_esp32_hartstone_native_us.sh", image}
    required |= {
        "FreeRTOS": {"series.c", "ph_esp_timer.h", "compile_commands.json",
                     "iotosbench_esp32_hartstone.bin", "bootloader.bin", "partition-table.bin"},
        "Zephyr": {"series.c", "math_compat.h", "errno_bridge.c", "compile_commands.json",
                   "zephyr.bin", "ph_native_us.conf"},
        "NuttX": {"hartstone_series.c", "ph_rt_timer.h", "Makefile", "Kconfig", "nuttx.bin",
                  "nuttx.map", "bootloader-esp32.bin", "partition-table-esp32.bin"},
    }[os]
    if fifo:
        required |= {"FreeRTOSConfig.h", "FreeRTOSConfig-stock.h", "kernel-defines.json"}
    audit_image_manifest(directory, required)
    if hashlib.sha256((directory / "small_whetstone.c").read_bytes()).hexdigest() != \
            "ff3547d384542f5024af647e62bbb84c69dfefaf9953840df8ff7b4770b38a8f":
        raise ValueError(f"{directory}: changed shared Small_Whetstone body")
    if hashlib.sha256((directory / "ph_us_schedule.h").read_bytes()).hexdigest() != \
            PH_NATIVE_SCHEDULE_SHA256:
        raise ValueError(f"{directory}: shared native release schedule mismatch")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in (directory / image).read_bytes():
        raise ValueError(f"{directory}: native profile compiler not proven")
    config = (directory / "config").read_text().splitlines()
    settings = {
        "FreeRTOS": ("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_UNICORE=y",
                     "CONFIG_FREERTOS_HZ=1000"),
        "Zephyr": ("CONFIG_SYS_CLOCK_TICKS_PER_SEC=100000", "CONFIG_TICKLESS_KERNEL=y",
                   "CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_MP_MAX_NUM_CPUS=1",
                   "# CONFIG_SMP is not set", "# CONFIG_TIMESLICING is not set",
                   "CONFIG_FPU=y", "CONFIG_FPU_SHARING=y"),
        "NuttX": ("CONFIG_USEC_PER_TICK=1000", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240",
                  "CONFIG_ARCH_FPU=y", "CONFIG_LIBM_TOOLCHAIN=y", "CONFIG_ESP32_RT_TIMER=y",
                  "CONFIG_EXAMPLES_HARTSTONE_HIGH_RES=y", "CONFIG_ESP32_RT_TIMER_TASK_PRIORITY=223",
                  "CONFIG_ESP32_RT_TIMER_TASK_STACK_SIZE=2048",
                  f"CONFIG_EXAMPLES_HARTSTONE_PH_EXPERIMENT={experiment}"),
    }[os]
    if any(setting not in config for setting in settings) or "CONFIG_SMP=y" in config:
        raise ValueError(f"{directory}: native timer configuration mismatch")
    if os == "NuttX":
        source = ROOT / "firmware/bsp/esp32/hartstone_nuttx"
        for name in ("hartstone_series.c", "ph_rt_timer.h", "Makefile", "Kconfig"):
            if (directory / name).read_bytes() != (source / name).read_bytes():
                raise ValueError(f"{directory}: {name} differs from the maintained native FIFO/timer implementation")
        reference = EVIDENCE / "hartstone-native-us-v1/nuttx/ph4/config"
        metadata = ("CONFIG_BASE_DEFCONFIG=", "CONFIG_EXAMPLES_HARTSTONE_PH_EXPERIMENT=")
        if [line for line in config if not line.startswith(metadata)] != [
            line for line in reference.read_text().splitlines() if not line.startswith(metadata)
        ]:
            raise ValueError(f"{directory}: native NuttX configuration changed outside experiment/build labels")
    if os == "Zephyr":
        reference = EVIDENCE / "hartstone-native-us-v1/zephyr/ph4"
        for name in ("config", "series.c", "small_whetstone.c", "small_whetstone.h",
                     "ph_us_schedule.h", "math_compat.h", "errno_bridge.c",
                     "ph_native_us.conf", "prj.conf", "CMakeLists.txt"):
            if (directory / name).read_bytes() != (reference / name).read_bytes():
                raise ValueError(f"{directory}: {name} differs from the audited native PH4 profile")
    if aligned and os == "FreeRTOS":
        if not {"CONFIG_COMPILER_OPTIMIZATION_SIZE=y", "CONFIG_LOG_DEFAULT_LEVEL=0"} <= set(config):
            raise ValueError(f"{directory}: FreeRTOS kernel/log configuration not aligned")
    if fifo:
        audit_freertos_no_timeslicing(directory, require_preemption="1")
    names = {"series.c", "small_whetstone.c"} if os != "NuttX" else \
            {"hartstone_series.c", "small_whetstone.c"}
    if os == "NuttX":
        log = (directory / "build.log").read_text()
        commands = [line for line in log.splitlines() if line.startswith("xtensa-esp32-elf-gcc -c ")
                    and any(f"{name} -o " in line for name in names)]
        if "esp-13.2.0_20230928" not in log:
            raise ValueError(f"{directory}: missing native math-library link provenance")
    else:
        rows = json.loads((directory / "compile_commands.json").read_text())
        commands = [row["command"] for row in rows if Path(row["file"]).name in names]
        if any("esp-13.2.0_20230928" not in line for line in commands):
            raise ValueError(f"{directory}: incorrect native application compiler")
        if aligned and os == "FreeRTOS":
            kernel = [row["command"] for row in rows if "/FreeRTOS-Kernel/" in row["file"]
                      and Path(row["file"]).name in ("tasks.c", "queue.c", "timers.c")]
            if len(kernel) != 3 or any(
                [arg for arg in shlex.split(line) if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]
                for line in kernel
            ):
                raise ValueError(f"{directory}: FreeRTOS scheduler/queue/timer optimization not proven")
    if len(commands) != 2:
        raise ValueError(f"{directory}: incomplete native application compile evidence")
    for command in commands:
        args = shlex.split(command)
        optimizations = [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        expected = {"-fno-fast-math", "-ffp-contract=off", f"-DPH_EXPERIMENT={experiment}"}
        if os != "NuttX":
            expected.add("-DPH_HIGH_RES=1")
        if optimizations[-1:] != ["-Os"] or not expected <= set(args):
            raise ValueError(f"{directory}: native application flags or experiment mismatch")
    if require_flash:
        audit_flash(directory, f"flash-{mode}.log", 1 if os == "Zephyr" else 3)
    return hashlib.sha256((directory / image).read_bytes()).hexdigest()


def report_rows(text):
    rows = {}
    lines = text.splitlines()
    def separator(line):
        return line.startswith("|") and line.endswith("|") and all(
            re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in line[1:-1].split("|"))
    for index, line in enumerate(lines):
        if line.startswith("|") and line.endswith("|"):
            if separator(line) or (index + 1 < len(lines) and separator(lines[index + 1])):
                continue
            cells = [cell.strip() for cell in line[1:-1].split("|")]
            if cells[0] in rows:
                raise ValueError(f"ambiguous duplicate report row: {cells[0]}")
            rows[cells[0]] = cells
    return rows


def audit_hartstone_native_cohort(directory, os, experiment, aligned=False, fifo=False):
    image_hash = audit_hartstone_native_image(directory, os, experiment, "full", aligned=aligned, fifo=fifo)
    paths = sorted(directory.glob("reset*.jsonl"))
    if len(paths) != 3:
        raise ValueError(f"{directory}: expected three native threshold captures")
    results = []
    previous_end = None
    for path in paths:
        result = audit_hartstone(path, os, experiment, high_resolution=True)
        if result["completion"] != "FIRST_LOSS_REACHED" or result["bounded_capture"]:
            raise ValueError(f"{path}: native threshold capture is incomplete")
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        start = datetime.fromisoformat(next(row["utc"] for row in raw if row["line"].startswith("rst:0x")))
        end = datetime.fromisoformat(raw[-1]["utc"])
        if start.utcoffset() is None or end.utcoffset() is None or end <= start or \
                (previous_end is not None and start <= previous_end):
            raise ValueError(f"{path}: native reset captures overlap or lack timezone evidence")
        previous_end = end
        results.append(result)
    return image_hash, results


def audit_report(text):
    from audit_esp32_tm_irq_match import NUTTX_REUSED_CASES, audit_cohort

    rows = report_rows(text)
    tm_cells = tm_captures = ph_cells = ph_captures = baseline_captures = 0
    tm_values = {}
    audit_freertos_memory_image(EVIDENCE / "tm-memory-pool-freertos")
    for case, label, groups in TM:
        image = EVIDENCE / "zephyr-gcc13-align" / case
        audit_zephyr_image(image, case)
        baseline = EVIDENCE / "zephyr-gcc13-align/basic_processing"
        for name in ("config", "port.c", "test.c", "main.c", "tm_override.h"):
            if (image / name).read_bytes() != (baseline / name).read_bytes():
                raise ValueError(f"{image}: {name} differs between original cases")
        cells = rows[label]
        for os, pattern in groups.items():
            if os == "FreeRTOS":
                image = EVIDENCE / "tm-freertos-native-aligned-v1" / case
                audit_cohort(image, os, case, uniform=True)
                for name in ("config", "FreeRTOSConfig.h", "port.c", "main.c", "test.c", "tm_override.h"):
                    if (image / name).read_bytes() != (EVIDENCE / "tm-freertos-native-aligned-v1/basic_processing" / name).read_bytes():
                        raise ValueError(f"{image}: {name} differs between uniform FreeRTOS cases")
            elif case in ("interrupt_processing", "interrupt_preemption_processing"):
                audit_cohort(EVIDENCE / "tm-irq-cpu2-v1" / os.lower() / case, os, case)
            elif os == "NuttX" and case == "cooperative_scheduling":
                result = audit_cohort(EVIDENCE / "tm-cooperative-native-nuttx-v1", os, case)
                counts = " / ".join(f'{run["original_window_totals"][0]:,}' for run in result["runs"])
                observed = [counts, f'{result["first_window_median"]:,}', "3",
                            f'`{result["elf_sha256"][:12]}`']
                if rows["NuttX / source-bound cooperative scheduling"][1:] != observed:
                    raise ValueError("NuttX cooperative source-bound report/record mismatch")
            elif os == "NuttX" and case in NUTTX_REUSED_CASES:
                audit_cohort(EVIDENCE / "tm-nuttx-native-aligned-v1" / case, os, case,
                             reuse_identical_image=True)
            elif os == "NuttX":
                result = audit_cohort(EVIDENCE / "tm-nuttx-native-aligned-v1" / case, os, case)
                counts = " / ".join(f'{run["original_window_totals"][0]:,}' for run in result["runs"])
                observed = [counts, f'{result["first_window_median"]:,}', "3",
                            f'`{result["elf_sha256"][:12]}`']
                if rows[f"NuttX / source-bound {label.lower()}"][1:] != observed:
                    raise ValueError(f"NuttX {case} source-bound report/record mismatch")
            if os == "NuttX":
                image = EVIDENCE / (
                    f"tm-irq-cpu2-v1/nuttx/{case}" if case.startswith("interrupt_") else
                    "tm-cooperative-native-nuttx-v1" if case == "cooperative_scheduling" else
                    f"tm-nuttx-native-aligned-v1/{case}")
                reference = EVIDENCE / "tm-cooperative-native-nuttx-v1"
                for name in ("config", "port.c", "test.c", "tm_override.h", "iotosbench_main.c", "Makefile"):
                    if (image / name).read_bytes() != (reference / name).read_bytes():
                        raise ValueError(f"{image}: {name} differs between native NuttX cases")
            paths = evidence(pattern, 3)
            totals = []
            reset_times = []
            for path in paths:
                raw = [json.loads(line) for line in path.read_text().splitlines()]
                resets = [row for row in raw if row["line"].startswith("rst:0x")]
                if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
                    raise ValueError(f"{path}: missing early independent ROM reset")
                reset_times.append(datetime.fromisoformat(resets[0]["utc"]))
                if case == "message_processing":
                    require_self_check(raw, "queue")
                if case == "synchronization_processing":
                    require_self_check(raw, "semaphore")
                if case == "memory_allocation" and os == "FreeRTOS":
                    require_memory_pool_metadata(raw)
                result = audit_tm(path, os, case)
                if not 25 < result["host_window_seconds"][0] < 40:
                    raise ValueError(f"{path}: first window is not near 30 seconds")
                totals.append(result["original_window_totals"][0])
            if len(set(reset_times)) != len(paths):
                raise ValueError(f"{label}/{os}: duplicate reset timestamps")
            published = int(cells[OSES.index(os) + 1].replace(",", ""))
            if statistics.median(totals) != published:
                raise ValueError(f"{label}/{os}: report {published}, raw {totals}")
            tm_cells += 1
            tm_captures += len(paths)
            tm_values[case, os] = published
    for case, label, _ in TM:
        if case not in TM_SCOPED_RANKING_CASES:
            continue
        normalized = {os: Fraction(tm_values[case, os], tm_values["basic_processing", os]) for os in OSES}
        ordered = sorted(OSES, key=normalized.get, reverse=True)
        ranking = ordered[0]
        for previous, os in zip(ordered, ordered[1:]):
            ranking += (" = " if normalized[previous] == normalized[os] else " > ") + os
        if rows[f"Scoped Thread-Metric / {label}"][1] != ranking:
            raise ValueError(f"{case}: scoped ordering differs from original Basic-normalized counts")
    if rows["FreeRTOS / stock time-slicing cooperative"][1:3] != ["Invalid", "2"]:
        raise ValueError("stock FreeRTOS invalid cooperative control became a score")
    for filename in ("idf-tm-v2-coop-uart.jsonl", "idf-tm-v2-coop-uart2.jsonl"):
        raw = [json.loads(line) for line in (EVIDENCE / "esp32-tm-v2" / filename).read_text().splitlines()]
        error = "ERROR: Invalid counter value(s). Cooperative counters should not be more that 1 different than the average!"
        if not any(row["line"].strip() == error for row in raw):
            raise ValueError(f"{filename}: historical negative control no longer shows the original error")

    cooperative_control_captures = 0
    for cohort, label in (
        ("tm-cooperative-no-timeslicing-v1", "FreeRTOS / no-time-slicing cooperative control"),
        ("tm-cooperative-mode-v1", "FreeRTOS / cooperative-mode control"),
    ):
        result = audit_cohort(EVIDENCE / cohort, "FreeRTOS", "cooperative_scheduling")
        counts = " / ".join(f'{run["original_window_totals"][0]:,}' for run in result["runs"])
        if rows[label][1:] != [counts, f'{result["first_window_median"]:,}', "3", f'`{result["elf_sha256"][:12]}`']:
            raise ValueError(f"{label}: report/control-record mismatch")
        cooperative_control_captures += result["reboot_count"]

    ph_labels = {
        1: "PH1, increase one task's frequency",
        2: "PH2, increase all frequencies",
        3: "PH3, increase per-task workload",
        4: "PH4, add a copy of the middle baseline task",
    }
    for experiment, os, pattern, count in PH:
        cell = rows[ph_labels[experiment]][OSES.index(os) + 1]
        match = re.fullmatch(r"(?:First loss step|Step) (\d+), (\d+) (?:resets?|complete run)", cell)
        if match is None:
            raise ValueError(f"PH{experiment}/{os}: malformed report cell {cell!r}")
        step, reported_count = map(int, match.groups())
        if reported_count != count:
            raise ValueError(f"PH{experiment}/{os}: wrong reported reset count")
        reset_times = []
        for path in evidence(pattern, count):
            raw = [json.loads(line) for line in path.read_text().splitlines()]
            reset = next(row for row in raw if row["line"].startswith("rst:0x"))
            reset_times.append(datetime.fromisoformat(reset["utc"]))
            result = audit_hartstone(path, os, experiment)
            if result["completion"] != "FIRST_LOSS_REACHED" or result["first_loss_step"] != step:
                raise ValueError(f"PH{experiment}/{os}: report step {step}, raw {result}")
            ph_captures += 1
        if len(set(reset_times)) != count:
            raise ValueError(f"PH{experiment}/{os}: duplicate reset timestamps")
        ph_cells += 1
    for os, folder, high_resolution, label in PH_BASELINES:
        directory = EVIDENCE / folder
        audit_hartstone_baseline_image(directory, os, high_resolution)
        paths = evidence(f"{folder}/reset*.jsonl", 3)
        starts = []
        results = []
        for path in paths:
            raw = [json.loads(line) for line in path.read_text().splitlines()]
            starts.append(next(row["utc"] for row in raw if row["line"].startswith("rst:0x")))
            results.append(audit_ph_baseline(path, os, high_resolution))
        if len(set(starts)) != 3:
            raise ValueError(f"{directory}: duplicate baseline reset timestamps")
        cells = rows[label]
        elapsed = " / ".join(f'{result["calibration_elapsed_us"]:,}' for result in results)
        speeds = " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results)
        utilization = f'{statistics.median(result["sei_baseline_utilization_pct"] for result in results):.2f}%'
        if cells[1:5] != [elapsed, speeds, utilization, "3/3"]:
            raise ValueError(f"{label}: report does not match the baseline records")
        if cells[5] != f'`{hashlib.sha256((directory / ("zephyr.elf" if os == "Zephyr" else "nuttx")).read_bytes()).hexdigest()[:12]}`':
            raise ValueError(f"{label}: baseline image identity mismatch")
        baseline_captures += len(paths)
    native_prefix_captures = 0
    for os in OSES:
        directory = EVIDENCE / "hartstone-native-us-v1" / os.lower() / "ph2"
        image_hash = audit_hartstone_native_image(directory, os, 2, "smoke")
        paths = evidence(f"hartstone-native-us-v1/{os.lower()}/ph2/smoke-reset*.jsonl", 1)
        result = audit_hartstone(paths[0], os, 2, allow_incomplete=True, high_resolution=True)
        if result["completion"] != "INCOMPLETE" or result["trials"] != 6 or \
                result["best_step"] != 5 or result["first_loss_step"] is not None:
            raise ValueError(f"{directory}: native pilot is not the reported six-trial prefix")
        cells = rows[f"{os} / native-us PH2 pilot"]
        if cells[1:] != ["Steps 0-5 only", "1", f'{result["raw_speed_kwips"]:,}',
                         f'{result["tick_hz"]:,}', f'`{image_hash[:12]}`']:
            raise ValueError(f"{directory}: native pilot report mismatch")
        native_prefix_captures += 1
    native_complete_captures = 0
    native_primary = {}
    for experiment in (2, 4):
        for os in OSES:
            aligned = os == "FreeRTOS"
            profile = "hartstone-native-us-aligned-v1" if aligned else "hartstone-native-us-v1"
            directory = EVIDENCE / profile / os.lower() / f"ph{experiment}"
            image_hash, results = audit_hartstone_native_cohort(directory, os, experiment, aligned=aligned)
            label = f"{os} / {'size-optimized ' if aligned else ''}native-us PH{experiment}"
            cells = rows[label]
            observed = [" / ".join(str(result["first_loss_step"]) for result in results),
                        " / ".join(str(result["best_step"]) for result in results),
                        " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results),
                        "3", f'`{image_hash[:12]}`']
            if cells[1:] != observed or not all(result["sei_baseline_in_guided_range"] for result in results):
                raise ValueError(f"native {os} PH{experiment} report or guided baseline mismatch")
            native_complete_captures += len(results)
            if os != "FreeRTOS":
                native_primary[experiment, os] = results
    directory = EVIDENCE / "hartstone-native-us-fifo-v1/freertos/ph4"
    image_hash, results = audit_hartstone_native_cohort(directory, "FreeRTOS", 4, fifo=True)
    control = EVIDENCE / "hartstone-native-us-aligned-v1/freertos/ph4"
    for name in ("config", "series.c", "small_whetstone.c", "small_whetstone.h", "ph_esp_timer.h",
                 "ph_us_schedule.h", "main-CMakeLists.txt", "CMakeLists.txt"):
        if (directory / name).read_bytes() != (control / name).read_bytes():
            raise ValueError(f"{directory}: {name} changed outside the FIFO scheduler control")
    cells = rows["FreeRTOS / FIFO native-us PH4"]
    observed = [" / ".join(str(result["first_loss_step"]) for result in results),
                " / ".join(str(result["best_step"]) for result in results),
                " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results),
                "3", f'`{image_hash[:12]}`']
    if cells[1:] != observed or not all(result["sei_baseline_in_guided_range"] for result in results):
        raise ValueError("FreeRTOS FIFO PH4 report or guided baseline mismatch")
    native_complete_captures += len(results)
    native_primary[4, "FreeRTOS"] = results
    fifo_control_captures = len(results)
    control = directory
    for experiment in (1, 2, 3):
        directory = EVIDENCE / f"hartstone-native-us-fifo-v1/freertos/ph{experiment}"
        image_hash, results = audit_hartstone_native_cohort(directory, "FreeRTOS", experiment, fifo=True)
        for name in ("config", "FreeRTOSConfig.h", "series.c", "small_whetstone.c",
                     "small_whetstone.h", "ph_esp_timer.h", "ph_us_schedule.h",
                     "main-CMakeLists.txt", "CMakeLists.txt"):
            if (directory / name).read_bytes() != (control / name).read_bytes():
                raise ValueError(f"{directory}: {name} differs from the audited FIFO PH4 profile")
        cells = rows[f"FreeRTOS / FIFO native-us PH{experiment}"]
        observed = [" / ".join(str(result["first_loss_step"]) for result in results),
                    " / ".join(str(result["best_step"]) for result in results),
                    " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results),
                    "3", f'`{image_hash[:12]}`']
        if cells[1:] != observed or not all(result["sei_baseline_in_guided_range"] for result in results):
            raise ValueError(f"FreeRTOS FIFO PH{experiment} report or guided baseline mismatch")
        native_complete_captures += len(results)
        native_primary[experiment, "FreeRTOS"] = results
    for experiment in (1, 3):
        directory = EVIDENCE / f"hartstone-native-us-v1/zephyr/ph{experiment}"
        image_hash, results = audit_hartstone_native_cohort(directory, "Zephyr", experiment)
        control = EVIDENCE / "hartstone-native-us-v1/zephyr/ph4"
        for name in ("config", "series.c", "small_whetstone.c", "small_whetstone.h",
                     "ph_us_schedule.h", "math_compat.h", "errno_bridge.c",
                     "ph_native_us.conf", "prj.conf", "CMakeLists.txt"):
            if (directory / name).read_bytes() != (control / name).read_bytes():
                raise ValueError(f"{directory}: {name} differs from the audited native PH4 profile")
        cells = rows[f"Zephyr / native-us PH{experiment}"]
        observed = [" / ".join(str(result["first_loss_step"]) for result in results),
                    " / ".join(str(result["best_step"]) for result in results),
                    " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results),
                    "3", f'`{image_hash[:12]}`']
        if cells[1:] != observed or not all(result["sei_baseline_in_guided_range"] for result in results):
            raise ValueError(f"Zephyr PH{experiment} report or guided baseline mismatch")
        native_complete_captures += len(results)
        native_primary[experiment, "Zephyr"] = results
    for experiment in (1, 3):
        directory = EVIDENCE / f"hartstone-native-us-v1/nuttx/ph{experiment}"
        image_hash, results = audit_hartstone_native_cohort(directory, "NuttX", experiment)
        cells = rows[f"NuttX / native-us PH{experiment}"]
        observed = [" / ".join(str(result["first_loss_step"]) for result in results),
                    " / ".join(str(result["best_step"]) for result in results),
                    " / ".join(f'{result["raw_speed_kwips"]:,}' for result in results),
                    "3", f'`{image_hash[:12]}`']
        if cells[1:] != observed or not all(result["sei_baseline_in_guided_range"] for result in results):
            raise ValueError(f"NuttX PH{experiment} report or guided baseline mismatch")
        native_complete_captures += len(results)
        native_primary[experiment, "NuttX"] = results
    if set(native_primary) != {(experiment, os) for experiment in (1, 2, 3, 4) for os in OSES}:
        raise ValueError("incomplete native Hartstone primary matrix")
    for experiment in (1, 2, 3, 4):
        best = {os: int(statistics.median(run["best_step"] for run in native_primary[experiment, os]))
                for os in OSES}
        values = []
        for os in OSES:
            step = best[os]
            values.append({1: f"{200 + 40 * step:,} Hz", 2: f"{(10 + step) / 10:.1f}x",
                           3: f"+{step} KWI/task", 4: f"{step} extra workers"}[experiment])
        ordered = sorted(OSES, key=best.get, reverse=True)
        ranking = ordered[0]
        for previous, os in zip(ordered, ordered[1:]):
            ranking += (" = " if best[previous] == best[os] else " > ") + os
        if rows[f"Scoped Hartstone / PH{experiment}"][1:] != values + [ranking]:
            raise ValueError(f"scoped Hartstone PH{experiment} original threshold comparison mismatch")
    directory = EVIDENCE / "hartstone-native-us-aligned-v1/freertos/ph4"
    image_hash = audit_hartstone_native_image(directory, "FreeRTOS", 4, "smoke", aligned=True)
    paths = evidence("hartstone-native-us-aligned-v1/freertos/ph4/smoke-reset*.jsonl", 1)
    result = audit_hartstone(paths[0], "FreeRTOS", 4, allow_incomplete=True, high_resolution=True)
    cells = rows["FreeRTOS / size-optimized native-us PH4 pilot"]
    if result["completion"] != "INCOMPLETE" or result["trials"] != 6 or \
            result["best_step"] != 5 or cells[1:] != [
                "Steps 0-5 only", "1", f'{result["raw_speed_kwips"]:,}', "1,000", f'`{image_hash[:12]}`']:
        raise ValueError("FreeRTOS kernel/log control prefix report mismatch")
    return {"audit": "pass", "thread_metric_cells": tm_cells,
            "thread_metric_captures": tm_captures,
            "thread_metric_scoped_ranking_eligible": True,
            "thread_metric_scoped_ranked_cases": list(TM_SCOPED_RANKING_CASES),
            "zephyr_gcc13_image_audits": len(TM),
            "freertos_uniform_image_audits": len(TM),
            "freertos_uniform_captures": 3 * len(TM),
            "nuttx_source_bound_cooperative_image_audits": 1,
            "nuttx_source_bound_cooperative_captures": 3,
            "nuttx_native_image_audits": len(TM),
            "nuttx_native_captures": 3 * len(TM),
            "nuttx_fresh_replacement_captures": 9,
            "nuttx_identical_rebuild_image_audits": len(NUTTX_REUSED_CASES),
            "nuttx_identical_rebuild_reused_captures": 3 * len(NUTTX_REUSED_CASES),
            "stock_cooperative_invalid_captures": 2,
            "freertos_private_memory_pool_image_audits": 1,
            "matched_peripheral_irq_image_audits": 6,
            "matched_peripheral_irq_captures": 18,
            "cooperative_configuration_control_captures": cooperative_control_captures,
            "hartstone_cells": ph_cells, "hartstone_complete_captures": ph_captures,
            "hartstone_gcc13_baseline_captures": baseline_captures,
            "hartstone_native_prefix_captures": native_prefix_captures,
            "hartstone_native_complete_captures": native_complete_captures,
            "hartstone_primary_cells": len(native_primary),
            "hartstone_primary_captures": sum(len(runs) for runs in native_primary.values()),
            "hartstone_stock_control_captures": native_complete_captures - sum(
                len(runs) for runs in native_primary.values()),
            "hartstone_scoped_ranking_eligible": True,
            "hartstone_scoped_ranked_experiments": [1, 2, 3, 4],
            "hartstone_fifo_control_captures": fifo_control_captures,
            "hartstone_kernel_size_log_control_prefix_captures": len(paths),
            "unrestricted_product_ranking_eligible": False,
            "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    print(json.dumps(audit_report(args.report.read_text()), sort_keys=True))
