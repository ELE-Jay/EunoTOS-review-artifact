#!/usr/bin/env python3
"""Replay original tmck calibration and original Rhealstone corrected inputs."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_rhealstone_iram import ROOT, SOURCE, ORIGINAL, REVISION, CASES, audit_case, verify_official
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_rhealstone import audit_capture
from audit_esp32_rhealstone_zephyr import audit as zephyr_reference
from audit_esp32_rhealstone_riot import audit as riot_reference, NATIVE_SOURCES as RIOT_THREAD, SYNC_SOURCES as RIOT_SYNC
from audit_esp32_rhealstone_nuttx import audit as nuttx_reference, UPSTREAM as NUTTX_UPSTREAM
from audit_esp32_rhealstone_alios import audit as alios_reference, UPSTREAM as ALIOS_UPSTREAM
from audit_esp32_rhealstone_irq_alios import NATIVE as ALIOS_IRQ_NATIVE, ARCHIVE as ALIOS_ARCHIVE, native_path as alios_native_path
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_isr import irq_archive_member, rhino_vector_dispatch
from audit_esp32_riot_original import UPSTREAM as RIOT_UPSTREAM
from audit_esp32_rhealstone_irq_riot import SDK as RIOT_SDK
from audit_esp32_rhealstone_irq_zephyr import HAL
from audit_esp32_resources import audit_elf_image, static_footprint
from collect_esp32_rhealstone_calibrated_control import collector_source, ZEPHYR_EXTRA, RIOT_EXTRA, NUTTX_EXTRA, ALIOS_EXTRA
from collect_esp32_rhealstone_iram_control import functions
from collect_esp32_rhealstone_irq_control import NORETURN

DIRECTORY = ROOT / "artifacts/reports/rhealstone-freertos-calibrated-v1"
SOURCES = dict(ORIGINAL, **{"tmck-task1.c": "testsuites/tmtests/tmck/task1.c", "system.h": "testsuites/tmtests/tmck/system.h"})
ZEPHYR_NATIVE = ("kernel/thread.c", "kernel/sched.c", "kernel/init.c", "kernel/mutex.c", "kernel/msg_q.c",
    "arch/xtensa/core/xtensa_intgen.tmpl", "drivers/timer/xtensa_sys_timer.c", "hal/esp_clk.c")
RIOT_NATIVE = RIOT_THREAD + RIOT_SYNC + ("cpu/esp_common/vendor/xtensa/portasm.S",
    "cpu/esp_common/vendor/xtensa/xtensa_vectors.S", "pkg/esp32_sdk/Makefile", "sdk/components/esp_hw_support/esp_clk.c")
NUTTX_NATIVE = ("sched/signal/sig_default.c", "sched/signal/sig_dispatch.c", "sched/signal/sig_kill.c",
    "sched/sched/sched_suspend.c", "sched/sched/sched_yield.c", "sched/sched/sched_setscheduler.c",
    "sched/group/group_continue.c", "sched/task/task_restart.c", "sched/task/task_create.c",
    "sched/pthread/pthread_mutexinit.c", "sched/pthread/pthread_mutextimedlock.c", "sched/pthread/pthread_mutexunlock.c",
    "sched/mqueue/mq_send.c", "sched/mqueue/mq_receive.c", "fs/mqueue/mq_open.c",
    "libs/libc/stdlib/lib_exit.c", "libs/libc/pthread/pthread_mutex_lock.c",
    "arch/xtensa/src/esp32/esp32_clockconfig.c", "arch/xtensa/src/esp32/esp32_clockconfig.h",
    "arch/xtensa/src/esp32/esp32_timerisr.c")
ALIOS_NATIVE = ALIOS_IRQ_NATIVE + ("kernel/rhino/k_mutex.c", "kernel/rhino/k_buf_queue.c", "platform/mcu/esp32/aos/hook_impl.c")


def verify_alios_native(directory):
    rows = []
    for name in (*ALIOS_NATIVE, ALIOS_ARCHIVE):
        path = alios_native_path(directory / "alios/taskswitch", name)
        url = ALIOS_UPSTREAM + name
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != path.read_bytes():
            raise ValueError("fixed Rhino original native source/archive differs: " + name)
        rows.append({"path": name, "url": url, "sha256": digest(path)})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def verify_nuttx_native(directory):
    rows = []
    for name in NUTTX_NATIVE:
        path = directory / "nuttx/taskswitch/native-source" / name
        url = NUTTX_UPSTREAM + name
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != path.read_bytes():
            raise ValueError("fixed NuttX original native source differs: " + name)
        rows.append({"path": name, "url": url, "sha256": digest(path)})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def riot_source_urls():
    return {name: ("https://raw.githubusercontent.com/espressif/esp-idf/" + RIOT_SDK + "/" + name[4:]
        if name.startswith("sdk/") else RIOT_UPSTREAM + name) for name in RIOT_NATIVE}


def verify_riot_native(directory):
    rows = []
    for name, url in riot_source_urls().items():
        path = directory / "riot/taskswitch/native-source" / name
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != path.read_bytes():
            raise ValueError("fixed RIOT original native source differs: " + name)
        rows.append({"path": name, "url": url, "sha256": digest(path)})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def audit_native_control(directory, case, system, extra, expected_section, guards):
    generated = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(),
        case, (SOURCE / (case + ".c")).read_text(), system)
    if (directory / "collect-irq-control.py").read_text() != generated or \
            {line.split(maxsplit=1)[1] for line in (directory / "irq-control.sha256").read_text().splitlines()} != \
            {"application.elf", "image.sha256", "capture.sha256", "irq-control-flow.txt", "collect-irq-control.py"}:
        raise ValueError("calibrated original control coverage differs")
    names = set(functions((SOURCE / (case + ".c")).read_text()) + extra)
    checked, placement = 0, {}
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, names, noreturn=NORETURN + {"riot": ("sched_task_exit",), "nuttx": ("exit",)}.get(system, ()))
        for name in sorted(names):
            symbol = max(symbols.get_symbol_by_name(name), key=lambda item: item["st_size"])
            section = elf.get_section(symbol["st_shndx"])
            if section.name != (expected_section[name] if isinstance(expected_section, dict) else expected_section):
                raise ValueError("native original/adapter Flash placement changed: " + name)
            placement[name] = {"section": section.name, "address": hex(symbol["st_value"])}
        if symbols.get_symbol_by_name("esp_wifi_init"):
            raise ValueError("unexpected native Wi-Fi initialization linked into original CPU test")
        for rows in control.values():
            for row in rows.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([^>]+)>", row)
                if not match:
                    continue
                address, encoding, printed = (int(x, 16) for x in match.groups()[:3])
                targets = symbols.get_symbol_by_name(match[4])
                if not targets:
                    raise ValueError("actual native call target missing")
                destination = max(targets, key=lambda item: item["st_size"])["st_value"]
                offset = encoding >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or printed != destination:
                    raise ValueError("actual encoded original/native call differs")
                checked += 1
        for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if sum(bool(re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", row)) for row in control[name].values()) != 1:
                raise ValueError("calibrated native timer counter differs")
        common = (("rh_begin", "legacy_rh_begin", 1), ("rh_begin", "rh_timer_check", 2),
            ("rh_timer_check", "check_read_timer", 1), ("check_read_timer", "benchmark_timer_initialize", 1),
            ("check_read_timer", "benchmark_timer_read", 1), ("rh_end", "legacy_rh_end", 1))
        for caller, target, count in common + guards:
            if sum(bool(re.fullmatch(r"[0-9a-f]+: [0-9a-f]{6} call8\s+[0-9a-f]+ <" + target + ">", row))
                    for row in control[caller].values()) != count:
                raise ValueError("actual calibration/native call count differs: " + caller)
    return names, checked, placement


def zephyr_source_urls():
    return {name: ("https://raw.githubusercontent.com/zephyrproject-rtos/hal_espressif/" + HAL +
        "/components/esp_hw_support/esp_clk.c" if name.startswith("hal/") else
        "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/" + name) for name in (*ZEPHYR_NATIVE, "west.yml")}


def verify_zephyr_native(directory):
    rows = []
    for name, url in zephyr_source_urls().items():
        path = directory / "zephyr/taskswitch" / (name if name == "west.yml" else "native-source/" + name)
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if data != path.read_bytes():
            raise ValueError("fixed Zephyr original native source differs: " + name)
        rows.append({"path": name, "url": url, "sha256": digest(path)})
    (directory / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def audit_zephyr_case(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "zephyr":
        raise ValueError("unsupported calibrated Zephyr case")
    reference = ROOT / "artifacts/reports/rhealstone-zephyr-v3/zephyr" / case
    old = zephyr_reference(reference)
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    recipe = ROOT / "firmware/bsp/esp32/rhealstone/zephyr_calibrated"
    for saved, current in (("port.c", recipe / "port.c"), ("CMakeLists.txt", recipe / "CMakeLists.txt"),
            ("native_rhealstone_port.h", reference / "port.c"), ("prj.conf", reference / "prj.conf"),
            ("compiler.txt", reference / "compiler.txt"),
            ("build_esp32_rhealstone_zephyr_calibrated.sh", ROOT / "tools/build_esp32_rhealstone_zephyr_calibrated.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_zephyr_calibrated.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("calibrated Zephyr recipe/mapping/acquisition differs: " + saved)
    for name in (case + ".c", "timesys.h", "tmck-task1.c", "system.h", "btimer.h"):
        if (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("original measurement/calibration body differs")
    for folder in ("include", "calibrated_timer"):
        base = ROOT / "firmware/bsp/esp32/rhealstone" / folder
        for path in base.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / folder / path.relative_to(base)).read_bytes():
                raise ValueError("original native API/timer service differs")
    config = set((directory / "config").read_text().splitlines())
    previous = set((reference / "config").read_text().splitlines())
    metadata = {"CONFIG_TAINT=y", "CONFIG_TAINT_BLOBS=y"}
    if config - previous != metadata or previous - config or (directory / "config-comparison.log").read_text():
        raise ValueError("Zephyr profile changed beyond two installed-module taint metadata flags")
    proof = json.loads((directory.parent.parent / "official-native-source.json").read_text())
    urls = zephyr_source_urls()
    if len(proof) != len(urls) or {row["path"] for row in proof} != set(urls) or \
            (directory / "hal-revision.txt").read_text().strip() != HAL:
        raise ValueError("Zephyr fixed native/hal inventory differs")
    for row in proof:
        name = row["path"]
        path = directory / (name if name == "west.yml" else "native-source/" + name)
        if row["url"] != urls[name] or digest(path) != row["sha256"]:
            raise ValueError("fixed official native source differs: " + name)
    commands = json.loads((directory / "compile_commands.json").read_text())
    compiled = ("rhealstone/zephyr_calibrated/port.c", "rhealstone-original/" + case + ".c",
        "rhealstone-original/tmck-task1.c", *[name for name in ZEPHYR_NATIVE if name.endswith(".c") and not name.startswith("hal/")],
        "components/esp_hw_support/esp_clk.c")
    for name in compiled:
        entries = [shlex.split(row["command"]) for row in commands if row["file"].endswith("/" + name)]
        if len(entries) != 1 or Path(entries[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in entries[0] or \
                [arg for arg in entries[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("actual original/native Zephyr compilation differs: " + name)
        definitions = {arg for arg in entries[0] if arg.startswith("-D") and arg.split("=", 1)[0] in
            ("-DInit", "-DTask_1", "-Drtems_test_name", "-DTask_name")}
        expected = {"-DInit=tmck_Init", "-DTask_1=tmck_Task_1", "-Drtems_test_name=tmck_test_name", "-DTask_name=tmck_Task_name"}
        if definitions != (expected if name.endswith("tmck-task1.c") else set()) or any(
                arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION")) for arg in entries[0]):
            raise ValueError("original tmck defaults/namespaced source differ")
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=True)
    names, checked, placement = audit_native_control(directory, case, "zephyr", ZEPHYR_EXTRA, ".flash.text",
        (("create", "z_impl_k_thread_create", 1), ("rtems_task_start", "z_impl_k_thread_start", 1),
         ("main", "z_impl_k_thread_create", 1)))
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 1 or \
            written != [((directory / "application.bin").stat().st_size, 0x1000)]:
        raise ValueError("actual Zephyr board/verified image size differs")
    captures = []
    for index in (1, 2, 3):
        rows = read_raw_capture(directory, index)
        lines = [row["line"] for row in rows]
        if lines.count("*** Booting Zephyr OS build 3.7.0 ***") != 1 or \
                sum("Unicore bootloader" in line for line in lines) != 1:
            raise ValueError("actual Zephyr native boot differs")
        capture = audit_capture(directory / f"reset{index}.jsonl", case, "Zephyr")
        capture["original_arithmetic_positive"] = capture["measurement_eligible"]
        capture["original_arithmetic_reason"] = capture["measurement_reason"]
        capture["measurement_eligible"] = False
        captures.append(capture)
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("Zephyr independent resets overlap")
    return {"audit": "pass", "os": "Zephyr 3.7.0", "case": case, "resets": 3, "captures": captures,
        "raw_original_cycles": [row["raw_original_cycles"] for row in captures], "measurement_eligible": False,
        "original_arithmetic_positive": all(row["original_arithmetic_positive"] for row in captures),
        "median_us": None, "range_us": None, "ranking_eligible": False,
        "binary_sha256": digest(directory / "application.bin"), "original_test_body_unchanged": True,
        "native_adapter_unchanged": False, "native_profile_unchanged_except_taint_metadata": True,
        "config_metadata_additions": sorted(metadata), "native_source_files": len(ZEPHYR_NATIVE),
        "actual_compiled_units_checked": len(compiled), "reachable_functions": len(names),
        "encoded_direct_calls_checked": checked, "elf_bin_all_initialized_sections_bound": True,
        "function_placement": placement, "native_source_proof_sha256": digest(directory.parent.parent / "official-native-source.json"),
        "reference_original_cycles": old["raw_original_cycles"], "reference_binary_sha256": old["binary_sha256"],
        "installed_flash_bytes": (directory / "application.bin").stat().st_size,
        "static_footprint": static_footprint(directory / "application.elf")}


def audit_riot_case(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "riot":
        raise ValueError("unsupported calibrated RIOT case")
    revision = "v4" if case in ("taskswitch", "taskpreempt") else "v5"
    reference = ROOT / ("artifacts/reports/rhealstone-riot-" + revision + "/riot") / case
    old = riot_reference(reference)
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    recipe = ROOT / "firmware/bsp/esp32/rhealstone/riot_calibrated"
    for saved, current in (("port.c", recipe / "port.c"), ("Makefile", recipe / "Makefile"), ("tmck.c", recipe / "tmck.c"),
            ("native_rhealstone_port.h", reference / "port.c"), ("config.h", reference / "config.h"),
            ("compiler.txt", reference / "compiler.txt"),
            ("build_esp32_rhealstone_riot_calibrated.sh", ROOT / "tools/build_esp32_rhealstone_riot_calibrated.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_riot_calibrated.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("RIOT calibrated recipe/native profile/acquisition differs: " + saved)
    for saved, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h"),
            *(("original/" + name, name) for name in ("tmck-task1.c", "system.h", "timesys.h", "btimer.h"))):
        if (directory / saved).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("RIOT original measurement/calibration source differs")
    for folder in ("include", "calibrated_timer"):
        base = ROOT / "firmware/bsp/esp32/rhealstone" / folder
        for path in base.rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / folder / path.relative_to(base)).read_bytes():
                raise ValueError("RIOT original API/timer service differs")
    proof = json.loads((directory.parent.parent / "official-native-source.json").read_text())
    urls = riot_source_urls()
    if len(proof) != len(urls) or {row["path"] for row in proof} != set(urls):
        raise ValueError("RIOT fixed native inventory differs")
    for row in proof:
        if row["url"] != urls[row["path"]] or digest(directory / "native-source" / row["path"]) != row["sha256"]:
            raise ValueError("RIOT fixed official native source differs")
    if "PKG_VERSION=" + RIOT_SDK not in (directory / "native-source/pkg/esp32_sdk/Makefile").read_text():
        raise ValueError("RIOT native SDK revision differs")
    log = (directory / "build.log").read_text().replace("\\\n", " ")
    commands = [shlex.split(line) for line in log.splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    required = ["rhealstone/riot_calibrated/" + name for name in ("original.c", "port.c", "tmck.c")]
    required += [name for name in RIOT_NATIVE if name.endswith((".c", ".S")) and name != "core/mbox.c"]
    if case == "mlatency":
        required.append("core/mbox.c")
    required = [name[4:] if name.startswith("sdk/") else name for name in required]
    for name in required:
        selected = [args for args in commands if any(arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                "-DTHREAD_PRIORITY_MAIN=0" not in selected[0] or "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1" not in selected[0]:
            raise ValueError("actual original/native RIOT compilation differs: " + name)
        if any(arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-Drtems_test_name", "-DTask_name"))
                or "RHEALSTONE_DIAGNOSTIC" in arg for arg in selected[0]):
            raise ValueError("original tmck defaults/namespace or diagnostic profile differ")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    guards = (("legacy_rh_begin", "esp_clk_cpu_freq", 1), ("main", "thread_create", 1),
        ("main", "thread_wakeup", 1), ("main", "thread_sleep", 1),
        ("rtems_task_create", "thread_create", 1), ("rtems_task_start", "thread_wakeup", 1))
    if case in ("taskswitch", "semshuffle"):
        guards += (("rtems_task_wake_after", "thread_yield", 1),)
    if case in ("taskpreempt", "semshuffle", "deadlockbrk"):
        guards += (("rtems_task_suspend", "thread_sleep", 1), ("rtems_task_resume", "thread_wakeup", 1)) if case == "taskpreempt" else \
            (("rtems_task_suspend", "thread_sleep", 1), ("rtems_task_restart", "thread_kill_zombie", 1))
    if case in ("semshuffle", "deadlockbrk"):
        guards += (("rtems_semaphore_obtain", "mutex_lock_internal", 1), ("rtems_semaphore_release", "mutex_unlock", 1))
    if case == "mlatency":
        guards += (("rtems_message_queue_send", "_mbox_put", 1), ("rtems_message_queue_receive", "_mbox_get", 1))
    names, checked, placement = audit_native_control(directory, case, "riot", RIOT_EXTRA, ".flash.text", guards)
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    expected = [((directory / name).stat().st_size, offset) for name, offset in
        (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or written != expected:
        raise ValueError("actual RIOT board/verified image sizes differ")
    captures = []
    for index in (1, 2, 3):
        lines = [row["line"] for row in read_raw_capture(directory, index)]
        if lines.count("Single core mode") != 1 or lines.count("main(): This is RIOT! (Version: 2024.10-devel)") != 1 or \
                any("RHEALSTONE DIAG" in line for line in lines) or (case == "mlatency" and lines.count(
                    "RHEALSTONE queue self-check PASS family=mbox-owned-payload capacity=1 bytes=16") != 1):
            raise ValueError("RIOT actual native boot/mailbox admission differs")
        capture = audit_capture(directory / f"reset{index}.jsonl", case, "RIOT", "native-tickless")
        capture["original_arithmetic_positive"] = capture["measurement_eligible"]
        capture["original_arithmetic_reason"] = capture["measurement_reason"]
        capture["measurement_eligible"] = False
        captures.append(capture)
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("RIOT independent resets overlap")
    return {"audit": "pass", "os": "RIOT native tickless/GCC12", "case": case, "resets": 3, "captures": captures,
        "raw_original_cycles": [row["raw_original_cycles"] for row in captures], "measurement_eligible": False,
        "original_arithmetic_positive": all(row["original_arithmetic_positive"] for row in captures),
        "median_us": None, "range_us": None, "ranking_eligible": False,
        "binary_sha256": digest(directory / "application.bin"), "original_test_body_unchanged": True,
        "native_adapter_unchanged": False, "native_profile_unchanged": True, "tick_hz": None,
        "native_source_files": len(RIOT_NATIVE), "actual_compiled_units_checked": len(required),
        "reachable_functions": len(names), "encoded_direct_calls_checked": checked, "function_placement": placement,
        "elf_bin_all_initialized_sections_bound": True, "reference_original_cycles": old["raw_original_cycles"],
        "reference_binary_sha256": old["binary_sha256"], "qualification": old["qualification"],
        "reference_adapter_cohort": "rhealstone-riot-" + revision,
        "native_source_proof_sha256": digest(directory.parent.parent / "official-native-source.json"),
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partitions.bin", "application.bin")),
        "static_footprint": static_footprint(directory / "application.elf")}


def audit_nuttx_case(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "nuttx":
        raise ValueError("unsupported calibrated NuttX case")
    reference = ROOT / "artifacts/reports/rhealstone-nuttx-v2/nuttx" / case
    old = nuttx_reference(reference)
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    recipe = ROOT / "firmware/bsp/esp32/rhealstone/nuttx_calibrated"
    base = ROOT / "firmware/bsp/esp32/rhealstone"
    for saved, current in (("port.c", recipe / "port.c"), ("Makefile", recipe / "Makefile"),
            ("Kconfig", base / "nuttx/Kconfig"), ("Make.defs", base / "nuttx/Make.defs"),
            ("tmck.c", base / "riot_calibrated/tmck.c"), ("native_rhealstone_port.h", reference / "port.c"),
            ("compiler.txt", reference / "compiler.txt"),
            ("build_esp32_rhealstone_nuttx_calibrated.sh", ROOT / "tools/build_esp32_rhealstone_nuttx_calibrated.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_nuttx_calibrated.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("NuttX calibrated recipe/native mapping/acquisition differs: " + saved)
    for saved, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h"),
            *(("original/" + name, name) for name in ("tmck-task1.c", "system.h", "timesys.h", "btimer.h"))):
        if (directory / saved).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("NuttX original measurement/calibration body differs")
    for folder in ("include", "calibrated_timer"):
        for path in (base / folder).rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / folder / path.relative_to(base / folder)).read_bytes():
                raise ValueError("NuttX original API/timer service differs")
    configs = [(reference / "config").read_text().splitlines(),
        (directory / "native-profile-config").read_text().splitlines(), (directory / "config").read_text().splitlines()]
    labels = [[line for line in lines if line.startswith("CONFIG_BASE_DEFCONFIG=")] for lines in configs]
    if any(len(rows) != 1 or not re.fullmatch(r'CONFIG_BASE_DEFCONFIG="esp32-devkitc:nsh(?:-dirty)+"', rows[0]) for rows in labels) or \
            any([line for line in configs[0] if not line.startswith("CONFIG_BASE_DEFCONFIG=")] !=
                [line for line in lines if not line.startswith("CONFIG_BASE_DEFCONFIG=")] for lines in configs[1:]):
        raise ValueError("NuttX native runtime configuration differs beyond dirty build-label metadata")
    proof = json.loads((directory.parent.parent / "official-native-source.json").read_text())
    if len(proof) != len(NUTTX_NATIVE) or {row["path"] for row in proof} != set(NUTTX_NATIVE) or any(
            row["url"] != NUTTX_UPSTREAM + row["path"] or digest(directory / "native-source" / row["path"]) != row["sha256"]
            for row in proof):
        raise ValueError("NuttX fixed official native source inventory differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compiled = ("original.c", "port.c", "tmck.c", *(name for name in NUTTX_NATIVE if name.endswith(".c")))
    for name in compiled:
        selected = [args for args in commands if any(Path(arg).name == Path(name).name for arg in args if not arg.startswith("-"))]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError("actual original/native NuttX compilation differs: " + name)
        if any(arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-Drtems_test_name", "-DTask_name"))
                for arg in selected[0]):
            raise ValueError("original tmck defaults/namespace differ")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    guards = (("legacy_rh_begin", "esp_clk_cpu_freq", 1), ("rhealstone_main", "sched_setscheduler", 1),
        ("rtems_task_start", "task_create", 1))
    if case in ("taskswitch", "semshuffle"):
        guards += (("rtems_task_wake_after", "sched_yield", 1),)
    if case == "taskpreempt":
        guards += (("rtems_task_suspend", "kill", 1), ("rtems_task_resume", "kill", 1))
    if case in ("semshuffle", "deadlockbrk"):
        guards += (("rtems_task_suspend", "kill", 1), ("rtems_task_restart", "task_restart", 1),
            ("rtems_semaphore_obtain", "pthread_mutex_lock", 1), ("rtems_semaphore_release", "pthread_mutex_unlock", 1))
    if case == "mlatency":
        guards += (("rtems_message_queue_send", "mq_send", 1), ("rtems_message_queue_receive", "mq_receive", 1))
    names, checked, placement = audit_native_control(directory, case, "nuttx", NUTTX_EXTRA, ".flash.text", guards)
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    expected = [((directory / name).stat().st_size, offset) for name, offset in
        (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or written != expected:
        raise ValueError("actual NuttX board/verified image sizes differ")
    captures = []
    for index in (1, 2, 3):
        rows = read_raw_capture(directory, index)
        lines = [row["line"].strip() for row in rows]
        resets = [row for row in rows if row["line"].startswith("rst:0x")]
        if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines.count("NuttShell (NSH)") != 1 or \
                lines.count("rhealstone") != 1 or lines[-1] != "RHEALSTONE END" or any(
                    re.search(r"FAIL|panic|ASSERT|watchdog|Brownout|Error ==> ", line, re.I) for line in lines):
            raise ValueError("actual NuttX physical reset/command/completion differs")
        capture = audit_capture(directory / f"reset{index}.jsonl", case, "NuttX")
        capture["original_arithmetic_positive"] = capture["measurement_eligible"]
        capture["original_arithmetic_reason"] = capture["measurement_reason"]
        capture["measurement_eligible"] = False
        captures.append(capture)
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("NuttX independent resets overlap")
    return {"audit": "pass", "os": "NuttX 12.2.1", "case": case, "resets": 3, "captures": captures,
        "raw_original_cycles": [row["raw_original_cycles"] for row in captures], "measurement_eligible": False,
        "original_arithmetic_positive": all(row["original_arithmetic_positive"] for row in captures),
        "median_us": None, "range_us": None, "ranking_eligible": False,
        "binary_sha256": digest(directory / "application.bin"), "original_test_body_unchanged": True,
        "native_adapter_unchanged": False, "native_runtime_profile_unchanged": True, "tick_hz": 100,
        "configuration_build_labels": labels, "native_source_files": len(NUTTX_NATIVE),
        "actual_compiled_units_checked": len(compiled), "reachable_functions": len(names),
        "encoded_direct_calls_checked": checked, "function_placement": placement,
        "elf_bin_all_initialized_sections_bound": True, "reference_original_cycles": old["raw_original_cycles"],
        "reference_binary_sha256": old["binary_sha256"], "qualification": old["qualification"],
        "native_source_proof_sha256": digest(directory.parent.parent / "official-native-source.json"),
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partitions.bin", "application.bin")),
        "static_footprint": static_footprint(directory / "application.elf")}


def audit_alios_case(directory):
    case = directory.name
    if case not in CASES or directory.parent.name != "alios":
        raise ValueError("unsupported calibrated Rhino case")
    reference = ROOT / "artifacts/reports/rhealstone-alios-v1/alios" / case
    old = alios_reference(reference)
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    base = ROOT / "firmware/bsp/esp32/rhealstone"
    for saved, current in (("port.c", base / "alios_calibrated/port.c"), ("aos.mk", base / "alios_calibrated/aos.mk"),
            ("Config.in", base / "alios/Config.in"), ("examples-Config.in", base / "alios/examples-Config.in"),
            ("tmck.c", base / "riot_calibrated/tmck.c"), ("native_rhealstone_port.h", reference / "port.c"),
            *((name, reference / name) for name in ("compiler.txt", "config", "sdkconfig.h", "k_config.h")),
            ("build_esp32_rhealstone_alios_calibrated.sh", ROOT / "tools/build_esp32_rhealstone_alios_calibrated.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_rhealstone_alios_calibrated.sh"),
            ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("Rhino calibrated recipe/native profile/acquisition differs: " + saved)
    for saved, source in (("original.c", case + ".c"), ("include/timesys.h", "timesys.h"),
            *(("original/" + name, name) for name in ("tmck-task1.c", "system.h", "timesys.h", "btimer.h"))):
        if (directory / saved).read_bytes() != (SOURCE / source).read_bytes():
            raise ValueError("Rhino original measurement/calibration body differs")
    for folder in ("include", "calibrated_timer"):
        for path in (base / folder).rglob("*"):
            if path.is_file() and path.read_bytes() != (directory / folder / path.relative_to(base / folder)).read_bytes():
                raise ValueError("Rhino original API/timer service differs")
    board = ROOT / "firmware/bsp/esp32/alios_board"
    for saved, source in (("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"),
            ("sdkconfig.h", "esp32bench/sdkconfig.h"), ("k_config.h", "esp32bench/k_config.h")):
        if (directory / saved).read_bytes() != (board / source).read_bytes():
            raise ValueError("Rhino native board/IRQ/configuration port differs")
    proof = json.loads((directory.parent.parent / "official-native-source.json").read_text())
    if len(proof) != len(ALIOS_NATIVE) + 1 or {row["path"] for row in proof} != set((*ALIOS_NATIVE, ALIOS_ARCHIVE)) or any(
            row["url"] != ALIOS_UPSTREAM + row["path"] or digest(alios_native_path(directory, row["path"])) != row["sha256"]
            for row in proof):
        raise ValueError("Rhino fixed official native source/archive inventory differs")
    if irq_archive_member(alios_native_path(directory, ALIOS_ARCHIVE)) != (directory / "sdk-intr_alloc.o").read_bytes() or \
            ALIOS_ARCHIVE not in (directory / "link.opts").read_text() or not re.search(
                r"\.text\.esp_intr_alloc\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*libesp32\.a\(intr_alloc\.o\)",
                (directory / "application.map").read_text()):
        raise ValueError("Rhino fixed native SDK archive/member linkage differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    compiled = ("app/example/rhealstone/port.c", "app/example/rhealstone/original.c", "app/example/rhealstone/tmck.c",
        *(name for name in ALIOS_NATIVE if name.endswith((".c", ".S"))),
        "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for name in compiled:
        selected = [args for args in commands if name in args]
        if len(selected) != 1 or any(arg.startswith("-DRHINO_CONFIG_TICKS_PER_SECOND=") for arg in selected[0]) or \
                (not name.endswith(".S") and ([arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or
                    "-DAOS_NO_WIFI" not in selected[0])) or \
                (name.endswith(".S") and ("-include" not in selected[0] or "out/config/autoconf.h" not in selected[0])):
            raise ValueError("actual original/native Rhino compilation differs: " + name)
        if any(arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-Drtems_test_name", "-DTask_name"))
                for arg in selected[0]):
            raise ValueError("original tmck defaults/namespace differ")
    divisors = hardware_tick_divisors(directory, expected_hz=100)
    vector = rhino_vector_dispatch(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    guards = (("legacy_rh_begin", "esp_clk_cpu_freq", 1), ("create", "krhino_task_create", 1),
        ("application_start", "krhino_task_create", 1), ("application_start", "krhino_task_suspend", 1),
        ("rtems_task_start", "krhino_task_resume", 1), ("espos_isr_enter", "krhino_intrpt_enter", 1),
        ("espos_isr_exit", "krhino_intrpt_exit", 1))
    if case in ("taskswitch", "semshuffle"):
        guards += (("rtems_task_wake_after", "krhino_task_yield", 1),)
    if case in ("taskpreempt", "semshuffle", "deadlockbrk"):
        guards += (("rtems_task_suspend", "krhino_task_suspend", 1),)
    if case in ("taskpreempt", "deadlockbrk"):
        guards += (("rtems_task_resume", "krhino_task_resume", 1),)
    if case in ("semshuffle", "deadlockbrk"):
        guards += (("rtems_task_restart", "krhino_task_del", 1), ("rtems_semaphore_obtain", "krhino_mutex_lock", 1),
            ("rtems_semaphore_release", "krhino_mutex_unlock", 1))
    if case == "mlatency":
        guards += (("rtems_message_queue_send", "krhino_buf_queue_send", 1), ("rtems_message_queue_receive", "krhino_buf_queue_recv", 1))
    sections = {name: ".iram0.text" if name in ALIOS_EXTRA[-5:] else ".flash.text"
        for name in functions((SOURCE / (case + ".c")).read_text()) + ALIOS_EXTRA}
    names, checked, placement = audit_native_control(directory, case, "alios", ALIOS_EXTRA, sections, guards)
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    expected = [((directory / name).stat().st_size, offset) for name, offset in
        (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or written != expected:
        raise ValueError("actual Rhino board/verified image sizes differ")
    captures = []
    for index in (1, 2, 3):
        rows = read_raw_capture(directory, index)
        lines = [row["line"].strip() for row in rows]
        resets = [row for row in rows if row["line"].startswith("rst:0x")]
        if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines.count("bootload image") != 1 or \
                sum("cpu_start: Pro cpu start user code" in line for line in lines) != 1 or \
                lines[-1] != "RHEALSTONE END" or any(re.search(
                    r"FAIL|Guru Meditation|panic|assert failed|watchdog|Brownout|Error ==> ", line, re.I) for line in lines):
            raise ValueError("actual Rhino physical reset/boot/completion differs")
        capture = audit_capture(directory / f"reset{index}.jsonl", case, "AliOS-Rhino")
        capture["original_arithmetic_positive"] = capture["measurement_eligible"]
        capture["original_arithmetic_reason"] = capture["measurement_reason"]
        capture["measurement_eligible"] = False
        captures.append(capture)
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("Rhino independent resets overlap")
    return {"audit": "pass", "os": "AliOS/Rhino native GCC5", "case": case, "resets": 3, "captures": captures,
        "raw_original_cycles": [row["raw_original_cycles"] for row in captures], "measurement_eligible": False,
        "original_arithmetic_positive": all(row["original_arithmetic_positive"] for row in captures),
        "median_us": None, "range_us": None, "ranking_eligible": False,
        "binary_sha256": digest(directory / "application.bin"), "original_test_body_unchanged": True,
        "native_adapter_unchanged": False, "native_profile_unchanged": True, "tick_hz": 100,
        "native_source_files": len(ALIOS_NATIVE), "official_prebuilt_sdk_archives": 1,
        "prebuilt_native_irq_archive_source_rebuilt": False, "actual_compiled_units_checked": len(compiled),
        "reachable_functions": len(names), "encoded_direct_calls_checked": checked, "function_placement": placement,
        "hardware_tick_divisors": divisors, "native_vector_enter_exit_call_sites": vector,
        "elf_bin_all_initialized_sections_bound": True, "reference_original_cycles": old["raw_original_cycles"],
        "reference_binary_sha256": old["binary_sha256"], "qualification": old["qualification"],
        "native_source_proof_sha256": digest(directory.parent.parent / "official-native-source.json"),
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partitions.bin", "application.bin")),
        "static_footprint": static_footprint(directory / "application.elf")}


def timer_capture(directory, index, capture):
    lines = [row["line"] for row in read_raw_capture(directory, index)]
    phases, positions, overhead = [], [], None
    for raw_mode in (1, 0):
        begin = f"RHEALSTONE TMCK BEGIN raw={raw_mode} operations=100 maximum_distribution=1000"
        ends = [(i, re.fullmatch(r"RHEALSTONE TMCK END raw=" + str(raw_mode) +
            r" attempts=(\d+) accepted=100 sum=(\d+) average=(\d+) minimum=(\d+) maximum=(\d+) overhead=(\d+)", line))
            for i, line in enumerate(lines)]
        ends = [(i, match) for i, match in ends if match]
        if lines.count(begin) != 1 or len(ends) != 1:
            raise ValueError("original tmck phase count or completion differs")
        start, (end, match) = lines.index(begin), ends[0]
        if start >= end:
            raise ValueError("original tmck phase order differs")
        body = lines[start + 1:end]
        fields = list(map(int, match.groups()))
        attempts, reported_sum, average, minimum, maximum, installed_overhead = fields
        samples = [tuple(map(int, found.groups())) for line in body if (found := re.fullmatch(
            r"RHEALSTONE TMCK SAMPLE index=(\d+) raw=(\d+)", line))]
        if not 100 <= attempts <= 256 or len(samples) != attempts or [i for i, _ in samples] != list(range(attempts)) or \
                any(not 0 <= value < 2 ** 32 for _, value in samples):
            raise ValueError("original tmck raw sample coverage differs")
        values = [value if raw_mode else max(value - overhead, 0) for _, value in samples]
        accepted, rejected = [], []
        for value in values:
            if value > 1000:
                rejected.append(f"TOO LONG ({value}) at index {len(accepted) + 1}!!!")
            else:
                accepted.append(value)
        histogram = [(int(found[1]), int(found[2])) for line in body if (found := re.fullmatch(r"(\d+) (\d+)", line))]
        expected_histogram = sorted(Counter(accepted).items())
        total = sum(accepted)
        expected_prefix = [*rejected, "Units may not be in microseconds for this test!!!",
            *[f"{value} {count}" for value, count in expected_histogram], f"Total time = {total}", f"Average time = {total // 100}"]
        if len(accepted) != 100 or histogram != expected_histogram or body[:len(expected_prefix)] != expected_prefix or \
                body[len(expected_prefix):] != [f"RHEALSTONE TMCK SAMPLE index={i} raw={value}" for i, value in samples] or \
                (reported_sum, average, minimum, maximum) != (total, total // 100, min(accepted), max(accepted)):
            raise ValueError("original tmck histogram/average does not reproduce raw samples")
        if raw_mode:
            overhead = total // 100
            if not overhead:
                raise ValueError("invalid zero average timer overhead")
        if installed_overhead != overhead:
            raise ValueError("installed average timer overhead differs")
        phases.append({"raw_mode": bool(raw_mode), "accepted": 100, "attempts": attempts,
            "histogram": expected_histogram, "sum_cycles": total, "average_cycles": average,
            "raw_sample_cycles": [value for _, value in samples], "minimum": minimum, "maximum": maximum})
        positions.extend((start, end))
    mode = f"RHEALSTONE TIMER MODE raw=0 average_overhead={overhead} unit=cycles"
    if lines.count(mode) != 1 or positions != sorted(positions) or positions[-1] >= lines.index(mode) or \
            lines.index(mode) >= next(i for i, line in enumerate(lines) if line.startswith("Rhealstone: ")):
        raise ValueError("calibration/default-mode/original measurement ordering differs")
    raw_rows = [found for line in lines if (found := re.fullmatch(r"RHEALSTONE TIMER_RAW count=(\d+)((?: value\d+=\d+)+)", line))]
    if len(raw_rows) != 1:
        raise ValueError("original timing raw endpoint trace missing")
    raw_reads = [(int(i), int(value)) for i, value in re.findall(r"value(\d+)=(\d+)", raw_rows[0][2])]
    if int(raw_rows[0][1]) != len(raw_reads) or [i for i, _ in raw_reads] != list(range(len(raw_reads))) or \
            any(not 0 <= value < 2 ** 32 for _, value in raw_reads) or \
            [max(value - overhead, 0) for _, value in raw_reads] != capture["timer_reads_cycles"]:
        raise ValueError("default timer overhead removal does not reproduce original returned inputs")
    return {"tmck_original_function_unchanged": True, "tmck_default_operations": 100, "tmck_default_maximum_distribution": 1000,
        "calibration_phases": phases, "timer_average_overhead_cycles": overhead,
        "original_timer_raw_reads_cycles": [value for _, value in raw_reads],
        "original_timer_overhead_contract_restored": True, "empty_corrected_average_zero": phases[1]["average_cycles"] == 0}


def audit(directory=DIRECTORY, system="freertos"):
    if system not in ("freertos", "zephyr", "riot", "nuttx", "alios"):
        raise ValueError("unsupported calibrated native port")
    proof = {row["name"]: row for row in json.loads((directory / "original-source-proof.json").read_text())}
    if set(proof) != set(SOURCES):
        raise ValueError("original tmck source proof coverage differs")
    for name, path in SOURCES.items():
        if proof[name]["url"] != "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + path or \
                proof[name]["sha256"] != digest(SOURCE / name):
            raise ValueError("fixed original tmck/interface source proof differs")
    cells = []
    for case in CASES:
        image = directory / system / case
        cell = audit_case(image, calibrated=True) if system == "freertos" else {"zephyr": audit_zephyr_case, "riot": audit_riot_case,
            "nuttx": audit_nuttx_case, "alios": audit_alios_case}[system](image)
        for index, capture in enumerate(cell["captures"], 1):
            capture.update(timer_capture(image, index, capture))
            capture["measurement_reason"] = "timer calibrated; original native directive/null-path subtraction remains scoped, not isolated full operation latency"
        cell.update({"original_timer_overhead_contract_restored": True, "tmck_original_function_unchanged": True,
            "original_full_tmck_suite_measured": False, "native_non_timer_adapter_unchanged": True,
            "placement": "original bodies, original tmck function and calibrated adapter text/literals in IRAM; constants in DRAM" if system == "freertos" else "native " + {"zephyr": "Zephyr", "riot": "RIOT", "nuttx": "NuttX", "alios": "Rhino"}[system] + " linker placement; no application IRAM-placement control",
            "timer_average_overhead_cycles": [row["timer_average_overhead_cycles"] for row in cell["captures"]],
            "measurement_reason": "calibrated native-method observations; original directive baseline and API semantic differences do not establish isolated operation latency"})
        if system == "freertos":
            control = ROOT / "artifacts/reports/rhealstone-freertos-iram-v1/freertos" / case
            cell["reference_iram_original_cycles"] = audit_case(control)["raw_original_cycles"]
        cells.append(cell)
    captures = sorted([capture for cell in cells for capture in cell["captures"]], key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("calibrated independent boot captures overlap")
    result = {"audit": "pass", "scope": {"freertos": "FreeRTOS", "zephyr": "Zephyr", "riot": "RIOT", "nuttx": "NuttX", "alios": "AliOS/Rhino"}[system] + " original-program calibrated native port",
        "independent_boots": 15, "original_source_files": len(SOURCES), "cells": cells,
        "original_timer_overhead_contract_restored": True, "original_full_tmck_suite_measured": False,
        "ranking_eligible": False, "composite_score": None,
        "boundary": "original tmck calibration function, not full suite or a new benchmark; directive/null-path baseline, API semantic and cache interpretations remain unqualified"}
    if system == "riot":
        failed = ROOT / "artifacts/reports/rhealstone-riot-calibrated-v1/riot/taskswitch"
        check_manifest(failed, "failed-source.sha256")
        if any((failed / name).exists() for name in ("application.elf", "application.bin", "flash.log")) or \
                list(failed.glob("reset*")) or "-Werror=old-style-definition" not in (failed / "build.log").read_text():
            raise ValueError("failed RIOT original tmck build acquired a firmware/run claim")
        result["excluded_failed_builds"] = [{"cohort": "rhealstone-riot-calibrated-v1", "case": "taskswitch",
            "reason": "unchanged original timer-check old-style definition rejected by native -Werror",
            "firmware_built": False, "board_boots": 0, "source_inventory_sha256": digest(failed / "failed-source.sha256")}]
    return result


def render_table(result):
    if not result["scope"].startswith("FreeRTOS"):
        label = result["scope"].split()[0]
        return "\n".join(["| Original Rhealstone / " + label + " | Prior raw-timer cycles | Calibrated-timer cycles (three boots) |",
            "| --- | --- | --- |", *["| " + label + " calibrated / " + row["case"] + " | " + " / ".join(map(str, row["reference_original_cycles"])) +
            " | " + " / ".join(map(str, row["raw_original_cycles"])) + " |" for row in result["cells"]]])
    return "\n".join(["| Original Rhealstone / FreeRTOS | Raw-timer IRAM cycles | Calibrated-timer cycles (three boots) |",
        "| --- | --- | --- |", *["| Calibrated / " + row["case"] + " | " + " / ".join(map(str, row["reference_iram_original_cycles"])) +
        " | " + " / ".join(map(str, row["raw_original_cycles"])) + " |" for row in result["cells"]]])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--system", choices=("freertos", "zephyr", "riot", "nuttx", "alios"), default="freertos")
    parser.add_argument("--verify-official", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = args.directory or ROOT / ("artifacts/reports/rhealstone-" + args.system + "-calibrated-" + ("v2" if args.system == "riot" else "v1"))
    if args.verify_official:
        verify_official(directory, SOURCES)
        if args.system == "zephyr":
            verify_zephyr_native(directory)
        elif args.system == "riot":
            verify_riot_native(directory)
        elif args.system == "nuttx":
            verify_nuttx_native(directory)
        elif args.system == "alios":
            verify_alios_native(directory)
    result = audit(directory, args.system)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
