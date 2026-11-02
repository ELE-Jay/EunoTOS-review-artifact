#!/usr/bin/env python3
"""Replay original condvar endpoints on FreeRTOS with official IDF pthread."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_zephyr_thread import ROOT, REFERENCE, SHARED, CONDVAR_TAGS, capture, read_control_rows
from audit_esp32_zephyr_condvar import ORIGINALS, ZEPHYR_UPSTREAM, check_manifest, digest, render_table
from audit_esp32_resources import audit_elf_image, static_footprint
from collect_esp32_zephyr_condvar_freertos_control import FUNCTIONS, NORETURN, collector_source

DIRECTORY = ROOT / "artifacts/reports/zephyr-condvar-freertos-v1"
PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_condvar/freertos"
LIFECYCLE = ROOT / "firmware/bsp/esp32/zephyr_latency_thread"
UPSTREAM = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/"
NATIVE = tuple("components/freertos/FreeRTOS-Kernel/" + name for name in (
    "tasks.c", "queue.c", "list.c", "portable/xtensa/port.c", "portable/xtensa/portasm.S")) + (
    "components/pthread/pthread.c", "components/pthread/pthread_cond_var.c",
    "components/pthread/pthread_internal.h", "components/newlib/locks.c")


def capture_condvar(directory, index):
    result = capture(directory, index, "freertos", condvar_subset=True)
    lines = [json.loads(line)["line"] for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    objects = [line for line in lines if line.startswith(("CONDVAR ORIGINAL MUTEX ", "CONDVAR ORIGINAL OBJECT "))]
    if objects != ["CONDVAR ORIGINAL MUTEX trylock=EBUSY retained_locked=1",
            "CONDVAR ORIGINAL OBJECT destroy_status=0 waiters_empty=1"]:
        raise ValueError("official pthread retained mutex/empty waiter list postcheck differs")
    result["final_original_objects"] = objects
    return result


def machine_paths(directory):
    check_manifest(directory, "condvar-control.sha256")
    expected = {"application.elf", "image.sha256", "capture.sha256", "condvar-control-flow.txt", "collect-condvar-control.py"}
    if {line.split(maxsplit=1)[1] for line in (directory / "condvar-control.sha256").read_text().splitlines()} != expected or \
            (directory / "collect-condvar-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("original pthread entry-driven control coverage/collector differs")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        rows = read_control_rows((directory / "condvar-control-flow.txt").read_text(), "CONDVAR CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        calls = []
        for caller, body in rows.items():
            for row in body.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([^>]+)>", row)
                if not match:
                    continue
                address, encoding, target = map(lambda value: int(value, 16), match.groups()[:3])
                displacement = encoding >> 6
                if displacement & (1 << 17):
                    displacement -= 1 << 18
                candidates = symbols.get_symbol_by_name(match[4]) or []
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + displacement * 4 != target or \
                        not any(symbol["st_value"] == target for symbol in candidates):
                    raise ValueError("actual encoded original/pthread/native call differs")
                calls.append((caller, match[4]))
        for caller, target, count in (
            ("app_main", "condvar_blocking_ops", 1), ("condvar_blocking_ops", "k_thread_create", 2),
            ("condvar_blocking_ops", "timing_cycles_to_ns_avg", 2),
            ("start_thread_entry", "z_impl_timing_timestamp_get", 2), ("start_thread_entry", "k_mutex_lock", 1),
            ("start_thread_entry", "k_condvar_wait", 1), ("alt_thread_entry", "z_impl_timing_timestamp_get", 1),
            ("alt_thread_entry", "k_condvar_signal", 1), ("k_condvar_wait", "pthread_cond_wait", 1),
            ("k_condvar_signal", "pthread_cond_signal", 1), ("pthread_cond_wait", "pthread_cond_timedwait", 1),
            ("pthread_cond_timedwait", "xQueueCreateCountingSemaphoreStatic", 1),
            ("pthread_cond_timedwait", "pthread_mutex_unlock", 1),
            ("pthread_cond_timedwait", "xQueueSemaphoreTake", 1),
            ("pthread_cond_timedwait", "vQueueDelete", 1), ("pthread_cond_timedwait", "pthread_mutex_lock", 1),
            ("pthread_cond_signal", "xQueueGenericSend", 1),
            ("k_thread_create", "xTaskCreateStaticPinnedToCore", 1), ("k_thread_join", "k_thread_abort", 1),
            ("k_thread_abort", "vTaskDelete", 1), ("k_thread_abort", "vQueueDelete", 1),
            ("native_mutex_inspect", "pthread_mutex_trylock", 1),
            ("native_condvar_inspect", "pthread_cond_destroy", 1)):
            if calls.count((caller, target)) != count:
                raise ValueError("original pthread/native call coverage differs: " + caller + " -> " + target)
        for name, pattern, count in (
            ("app_main", r"\bmovi\s+a10, 0x3e8$", 2),
            ("condvar_blocking_ops", r"\bmovi\s+a12, 0x700$", 2),
            ("z_impl_timing_timestamp_get", r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)$", 1)):
            if sum(bool(re.search(pattern, row)) for row in rows[name].values()) != count:
                raise ValueError("original iteration/stack/native timestamp differs: " + name)
        placement = {}
        for name in FUNCTIONS:
            symbol = max(symbols.get_symbol_by_name(name), key=lambda item: item["st_size"])
            placement[name] = {"address": hex(symbol["st_value"]), "section": elf.get_section(symbol["st_shndx"]).name}
        if symbols.get_symbol_by_name("thread_ops") or symbols.get_symbol_by_name("unused_lifecycle_main") or \
                symbols.get_symbol_by_name("esp_wifi_init"):
            raise ValueError("unexecuted lifecycle or unexpected Wi-Fi linked into condition-variable image")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": len(calls),
        "function_placement": placement, "original_loop_callback_and_native_wait_signal_paths_bound": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    for manifest in ("image.sha256", "capture.sha256"):
        check_manifest(directory, manifest)
    original = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in ORIGINALS:
        row = original["src/" + name]
        if row["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                row["sha256"] != digest(directory / "source" / name) or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original condvar body/statistics changed")
    for path in PORT.rglob("*"):
        if path.is_file() and path.read_bytes() != (directory / "build-files" / path.relative_to(PORT)).read_bytes():
            raise ValueError("current original condvar port/build differs")
    for name in ("port.c", "include/zephyr/kernel.h"):
        if (directory / name).read_bytes() != (PORT / name).read_bytes():
            raise ValueError("compiled original condvar adapter differs")
    for name, current in (("native_lifecycle_port.h", LIFECYCLE / "port.c"),
            ("native_lifecycle_kernel.h", LIFECYCLE / "include/zephyr/kernel.h"),
            ("build-script.sh", ROOT / "tools/build_esp32_zephyr_condvar_freertos.sh"),
            ("runner.sh", ROOT / "tools/run_esp32_zephyr_condvar_freertos.sh"),
            ("capture_esp32_uart.py", ROOT / "tools/capture_esp32_uart.py")):
        if (directory / name).read_bytes() != current.read_bytes():
            raise ValueError("reused native lifecycle/acquisition differs: " + name)
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                path.read_bytes() != (directory / "include" / path.relative_to(SHARED)).read_bytes():
            raise ValueError("original timestamp/format adapter differs")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE:
            with urlopen(UPSTREAM + name, timeout=60) as response:
                data = response.read()
            if data != (directory / "native-source" / name).read_bytes():
                raise ValueError("official fixed pthread/native source differs: " + name)
            records.append({"path": name, "url": UPSTREAM + name, "sha256": digest(directory / "native-source" / name)})
        provenance.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE) or {row["path"] for row in records} != set(NATIVE) or any(
            row["url"] != UPSTREAM + row["path"] or row["sha256"] != digest(directory / "native-source" / row["path"])
            for row in records):
        raise ValueError("official pthread/native source inventory differs")
    reference = ROOT / "artifacts/reports/zephyr-latency-freertos-v2"
    if (directory / "config").read_bytes() != (reference / "config").read_bytes() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (reference / "FreeRTOSConfig.h").read_bytes() or \
            "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("original one-core/240MHz/1Hz/FIFO/toolchain profile differs")
    commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    compiled = ["app-freertos/" + name for name in ("port.c", "condvar.c", "timing_sc.c")]
    compiled += [name.removeprefix("components/freertos/") if name.startswith("components/freertos/") else name
        for name in NATIVE if name.endswith((".c", ".S"))]
    for name in compiled:
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                any(arg.startswith(("-flto", "-Dnum_iterations", "-DCONFIG_TEST_EXTRA_STACK_SIZE")) for arg in selected[0]):
            raise ValueError("actual original/pthread/native compilation differs: " + name)
    failed = directory / "failed-initial-configure"
    if "components/spiffs/spiffs/src" not in (failed / "configure.log").read_text() or \
            (failed / "CMakeLists.txt").read_text().replace("include($ENV", "set(COMPONENTS main)\ninclude($ENV") != (PORT / "CMakeLists.txt").read_text() or \
            any(failed.glob("*.bin")) or any(failed.glob("reset*")):
        raise ValueError("initial unbuilt/unflashed component-selection failure archive differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    paths = machine_paths(directory)
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("verified image/physical board binding differs")
    captures = [capture_condvar(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("independent original condvar boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
        "median_of_three_means_ns": statistics.median(values)} for tag in CONDVAR_TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 original condition-variable kernel subset",
        "os": "FreeRTOS + ESP-IDF pthread", "metric_count": 2, "original_iterations": 1000, "resets": 3,
        "captures": captures, "metrics": metrics, "clock_mhz": 240, "cores": 1, "tick_hz": 1,
        "compiler": "13.2.0", "worker_stack_bytes": 1792, "native_worker_priorities": [16, 15], "controller_priority": 14,
        "original_source_files": 4, "native_source_files": len(NATIVE), "actual_compiled_units_checked": len(compiled),
        "original_test_body_unchanged": True, "original_subtracts_timestamp_overhead": False,
        "ranking_eligible": False, "unmodified_official_native_suite": False, "full_original_suite_measured": False,
        "original_explicitly_unlocks_mutex_before_exit": False, "general_object_cleanup_claim_eligible": False,
        "native_pthread_workers_used": False, "official_pthread_condition_variable_objects_used": True,
        "post_timing_condvar_destroyed": True, "original_mutex_retained_locked": True,
        "binary_sha256": digest(directory / "application.bin"), "source_proof_sha256": digest(provenance),
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partitions.bin", "application.bin")),
        "static_footprint": static_footprint(directory / "application.elf"), **paths,
        "excluded_failed_configurations": [{"cause": "initial all-component selection reached missing unused SPIFFS submodule",
            "firmware_built": False, "board_boots": 0, "configure_log_sha256": digest(failed / "configure.log")}],
        "boundary": "unchanged original wait/midpoint/signal-to-higher-priority-worker endpoints and integer means; official IDF pthread object layer on native FreeRTOS static tasks, not FreeRTOS core condvar; wait creates/deletes stack counting semaphore and reacquires PI/recursive mutex; internal condvar lock may delay preempted waiter; original no overhead subtraction, warm paths/cache/layout/SDK adaptation retained; native joins park/delete workers and restore task count, mutex remains held, condvar empty-list destroy occurs after timing; no general heap cleanup, runtime RAM, energy, full-suite or cross-OS rank"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
