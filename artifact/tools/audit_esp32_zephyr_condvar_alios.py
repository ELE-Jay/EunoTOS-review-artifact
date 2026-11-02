#!/usr/bin/env python3
"""Replay original condvar cases with unchanged official Rhino POSIX objects."""
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
from audit_esp32_zephyr_latency_alios import UPSTREAM, hardware_tick_divisors
from audit_esp32_zephyr_syskernel_sema_alios import elf_bytes
from audit_esp32_zephyr_syskernel_sema import literal_word
from collect_esp32_zephyr_condvar_alios_control import FUNCTIONS, NORETURN, INDIRECT_ADDRESS, TABLE_ADDRESS, INDIRECT_TARGETS, collector_source

DIRECTORY = ROOT / "artifacts/reports/zephyr-condvar-alios-v1"
PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_condvar/alios"
LIFECYCLE = ROOT / "firmware/bsp/esp32/zephyr_latency_thread"
NATIVE = ("kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_sched.c", "kernel/rhino/k_pend.c",
    "kernel/rhino/k_mutex.c", "kernel/rhino/k_mm.c", "kernel/rhino/k_sys.c", "kernel/rhino/include/k_task.h",
    "kernel/rhino/include/k_sem.h", "kernel/rhino/include/k_mutex.h", "kernel/rhino/include/k_list.h",
    "kernel/rhino/include/k_obj.h", "kernel/rhino/include/k_internal.h", "kernel/rhino/include/k_err.h",
    "kernel/rhino/include/k_default_config.h", "platform/arch/xtensa/lx6/xtensa_init.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h", "osal/posix/pthread_cond.c", "osal/posix/pthread_mutex.c",
    "include/posix/pthread.h", "include/posix/posix_config.h")


def capture_condvar(directory, index):
    result = capture(directory, index, "alios", condvar_subset=True)
    lines = [json.loads(line)["line"] for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    expected = ["CONDVAR ORIGINAL MUTEX owner_none=1 depth=1 native_exit_release=1",
        "CONDVAR ORIGINAL OBJECT waiting=0 signals=0 semaphores_deleted=2 internal_lock_retained=1"]
    if [line for line in lines if line.startswith(("CONDVAR ORIGINAL MUTEX ", "CONDVAR ORIGINAL OBJECT "))] != expected:
        raise ValueError("native exit release/retained condition lock postcheck differs")
    registry = [match.groups() for line in lines if (match := re.fullmatch(
        r"CONDVAR OBJECT REGISTRY sem_before=(\d+) sem_after=(\d+) mutex_before=(\d+) mutex_after=(\d+)", line))]
    tasks = [match.groups() for line in lines if (match := re.fullmatch(r"CONDVAR NATIVE JOIN before=(\d+) after=(\d+)", line))]
    if registry != [("16", "14", "10", "10")] or tasks != [("8", "8")]:
        raise ValueError("native task/semaphore/mutex registry postcheck differs")
    result.update(final_original_objects=expected, native_object_registry=registry, native_registry=tasks)
    return result


def machine_paths(directory):
    check_manifest(directory, "condvar-control.sha256")
    if {line.split(maxsplit=1)[1] for line in (directory / "condvar-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "capture.sha256", "condvar-control-flow.txt", "collect-condvar-control.py"} or \
            (directory / "collect-condvar-control.py").read_text() != collector_source(
                (ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("original POSIX/native entry-driven collector or coverage differs")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        targets = tuple(int.from_bytes(elf_bytes(elf, TABLE_ADDRESS + i * 4, 4), "little") for i in range(6))
        if targets != INDIRECT_TARGETS or int.from_bytes(elf_bytes(elf, 0x400808a0, 4), "little") != TABLE_ADDRESS:
            raise ValueError("native task-deletion jump table binding differs")
        rows = read_control_rows((directory / "condvar-control-flow.txt").read_text(), "CONDVAR CONTROL", elf, symbols,
            set(FUNCTIONS), noreturn=NORETURN, indirect_targets={("krhino_task_del", INDIRECT_ADDRESS): set(targets)})
        for register, names in ((13, ("start_thread_entry", "alt_thread_entry")), (11, ("start_stack", "alt_stack"))):
            observed = [literal_word(elf, row, register) for _, row in sorted(rows["condvar_blocking_ops"].items())
                if re.search(r"\bl32r\s+a" + str(register) + ",", row)]
            expected_values = [max(symbols.get_symbol_by_name(name), key=lambda item: item["st_size"])["st_value"] for name in names]
            if observed != expected_values:
                raise ValueError("original callbacks/stacks literal binding differs")
        if literal_word(elf, rows["krhino_task_del"][0x400853a4], 8) != TABLE_ADDRESS or \
                "040c movi.n\ta4, 0" not in rows["task_mutex_free$isra$1"][0x40084daf] or \
                "6249 s32i.n\ta4, a2, 24" not in rows["task_mutex_free$isra$1"][0x40084dd1]:
            raise ValueError("native task-deletion dispatch/empty-list owner release differs")
        aliases = symbols.get_symbol_by_name("klist_rm") or []
        if len(aliases) != 2 or len({elf_bytes(elf, item["st_value"], item["st_size"]) for item in aliases}) != 1:
            raise ValueError("two native registry-removal bodies are no longer identical")
        calls, placements = [], {}
        for name, body in rows.items():
            symbol = max(symbols.get_symbol_by_name(name), key=lambda item: item["st_size"])
            placements[name] = {"address": hex(symbol["st_value"]), "section": elf.get_section(symbol["st_shndx"]).name}
            for row in body.values():
                match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                address, encoding, target = (int(value, 16) for value in match.groups()[:3])
                offset = encoding >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if encoding & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != target or not any(
                        item["st_value"] == target for item in symbols.get_symbol_by_name(match[4]) or []):
                    raise ValueError("actual encoded original/POSIX/native call differs")
                calls.append((name, match[4]))
        expected = (("application_start", "krhino_task_create", 1), ("condvar_controller", "condvar_blocking_ops", 1),
            ("condvar_blocking_ops", "k_thread_create", 2), ("condvar_blocking_ops", "timing_cycles_to_ns_avg", 2),
            ("start_thread_entry", "z_impl_timing_timestamp_get", 2), ("start_thread_entry", "k_mutex_lock", 1),
            ("start_thread_entry", "k_condvar_wait", 1), ("alt_thread_entry", "z_impl_timing_timestamp_get", 1),
            ("alt_thread_entry", "k_condvar_signal", 1), ("k_mutex_lock", "pthread_mutex_lock", 1),
            ("k_condvar_wait", "pthread_cond_wait", 1), ("k_condvar_signal", "pthread_cond_signal", 1),
            ("pthread_cond_wait", "krhino_mutex_lock", 3), ("pthread_cond_wait", "krhino_mutex_unlock", 3),
            ("pthread_cond_wait", "krhino_sem_take", 2), ("pthread_cond_wait", "krhino_sem_give", 1),
            ("pthread_cond_signal", "krhino_mutex_lock", 1), ("pthread_cond_signal", "krhino_mutex_unlock", 2),
            ("pthread_cond_signal", "krhino_sem_give", 1), ("pthread_cond_signal", "krhino_sem_take", 1),
            ("pthread_cond_init", "krhino_mutex_dyn_create", 1), ("pthread_cond_init", "krhino_sem_dyn_create", 2),
            ("pthread_cond_destroy", "krhino_sem_dyn_del", 2), ("pthread_cond_destroy", "krhino_mutex_dyn_del", 0),
            ("native_condvar_inspect", "pthread_cond_destroy", 1), ("k_thread_create", "krhino_task_create", 1),
            ("k_thread_join", "k_thread_abort", 1), ("k_thread_abort", "krhino_task_del", 1),
            ("k_thread_abort", "krhino_sem_del", 1), ("krhino_task_del", "task_mutex_free$isra$1", 1))
        for caller, target, count in expected:
            if calls.count((caller, target)) != count:
                raise ValueError("original POSIX/native call coverage differs: " + caller + " -> " + target)
        for name, pattern, count in (("condvar_controller", r"\bmovi\s+a10, 0x3e8$", 2),
                ("condvar_blocking_ops", r"\bmovi\s+a12, 0x700$", 2),
                ("z_impl_timing_timestamp_get", r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)$", 1)):
            if sum(bool(re.search(pattern, row)) for row in rows[name].values()) != count:
                raise ValueError("original iteration/stack/native timestamp differs: " + name)
        for name in ("start_stack", "alt_stack"):
            if [symbol["st_size"] for symbol in symbols.get_symbol_by_name(name) or []] != [1792]:
                raise ValueError("original nominal worker-stack allocation differs")
        for name in ("thread_ops", "unused_lifecycle_start", "pthread_create", "esp_wifi_init"):
            if any(symbol["st_shndx"] != "SHN_UNDEF" for symbol in symbols.get_symbol_by_name(name) or []):
                raise ValueError("unexecuted lifecycle or full POSIX/Wi-Fi workers linked")
    return {"reachable_functions_checked": len(FUNCTIONS), "encoded_direct_calls_checked": len(calls),
        "function_placement": placements, "native_task_delete_dispatch_targets_checked": list(map(hex, targets)),
        "original_endpoints_and_official_notification_acknowledgement_bound": True}


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
    bindings = [(directory / "build-files" / path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(directory / name, PORT / name) for name in ("port.c", "include/zephyr/kernel.h", "include/native_posix_types.h")]
    bindings += [(directory / name, LIFECYCLE / path) for name, path in
        (("native_lifecycle_port.h", "port.c"), ("native_lifecycle_kernel.h", "include/zephyr/kernel.h"))]
    bindings += [(directory / archived, ROOT / "tools" / name) for archived, name in
        (("build-script.sh", "build_esp32_zephyr_condvar_alios.sh"), ("runner.sh", "run_esp32_zephyr_condvar_alios.sh"),
         ("capture_esp32_uart.py", "capture_esp32_uart.py"))]
    board = ROOT / "firmware/bsp/esp32/alios_board"
    bindings += [(directory / archived, board / name) for archived, name in
        (("k_config.h", "esp32bench/k_config.h"), ("sdkconfig.h", "esp32bench/sdkconfig.h"),
         ("rhino-port-pinned.c", "rhino-port.c"), ("rhino-vectors-pinned.S", "rhino-vectors.S"))]
    bindings += [(directory / "include" / path.relative_to(SHARED), path) for path in SHARED.rglob("*")
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h"]
    if any(a.read_bytes() != b.read_bytes() for a, b in bindings):
        raise ValueError("compiled original adapter/profile/acquisition binding differs")
    sources = {"native-source/" + name: UPSTREAM + name for name in NATIVE}
    sources["rhino-portasm-pinned.S"] = UPSTREAM + "platform/arch/xtensa/lx6/portasm.S"
    proof_path = directory / "official-native-source.json"
    if verify_upstream:
        proof = []
        for name, url in sources.items():
            with urlopen(url, timeout=60) as response:
                data = response.read()
            if data != (directory / name).read_bytes():
                raise ValueError("fixed official Rhino POSIX/native source differs: " + name)
            proof.append({"path": name, "url": url, "sha256": digest(directory / name)})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(sources) or {row["path"] for row in proof} != set(sources) or any(
            row["url"] != sources[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("official POSIX/native source inventory differs")
    config = (directory / "config").read_text().splitlines()
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="zephyr_condvar"', 'AOS_APP_ZEPHYR_CONDVAR=y'} <= set(config) or \
            "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native Rhino original application/compiler differs")
    reference = ROOT / "artifacts/reports/zephyr-latency-alios-v2"
    if any((directory / name).read_bytes() != (reference / name).read_bytes() for name in
            ("k_config.h", "sdkconfig.h", "rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S")):
        raise ValueError("existing core/BSP/FIFO profile changed")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
        if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    app_units = ["app/example/zephyr_condvar/" + name for name in
        ("port.c", "condvar.c", "timing_sc.c", "native-pthread/pthread_cond.c", "native-pthread/pthread_mutex.c")]
    units = app_units + [name for name in NATIVE if name.endswith(".c") and not name.startswith("osal/")] + [
        "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S"]
    for name in units:
        selected = [args for args in commands if name in args]
        if len(selected) != 1 or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0] or any(
                arg.startswith(("-flto", "-Dnum_iterations", "-DCONFIG_TEST_EXTRA_STACK_SIZE")) for arg in selected[0]):
            raise ValueError("actual original/POSIX/native compilation differs: " + name)
        if name.endswith(".c") and ([arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                not {"-DAOS_NO_WIFI", "-DPOSIX_CONFIG_PTHREAD_ENABLE=1"} <= set(selected[0])):
            raise ValueError("native original optimization/Wi-Fi/POSIX profile differs: " + name)
        header = "app/example/zephyr_condvar/include/native_posix_types.h"
        if name in app_units and not any(a == "-include" and b == header for a, b in zip(selected[0], selected[0][1:])):
            raise ValueError("official Rhino rather than SDK pthread type bridge absent")
        if name not in app_units and header in selected[0]:
            raise ValueError("POSIX type bridge leaked into SDK/core ABI")
    if "#if defined(_POSIX_THREADS) && !defined(__CYGWIN__)" not in (directory / "toolchain-source/sys/types.h").read_text() or \
            "#define _SYS_FEATURES_H" not in (directory / "toolchain-source/sys/features.h").read_text():
        raise ValueError("newlib declaration bridge premise differs")
    for failed, phrase in (("failed-initial-types", "conflicting types for 'pthread_cond_t'"),
            ("failed-include-path", "native_lifecycle_kernel.h: No such file or directory")):
        path = directory / failed
        if phrase not in (path / "build.log").read_text() or any(path.glob("*.bin")) or any(path.glob("reset*")):
            raise ValueError("unbuilt/unflashed failure archive differs")
    divisors = hardware_tick_divisors(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    machine = machine_paths(directory)
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("verified original image/physical board binding differs")
    captures = [capture_condvar(directory, index) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("independent original POSIX boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 original condition-variable kernel subset",
        "os": "AliOS-Rhino + official POSIX objects", "metric_count": 2, "original_iterations": 1000, "resets": 3,
        "captures": captures, "metrics": {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
            "median_of_three_means_ns": statistics.median(values)} for tag in CONDVAR_TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "5.2.0", "worker_stack_bytes": 1792,
        "native_worker_priorities": [8, 9], "controller_priority": 10,
        "original_source_files": 4, "native_source_files": len(sources), "actual_compiled_units_checked": len(units),
        "hardware_tick_divisors": divisors, **machine, "original_test_body_unchanged": True,
        "original_subtracts_timestamp_overhead": False, "ranking_eligible": False, "unmodified_official_native_suite": False,
        "full_original_suite_measured": False, "original_explicitly_unlocks_mutex_before_exit": False,
        "general_object_cleanup_claim_eligible": False, "native_pthread_workers_used": False,
        "official_posix_condition_variable_objects_used": True, "native_exit_releases_original_mutex_owner": True,
        "post_timing_condvar_semaphores_deleted": 2, "post_timing_internal_condition_lock_retained": True,
        "full_posix_component_profile_used": False, "sdk_libraries_source_rebuilt": False,
        "binary_sha256": digest(directory / "application.bin"), "source_proof_sha256": digest(proof_path),
        "static_footprint": static_footprint(directory / "application.elf"),
        "excluded_build_attempts": [{"cause": name, "firmware_built": False, "board_boots": 0,
            "build_log_sha256": digest(directory / name / "build.log")} for name in ("failed-initial-types", "failed-include-path")],
        "boundary": "original two midpoint handoff endpoints, 1000 loops/integer means/no calibration subtraction; two unchanged official Rhino POSIX object units on existing native static tasks, not SDK pthread workers/full POSIX suite; official internal PI locks/two semaphores/notification acknowledgement and recursive PI ownership retained; native task deletion releases original held mutex owner, leaves depth field one; public cond destroy deletes two empty semaphores but retains internal dynamic lock; registry checks outside timing, no general heap cleanup/runtime RAM/energy/OS ranking; SDK libraries reused, native profile/240MHz/FIFO/1Hz/GCC5 and warm cache/placement differ"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
