#!/usr/bin/env python3
"""Replay unchanged sys_kernel semaphore scenarios through native RIOT sema/threads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_zephyr_slab import ROOT, REFERENCE, original_syskernel_cases
from audit_esp32_zephyr_syskernel_sema import SOURCES as FREE_SOURCES, TAGS, SHARED, original_callbacks, literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_syskernel_sema_riot_control import FUNCTIONS, NORETURN, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_sema_riot"
DIRECTORY = ROOT / "artifacts/reports/zephyr-syskernel-sema-riot-v1"
NATIVE = ("sys/sema/sema.c", "sys/include/sema.h", "core/thread.c", "core/sched.c", "core/mutex.c",
    "core/include/thread.h", "core/include/sched.h", "core/include/mutex.h", "cpu/esp_common/esp-xtensa/thread_arch.c",
    "sys/ztimer/core.c", "sys/ztimer/util.c", "sys/include/ztimer.h")
SOURCES = {key: value for key, value in FREE_SOURCES.items() if key.startswith(("source/", "include/"))}
SOURCES.update({"native-source/" + name: RIOT_UPSTREAM + name for name in NATIVE})
BEGIN = "SEMA PORT BEGIN RIOT Zephyr-3.7.0-subset count=1000 clock=240 cores=1 tick=native-tickless stack=2048"


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [row["line"].strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "SEMA PORT END", "main(): This is RIOT! (Version: 2024.10-devel)", "Single core mode", "Pro cpu up.",
        "SEMA NATIVE PRIORITY controller=10 workers=8 peer_timeslicing=0 cooperative_class=0",
        "SEMA NATIVE FINAL semaphores=0 registry_restored=1")
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "SEMA PORT END" or any(re.search(
                r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("RIOT semaphore reset/profile/completion/correctness differs")
    registry = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"SEMA NATIVE REGISTRY before=(\d+) after=(\d+) retired=(\d+)", line))]
    if registry != [(3, 3, 5)]:
        raise ValueError("native RIOT registry/automatic retirement differs")
    result = original_syskernel_cases(lines, TAGS, "SEMA")
    if next(i for i, line in enumerate(lines) if line.startswith("SEMA NATIVE REGISTRY")) <= \
            max(i for i, line in enumerate(lines) if line == "END TEST CASE"):
        raise ValueError("native retirement observation entered original semaphore window")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
        "registry_before": 3, "registry_after": 3, "retired_workers": 5,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full original suite remains linked")
        control = read_control_rows((directory / "sema-control-flow.txt").read_text(), "SEMA CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        calls, placements = {}, {}
        iram = set(FUNCTIONS[23:])
        for name, rows in control.items():
            expected = ".iram0.text" if name in iram else ".flash.text"
            if elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"]).name != expected:
                raise ValueError("original/native RIOT semaphore placement differs")
            placements[name] = expected
            for row in rows.values():
                m = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call(0|8)\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                address, value, kind, target, callee = int(m[1], 16), int(m[2], 16), m[3], int(m[4], 16), m[5]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destinations = {symbol["st_value"] for symbol in symbols.get_symbol_by_name(callee)}
                destination = (address & ~3) + 4 + 4 * offset
                if value & 0x3f != (0x05 if kind == "0" else 0x25) or destination not in destinations or target != destination:
                    raise ValueError("native RIOT semaphore call target differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        expected = (("main", "sema_test", 1), ("sema_test", "sema_test_init", 3), ("sema_test_init", "k_sem_init", 2),
            ("sema_test", "k_thread_create", 5), ("sema_test", "begin_test", 3), ("sema_test", "TIME_STAMP_DELTA_GET", 6),
            ("sema_test", "check_result", 3), ("sema_test", "k_sem_take$part$0", 1), ("sema_test", "k_sem_give", 1),
            ("sema_thread1", "k_sem_take$part$0", 1), ("sema_thread1", "k_sem_give", 1),
            ("sema_thread2", "k_sem_take$part$0", 1), ("sema_thread2", "k_sem_give", 1),
            ("sema_thread3", "k_sem_take", 1), ("sema_thread3", "k_sem_give", 1), ("sema_thread3", "thread_yield", 1),
            ("k_sem_init", "sema_create", 1), ("k_sem_init", "sema_destroy", 1), ("k_sem_init", "verify_retired", 2),
            ("k_sem_take", "_sema_wait_ztimer", 1), ("k_sem_take$part$0", "_sema_wait_ztimer", 1),
            ("k_sem_give", "sema_post", 1), ("k_thread_create", "thread_create", 1),
            ("thread_create", "thread_stack_init", 1), ("thread_create", "sched_switch", 1),
            ("sema_create", "mutex_lock_internal", 1), ("sema_destroy", "mutex_unlock", 1),
            ("sema_post", "mutex_unlock", 1), ("_sema_wait_ztimer", "mutex_lock_internal", 1),
            ("mutex_unlock", "sched_switch", 1), ("mutex_lock_internal", "thread_yield_higher", 1),
            ("thread_yield", "thread_yield_higher", 1), ("task_exit", "sched_set_status", 1),
            ("task_exit", "sched_run", 1), ("task_exit", "_frxt_int_exit", 1),
            ("k_sleep", "ztimer_sleep", 1), ("begin_test", "k_sleep", 1), ("begin_test", "k_uptime_delta", 1),
            ("check_result", "k_uptime_delta", 1), ("check_result", "native_sema_mean", 1))
        if any(calls.get((a, b), 0) != count for a, b, count in expected):
            raise ValueError("original/native RIOT semaphore call coverage differs")
        relevant = {"sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET", "k_thread_create", "k_sem_give", "k_sem_take$part$0", "check_result"}
        ordered = [m[1] for _, row in sorted(control["sema_test"].items()) if
                   (m := re.search(r"call8\s+[0-9a-f]+ <([\w.$]+)>", row)) and m[1] in relevant]
        phase = ["sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET"]
        end = ["TIME_STAMP_DELTA_GET", "check_result"]
        if ordered != (phase + ["k_thread_create"] * 2 + end) * 2 + phase + ["k_thread_create", "k_sem_give", "k_sem_take$part$0"] + end:
            raise ValueError("original RIOT semaphore create/handshake/timestamp order differs")
        for name, count in (("main", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original semaphore calibration/endpoints are not encoded CCOUNT reads")
        original_callbacks(control, elf, symbols)
        witnesses = {"sema_thread3": ("0b0c movi.n\ta11, 0", "feba56 bnez\ta10,"),
            "k_sem_take": ("03bd mov.n\ta11, a3", "9abb addi.n\ta9, a10, 11"),
            "k_sem_take$part$0": ("1b0c movi.n\ta11, 1", "0d0c movi.n\ta13, 0", "0dcd mov.n\ta12, a13"),
            "k_thread_create": ("8c0c movi.n\ta12, 8", "11b450 slli\ta11, a4, 11", "005d16 beqz\ta13,"),
            "thread_entry": ("1288 l32i.n\ta8, a2, 4", "0008e0 callx8\ta8", "f01d retw.n"),
            "thread_stack_init": ("3a99 s32i.n\ta9, a10, 12", "7a99 s32i.n\ta9, a10, 28"),
            "task_exit": ("0829 s32i.n\ta2, a8, 0", "880b addi.n\ta8, a8, -1", "006982 s32i\ta8, a9, 0", "0329 s32i.n\ta2, a3, 0")}
        for name, instructions in witnesses.items():
            if any(instruction not in "\n".join(control[name].values()) for instruction in instructions):
                raise ValueError(("native RIOT semaphore polling/priority/automatic exit instruction differs", name))
        for name in ("sema_thread1", "sema_thread2", "sema_thread3", "sema_test"):
            if not any(" blt" in row for row in control[name].values()):
                raise ValueError("original semaphore loop absent")
        if literal_word(elf, next(row for row in control["k_thread_create"].values() if "l32r\ta14," in row), 14) != \
                symbols.get_symbol_by_name("thread_entry")[0]["st_value"] or \
                literal_word(elf, next(row for row in control["thread_stack_init"].values() if "l32r\ta9," in row), 9) != \
                symbols.get_symbol_by_name("task_exit")[0]["st_value"]:
            raise ValueError("native worker entry/return exit literal differs")
        for register, name in ((9, "sched_num_threads"), (2, "sched_threads"), (3, "sched_active_thread")):
            row = next(row for row in control["task_exit"].values() if "l32r\ta" + str(register) + "," in row and "<" + name + ">" in row)
            if literal_word(elf, row, register) != symbols.get_symbol_by_name(name)[0]["st_value"]:
                raise ValueError("native registry exit address differs")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("thread_stack1", "thread_stack2")}
        if sizes != {"thread_stack1": 2048, "thread_stack2": 2048} or any(symbols.get_symbol_by_name(name)[0]["st_value"] % 16 for name in sizes):
            raise ValueError("original semaphore worker stack dimensions/alignment differ")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
        "original_stack_sizes": sizes, "original_worker_callback_literals_checked": 5,
        "original_timestamp_reads_retained": True, "original_create_and_handshake_order_retained": True,
        "native_blocking_and_nonblocking_arguments_checked": True, "native_automatic_exit_and_registry_unlink_checked": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "sema-control.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    if not {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "compiler.txt", "build.log",
            "port.c", "original_stats.c", "Makefile", "build-script.sh", "include/zephyr/kernel.h", *SOURCES} <= inventories["image.sha256"] or \
            not {"image.sha256", "runner.sh", "flash.log", "capture_esp32_uart.py",
                *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["sema-control.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
                "collect-sema-control.py", "collect-sema-riot-wrapper.py", "collector-base.py"}:
        raise ValueError("native RIOT semaphore source/image/capture/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("native semaphore source differs from pinned official revision", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {r["path"] for r in proof} != set(SOURCES) or any(
            r["url"] != SOURCES[r["path"]] or r["sha256"] != digest(directory / r["path"]) for r in proof):
        raise ValueError("original/native RIOT semaphore provenance differs")
    for name in ("sema.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original semaphore test/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(archived), ROOT / "tools" / local) for archived, local in (
        ("build-script.sh", "build_esp32_zephyr_syskernel_sema_riot.sh"), ("runner.sh", "run_esp32_zephyr_syskernel_sema_riot.sh"),
        ("capture_esp32_uart.py", "capture_esp32_uart.py"), ("collector-base.py", "collect_esp32_zephyr_slab_control.py"),
        ("collect-sema-riot-wrapper.py", "collect_esp32_zephyr_syskernel_sema_riot_control.py"))]
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-sema-control.py").read_text() != collector_source((directory / "collector-base.py").read_text()):
        raise ValueError("reviewed original/native RIOT semaphore recipe differs")
    config = (directory / "config").read_text()
    required = {"THREAD_PRIORITY_MAIN": 10, "CONFIG_XTENSA": 1, "CONFIG_SRAM_SIZE": 320,
        "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240": 1, "CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE": 1, "MODULE_SEMA": 1,
        "MODULE_ZTIMER_USEC": 1, "SCHED_TEST_STACK": 1}
    if any(not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M) for name, value in required.items()) or \
            any(name in config for name in ("MODULE_SCHED_ROUND_ROBIN", "MODULE_CORE_MUTEX_PRIORITY_INHERITANCE")) or \
            "12.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native RIOT semaphore clock/core/priority/timer/compiler differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    units = ("/app/port.c", "/app/original_stats.c", *("/" + name for name in NATIVE if name.endswith(".c")))
    for name in units:
        selected = [args for args in commands if any(not a.startswith("-") and a.endswith(name) for a in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or \
                [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320", "-DTHREAD_PRIORITY_MAIN=10"} <= set(selected[0]) or \
                any(a.startswith("-DNUMBER_OF_LOOPS") for a in selected[0]):
            raise ValueError(("actual original/native RIOT semaphore compilation differs", name, len(selected)))
    machine = machine_paths(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("RIOT semaphore installed image/board binding differs")
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("RIOT semaphore independent boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original semaphore subset", "os": "RIOT",
        "metric_count": 3, "resets": 3, "iterations": 1000, "original_files": 5, "native_source_files": len(NATIVE),
        "actual_compiled_units_checked": len(units), "captures": captures, "machine_paths": machine,
        "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": None, "compiler": "12.2.0", "worker_stack_bytes": 2048,
        "native_controller_priority": 10, "native_worker_priority": 8, "native_time_slicing": False,
        "native_per_thread_cooperative_priority_class": False, "original_tick_phase_synchronization_preserved": False,
        "native_semaphore_limit_one_enforced": False, "native_semaphore_priority_inheritance": False,
        "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
        "boundary": "three unchanged original semaphore handshake scenarios, 1000 iterations; native thread create and automatic return/exit included, registry retirement checks before static stack reuse outside timing; native non-PI mutex-backed counting semaphores start empty, selected protocol never overfills one but general one-token saturation not enforced; native strict priority controller 10/workers 8, no peer timeslicing or Zephyr cooperative priority class; one-second native tickless sleep, not original phase synchronization; original calibration/coarse elapsed guards/means retained; original 2048-byte stack allocations include RIOT TCB/architecture frame reservation, not 2048-byte usable stack; application/sema paths in Flash and thread/scheduler/mutex paths in IRAM, native stack guard enabled; registry 3 to 3, five native worker retirements, final empty semaphores destroyed; no full suite, cross-OS rank, new-image RAM/energy"}


def render_table(result):
    return "\n".join(["| Original sys_kernel semaphore scenario / OS | Mean, ns (three boots) |", "| --- | --- |",
        *("| " + tag + " / RIOT | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |" for tag in TAGS)])


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
