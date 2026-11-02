#!/usr/bin/env python3
"""Replay the original sys_kernel semaphore scenarios on native NuttX FIFO pthreads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_slab import ROOT, REFERENCE, original_syskernel_cases
from audit_esp32_zephyr_syskernel_sema import SOURCES as FREE_SOURCES, TAGS, SHARED, original_callbacks, literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_syskernel_sema_nuttx_control import FUNCTIONS, NORETURN, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_sema_nuttx"
DIRECTORY = ROOT / "artifacts/reports/zephyr-syskernel-sema-nuttx-v2"
NATIVE = ("libs/libc/pthread/pthread_create.c", "libs/libc/pthread/pthread_exit.c", "libs/libc/pthread/pthread_attr_setstack.c",
    "sched/pthread/pthread_create.c", "sched/pthread/pthread_exit.c", "sched/pthread/pthread_join.c",
    "sched/pthread/pthread_completejoin.c", "sched/pthread/pthread_findjoininfo.c",
    "sched/semaphore/sem_post.c", "sched/semaphore/sem_wait.c", "sched/semaphore/sem_trywait.c",
    "sched/semaphore/sem_setprotocol.c", "libs/libc/semaphore/sem_init.c", "sched/semaphore/sem_destroy.c",
    "sched/sched/sched_foreach.c", "sched/sched/sched_yield.c", "sched/clock/clock_systime_ticks.c", "sched/signal/sig_usleep.c",
    "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_releasestack.c",
    "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/esp32/esp32_clockconfig.c", "include/pthread.h", "include/semaphore.h")
SOURCES = {key: value for key, value in FREE_SOURCES.items() if key.startswith(("source/", "include/"))}
SOURCES.update({"native-source/" + name: "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/" + name for name in NATIVE})
BEGIN = "SEMA PORT BEGIN NuttX Zephyr-3.7.0-subset count=1000 clock=240 cores=1 tick=1 stack=2048"


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    reset = [row for row in rows if row["line"].startswith("rst:0x")]
    if len(reset) != 1 or reset[0]["elapsed_s"] > 2 or lines.count(BEGIN) != 1 or \
            lines.count("SEMA PORT END") != 1 or lines[-1] != "SEMA PORT END" or \
            lines.count("NuttShell (NSH) NuttX-12.2.1") != 1 or lines.count("SEMA NATIVE VERSION NuttX 12.2.1") != 1 or \
            lines.count("SEMA NATIVE PRIORITY controller=150 workers=160 peer_timeslicing=0 cooperative_class=0") != 1 or \
            lines.count("SEMA NATIVE FINAL semaphores=0 registry_restored=1") != 1 or \
            any(re.search(r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("NuttX semaphore reset/profile/completion/correctness differs")
    registry = [tuple(map(int, m.groups())) for line in lines if (m := re.fullmatch(
        r"SEMA NATIVE REGISTRY before=(\d+) after=(\d+) joined=(\d+)", line))]
    if len(registry) != 1 or registry[0][0] < 2 or registry[0][0] != registry[0][1] or registry[0][2] != 5:
        raise ValueError("native pthread registry/join restoration differs")
    result = original_syskernel_cases(lines, TAGS, "SEMA")
    if next(i for i, line in enumerate(lines) if line.startswith("SEMA NATIVE REGISTRY")) <= \
            max(i for i, line in enumerate(lines) if line == "END TEST CASE"):
        raise ValueError("native join observation entered original semaphore window")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
        "registry_before": registry[0][0], "registry_after": registry[0][1], "joined_workers": registry[0][2],
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main") or symbols.get_symbol_by_name("zephyr_isr_main"):
            raise ValueError("unexecuted original suite/old experiment entry remains linked")
        control = read_control_rows((directory / "sema-control-flow.txt").read_text(), "SEMA CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        calls = {}
        for name, rows in control.items():
            if elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"]).name != ".flash.text":
                raise ValueError("native NuttX semaphore placement differs")
            for row in rows.values():
                m = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                address, value, target, callee = int(m[1], 16), int(m[2], 16), int(m[3], 16), m[4]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != destination or target != destination:
                    raise ValueError("native NuttX semaphore call target differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        expected = (("zephyr_sema_main", "run_original", 1), ("run_original", "sema_test", 1),
            ("sema_test", "sema_test_init", 3), ("sema_test_init", "k_sem_init", 2),
            ("sema_test", "k_thread_create", 5), ("sema_test", "begin_test", 3),
            ("sema_test", "TIME_STAMP_DELTA_GET", 6), ("sema_test", "check_result", 3),
            ("sema_thread1", "k_sem_take", 1), ("sema_thread1", "k_sem_give", 1),
            ("sema_thread2", "k_sem_take", 1), ("sema_thread2", "k_sem_give", 1),
            ("sema_thread3", "k_sem_take", 1), ("sema_thread3", "k_yield", 1),
            ("k_sem_init", "sem_setprotocol", 1), ("k_sem_init", "sem_init", 1),
            ("k_sem_take", "sem_wait", 1), ("k_sem_take", "sem_trywait", 1), ("k_sem_give", "sem_post", 1),
            ("k_thread_create", "pthread_attr_setstack", 1), ("k_thread_create", "pthread_attr_setinheritsched", 1),
            ("k_thread_create", "pthread_attr_setschedpolicy", 1), ("k_thread_create", "pthread_attr_setschedparam", 1),
            ("k_thread_create", "pthread_create", 1), ("pthread_create", "nx_pthread_create", 1),
            ("pthread_startup", "pthread_exit", 1), ("pthread_exit", "nx_pthread_exit", 1),
            ("nx_pthread_exit", "pthread_completejoin", 1), ("nx_pthread_exit", "up_exit", 1),
            ("nx_pthread_create", "up_use_stack", 1), ("nx_pthread_create", "nxtask_activate", 1),
            ("reap_worker", "pthread_join", 1), ("k_sleep", "reap_worker", 2), ("k_sleep", "nxsig_usleep", 1),
            ("begin_test", "k_sleep", 1), ("begin_test", "k_uptime_delta", 1),
            ("check_result", "k_uptime_delta", 1), ("check_result", "native_sema_mean", 1),
            ("sem_post", "nxsem_post", 1), ("sem_wait", "nxsem_wait", 1), ("sem_trywait", "nxsem_trywait", 1),
            ("sem_setprotocol", "nxsem_set_protocol", 1), ("sched_yield", "nxsched_set_priority", 1),
            ("esp32_timerisr", "nxsched_process_timer", 1))
        if any(calls.get((a, b), 0) != count for a, b, count in expected):
            raise ValueError("original/native NuttX semaphore call coverage differs")
        relevant = {"sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET", "k_thread_create", "k_sem_give", "k_sem_take", "check_result"}
        ordered = [m[1] for _, row in sorted(control["sema_test"].items()) if
                   (m := re.search(r"call8\s+[0-9a-f]+ <([\w.$]+)>", row)) and m[1] in relevant]
        phase = ["sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET"]
        end = ["TIME_STAMP_DELTA_GET", "check_result"]
        if ordered != (phase + ["k_thread_create"] * 2 + end) * 2 + phase + ["k_thread_create", "k_sem_give", "k_sem_take"] + end:
            raise ValueError("original NuttX semaphore create/handshake/timestamp order differs")
        init_rows = [row for _, row in sorted(control["k_sem_init"].items())]
        protocol = next(i for i, row in enumerate(init_rows) if "<sem_setprotocol>" in row)
        if "00a0b2 movi\ta11, 0" not in init_rows[protocol - 2]:
            raise ValueError("native semaphore is not the encoded non-PI protocol")
        for name, count in (("run_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original semaphore calibration/endpoints are not encoded CCOUNT reads")
        original_callbacks(control, elf, symbols)
        witnesses = {"sema_thread1": ("ffafb2 movi\ta11, -1",), "sema_thread2": ("ffafb2 movi\ta11, -1",),
            "sema_thread3": ("00a0b2 movi\ta11, 0", "ff0a56 bnez\ta10,"),
            "k_thread_create": ("a0a082 movi\ta8, 160", "11cc50 slli\ta12, a12, 11"),
            "k_sem_init": ("00a0b2 movi\ta11, 0", "00a0c2 movi\ta12, 0"),
            "thread_entry": ("2288 l32i.n\ta8, a2, 8", "0008e0 callx8\ta8"),
            "pthread_startup": ("0002e0 callx8\ta2",)}
        for name, instructions in witnesses.items():
            if any(instruction not in "\n".join(control[name].values()) for instruction in instructions):
                raise ValueError(("native NuttX semaphore priority/polling/callback instruction differs", name))
        if any(not any(" blt" in row for row in control[name].values()) for name in (
                "sema_thread1", "sema_thread2", "sema_thread3", "sema_test")):
            raise ValueError("original semaphore loops absent")
        init, timer = list(control["up_timer_initialize"].values()), list(control["esp32_timerisr"].values())
        if literal_word(elf, next(row for row in init if "l32r\ta9," in row), 9) != 240000000 or \
                literal_word(elf, next(row for row in init if "l32r\ta8," in row), 8) != symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"] or \
                literal_word(elf, next(row for row in timer if "l32r\ta8," in row), 8) != symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"] or \
                not any("13f080 wsr.ccompare0\ta8" in row for row in init) or not any("13f080 wsr.ccompare0\ta8" in row for row in timer):
            raise ValueError("native NuttX semaphore hardware tick differs")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("thread_stack1", "thread_stack2")}
        if sizes != {"thread_stack1": 2048, "thread_stack2": 2048} or any(symbols.get_symbol_by_name(name)[0]["st_value"] % 16 for name in sizes):
            raise ValueError("original semaphore worker stack dimensions/alignment differ")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()),
        "placements": ".flash.text", "hardware_tick_divisor": 240000000, "original_stack_sizes": sizes,
        "original_worker_callback_literals_checked": 5, "original_timestamp_reads_retained": True,
        "original_create_and_handshake_order_retained": True, "native_non_pi_protocol_argument_checked": True,
        "native_polling_yield_and_automatic_pthread_exit_retained": True, "native_join_outside_original_windows": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "sema-control.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    if not {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "compiler.txt", "build.log",
            "port.c", "original_stats.c", "Makefile", "Make.defs", "Kconfig", "build-script.sh", "actual-build-script.sh",
            "archive-recovery.json", "include/zephyr/kernel.h", *SOURCES} <= inventories["image.sha256"] or \
            not {"image.sha256", "runner.sh", "flash.log", "capture_esp32_uart.py",
                *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["sema-control.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
                "collect-sema-control.py", "collect-sema-nuttx-wrapper.py", "collector-base.py", "sema-collector-base.py"}:
        raise ValueError("native semaphore source/image/capture/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("native semaphore source differs from original official revision", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {r["path"] for r in proof} != set(SOURCES) or any(
            r["url"] != SOURCES[r["path"]] or r["sha256"] != digest(directory / r["path"]) for r in proof):
        raise ValueError("original/native NuttX semaphore provenance differs")
    for name in ("sema.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original semaphore test/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(archived), ROOT / "tools" / local) for archived, local in (
        ("build-script.sh", "build_esp32_zephyr_syskernel_sema_nuttx.sh"), ("runner.sh", "run_esp32_zephyr_syskernel_sema_nuttx.sh"),
        ("capture_esp32_uart.py", "capture_esp32_uart.py"), ("collector-base.py", "collect_esp32_zephyr_slab_control.py"),
        ("sema-collector-base.py", "collect_esp32_zephyr_syskernel_sema_control.py"),
        ("collect-sema-nuttx-wrapper.py", "collect_esp32_zephyr_syskernel_sema_nuttx_control.py"))]
    recipe = (directory / "build-script.sh").read_text()
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-sema-control.py").read_text() != collector_source((directory / "collector-base.py").read_text()) or \
            recipe.replace("libs/libc/semaphore/sem_init.c", "sched/semaphore/sem_init.c") != (directory / "actual-build-script.sh").read_text():
        raise ValueError("reviewed original/native semaphore recipe or post-build archive correction differs")
    recovery = json.loads((directory / "archive-recovery.json").read_text())
    if recovery != {"stage": "post-build source archival only", "source_path_correction": ["sched/semaphore/sem_init.c", "libs/libc/semaphore/sem_init.c"],
                    "firmware_rebuilt": False, "elf_sha256": digest(directory / "application.elf"), "bin_sha256": digest(directory / "application.bin")}:
        raise ValueError("archive recovery altered measured firmware")
    config = (directory / "config").read_text().splitlines()
    if not {"CONFIG_EXAMPLES_ZEPHYR_SEMA=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_USEC_PER_TICK=1000000",
            "CONFIG_RR_INTERVAL=0", "CONFIG_MM_BACKTRACE=-1", "# CONFIG_MM_KASAN is not set"} <= set(config) or \
            any(line in config for line in ("CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y", "CONFIG_EXAMPLES_ZEPHYR_ISR=y")) or \
            "13.2.0" not in (directory / "compiler.txt").read_text() or "12.2.1" not in (directory / "version-header.h").read_text():
        raise ValueError("native NuttX semaphore clock/core/FIFO/tick/compiler/version differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if line.startswith("xtensa-esp32-elf-gcc -c ")]
    units = ("port.c", "original_stats.c", *(name for name in NATIVE if name.endswith(".c")))
    for name in units:
        if name in ("port.c", "original_stats.c"):
            file, scope = name, "/apps/examples/zephyr_sema/"
        elif name.startswith("libs/libc/"):
            file, scope = name[10:], "/nuttx/libs/libc"
        elif name.startswith("sched/"):
            file, scope = name[6:], "/nuttx/sched"
        else:
            file = name.replace("arch/xtensa/src/esp32/", "chip/").replace("arch/xtensa/src/", "")
            scope = "/nuttx/arch/xtensa/src"
        selected = [args for args in commands if file in args and any(scope in arg for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("actual native NuttX semaphore compilation differs", name, len(selected)))
        if name in ("port.c", "original_stats.c") and not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(selected[0]):
            raise ValueError("original semaphore timing branch differs")
    machine = machine_paths(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("NuttX semaphore installed image/board binding differs")
    failed = directory.with_name("zephyr-syskernel-sema-nuttx-v1")
    check_manifest(failed, "failed-build.sha256")
    if "multiple definition of" not in (failed / "build.log").read_text() or any(failed.glob("reset*")) or (failed / "flash.log").exists():
        raise ValueError("NuttX initial link failure promoted into board measurements")
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("NuttX semaphore independent boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original semaphore subset", "os": "NuttX",
        "metric_count": 3, "resets": 3, "iterations": 1000, "original_files": 5, "native_source_files": len(NATIVE),
        "actual_compiled_units_checked": len(units), "captures": captures, "machine_paths": machine,
        "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "13.2.0", "worker_stack_bytes": 2048,
        "native_controller_priority": 150, "native_worker_priority": 160, "native_time_slicing": False,
        "native_per_thread_cooperative_priority_class": False, "original_tick_phase_synchronization_preserved": False,
        "native_semaphore_limit_one_enforced": False, "native_semaphore_priority_inheritance": False,
        "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
        "excluded_initial_link_failure_board_boots": 0, "post_build_archive_recovery_only": True,
        "boundary": "three unchanged original binary-semaphore handshake scenarios, 1000 iterations; native FIFO pthread attribute setup/create and automatic exit included, joins outside timing before static stack reuse; native non-PI counting semaphores start empty, selected protocol does not overflow one but general one-token saturation not enforced; native preemptive controller 150/workers 160, no Zephyr cooperative priority class; one-second native sleep request rounds across tick scheduling, not original phase synchronization; original calibration/coarse elapsed guards/means retained; 2048-byte static stacks, all audited paths in Flash; registry 3 to 3, five native joins, final empty semaphores destroyed; v1 link failure not flashed, v2 post-build source archival recovered without changing firmware; no full suite, cross-OS rank, general heap cleanup, new-image RAM/energy"}


def render_table(result):
    return "\n".join(["| Original sys_kernel semaphore scenario / OS | Mean, ns (three boots) |", "| --- | --- |",
        *("| " + tag + " / NuttX | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |" for tag in TAGS)])


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
