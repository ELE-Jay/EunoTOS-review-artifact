#!/usr/bin/env python3
"""Replay unchanged sys_kernel semaphore scenarios and native Rhino deletion."""
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
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_slab import ROOT, REFERENCE, original_syskernel_cases
from audit_esp32_zephyr_syskernel_sema import SOURCES as FREE_SOURCES, TAGS, SHARED, original_callbacks, literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_syskernel_sema_alios_control import FUNCTIONS, NORETURN, INDIRECT_ADDRESS, INDIRECT_TARGETS, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_sema_alios"
DIRECTORY = ROOT / "artifacts/reports/zephyr-syskernel-sema-alios-v1"
NATIVE = ("kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_sched.c", "kernel/rhino/k_pend.c",
    "kernel/rhino/k_time.c", "kernel/rhino/k_sys.c", "kernel/rhino/include/k_task.h", "kernel/rhino/include/k_sem.h",
    "kernel/rhino/include/k_sys.h", "kernel/rhino/include/k_default_config.h", "kernel/rhino/include/k_obj.h",
    "kernel/rhino/include/k_list.h", "kernel/rhino/include/k_internal.h", "kernel/rhino/include/k_err.h",
    "platform/mcu/esp32/aos/hook_impl.c", "platform/arch/xtensa/lx6/xtensa_init.c",
    "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h")
SOURCES = {key: value for key, value in FREE_SOURCES.items() if key.startswith(("source/", "include/"))}
SOURCES.update({"native-source/" + name: UPSTREAM + name for name in NATIVE})
SOURCES["rhino-portasm-pinned.S"] = UPSTREAM + "platform/arch/xtensa/lx6/portasm.S"
BEGIN = "SEMA PORT BEGIN AliOS-Rhino Zephyr-3.7.0-subset count=1000 clock=240 cores=1 tick=1 stack=2048"


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    required = (BEGIN, "SEMA PORT END", "Welcome to AliOS Things", "bootload image",
        "SEMA NATIVE TICK divisor=240000000", "SEMA NATIVE REGISTRY before=8 after=8 retired=5",
        "SEMA NATIVE SEM REGISTRY before=13 after=13",
        "SEMA NATIVE PRIORITY controller=10 workers=8 peer_timeslicing=0 cooperative_class=0",
        "SEMA NATIVE FINAL semaphores=0 registry_restored=1")
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "SEMA PORT END" or any(re.search(
                r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("Rhino semaphore reset/profile/completion/correctness differs")
    result = original_syskernel_cases(lines, TAGS, "SEMA")
    if lines.index(required[5]) <= max(i for i, line in enumerate(lines) if line == "END TEST CASE") or \
            lines.index(required[6]) <= lines.index(required[5]):
        raise ValueError("native retirement/empty-semaphore deletion observation entered original window")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
        "registry_before": 8, "registry_after": 8, "retired_workers": 5,
        "semaphore_registry_before": 13, "semaphore_registry_after": 13,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def elf_bytes(elf, address, size):
    sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                s["sh_addr"] <= address and address + size <= s["sh_addr"] + s["sh_size"]]
    if len(sections) != 1:
        raise ValueError("native semaphore data not uniquely bound to ELF")
    start = address - sections[0]["sh_addr"]
    return sections[0].data()[start:start + size]


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full original suite remains linked")
        # Bind all six state-dispatch targets before accepting indirect reachability.
        table = 0x3f40482c
        targets = tuple(int.from_bytes(elf_bytes(elf, table + i * 4, 4), "little") for i in range(6))
        if targets != INDIRECT_TARGETS:
            raise ValueError("native task deletion jump table differs")
        control = read_control_rows((directory / "sema-control-flow-v2.txt").read_text(), "SEMA CONTROL", elf, symbols,
            set(FUNCTIONS), noreturn=NORETURN, indirect_targets={("krhino_task_del", INDIRECT_ADDRESS): set(targets)})
        calls, placements = {}, {}
        for name, rows in control.items():
            selected = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
            expected = ".iram0.text" if name in FUNCTIONS[22:] else ".flash.text"
            if elf.get_section(selected["st_shndx"]).name != expected:
                raise ValueError("original/native Rhino semaphore placement differs")
            placements[name] = expected
            for row in rows.values():
                m = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                address, value, target, callee = int(m[1], 16), int(m[2], 16), int(m[3], 16), m[4]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = (address & ~3) + 4 + 4 * offset
                if value & 0x3f != 0x25 or target != destination or destination not in {
                        s["st_value"] for s in symbols.get_symbol_by_name(callee)}:
                    raise ValueError("native semaphore call label differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
        expected = (("application_start", "krhino_task_create", 1), ("controller_entry", "run_original", 1),
            ("run_original", "sema_test", 1), ("sema_test", "sema_test_init", 3), ("sema_test_init", "k_sem_init", 2),
            ("sema_test", "k_thread_create", 5), ("sema_test", "begin_test", 3), ("sema_test", "TIME_STAMP_DELTA_GET", 6),
            ("sema_test", "check_result", 3), ("sema_test", "k_sem_give", 1), ("sema_test", "k_sem_take", 1),
            ("sema_thread1", "k_sem_take", 1), ("sema_thread1", "k_sem_give", 1),
            ("sema_thread2", "k_sem_take", 1), ("sema_thread2", "k_sem_give", 1),
            ("sema_thread3", "k_sem_take", 1), ("sema_thread3", "k_sem_give", 1), ("sema_thread3", "k_yield", 1),
            ("k_sem_init", "krhino_sem_create", 1), ("k_sem_init", "krhino_sem_del", 1), ("k_sem_init", "verify_retired", 2),
            ("k_sem_give", "krhino_sem_give", 1), ("krhino_sem_give", "sem_give", 1), ("k_sem_take", "krhino_sem_take", 1),
            ("krhino_sem_take", "pend_to_blk_obj", 1), ("krhino_sem_take", "core_sched", 1),
            ("k_thread_create", "krhino_task_create", 1), ("krhino_task_create", "task_create$part$0", 1),
            ("task_create$part$0", "cpu_task_stack_init", 1), ("k_yield", "krhino_task_yield", 1),
            ("k_sleep", "krhino_task_sleep", 1), ("begin_test", "k_sleep", 1), ("begin_test", "k_uptime_delta", 1),
            ("check_result", "k_uptime_delta", 1), ("check_result", "native_sema_mean", 1),
            ("k_uptime_delta", "krhino_sys_tick_get", 1), ("krhino_task_deathbed", "krhino_task_del", 1),
            ("krhino_task_del", "ready_list_rm", 1), ("krhino_task_del", "klist_rm", 2),
            ("krhino_task_del", "tick_list_rm", 2), ("krhino_task_del", "mutex_task_pri_reset", 1),
            ("krhino_task_del", "krhino_task_del_hook", 1), ("krhino_task_del", "core_sched", 1))
        if any(calls.get((a, b), 0) != count for a, b, count in expected):
            raise ValueError("original/native Rhino semaphore call coverage differs")
        relevant = {"sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET", "k_thread_create", "k_sem_give", "k_sem_take", "check_result"}
        ordered = [m[1] for _, row in sorted(control["sema_test"].items()) if
                   (m := re.search(r"call8\s+[0-9a-f]+ <([\w.$]+)>", row)) and m[1] in relevant]
        phase, end = ["sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET"], ["TIME_STAMP_DELTA_GET", "check_result"]
        if ordered != (phase + ["k_thread_create"] * 2 + end) * 2 + phase + ["k_thread_create", "k_sem_give", "k_sem_take"] + end:
            raise ValueError("original Rhino semaphore create/handshake/timestamp order differs")
        original_callbacks(control, elf, symbols)
        for name, count in (("run_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original semaphore calibration/endpoints differ")
        witnesses = {"sema_thread3": ("00a0b2 movi\ta11, 0", "ff0a56 bnez\ta10,"),
            "k_sem_take": ("c31b addi.n\ta12, a3, 1", "282cf6 bgeui\ta12, 2", "0d0c movi.n\ta13, 0",
                "60c040 neg\ta12, a4", "60d0d0 neg\ta13, a13", "70ae22 movi\ta2, 0xfffffe70", "ffaf22 movi\ta2, -1"),
            "k_thread_create": ("236252 s32i\ta5, a2, 140", "00a252 movi\ta5, 0x200", "8d0c movi.n\ta13, 8",
                "026152 s32i\ta5, a1, 8", "3149 s32i.n\ta4, a1, 12", "1159 s32i.n\ta5, a1, 4"),
            "thread_entry": ("232282 l32i\ta8, a2, 140", "0008e0 callx8\ta8", "f01d retw.n"),
            "cpu_task_stack_init": ("7289 s32i.n\ta8, a2, 28", "1259 s32i.n\ta5, a2, 4"),
            "krhino_task_deathbed": ("810a82 l8ui\ta8, a10, 129", "0a0c movi.n\ta10, 0", "052866 bnei\ta8, 2"),
            "verify_retired": ("192282 l32i\ta8, a2, 100", "057826 beqi\ta8, 7"),
            "krhino_task_del": ("192232 l32i\ta3, a2, 100", "ffc332 addi\ta3, a3, -1", "4763f6 bgeui\ta3, 6",
                "a03380 addx4\ta3, a3, a8", "002382 l32i\ta8, a3, 0", "0008a0 jx\ta8",
                "196232 s32i\ta3, a2, 100", "34c2a2 addi\ta10, a2, 52"),
            "klist_rm": ("1288 l32i.n\ta8, a2, 4", "0298 l32i.n\ta9, a2, 0", "0899 s32i.n\ta9, a8, 0", "1289 s32i.n\ta8, a2, 4")}
        for name, instructions in witnesses.items():
            if any(instruction not in "\n".join(control[name].values()) for instruction in instructions):
                raise ValueError(("native Rhino polling/creation/exit instruction differs", name))
        bindings = (("k_thread_create", 5, "thread_entry", 0x400d5b30),
                    ("cpu_task_stack_init", 8, "krhino_task_deathbed", 0x400868ef),
                    ("verify_retired", 10, "g_kobj_list", 0x400d597d))
        for name, register, target, address in bindings:
            if literal_word(elf, control[name][address], register) != symbols.get_symbol_by_name(target)[0]["st_value"]:
                raise ValueError("native worker entry/exit/registry literal differs")
        row = control["krhino_task_del"][0x40085324]
        if literal_word(elf, row, 8) != table:
            raise ValueError("native task deletion jump table pointer differs")
        # The called static inline copy has the same name twice; bind both actual bodies.
        copies = symbols.get_symbol_by_name("klist_rm")
        if len(copies) != 2 or any(s["st_size"] != 15 for s in copies) or len({
                elf_bytes(elf, s["st_value"], s["st_size"]) for s in copies}) != 1:
            raise ValueError("native called registry unlink copies differ")
        for name in ("sema_thread1", "sema_thread2", "sema_thread3", "sema_test"):
            if not any(" blt" in row for row in control[name].values()):
                raise ValueError("original semaphore loop absent")
        restore = [row for row in control["registry_count"].values() if " l32r\ta8," in row]
        rom = symbols.get_symbol_by_name("_xtos_set_intlevel")[0]
        if rom["st_shndx"] != "SHN_ABS" or rom["st_value"] != 0x4000bfdc or len(restore) != 2 or \
                any(literal_word(elf, row, 8) != rom["st_value"] for row in restore) or \
                not any("0063a0 rsil\ta10, 3" in row for row in control["registry_count"].values()):
            raise ValueError("native registry IRQ protection/ROM restore differs")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("thread_stack1", "thread_stack2")}
        if sizes != {"thread_stack1": 2048, "thread_stack2": 2048} or any(symbols.get_symbol_by_name(name)[0]["st_value"] % 16 for name in sizes):
            raise ValueError("original semaphore stack dimensions/alignment differ")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
        "original_stack_sizes": sizes, "original_worker_callback_literals_checked": 5,
        "original_timestamp_reads_retained": True, "original_create_and_handshake_order_retained": True,
        "native_blocking_and_nonblocking_arguments_checked": True, "native_automatic_exit_and_registry_unlink_checked": True,
        "native_deletion_jump_table_targets": list(targets), "native_registry_unlink_identical_copies_checked": 2,
        "control_supplement": "v2", "initial_control_supplement_incomplete_not_used": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "sema-control.sha256", "sema-control-v2.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    if not {"application.elf", "application.bin", "application.map", "bootloader.bin", "partitions.bin", "link.opts",
            "config", "sdkconfig.h", "k_config.h", "compiler.txt", "configure.log", "build.log", "port.c", "original_stats.c",
            "aos.mk", "Config.in", "examples-Config.in", "build-script.sh", "rhino-port-pinned.c", "rhino-vectors-pinned.S", *SOURCES} <= inventories["image.sha256"] or \
            not {"image.sha256", "runner.sh", "flash.log", "capture_esp32_uart.py", *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["sema-control-v2.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "sema-control-flow-v2.txt",
                "collect-sema-control-v2.py", "collect-sema-alios-wrapper-v2.py", "collector-base-v2.py"}:
        raise ValueError("native Rhino semaphore source/image/capture/control inventory incomplete")
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
        raise ValueError("original/native Rhino semaphore provenance differs")
    for name in ("sema.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original semaphore test/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(archived), ROOT / "tools" / local) for archived, local in (
        ("build-script.sh", "build_esp32_zephyr_syskernel_sema_alios.sh"), ("runner.sh", "run_esp32_zephyr_syskernel_sema_alios.sh"),
        ("capture_esp32_uart.py", "capture_esp32_uart.py"), ("collector-base-v2.py", "collect_esp32_zephyr_slab_control.py"),
        ("collect-sema-alios-wrapper-v2.py", "collect_esp32_zephyr_syskernel_sema_alios_control.py"))]
    board = ROOT / "firmware/bsp/esp32/alios_board"
    bindings += [(Path(name), board / path) for name, path in (("rhino-port-pinned.c", "rhino-port.c"),
        ("rhino-vectors-pinned.S", "rhino-vectors.S"), ("k_config.h", "esp32bench/k_config.h"), ("sdkconfig.h", "esp32bench/sdkconfig.h"))]
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-sema-control-v2.py").read_text() != collector_source((directory / "collector-base-v2.py").read_text()):
        raise ValueError("reviewed original/native Rhino semaphore recipe differs")
    config = (directory / "config").read_text().splitlines()
    if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="zephyr_sema"', 'AOS_APP_ZEPHYR_SEMA=y'} <= set(config) or \
            "5.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("native Rhino semaphore application/compiler differs")
    for name, value in (("RHINO_CONFIG_CPU_NUM", 1), ("RHINO_CONFIG_SCHED_RR", 0)):
        if not re.search(r"^#define " + name + r"\s+" + str(value) + "$", (directory / "k_config.h").read_text(), re.M):
            raise ValueError("native semaphore scheduler profile differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    units = ("app/example/zephyr_sema/port.c", "app/example/zephyr_sema/original_stats.c",
        *(name for name in NATIVE if name.endswith(".c")), "platform/arch/xtensa/lx6/port.c",
        "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S")
    for name in units:
        selected = [args for args in commands if any(a == name or a.endswith("/" + name) for a in args if not a.startswith("-"))]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0] or \
                any(a.startswith("-DNUMBER_OF_LOOPS") for a in selected[0]):
            raise ValueError(("actual native semaphore compilation/tick/count differs", name))
        if name.endswith(".c") and ([a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                not {"-DAOS_NO_WIFI", "-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(selected[0])):
            raise ValueError(("native semaphore optimization/WiFi/timer branch differs", name))
    divisors = hardware_tick_divisors(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    machine = machine_paths(directory)
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("Rhino semaphore installed image/board binding differs")
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("Rhino semaphore independent boots overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original semaphore subset", "os": "AliOS-Rhino",
        "metric_count": 3, "resets": 3, "iterations": 1000, "original_files": 5, "native_source_files": len(NATIVE) + 1,
        "actual_compiled_units_checked": len(units), "captures": captures, "machine_paths": machine, "hardware_tick_divisors": divisors,
        "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "5.2.0", "worker_stack_bytes": 2048,
        "native_controller_priority": 10, "native_worker_priority": 8, "native_time_slicing": False,
        "native_per_thread_cooperative_priority_class": False, "original_one_native_tick_preparation_preserved": True,
        "native_semaphore_limit_one_enforced": False, "measurement_eligible": True, "ranking_eligible": False,
        "full_original_suite_measured": False,
        "boundary": "three unchanged 1000-iteration scenarios; original windows include native worker creation/automatic return and deletion; static-worker retirement/registry checks and empty-semaphore destruction outside timing; counting semaphores do not generally cap at one token; no Zephyr cooperative priority class or exact tick-phase equivalence; native C/ASM tick 1 Hz, GCC5/Os and Flash/IRAM placement retained; nominal stacks reserve architecture frame/guard; zero coarse guard/identical integer means do not establish IRQ-free or zero uncertainty; original v1 control archive retained, complete deletion jump table audited in v2 on same unchanged image/captures; ROM/SDK not rebuilt; no full-suite, cross-OS rank, general heap-cleanup or new-image RAM/energy claim"}


def render_table(result):
    return "\n".join(["| Original sys_kernel semaphore scenario / OS | Mean, ns (three boots) |", "| --- | --- |",
        *("| " + tag + " / AliOS-Rhino | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |" for tag in TAGS)])


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
