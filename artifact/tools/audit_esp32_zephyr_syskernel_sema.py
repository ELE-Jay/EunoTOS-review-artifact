#!/usr/bin/env python3
"""Replay the unchanged sys_kernel semaphore scenarios on native FreeRTOS."""
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
from audit_esp32_zephyr_slab import ROOT, REFERENCE, ZEPHYR, original_syskernel_cases
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_syskernel_sema_control import FUNCTIONS, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_sema_freertos"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_syskernel_slab_riot"
DIRECTORY = ROOT / "artifacts/reports/zephyr-syskernel-sema-freertos-v1"
TAGS = tuple("Semaphore #" + str(i) for i in (1, 2, 3))
NATIVE = tuple("components/freertos/" + name for name in (
    "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
    "FreeRTOS-Kernel/portable/xtensa/portasm.S", "FreeRTOS-Kernel/include/freertos/task.h",
    "FreeRTOS-Kernel/include/freertos/semphr.h", "FreeRTOS-Kernel/include/freertos/FreeRTOS.h",
    "esp_additions/freertos_tasks_c_additions.h"))
IDF = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/"
SOURCES = {"source/" + name: ZEPHYR + "tests/benchmarks/sys_kernel/src/" + name
           for name in ("sema.c", "syskernel.c", "syskernel.h")}
SOURCES.update({"include/zephyr/" + name: ZEPHYR + "subsys/testsuite/include/zephyr/" + name
                for name in ("timestamp.h", "test_asm_inline_gcc.h")})
SOURCES.update({"native-source/" + name: IDF + name for name in NATIVE})
SOURCES["native-control-source/assert.c"] = IDF + "components/newlib/assert.c"
BEGIN = "SEMA PORT BEGIN FreeRTOS Zephyr-3.7.0-subset count=1000 clock=240 cores=1 tick=1 stack=2048"
REGISTRY = "SEMA NATIVE REGISTRY before=3 after=3"


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines.count(BEGIN) != 1 or \
            lines.count("SEMA PORT END") != 1 or lines[-1] != "SEMA PORT END" or \
            any(sum(fragment in line for line in lines) != 1 for fragment in (
                "2nd stage bootloader", "Single core mode", "cpu freq: 240000000 Hz",
                "Project name:     zephyr_syskernel_sema_port", "main_task: Calling app_main()",
                "ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "...")) or \
            any(re.search(r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I)
                for line in lines):
        raise ValueError("semaphore reset/profile/image/completion/correctness differs")
    # A UART timeout splits the final unterminated case marker from the later registry line.
    joint = "END TEST CASE" + REGISTRY
    if (directory / f"reset{index}.raw").read_bytes().count(joint.encode()) != 1 or \
            lines.count("END TEST CASE") != 3 or lines.count(REGISTRY) != 1 or \
            lines.count("SEMA NATIVE PRIORITY controller=14 workers=20 peer_timeslicing=0 cooperative_class=0") != 1 or \
            lines.count("SEMA NATIVE FINAL semaphores=0 registry_restored=1") != 1:
        raise ValueError("native semaphore/worker retirement witness differs")
    result = original_syskernel_cases(lines, TAGS, "SEMA")
    if lines.index(REGISTRY) <= max(i for i, line in enumerate(lines) if line == "END TEST CASE"):
        raise ValueError("registry observation entered original semaphore window")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
            "registry_before": 3, "registry_after": 3, "final_case_end_and_registry_share_uart_line": True,
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def literal_word(elf, row, register):
    match = re.fullmatch(r"([0-9a-f]+): ([0-9a-f]{6}) l32r\s+a" + str(register) + r", ([0-9a-f]+) <.*", row)
    if not match:
        raise ValueError("original/native literal instruction absent")
    address, value, pool = (int(x, 16) for x in match.groups())
    offset = value >> 8
    if offset & 0x8000:
        offset -= 0x10000
    if value & 0xff != 1 + (register << 4) or ((address + 3) & ~3) + 4 * offset != pool:
        raise ValueError("original/native literal target differs from encoding")
    sections = [s for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and
                s["sh_addr"] <= pool and pool + 4 <= s["sh_addr"] + s["sh_size"]]
    if len(sections) != 1:
        raise ValueError("original/native literal not uniquely bound")
    start = pool - sections[0]["sh_addr"]
    return int.from_bytes(sections[0].data()[start:start + 4], "little")


def original_callbacks(control, elf, symbols):
    callbacks = [literal_word(elf, row, 13) for _, row in sorted(control["sema_test"].items()) if " l32r\ta13," in row]
    if callbacks != [symbols.get_symbol_by_name(name)[0]["st_value"] for name in (
            "sema_thread1", "sema_thread2", "sema_thread1", "sema_thread3", "sema_thread1")]:
        raise ValueError("original semaphore worker entry binding differs")


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols.get_symbol_by_name("unexecuted_original_suite_main"):
            raise ValueError("unexecuted full original suite remains linked")
        control = read_control_rows((directory / "sema-control-flow.txt").read_text(), "SEMA CONTROL",
                                    elf, symbols, set(FUNCTIONS), noreturn=("fail", "__assert_func"))
        calls, placements, ordered = {}, {}, {}
        for name, rows in control.items():
            section = elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"])
            expected = ".flash.text" if name in FUNCTIONS[:18] else ".iram0.text"
            if section.name != expected:
                raise ValueError("original/native semaphore code placement differs")
            placements[name] = section.name
            ordered[name] = []
            for address in sorted(rows):
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", rows[address])
                if not match:
                    continue
                value, target, callee = int(match[1], 16), int(match[2], 16), match[3]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != destination or target != destination:
                    raise ValueError("native semaphore call label differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
                ordered[name].append(callee)
        expected_calls = (("app_main", "run_original", 1), ("run_original", "sema_test", 1),
            ("sema_test_init", "k_sem_init", 2), ("sema_test", "k_thread_create", 5),
            ("sema_test", "sema_test_init", 3), ("sema_test", "begin_test", 3),
            ("sema_test", "TIME_STAMP_DELTA_GET", 6), ("sema_test", "check_result", 3),
            ("sema_thread1", "k_sem_take", 1), ("sema_thread1", "k_sem_give", 1),
            ("sema_thread2", "k_sem_take", 1), ("sema_thread2", "k_sem_give", 1),
            ("sema_thread3", "k_sem_take", 1), ("sema_thread3", "k_sem_give", 1),
            ("sema_thread3", "vPortYield", 1), ("thread_entry", "vTaskDelete", 1),
            ("k_sem_init", "xQueueGenericCreateStatic", 1), ("k_sem_init", "vQueueDelete", 1),
            ("k_sem_give", "xQueueGenericSend", 1), ("k_sem_take", "xQueueSemaphoreTake", 1),
            ("k_thread_create", "xTaskCreateStaticPinnedToCore", 1), ("k_sleep", "vTaskDelay", 1),
            ("k_sleep", "uxTaskGetNumberOfTasks", 1), ("k_uptime_delta", "xTaskGetTickCount", 1),
            ("begin_test", "k_sleep", 1), ("begin_test", "k_uptime_delta", 1),
            ("check_result", "k_uptime_delta", 1), ("check_result", "native_sema_mean", 1),
            ("prvIdleTask", "prvDeleteTCB", 1), ("prvDeleteTCB", "__assert_func", 1))
        if any(calls.get((a, b), 0) != count for a, b, count in expected_calls):
            raise ValueError("original/native semaphore call coverage differs")
        timed_calls = {"sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET", "k_thread_create",
                       "k_sem_give", "k_sem_take", "check_result"}
        phase = ["sema_test_init", "begin_test", "TIME_STAMP_DELTA_GET"]
        end = ["TIME_STAMP_DELTA_GET", "check_result"]
        # GCC lays the third loop body after the return; its branch returns to the guard.
        expected_order = (phase + ["k_thread_create"] * 2 + end) * 2 + phase + [
            "k_thread_create"] + end + ["k_sem_give", "k_sem_take"]
        if [name for name in ordered["sema_test"] if name in timed_calls] != expected_order:
            raise ValueError("original semaphore timestamp/create/handshake order differs")
        for name, count in (("run_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("semaphore original calibration/endpoints are not encoded CCOUNT reads")
        witnesses = {
            "sema_thread1": ("fb7c movi.n\ta11, -1",),
            "sema_thread2": ("ffafb2 movi\ta11, -1",),
            "sema_thread3": ("00a0b2 movi\ta11, 0", "00ba56 bnez\ta10,"),
            "k_thread_create": ("4e1c movi.n\ta14, 20", "11cc50 slli\ta12, a12, 11",
                                "01a0c2 movi\ta12, 1", "016182 s32i\ta8, a1, 4"),
            "run_original": ("0ea0b2 movi\ta11, 14", "e8a392 movi\ta9, 0x3e8"),
            "thread_entry": ("542282 l32i\ta8, a2, 0x150", "0008e0 callx8\ta8", "0a0c movi.n\ta10, 0"),
            "k_sleep": ("01a0a2 movi\ta10, 1",),
            "k_sem_init": ("3e0c movi.n\ta14, 3", "1a0c movi.n\ta10, 1", "00a0c2 movi\ta12, 0"),
            "k_sem_take": ("60b0b0 neg\ta11, a11",),
            "sema_test": ("0f3897 bltu\ta8, a9, 400d2bd4", "fff446 j\t400d2bbd"),
        }
        for name, instructions in witnesses.items():
            body = "\n".join(control[name].values())
            if any(instruction not in body for instruction in instructions):
                raise ValueError(("native semaphore profile/polling/retirement instruction differs", name))
        for name in ("sema_thread1", "sema_thread2", "sema_thread3", "sema_test"):
            if not any(" blt" in row for row in control[name].values()):
                raise ValueError("original semaphore loop removed")
        # Bind indirect original callbacks to actual ELF literal words, not annotations.
        original_callbacks(control, elf, symbols)
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("thread_stack1", "thread_stack2")}
        if sizes != {"thread_stack1": 2048, "thread_stack2": 2048} or any(
                symbols.get_symbol_by_name(name)[0]["st_value"] % 16 for name in sizes):
            raise ValueError("original worker stack dimensions/alignment differ")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
            "original_timestamp_reads_retained": True, "original_create_and_handshake_order_retained": True,
            "original_worker_callback_literals_checked": 5, "original_stack_sizes": sizes,
            "native_polling_yield_and_automatic_retirement_retained": True,
            "native_idle_static_tcb_cleanup_and_noreturn_assert_path_checked": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "sema-control.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    image_sources = set(SOURCES) - {"native-control-source/assert.c"}
    if not {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "compiler.txt",
            "FreeRTOSConfig.h", "build.log", "compile_commands.json", "port.c", "original_stats.c", "build-script.sh",
            "CMakeLists.txt", "main/CMakeLists.txt", "include/zephyr/kernel.h", *image_sources} <= inventories["image.sha256"] or \
            not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py",
                *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["sema-control.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "sema-control-flow.txt",
                "collect-sema-control.py", "collect-sema-wrapper.py", "collector-base.py", "native-control-source/assert.c"}:
        raise ValueError("original semaphore source/image/capture/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("semaphore original/native official source differs", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {r["path"] for r in proof} != set(SOURCES) or any(
            r["url"] != SOURCES[r["path"]] or r["sha256"] != digest(directory / r["path"]) for r in proof):
        raise ValueError("original/native semaphore provenance differs")
    binding = json.loads((directory / "compiled-native-source-binding.json").read_text())
    native_paths = {"native-source/" + name: "tm-cooperative-no-timeslicing/freertos/" + name.split("components/freertos/")[1]
                    for name in NATIVE}
    native_paths["native-control-source/assert.c"] = "esp-idf-v5.2.5/components/newlib/assert.c"
    if binding["elf_sha256"] != digest(directory / "application.elf") or \
            binding["compile_commands_sha256"] != digest(directory / "compile_commands.json") or \
            len(binding["files"]) != len(native_paths) or {r["archived_path"] for r in binding["files"]} != set(native_paths) or \
            any(r["actual_path"] != native_paths[r["archived_path"]] or r["sha256"] != digest(directory / r["archived_path"])
                for r in binding["files"]):
        raise ValueError("actual compiled native source/header bytes differ from archived official files")
    for name in ("sema.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original semaphore body/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(archived), ROOT / "tools" / local) for archived, local in (
        ("build-script.sh", "build_esp32_zephyr_syskernel_sema_freertos.sh"),
        ("runner.sh", "run_esp32_zephyr_syskernel_sema_freertos.sh"), ("capture_esp32_uart.py", "capture_esp32_uart.py"),
        ("collector-base.py", "collect_esp32_zephyr_slab_control.py"),
        ("collect-sema-wrapper.py", "collect_esp32_zephyr_syskernel_sema_control.py"))]
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-sema-control.py").read_text() != collector_source((directory / "collector-base.py").read_text()):
        raise ValueError("reviewed original/native semaphore build/capture/collector binding differs")
    config = (directory / "config").read_text().splitlines()
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y",
            "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000"} <= set(config) or "13.2.0" not in (directory / "compiler.txt").read_text() or \
            (directory / "FreeRTOSConfig.h").read_bytes() != (ROOT / "artifacts/reports/zephyr-yield-freertos-v1/FreeRTOSConfig.h").read_bytes():
        raise ValueError("native semaphore clock/core/scheduler/tick/compiler profile differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    build = (directory / "build.log").read_text()
    units = ("zephyr-syskernel-sema-freertos/port.c", "zephyr-syskernel-sema-freertos/original_stats.c",
             "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
             "FreeRTOS-Kernel/portable/xtensa/portasm.S", "components/newlib/assert.c")
    for name in units:
        selected = [row for row in commands if row["file"].endswith("/" + name)]
        if len(selected) != 1:
            raise ValueError(("native semaphore actual compilation absent/duplicate", name))
        args = shlex.split(selected[0]["command"])
        output = args[args.index("-o") + 1]
        if Path(args[0]).name != "xtensa-esp32-elf-gcc" or "-c" not in args or \
                not re.search(r"Building (?:C|ASM) object " + re.escape(output) + r"$", build, re.M) or \
                [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                any(arg.startswith("-DNUMBER_OF_LOOPS") for arg in args):
            raise ValueError(("native semaphore actual compiler/optimization/count differs", name))
        if name.startswith("zephyr-") and not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(args):
            raise ValueError("original semaphore timer branch differs")
        if name.startswith("FreeRTOS-Kernel/") and not any(
                arg.endswith("/tm-cooperative-no-timeslicing/freertos/config/include") for arg in args):
            raise ValueError("native semaphore scheduler header scope differs")
    control = machine_paths(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native semaphore installed image/board binding differs")
    captures = [capture(directory, index) for index in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("original semaphore physical boot intervals overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original semaphore subset", "os": "FreeRTOS",
        "metric_count": 3, "resets": 3, "iterations": 1000, "original_files": 5, "native_source_files": 9,
        "actual_compiled_units_checked": len(units), "captures": captures, "machine_paths": control,
        "metrics": {tag: {"means_ns": [row["means_ns"][tag] for row in captures]} for tag in TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "13.2.0", "worker_stack_bytes": 2048,
        "native_controller_priority": 14, "native_worker_priority": 20, "native_time_slicing": False,
        "native_per_thread_cooperative_priority_class": False, "original_one_native_tick_preparation_preserved": True,
        "measurement_eligible": True, "ranking_eligible": False, "full_original_suite_measured": False,
        "uart_sdk_git_version_available": False,
        "actual_native_source_binding_sha256": digest(directory / "compiled-native-source-binding.json"),
        "boundary": "three unchanged original 1000-iteration binary-semaphore scenarios; two blocking workers, polling/yield worker, and lower-controller/higher-worker handshake; timestamp windows include native static task creation and automatic worker retirement, not isolated give/take latency; same-priority workers preemptive without time slicing, no native Zephyr cooperative priority class; 2048-byte stacks, core 0, controller 14/workers 20; native idle cleanup checked before static TCB reuse, registry 3 to 3, semaphores empty/deleted after timing; one native 1-Hz tick preparation and original elapsed guard/calibration/mean retained; adapters in Flash/native kernel in IRAM; official source bytes verified against pinned tags but UART SDK Git metadata unavailable; no full suite, cross-OS rank, general heap cleanup, new-image RAM or energy claim"}


def render_table(result):
    return "\n".join(["| Original sys_kernel semaphore scenario / OS | Mean, ns (three boots) |",
        "| --- | --- |", *("| " + tag + " / FreeRTOS | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |"
                            for tag in TAGS)])


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
