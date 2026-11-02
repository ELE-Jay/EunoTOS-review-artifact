#!/usr/bin/env python3
"""Replay unchanged two-slot sys_kernel stacks through FreeRTOS native queues."""
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
from audit_esp32_zephyr_syskernel_sema import SOURCES as SEMA_SOURCES, SHARED, IDF, PORT as SEMA_PORT, literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_zephyr_syskernel_stack_control import FUNCTIONS, NATIVE, collector_source

PORT = ROOT / "firmware/bsp/esp32/zephyr_syskernel_stack_freertos"
DIRECTORY = ROOT / "artifacts/reports/zephyr-syskernel-stack-freertos-v2"
SOURCES = {key: value for key, value in SEMA_SOURCES.items() if key.startswith(("source/", "include/"))}
SOURCES["source/stack.c"] = ZEPHYR + "tests/benchmarks/sys_kernel/src/stack.c"
SOURCES.update({"native-source/" + name: IDF + name for name in NATIVE})
SOURCES["native-control-source/assert.c"] = IDF + "components/newlib/assert.c"
TAGS = tuple("Stack #" + str(i) for i in (1, 2, 3))
BEGIN = "SYSSTACK PORT BEGIN FreeRTOS Zephyr-3.7.0-subset count=1000 clock=240 cores=1 tick=1 stack=2048 slots=2 item_bytes=4"


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    registry = "SYSSTACK NATIVE REGISTRY before=3 after=3"
    required = (BEGIN, "SYSSTACK PORT END", registry,
        "SYSSTACK NATIVE SELF_CHECK capacity=2 item_bytes=4 lifo=2 empty=1 full=1",
        "SYSSTACK NATIVE PRIORITY controller=14 workers=20 peer_timeslicing=0 cooperative_class=0",
        "SYSSTACK NATIVE FINAL queues=0 registry_restored=1")
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or any(lines.count(line) != 1 for line in required) or \
            lines[-1] != "SYSSTACK PORT END" or any(sum(fragment in line for line in lines) != 1 for fragment in (
                "2nd stage bootloader", "Single core mode", "cpu freq: 240000000 Hz",
                "Project name:     zephyr_syskernel_stack_port", "main_task: Calling app_main()",
                "ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "...")) or \
            any(re.search(r"PORT FAIL|FAILED|PARTIAL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I)
                for line in lines):
        raise ValueError("stack reset/profile/image/completion/correctness differs")
    result = original_syskernel_cases(lines, TAGS, "SYSSTACK")
    if lines.index(registry) <= max(i for i, line in enumerate(lines) if line == "END TEST CASE") or \
            lines.index(required[3]) >= lines.index(BEGIN):
        raise ValueError("stack self-check/retirement observation entered original window")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **result,
        "registry_before": 3, "registry_after": 3, "final_queues_empty_deleted": True,
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def machine_paths(directory):
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if any(symbols.get_symbol_by_name(name) for name in ("sema_test", "k_sem_init", "k_sem_give", "k_sem_take",
                "unexecuted_semaphore_app_main", "unexecuted_semaphore_run_original", "unexecuted_original_suite_main")):
            raise ValueError("unexecuted original suite/semaphore runner remains linked")
        control = read_control_rows((directory / "sysstack-control-flow-v2.txt").read_text(), "SYSSTACK CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=("fail", "__assert_func"))
        calls, placements, ordered = {}, {}, {}
        for name, rows in control.items():
            section = elf.get_section(symbols.get_symbol_by_name(name)[0]["st_shndx"])
            expected = ".flash.text" if name in FUNCTIONS[:18] or name == "BENCH_START" else ".iram0.text"
            if section.name != expected:
                raise ValueError("original/native stack placement differs")
            placements[name], ordered[name] = section.name, []
            for address, row in sorted(rows.items()):
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                value, target, callee = int(m[1], 16), int(m[2], 16), m[3]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = symbols.get_symbol_by_name(callee)[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or target != destination:
                    raise ValueError("stack call label differs from actual encoding")
                calls[name, callee] = calls.get((name, callee), 0) + 1
                ordered[name].append(callee)
        expected = (("app_main", "run_stack_original", 1), ("run_stack_original", "stack_test", 1),
            ("stack_test", "stack_test_init", 3), ("stack_test_init", "k_stack_init", 2),
            ("stack_test", "k_thread_create", 5), ("stack_test", "BENCH_START", 3),
            ("stack_test", "TIME_STAMP_DELTA_GET", 3), ("stack_test", "check_result", 3),
            ("stack_test", "k_stack_push", 2), ("stack_test", "k_stack_pop", 2),
            ("stack_thread1", "k_stack_push", 2), ("stack_thread1", "k_stack_pop", 2),
            ("stack_thread2", "k_stack_push", 1), ("stack_thread2", "k_stack_pop", 1),
            ("stack_thread3", "k_stack_push", 1), ("stack_thread3", "k_stack_pop", 1), ("stack_thread3", "vPortYield", 1),
            ("k_stack_init", "xQueueGenericCreateStatic", 1), ("k_stack_init", "vQueueDelete", 1),
            ("k_stack_push", "xQueueGenericSend", 1), ("k_stack_pop", "xQueueReceive", 1),
            ("k_thread_create", "xTaskCreateStaticPinnedToCore", 1), ("thread_entry", "vTaskDelete", 1),
            ("k_sleep", "vTaskDelay", 1), ("k_sleep", "uxTaskGetNumberOfTasks", 1),
            ("k_uptime_delta", "xTaskGetTickCount", 1), ("BENCH_START", "begin_test", 1),
            ("BENCH_START", "TIME_STAMP_DELTA_GET", 1),
            ("begin_test", "k_sleep", 1), ("begin_test", "k_uptime_delta", 1),
            ("check_result", "k_uptime_delta", 1), ("check_result", "native_sema_mean", 1),
            ("prvIdleTask", "prvDeleteTCB", 1), ("prvDeleteTCB", "__assert_func", 1))
        if any(calls.get((a, b), 0) != count for a, b, count in expected):
            raise ValueError("original/native stack call coverage differs")
        relevant = {"stack_test_init", "BENCH_START", "k_thread_create", "TIME_STAMP_DELTA_GET", "check_result", "k_stack_push", "k_stack_pop"}
        phase, end = ["stack_test_init", "BENCH_START"], ["TIME_STAMP_DELTA_GET", "check_result"]
        # Third loop is laid out after the return and branches back to its timed guard.
        if [name for name in ordered["stack_test"] if name in relevant] != (phase + ["k_thread_create"] * 2 + end) * 2 + \
                phase + ["k_thread_create"] + end + ["k_stack_push", "k_stack_push", "k_stack_pop", "k_stack_pop"]:
            raise ValueError("original stack timestamp/create/handshake order differs")
        for name, count in (("run_stack_original", 2), ("TIME_STAMP_DELTA_GET", 1)):
            reads = [row for row in control[name].values() if "rsr.ccount" in row]
            if len(reads) != count or any(int(row.split()[1], 16) & 0xffff0f != 0x03ea00 for row in reads):
                raise ValueError("original stack calibration/start/end encoded CCOUNT reads differ")
        callbacks = [literal_word(elf, row, 13) for _, row in sorted(control["stack_test"].items()) if " l32r\ta13," in row]
        if callbacks != [symbols.get_symbol_by_name(name)[0]["st_value"] for name in (
                "stack_thread1", "stack_thread2", "stack_thread1", "stack_thread3", "stack_thread1")]:
            raise ValueError("original stack callback literals differ")
        witnesses = {"k_stack_init": ("0f2466 bnei\ta4, 2", "4b0c movi.n\ta11, 4", "2a0c movi.n\ta10, 2", "0e0c movi.n\ta14, 0"),
            "k_stack_push": ("01a0d2 movi\ta13, 1", "00a0c2 movi\ta12, 0"),
            "k_stack_pop": ("01c442 addi\ta4, a4, 1", "2424f6 bgeui\ta4, 2", "60c0c0 neg\ta12, a12"),
            "stack_thread3": ("0c0c movi.n\ta12, 0", "eacc bnez.n\ta10,"),
            "k_thread_create": ("4e1c movi.n\ta14, 20", "11cc50 slli\ta12, a12, 11", "016182 s32i\ta8, a1, 4"),
            "thread_entry": ("542282 l32i\ta8, a2, 0x150", "0008e0 callx8\ta8", "0a0c movi.n\ta10, 0"),
            "k_sleep": ("01a0a2 movi\ta10, 1",), "BENCH_START": ("00a0a2 movi\ta10, 0",)}
        for name, instructions in witnesses.items():
            if any(instruction not in "\n".join(control[name].values()) for instruction in instructions):
                raise ValueError(("native stack front/timeout/priority/retirement instruction differs", name))
        entry = [row for row in control["k_thread_create"].values() if " l32r\ta10," in row and "<thread_entry>" in row]
        if len(entry) != 1 or literal_word(elf, entry[0], 10) != symbols.get_symbol_by_name("thread_entry")[0]["st_value"]:
            raise ValueError("native stack worker entry literal differs")
        for name in ("stack_thread1", "stack_thread2", "stack_thread3", "stack_test"):
            if not any(" blt" in row for row in control[name].values()):
                raise ValueError("original stack loop absent")
        sizes = {name: symbols.get_symbol_by_name(name)[0]["st_size"] for name in ("stack1", "stack2", "thread_stack1", "thread_stack2")}
        if sizes != {"stack1": 8, "stack2": 8, "thread_stack1": 2048, "thread_stack2": 2048} or any(
                symbols.get_symbol_by_name(name)[0]["st_value"] % 16 for name in ("thread_stack1", "thread_stack2")):
            raise ValueError("original two-slot/worker stack dimensions differ")
    return {"decoded_functions": len(control), "decoded_native_calls": sum(calls.values()), "placements": placements,
        "original_storage_sizes": sizes, "original_callback_literals_checked": 5,
        "native_front_argument_checked": True, "original_timestamp_reads_retained": True,
        "original_create_and_handshake_order_retained": True, "native_idle_static_tcb_cleanup_checked": True,
        "unexecuted_semaphore_test_and_runners_garbage_collected": True,
        "control_supplement": "v2", "initial_start_function_coverage_incomplete_not_used": True}


def audit(directory=DIRECTORY, verify_upstream=False):
    directory = directory.resolve()
    inventories = {}
    for name in ("image.sha256", "capture.sha256", "sysstack-control.sha256", "sysstack-control-v2.sha256"):
        check_manifest(directory, name)
        inventories[name] = {line.split(maxsplit=1)[1].removeprefix("./") for line in (directory / name).read_text().splitlines()}
    if not {"application.elf", "application.bin", "bootloader.bin", "partitions.bin", "config", "compiler.txt", "FreeRTOSConfig.h",
            "build.log", "compile_commands.json", "port.c", "native_syskernel_thread_port.c", "original_stats.c", "build-script.sh",
            "CMakeLists.txt", "main/CMakeLists.txt", "include/zephyr/kernel.h", "include/zephyr/native_sema_kernel.h",
            *(set(SOURCES) - {"native-control-source/assert.c"})} <= inventories["image.sha256"] or \
            not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= inventories["capture.sha256"] or \
            inventories["sysstack-control-v2.sha256"] != {"application.elf", "image.sha256", "capture.sha256", "sysstack-control-flow-v2.txt",
                "collect-sysstack-control-v2.py", "collect-sysstack-wrapper-v2.py", "collector-base-v2.py", "sema-collector-base-v2.py",
                "native-control-source/assert.c", "compiled-native-source-binding.json"}:
        raise ValueError("original stack source/image/capture/control inventory incomplete")
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in SOURCES.items():
            with urlopen(url, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / name):
                raise ValueError(("stack original/native source differs from fixed official revision", name))
            proof.append({"path": name, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES) or {r["path"] for r in proof} != set(SOURCES) or any(
            r["url"] != SOURCES[r["path"]] or r["sha256"] != digest(directory / r["path"]) for r in proof):
        raise ValueError("original/native stack provenance differs")
    for name in ("stack.c", "sema.c", "syskernel.c", "syskernel.h"):
        if (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original stack/reused unused source/statistics changed")
    bindings = [(path.relative_to(PORT), path) for path in PORT.rglob("*") if path.is_file()]
    bindings += [(Path("original_stats.c"), SHARED / "original_stats.c"),
        (Path("native_syskernel_thread_port.c"), SEMA_PORT / "port.c"),
        (Path("include/zephyr/native_sema_kernel.h"), SEMA_PORT / "include/zephyr/kernel.h")]
    bindings += [(path.relative_to(SHARED), path) for path in (SHARED / "include").rglob("*") if path.is_file() and path.name != "kernel.h"]
    bindings += [(Path(archived), ROOT / "tools" / local) for archived, local in (
        ("build-script.sh", "build_esp32_zephyr_syskernel_stack_freertos.sh"), ("runner.sh", "run_esp32_zephyr_syskernel_stack_freertos.sh"),
        ("capture_esp32_uart.py", "capture_esp32_uart.py"), ("collector-base-v2.py", "collect_esp32_zephyr_slab_control.py"),
        ("sema-collector-base-v2.py", "collect_esp32_zephyr_syskernel_sema_control.py"),
        ("collect-sysstack-wrapper-v2.py", "collect_esp32_zephyr_syskernel_stack_control.py"))]
    if any((directory / archived).read_bytes() != source.read_bytes() for archived, source in bindings) or \
            (directory / "collect-sysstack-control-v2.py").read_text() != collector_source((directory / "collector-base-v2.py").read_text()):
        raise ValueError("reviewed original/native stack adapter/recipe differs")
    binding = json.loads((directory / "compiled-native-source-binding.json").read_text())
    paths = {"native-source/" + name: "tm-cooperative-no-timeslicing/freertos/" + name.split("components/freertos/")[1] for name in NATIVE}
    paths["native-control-source/assert.c"] = "esp-idf-v5.2.5/components/newlib/assert.c"
    if binding["elf_sha256"] != digest(directory / "application.elf") or binding["compile_commands_sha256"] != digest(directory / "compile_commands.json") or \
            len(binding["files"]) != len(paths) or {r["archived_path"] for r in binding["files"]} != set(paths) or any(
                r["actual_path"] != paths[r["archived_path"]] or r["sha256"] != digest(directory / r["archived_path"]) for r in binding["files"]):
        raise ValueError("actual compiled native stack source/header binding differs")
    config = (directory / "config").read_text().splitlines()
    if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y", "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000"} <= set(config) or \
            "13.2.0" not in (directory / "compiler.txt").read_text() or (directory / "FreeRTOSConfig.h").read_bytes() != \
            (ROOT / "artifacts/reports/zephyr-yield-freertos-v1/FreeRTOSConfig.h").read_bytes():
        raise ValueError("native stack clock/core/scheduler/tick/compiler differs")
    commands = json.loads((directory / "compile_commands.json").read_text())
    build = (directory / "build.log").read_text()
    units = ("zephyr-syskernel-stack-freertos/port.c", "zephyr-syskernel-stack-freertos/original_stats.c",
        "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
        "FreeRTOS-Kernel/portable/xtensa/portasm.S", "components/newlib/assert.c")
    for name in units:
        selected = [r for r in commands if r["file"].endswith("/" + name)]
        if len(selected) != 1:
            raise ValueError(("native stack actual compilation absent/duplicate", name))
        args = shlex.split(selected[0]["command"])
        output = args[args.index("-o") + 1]
        if Path(args[0]).name != "xtensa-esp32-elf-gcc" or "-c" not in args or not re.search(
                r"Building (?:C|ASM) object " + re.escape(output) + "$", build, re.M) or \
                [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or any(a.startswith("-DNUMBER_OF_LOOPS") for a in args):
            raise ValueError(("native stack actual compiler/optimization/count differs", name))
        if name.startswith("zephyr-") and not {"-DCONFIG_XTENSA=1", "-DCONFIG_SRAM_SIZE=320"} <= set(args) or \
                name.startswith("FreeRTOS-Kernel/") and not any(a.endswith("/tm-cooperative-no-timeslicing/freertos/config/include") for a in args):
            raise ValueError("original stack timing/native scheduler header scope differs")
    machine = machine_paths(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("native stack installed image/board binding differs")
    captures = [capture(directory, i) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("native stack independent boots overlap")
    failed = ROOT / "artifacts/reports/zephyr-syskernel-stack-freertos-v1"
    if 'does not appear to contain CMakeLists.txt' not in (failed / "configure.log").read_text() or any(
            (failed / name).exists() for name in ("application.elf", "application.bin", "flash.log", "reset1.raw")):
        raise ValueError("excluded source-transfer/configure failure boundary differs")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 sys_kernel original two-slot stack subset", "os": "FreeRTOS",
        "metric_count": 3, "resets": 3, "iterations": 1000, "capacity": 2, "item_bytes": 4,
        "original_executed_test_files": 5, "archived_original_files": 6, "native_source_files": 10,
        "actual_compiled_units_checked": len(units), "captures": captures, "machine_paths": machine,
        "metrics": {tag: {"means_ns": [r["means_ns"][tag] for r in captures]} for tag in TAGS},
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "13.2.0", "worker_stack_bytes": 2048,
        "native_controller_priority": 14, "native_worker_priority": 20, "native_time_slicing": False,
        "native_per_thread_cooperative_priority_class": False, "original_one_native_tick_preparation_preserved": True,
        "native_queue_front_copy_mapping": True, "measurement_eligible": True, "ranking_eligible": False,
        "full_original_suite_measured": False, "actual_native_source_binding_sha256": digest(directory / "compiled-native-source-binding.json"),
        "excluded_unflashed_configure_failure_sha256": digest(failed / "configure.log"),
        "boundary": "unchanged original three 1000-iteration two-slot four-byte LIFO scenarios; native static queue front-copy and receive/blocking wake costs retained, not native intrusive LIFO; original timestamps include task creation/automatic exit; capacity/reverse-order/empty/full self-check outside timing; native idle cleanup verified before static TCB reuse, registry 3 to 3 and queues empty/deleted; original one native tick preparation, elapsed guard, calibration and integer mean retained, not exact Zephyr phase-sync; controller14/workers20 preemptive/no time slicing, not cooperative class; GCC13/Os/Flash adapter/IRAM native paths; unexecuted reused semaphore test/runners discarded from ELF; first configure/source-transfer failure not compiled/flashed; v1 incomplete start-control supplement retained, v2 adds actual BENCH_START without changing image/captures; no full-suite, rank, heap-cleanup, new-image RAM or energy claim"}


def render_table(result):
    return "\n".join(["| Original sys_kernel two-slot stack scenario / OS | Mean, ns (three boots) |", "| --- | --- |",
        *("| " + tag + " / FreeRTOS | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |" for tag in TAGS)])


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
