#!/usr/bin/env python3
"""Replay the complete original RTEMS Time Checker, not an OS score."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_rhealstone_iram import ROOT, SOURCE, REVISION, NATIVE
from audit_esp32_resources import audit_elf_image, image_length, static_footprint
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from collect_esp32_rhealstone_irq_control import NORETURN
from collect_esp32_rhealstone_tmck_control import FUNCTIONS, collector_source

DIRECTORY = ROOT / "artifacts/reports/rhealstone-tmck-freertos-v1/freertos/tmck"
PORT = ROOT / "firmware/bsp/esp32/rhealstone/freertos_tmck"
REFERENCE = ROOT / "artifacts/reports/rhealstone-v2/freertos/taskswitch"
ORIGINAL = {"tmck-task1.c": "testsuites/tmtests/tmck/task1.c", "system.h": "testsuites/tmtests/tmck/system.h",
    "timesys.h": "testsuites/tmtests/include/timesys.h", "btimer.h": "cpukit/include/rtems/btimer.h",
    "tmtests_empty_function.c": "testsuites/support/src/tmtests_empty_function.c",
    "tmtests_empty_function.h": "testsuites/support/include/tmtests_empty_function.h"}
ITERATIONS = (0, 1000, 10000, 50000, 100000)
TAGS = tuple("Time Check: " + ("NULL" if not n else f"LOOP ({n})") + " timer stopped at" for n in ITERATIONS)
BEGIN = "RHEALSTONE BEGIN TIME CHECKER FreeRTOS clock=240 cores=1 tick=100 timer=ccount unit=cycles"
PROFILE = "TMCK PROFILE controller=12 worker=19 stack=4096 raw=1 samples=100 maximum=1000 loops=1000,10000,50000,100000"


def original_outputs(lines, begin=BEGIN, profile=PROFILE):
    raw = [line for line in lines if line.startswith("TMCK RAW ")]
    if len(raw) != 1:
        raise ValueError("tmck raw sample record missing/duplicate")
    match = re.fullmatch(r"TMCK RAW count=(\d+)((?: value\d+=\d+)+)", raw[0])
    if not match:
        raise ValueError("tmck raw sample grammar differs")
    pairs = [(int(a), int(b)) for a, b in re.findall(r" value(\d+)=(\d+)", match[2])]
    if int(match[1]) != len(pairs) or [i for i, _ in pairs] != list(range(len(pairs))) or \
            not 105 <= len(pairs) <= 512 or any(not 0 <= n <= 0xffffffff for _, n in pairs):
        raise ValueError("tmck sample count/index/capacity differs")
    samples, trials = [n for _, n in pairs], [n for _, n in pairs[:-5]]
    accepted = [n for n in trials if n <= 1000]
    if len(accepted) != 100 or trials[-1] > 1000:
        raise ValueError("tmck original accepted sample count/last sample differs")
    warnings = []
    index = 1
    for n in trials:
        if n > 1000:
            warnings.append(f"TOO LONG ({n}) at index {index}!!!")
        else:
            index += 1
    histogram = [f"{n} {count}" for n, count in sorted(Counter(accepted).items())]
    total = sum(accepted)
    original_lines = warnings + ["Units may not be in microseconds for this test!!!"] + histogram + \
        [f"Total time = {total}", f"Average time = {total // 100}"] + \
        [f"{tag} - {n}" for tag, n in zip(TAGS, samples[-5:])]
    expected = [begin, profile] + original_lines + [raw[0], "RHEALSTONE END"]
    if lines[lines.index(begin):] != expected:
        raise ValueError("tmck original histogram/loop output/order/put_time arithmetic differs")
    return {"accepted": 100, "rejected": len(warnings), "raw_samples_cycles": samples,
        "raw_histogram": {str(k): v for k, v in sorted(Counter(accepted).items())},
        "original_total_cycles": total, "original_average_cycles": total // 100,
        "original_null_and_loop_cycles": samples[-5:]}


def capture(directory, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(s) != 1 for s in (BEGIN, PROFILE, "RHEALSTONE END")) or \
            lines[-1] != "RHEALSTONE END" or any(sum(fragment in line for line in lines) != 1 for fragment in (
                "2nd stage bootloader", "Single core mode", "cpu freq: 240000000 Hz", "main_task: Calling app_main()",
                "ELF file SHA256:  " + digest(directory / "rhealstone.elf")[:9] + "...")) or \
            any(re.search(r"RHEALSTONE FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("tmck reset/clock/image/completion differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **original_outputs(lines),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def machine_paths(directory):
    with (directory / "rhealstone.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        calls, ordered = Counter(), {}
        for name, rows in control.items():
            symbol = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
            if elf.get_section(symbol["st_shndx"]).name != ".iram0.text":
                raise ValueError("tmck original/adapter/native task path not in IRAM")
            ordered[name] = []
            for address, row in sorted(rows.items()):
                m = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not m:
                    continue
                value, printed, target = int(m[1], 16), int(m[2], 16), m[3]
                candidates = symbols.get_symbol_by_name(target)
                if not candidates:
                    raise ValueError("tmck actual call symbol missing")
                destination = max(candidates, key=lambda row: row["st_size"])["st_value"]
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or printed != destination:
                    raise ValueError("tmck printed call does not match actual encoding")
                calls[name, target] += 1
                ordered[name].append(target)
        expected = (("Init", "benchmark_timer_disable_subtracting_average_overhead", 1), ("Init", "rh_begin", 1),
            ("Init", "rtems_task_create", 1), ("Init", "rtems_task_start", 1), ("Init", "rtems_task_exit", 1),
            ("Task_1", "check_read_timer", 1), ("Task_1", "benchmark_timer_initialize", 5),
            ("Task_1", "benchmark_timer_read", 5), ("Task_1", "benchmark_timer_empty_function", 4),
            ("Task_1", "rh_printf", 5), ("Task_1", "rh_end", 1), ("Task_1", "rtems_test_exit", 1),
            ("check_read_timer", "benchmark_timer_initialize", 1), ("check_read_timer", "benchmark_timer_read", 1),
            ("rh_begin", "native_rh_begin", 1), ("app_main", "xTaskCreatePinnedToCore", 1),
            ("init_entry", "Init", 1), ("rtems_task_start", "xTaskCreatePinnedToCore", 1), ("rtems_task_exit", "vTaskDelete", 1))
        if any(calls[a, b] != n for a, b, n in expected):
            raise ValueError("tmck actual original/native call coverage differs")
        if ordered["Task_1"] != ["check_read_timer", "benchmark_timer_initialize", "benchmark_timer_read", "rh_printf"] + \
                ["benchmark_timer_initialize", "benchmark_timer_empty_function", "benchmark_timer_read", "rh_printf"] * 4 + \
                ["rh_end", "rtems_test_exit"]:
            raise ValueError("tmck actual original loop/timestamp order differs")
        witnesses = {"Init": ("01a0a2 movi\ta10, 1", "05a0b2 movi\ta11, 5", "11cc40 slli\ta12, a12, 12"),
            "Task_1": ("e8a352 movi\ta5, 0x3e8", "051c movi.n\ta5, 16", "27d552 addmi\ta5, a5, 0x2700"),
            "check_read_timer": ("e8a382 movi\ta8, 0x3e8", "e8a392 movi\ta9, 0x3e8", "65a082 movi\ta8, 101"),
            "benchmark_timer_empty_function": ("004136 entry\ta1, 32", "020c movi.n\ta2, 0", "f01d retw.n"),
            "benchmark_timer_read": ("03ea20 rsr.ccount\ta2", "c02280 sub\ta2, a2, a8", "0829 s32i.n\ta2, a8, 0"),
            "rtems_task_start": ("8e2c movi.n\ta14, 40", "c0ee80 sub\ta14, a14, a8", "41e1e0 srli\ta14, a14, 1", "ee2b addi.n\ta14, a14, 2", "11cc40 slli\ta12, a12, 12", "0179 s32i.n\ta7, a1, 0"),
            "app_main": ("ce0c movi.n\ta14, 12", "11cc40 slli\ta12, a12, 12", "080c movi.n\ta8, 0", "0189 s32i.n\ta8, a1, 0"),
            "entry": ("28a8 l32i.n\ta10, a8, 8", "012892 l32i\ta9, a8, 4", "0009e0 callx8\ta9")}
        if any(not any(row.endswith(" " + witness) for row in control[name].values())
                for name, values in witnesses.items() for witness in values):
            raise ValueError("tmck original loop/empty/raw/priority machine witness differs")
        if len(control["benchmark_timer_empty_function"]) != 3:
            raise ValueError("tmck original empty function changed")
        literals = [literal_word(elf, row, 5) for _, row in sorted(control["Task_1"].items()) if " l32r\ta5," in row]
        callback = [literal_word(elf, row, 11) for row in control["Init"].values() if " l32r\ta11," in row]
        if literals != [50000, 100000] or callback != [symbols.get_symbol_by_name("Task_1")[0]["st_value"]] or \
                sum("550b addi.n\ta5, a5, -1" in row for row in control["Task_1"].values()) != 4 or \
                sum("ff7556 bnez\ta5," in row for row in control["Task_1"].values()) != 4:
            raise ValueError("tmck original loop bounds/backedges/task callback differ")
        for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if sum("rsr.ccount" in row for row in control[name].values()) != 1:
                raise ValueError("tmck raw timestamp count differs")
        for name in ("Distribution", "samples", "sample_count", "raw_mode", "timer_start"):
            symbol = symbols.get_symbol_by_name(name)[0]
            if elf.get_section(symbol["st_shndx"])["sh_type"] != "SHT_NOBITS":
                raise ValueError("tmck diagnostic/default histogram is not zero-initialized BSS")
        if symbols.get_symbol_by_name("Distribution")[0]["st_size"] != 4004 or symbols.get_symbol_by_name("samples")[0]["st_size"] != 2048:
            raise ValueError("tmck original histogram/raw buffer capacity differs")
        footprint = static_footprint(directory / "rhealstone.elf")
    return {"decoded_functions": len(FUNCTIONS), "decoded_direct_calls": sum(calls.values()),
        "original_empty_function_present_out_of_line": True, "original_loop_bounds_and_backedges_bound": True,
        "raw_timestamp_subtraction_bound": True, "original_worker_callback_bound": True,
        "placement": "original tmck, empty function, adapter and native task paths in IRAM",
        "static_footprint": footprint}


def audit(directory=DIRECTORY, verify_upstream=False):
    for manifest in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, manifest)
    originals = {name: "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + path for name, path in ORIGINAL.items()}
    originals.update({"native-source/" + name: "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/components/freertos/FreeRTOS-Kernel/" + name for name in NATIVE})
    proof_path = directory / "official-source.json"
    if verify_upstream:
        proof = []
        for name, url in originals.items():
            with urlopen(url, timeout=40) as response:
                value = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / name) != value:
                raise ValueError("tmck fixed official source differs: " + name)
            proof.append({"path": name, "url": url, "sha256": value})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(originals) or {row["path"] for row in proof} != set(originals) or any(
            row["url"] != originals[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("tmck official source proof differs")
    for name in ORIGINAL:
        if (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("tmck original program/interface changed")
    comparisons = [("port.c", PORT / "port.c"), ("native_rhealstone_port.h", REFERENCE / "port.c"),
        *((name, REFERENCE / name) for name in ("config", "FreeRTOSConfig.h", "compiler.txt")),
        ("build_esp32_rhealstone_tmck_freertos.sh", ROOT / "tools/build_esp32_rhealstone_tmck_freertos.sh"),
        ("runner.sh", ROOT / "tools/run_esp32_rhealstone.sh"), ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")]
    comparisons += [("build-files/" + name, PORT / name) for name in ("CMakeLists.txt", "linker.lf", "main/CMakeLists.txt")]
    comparisons += [("port-include/" + p.relative_to(PORT / "include").as_posix(), p) for p in (PORT / "include").rglob("*") if p.is_file()]
    base = ROOT / "firmware/bsp/esp32/rhealstone/include"
    comparisons += [("base-include/" + p.relative_to(base).as_posix(), p) for p in base.rglob("*") if p.is_file()]
    for saved, current in comparisons:
        if (directory / saved).read_bytes() != current.read_bytes():
            raise ValueError("tmck adapter/profile/recipe/acquisition changed: " + saved)
    if (directory / "port-include/rtems/btimer.h").read_bytes() != (SOURCE / "btimer.h").read_bytes():
        raise ValueError("tmck actual benchmark timer API differs")
    commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    required = ["rhealstone/freertos_tmck/port.c", "rhealstone-original/tmck-task1.c",
        "rhealstone-original/tmtests_empty_function.c", *["tm-cooperative-no-timeslicing/freertos/FreeRTOS-Kernel/" + name for name in NATIVE]]
    for name in required:
        selected = [args for args in commands if any(not arg.startswith("-") and arg.endswith("/" + name) for arg in args)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or "-c" not in selected[0] or \
                [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                any(arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-flto")) for arg in selected[0]):
            raise ValueError("tmck original/native actual compilation/profile differs: " + name)
    if "[507/507]" not in (directory / "build.log").read_text() or "no work to do" in (directory / "build.log").read_text():
        raise ValueError("tmck complete clean build evidence missing")
    frozen = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text())
    if (directory / "collect-irq-control.py").read_text() != frozen:
        raise ValueError("tmck actual control collector changed")
    audit_elf_image(directory / "rhealstone.elf", directory / "rhealstone.bin")
    image_length((directory / "bootloader.bin").read_bytes())
    if not (directory / "partition-table.bin").read_bytes().startswith(b"\xaa\x50"):
        raise ValueError("tmck partition table invalid")
    flash = (directory / "flash.log").read_text()
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or written != [
            ((directory / name).stat().st_size, offset) for name, offset in (("bootloader.bin", 0x1000),
            ("partition-table.bin", 0x8000), ("rhealstone.bin", 0x10000))]:
        raise ValueError("tmck board/verified Flash binding differs")
    paths = machine_paths(directory)
    captures = [capture(directory, i) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("tmck independent reset intervals overlap")
    return {"audit": "pass", "scope": "FreeRTOS native port of complete original RTEMS Time Checker",
        "original_full_tmck_suite_measured": True, "original_test_body_and_empty_function_unchanged": True,
        "revision": REVISION, "resets": 3, "original_source_files": len(ORIGINAL), "native_source_files": len(NATIVE),
        "actual_compiled_units_checked": len(required), "configured_clock_mhz": 240, "cores": 1, "tick_hz": 100,
        "compiler": "GCC13.2 / Os", "original_accepted_samples": 100, "maximum_distribution": 1000,
        "original_empty_function_iterations": list(ITERATIONS[1:]), "unit": "CPU cycles", "captures": captures,
        "machine_paths": paths, "raw_mode_requested_by_original": True, "average_subtraction_used": False,
        "measurement_eligible": True, "ranking_eligible": False, "composite_score": None,
        "boundary": "timer-method validation, not an OS performance score; raw mode is the original tmck request, calibrated-mode service not exercised; ISR/cache/null-directive interpretation of existing Rhealstone remains unqualified; diagnostic stores occur after each endpoint and can change the next sample; no runtime RAM/energy observation",
        "binary_sha256": digest(directory / "rhealstone.bin"),
        "installed_flash_bytes": sum((directory / name).stat().st_size for name in ("bootloader.bin", "partition-table.bin", "rhealstone.bin"))}


def render_table(result):
    values = [row["original_null_and_loop_cycles"] for row in result["captures"]]
    rows = ["| RTEMS Time Checker 原项 | 第 1 / 2 / 3 次启动（CPU cycles） | 用途 |", "| --- | --- | --- |"]
    for i, n in enumerate(ITERATIONS):
        rows.append("| " + ("NULL timer" if not n else f"LOOP ({n})") + " | " + " / ".join(str(run[i]) for run in values) + " | 计时方法自检，不排名 |")
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(verify_upstream=args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
