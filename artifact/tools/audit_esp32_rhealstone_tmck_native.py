#!/usr/bin/env python3
"""Replay complete original Time Checker ports on native Zephyr and RIOT."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_rhealstone_tmck import ROOT, SOURCE, ORIGINAL, REVISION, ITERATIONS, original_outputs
from audit_esp32_rhealstone_calibrated import ZEPHYR_NATIVE, RIOT_NATIVE, zephyr_source_urls, riot_source_urls
from audit_esp32_resources import audit_elf_image, image_length, static_footprint
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_thread import read_control_rows, read_raw_capture
from collect_esp32_rhealstone_irq_control import NORETURN
from collect_esp32_rhealstone_tmck_native_control import FUNCTIONS, collector_source

PROFILES = {"zephyr": ("v2", "Zephyr", "100", 10, 2), "riot": ("v4", "RIOT", "native-tickless", 1, 0)}
PORT_BASE = ROOT / "firmware/bsp/esp32/rhealstone"


def directory_for(system):
    return ROOT / ("artifacts/reports/rhealstone-tmck-" + system + "-" + PROFILES[system][0]) / system / "tmck"


def markers(system):
    _, label, tick, controller, worker = PROFILES[system]
    return (f"RHEALSTONE BEGIN TIME CHECKER {label} clock=240 cores=1 tick={tick} timer=ccount unit=cycles",
        f"TMCK PROFILE controller={controller} worker={worker} stack=4096 raw=1 samples=100 maximum=1000 loops=1000,10000,50000,100000")


def capture(directory, system, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    begin, profile = markers(system)
    boot = "*** Booting Zephyr OS build 3.7.0 ***" if system == "zephyr" else "main(): This is RIOT! (Version: 2024.10-devel)"
    single_core = sum("Unicore bootloader" in line for line in lines) if system == "zephyr" else lines.count("Single core mode")
    if sum(line.startswith("rst:0x") for line in lines) != 1 or any(lines.count(s) != 1 for s in (begin, profile, boot, "RHEALSTONE END")) or \
            single_core != 1 or lines[-1] != "RHEALSTONE END" or \
            any(re.search(r"RHEALSTONE FAIL|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("native full tmck reset/profile/correctness/completion differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **original_outputs(lines, begin, profile),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def machine_paths(directory, system, profile=None):
    names = set(profile["functions"] if profile else FUNCTIONS[system])
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "irq-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, names, noreturn=NORETURN + (profile["noreturn"] if profile else
                (("sched_task_exit", "cpu_switch_context_exit") if system == "riot" else ())))
        calls, ordered, placement = Counter(), {}, {}
        for name, rows in control.items():
            symbol = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
            section = elf.get_section(symbol["st_shndx"]).name
            native = name in (profile["iram"] if profile else
                (("z_impl_k_thread_create", "z_impl_k_thread_start", "z_impl_k_thread_abort") if system == "zephyr" else
                ("thread_create", "thread_wakeup", "sched_task_exit")))
            if section != (".iram0.text" if native else ".flash.text"):
                raise ValueError("native full tmck original/adapter/kernel placement differs: " + name)
            placement[name] = section
            ordered[name] = []
            for address, row in sorted(rows.items()):
                match = re.fullmatch(r"[0-9a-f]+: ([0-9a-f]{6}) call8\s+([0-9a-f]+) <([\w.$]+)>", row)
                if not match:
                    continue
                value, printed, target = int(match[1], 16), int(match[2], 16), match[3]
                candidates = symbols.get_symbol_by_name(target)
                if not candidates:
                    raise ValueError("native full tmck actual call symbol missing")
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                destination = (address & ~3) + 4 + offset * 4
                if value & 0x3f != 0x25 or printed != destination or not any(row["st_value"] == destination for row in candidates):
                    raise ValueError("native full tmck call label differs from encoding")
                calls[name, target] += 1
                ordered[name].append(target)
        common = (("Init", "benchmark_timer_disable_subtracting_average_overhead", 1), ("Init", "rh_begin", 1),
            ("Init", "rtems_task_create", 1), ("Init", "rtems_task_start", 1), ("Init", "rtems_task_exit", 1),
            ("Task_1", "check_read_timer", 1), ("Task_1", "benchmark_timer_initialize", 5),
            ("Task_1", "benchmark_timer_read", 5), ("Task_1", "benchmark_timer_empty_function", 4),
            ("Task_1", "rh_printf", 5), ("Task_1", "rh_end", 1), ("Task_1", "rtems_test_exit", 1),
            ("check_read_timer", "benchmark_timer_initialize", 1), ("check_read_timer", "benchmark_timer_read", 1),
            ("rh_begin", "native_rh_begin", 1), (profile["init_caller"] if profile else "init_entry", "Init", 1))
        native_calls = profile["calls"] if profile else (("rtems_task_create", "create", 1), ("create", "z_impl_k_thread_create", 1),
            ("main", "z_impl_k_thread_create", 1), ("rtems_task_start", "z_impl_k_thread_start", 1),
            ("rtems_task_exit", "z_impl_k_thread_abort", 1)) if system == "zephyr" else (
            ("rtems_task_create", "thread_create", 1), ("main", "thread_create", 1), ("main", "thread_wakeup", 1),
            ("rtems_task_start", "thread_wakeup", 1), ("rtems_task_exit", "sched_task_exit", 1))
        if any(calls[a, b] != n for a, b, n in common + native_calls):
            raise ValueError("native full tmck original/native call coverage differs")
        wanted = ["check_read_timer", "benchmark_timer_initialize", "benchmark_timer_read", "rh_printf"] + \
            ["benchmark_timer_initialize", "benchmark_timer_empty_function", "benchmark_timer_read", "rh_printf"] * 4 + ["rh_end", "rtems_test_exit"]
        if ordered["Task_1"] != wanted:
            raise ValueError("native full tmck original loop/timestamp order differs")
        witnesses = {"Task_1": ("e8a352 movi\ta5, 0x3e8", "051c movi.n\ta5, 16", "27d552 addmi\ta5, a5, 0x2700"),
            "check_read_timer": ("e8a392 movi\ta9, 0x3e8", "65a082 movi\ta8, 101"),
            "benchmark_timer_empty_function": ("004136 entry\ta1, 32", "020c movi.n\ta2, 0", "f01d retw.n"),
            "benchmark_timer_read": ("03ea20 rsr.ccount\ta2", "c02280 sub\ta2, a2, a8", "0829 s32i.n\ta2, a8, 0"),
            "Init": ("01a0a2 movi\ta10, 1", "11cc40 slli\ta12, a12, 12")}
        if profile:
            witnesses.update(profile["witnesses"])
        elif system == "zephyr":
            witnesses.update({"Init": witnesses["Init"] + ("5b0c movi.n\ta11, 5",),
                "create": ("418180 srli\ta8, a8, 1", "11cc40 slli\ta12, a12, 12", "f97c movi.n\ta9, -1"),
                "main": ("0aa092 movi\ta9, 10", "11cc40 slli\ta12, a12, 12"),
                "entry": ("1928a2 l32i\ta10, a8, 100", "182892 l32i\ta9, a8, 96", "0009e0 callx8\ta9")})
        else:
            witnesses.update({"Task_1": ("e8a342 movi\ta4, 0x3e8", "71a242 movi\ta4, 0x271", "1144c0 slli\ta4, a4, 4"),
                "check_read_timer": ("e8a342 movi\ta4, 0x3e8", "65a032 movi\ta3, 101"),
                "Init": witnesses["Init"] + ("5b0c movi.n\ta11, 5",),
                "rtems_task_create": ("fbc332 addi\ta3, a3, -5", "112d40 slli\ta2, a13, 12", "04bd mov.n\ta11, a4",
                    "1d0c movi.n\ta13, 1", "20c220 or\ta12, a2, a2", "0c4522 s8i\ta2, a5, 12"),
                "main": ("1d0c movi.n\ta13, 1", "0dcd mov.n\ta12, a13", "11bd40 slli\ta11, a13, 12"),
                "entry": ("28a8 l32i.n\ta10, a8, 8", "012892 l32i\ta9, a8, 4", "0009e0 callx8\ta9")})
        if any(not any(row.endswith(" " + witness) for row in control[name].values())
                for name, values in witnesses.items() for witness in values):
            raise ValueError("native full tmck loop/empty/raw/priority machine witness differs")
        loop_register = profile["loop_register"] if profile else (5 if system == "zephyr" else 4)
        decrement = "550b addi.n\ta5, a5, -1" if loop_register == 5 else "440b addi.n\ta4, a4, -1"
        backedge = profile["backedge"] if profile else ("ff7556 bnez\ta5," if system == "zephyr" else "ff4456 bnez\ta4,")
        if len(control["benchmark_timer_empty_function"]) != 3 or sum(decrement in row for row in control["Task_1"].values()) != 4 or \
                sum(backedge in row for row in control["Task_1"].values()) != 4:
            raise ValueError("native full tmck empty function/backedges differ")
        limits = [literal_word(elf, row, loop_register) for _, row in sorted(control["Task_1"].items()) if f" l32r\ta{loop_register}," in row]
        callback = [literal_word(elf, row, 11) for row in control["Init"].values() if " l32r\ta11," in row]
        if limits != (profile["loop_literals"] if profile else [50000, 100000]) or callback != [symbols.get_symbol_by_name("Task_1")[0]["st_value"]]:
            raise ValueError("native full tmck original loop literals/callback differ")
        if profile:
            for name, register, expected in profile["literals"]:
                values = [literal_word(elf, row, register) for row in control[name].values() if f" l32r\ta{register}," in row]
                wanted_values = [symbols.get_symbol_by_name(value)[0]["st_value"] if isinstance(value, str) else value for value in expected]
                if values != wanted_values:
                    raise ValueError("native full tmck stack/entry/clock literal differs: " + name)
        for name in ("benchmark_timer_initialize", "benchmark_timer_read"):
            if sum("rsr.ccount" in row for row in control[name].values()) != 1:
                raise ValueError("native full tmck timestamp count differs")
        for name, size in (("Distribution", 4004), ("samples", 2048), ("sample_count", 4), ("raw_mode", 1)):
            symbol = symbols.get_symbol_by_name(name)[0]
            if symbol["st_size"] != size or elf.get_section(symbol["st_shndx"])["sh_type"] != "SHT_NOBITS":
                raise ValueError("native full tmck zero-initialized histogram/raw buffer differs")
    return {"decoded_functions": len(names), "decoded_direct_calls": sum(calls.values()), "placement": placement,
        "original_empty_function_present_out_of_line": True, "original_loop_bounds_and_backedges_bound": True,
        "raw_timestamp_subtraction_bound": True, "original_worker_callback_bound": True}


def audit(system):
    if system not in PROFILES:
        raise ValueError("unsupported full tmck native OS")
    directory = directory_for(system)
    for manifest in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, manifest)
    source_proof = ROOT / "artifacts/reports/rhealstone-tmck-freertos-v1/freertos/tmck/official-source.json"
    original_proof = {r["path"]: r for r in json.loads(source_proof.read_text())}
    for name, path in ORIGINAL.items():
        row = original_proof[name]
        if row["url"] != "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + path or \
                row["sha256"] != digest(directory / name) or (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("native full tmck official original source/proof differs")
    recipe = PORT_BASE / (system + "_tmck")
    reference = ROOT / ("artifacts/reports/rhealstone-zephyr-v3/zephyr/taskswitch" if system == "zephyr" else "artifacts/reports/rhealstone-riot-v4/riot/taskswitch")
    native_reference = reference if system == "zephyr" else ROOT / "artifacts/reports/rhealstone-riot-v5/riot/semshuffle"
    bindings = [("port.c", recipe / "port.c"), ("native_rhealstone_port.h", native_reference / "port.c"),
        ("compiler.txt", reference / "compiler.txt"), ("build_esp32_rhealstone_tmck_" + system + ".sh", ROOT / ("tools/build_esp32_rhealstone_tmck_" + system + ".sh")),
        ("runner.sh", ROOT / ("tools/run_esp32_rhealstone_tmck_native.sh" if system == "zephyr" else "tools/run_esp32_rhealstone_tmck_riot.sh")),
        ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py")]
    bindings += [(path.relative_to(PORT_BASE).as_posix(), path) for path in (PORT_BASE / "full_tmck").rglob("*") if path.is_file()]
    if system == "zephyr":
        bindings += [("CMakeLists.txt", recipe / "CMakeLists.txt"), ("prj.conf", reference / "prj.conf")]
        metadata = {"CONFIG_TAINT=y", "CONFIG_TAINT_BLOBS=y"}
        config, old = set((directory / "config").read_text().splitlines()), set((reference / "config").read_text().splitlines())
        if config - old != metadata or old - config or (directory / "config-comparison.log").read_text():
            raise ValueError("full tmck Zephyr native profile changed beyond taint metadata")
        bindings += [("include/" + p.relative_to(PORT_BASE / "include").as_posix(), p) for p in (PORT_BASE / "include").rglob("*") if p.is_file()]
    else:
        bindings += [("Makefile", recipe / "Makefile")]
        config = (directory / "config.h").read_text()
        if config.count('#define TMCK_RIOT 1\n') != 1 or config.count('#define RIOT_APPLICATION "rhealstone-tmck"\n') != 1 or \
                config.replace('#define TMCK_RIOT 1\n', '').replace('#define RIOT_APPLICATION "rhealstone-tmck"\n',
                '#define RIOT_APPLICATION "rhealstone-taskswitch"\n') != (reference / "config.h").read_text():
            raise ValueError("full tmck RIOT native profile changed beyond adapter/application identities")
        check_manifest(directory, "prearchive-images.sha256")
        bindings += [("include/" + p.relative_to(PORT_BASE / "include").as_posix(), p) for p in (PORT_BASE / "include").rglob("*") if p.is_file()]
        bindings += [("include/" + name, SOURCE / name) for name in ("timesys.h", "system.h", "tmtests_empty_function.h")]
    bindings.append(("full_tmck/include/rtems/btimer.h", SOURCE / "btimer.h"))
    if any((directory / archived).read_bytes() != current.read_bytes() for archived, current in bindings):
        raise ValueError("full tmck native adapter/profile/recipe/acquisition changed")
    version = "v1" if system == "zephyr" else "v2"
    native_proof_path = ROOT / ("artifacts/reports/rhealstone-" + system + "-calibrated-" + version + "/official-native-source.json")
    proof = json.loads(native_proof_path.read_text())
    urls = zephyr_source_urls() if system == "zephyr" else riot_source_urls()
    if len(proof) != len(urls) or {r["path"] for r in proof} != set(urls):
        raise ValueError("full tmck fixed native source proof coverage differs")
    for row in proof:
        path = directory / (row["path"] if row["path"] == "west.yml" else "native-source/" + row["path"])
        if row["url"] != urls[row["path"]] or row["sha256"] != digest(path):
            raise ValueError("full tmck fixed official native source differs")
    if (directory / "collect-irq-control.py").read_text() != collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(), system):
        raise ValueError("full tmck frozen native collector differs")
    if system == "zephyr":
        commands = [(row["file"], shlex.split(row["command"])) for row in json.loads((directory / "compile_commands.json").read_text())]
        required = ["rhealstone/zephyr_tmck/port.c", "rhealstone-original/tmck-task1.c", "rhealstone-original/tmtests_empty_function.c",
            *[n for n in ZEPHYR_NATIVE if n.endswith(".c") and not n.startswith("hal/")], "components/esp_hw_support/esp_clk.c"]
    else:
        commands = []
        for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines():
            if "xtensa-esp32-elf-gcc" not in line or " -c " not in line:
                continue
            args = shlex.split(ANSI.sub("", line))
            sources = [arg for arg in args if arg.endswith((".c", ".S")) and not arg.startswith("-")]
            if len(sources) != 1:
                raise ValueError("full tmck RIOT compiler source argument ambiguous")
            commands.append((sources[0], args))
        required = ["rhealstone/riot_tmck/" + n for n in ("port.c", "tmck-task1.c", "tmtests_empty_function.c")]
        required += [n for n in RIOT_NATIVE if n.endswith((".c", ".S")) and any(p.endswith("/" + n) for p, _ in commands)]
        required.append("components/esp_hw_support/esp_clk.c")
        if not {"core/thread.c", "core/sched.c", "cpu/esp32/irq_arch.c", "cpu/esp_common/esp-xtensa/thread_arch.c",
                "cpu/esp_common/vendor/xtensa/portasm.S", "cpu/esp_common/vendor/xtensa/xtensa_vectors.S"}.issubset(required):
            raise ValueError("full tmck RIOT native core/architecture compile coverage incomplete")
    for name in required:
        selected = [args for path, args in commands if path.endswith("/" + name)]
        if len(selected) != 1 or Path(selected[0][0]).name != "xtensa-esp32-elf-gcc" or \
                [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-flto")) for a in selected[0]):
            raise ValueError("full tmck original/native clean compile/profile differs: " + name)
    audit_elf_image(directory / "application.elf", directory / "application.bin", ram_only_header=system == "zephyr")
    images = (("application.bin", 0x1000),) if system == "zephyr" else (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))
    if system == "riot":
        image_length((directory / "bootloader.bin").read_bytes())
        if not (directory / "partitions.bin").read_bytes().startswith(b"\xaa\x50"):
            raise ValueError("full tmck RIOT partition table invalid")
    flash = (directory / "flash.log").read_text()
    written = [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != len(images) or \
            written != [((directory / n).stat().st_size, a) for n, a in images]:
        raise ValueError("full tmck native physical board/Flash image differs")
    paths = machine_paths(directory, system)
    captures = [capture(directory, system, i) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("full tmck native independent captures overlap")
    failures = []
    for version in ((1,) if system == "zephyr" else (1, 2, 3)):
        failed = ROOT / f"artifacts/reports/rhealstone-tmck-{system}-v{version}" / system / "tmck"
        check_manifest(failed, "failed-source.sha256")
        if any((failed / name).exists() for name in ("image.sha256", "application.elf", "flash.log")) or list(failed.glob("reset*")):
            raise ValueError("full tmck failed build acquired a firmware/capture claim")
        failures.append({"cohort": failed.parents[1].name, "board_boots": 0, "firmware_built": False,
            "source_inventory_sha256": digest(failed / "failed-source.sha256")})
    return {"audit": "pass", "scope": PROFILES[system][1] + " native port of complete original RTEMS Time Checker",
        "original_full_tmck_suite_measured": True, "original_test_body_and_empty_function_unchanged": True,
        "resets": 3, "original_source_files": 6, "native_source_files": len(ZEPHYR_NATIVE if system == "zephyr" else RIOT_NATIVE),
        "actual_compiled_units_checked": len(required), "configured_clock_mhz": 240, "cores": 1,
        "tick_hz": 100 if system == "zephyr" else None, "compiler": "GCC13.2 / Os" if system == "zephyr" else "GCC12.2 / Os",
        "original_accepted_samples": 100, "maximum_distribution": 1000, "original_empty_function_iterations": list(ITERATIONS[1:]),
        "unit": "CPU cycles", "captures": captures, "machine_paths": paths, "excluded_failed_builds": failures,
        "raw_mode_requested_by_original": True, "average_subtraction_used": False, "measurement_eligible": True,
        "ranking_eligible": False, "composite_score": None, "binary_sha256": digest(directory / "application.bin"),
        "native_source_proof_sha256": digest(native_proof_path), "original_source_proof_sha256": digest(source_proof),
        "installed_flash_bytes": sum((directory / n).stat().st_size for n, _ in images), "static_footprint": static_footprint(directory / "application.elf"),
        "boundary": "timer-method validation, not an OS score; original asks raw mode, calibrated mode not exercised; original/adapter Flash versus native task IRAM, compiler/tick differences retained; post-endpoint diagnostic stores can affect later samples; no IRQ/cache attribution, runtime RAM or energy result; existing Rhealstone directive/null-path/API qualification unchanged"}


def render_table(result):
    label = result["scope"].split(" native", 1)[0]
    values = [r["original_null_and_loop_cycles"] for r in result["captures"]]
    rows = ["| " + label + " / RTEMS Time Checker 原项 | 第 1 / 2 / 3 次启动（CPU cycles） | 用途 |", "| --- | --- | --- |"]
    for i, n in enumerate(ITERATIONS):
        rows.append("| " + label + " / " + ("NULL timer" if not n else f"LOOP ({n})") + " | " + " / ".join(str(r[i]) for r in values) + " | 计时方法自检，不排名 |")
    return "\n".join(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", choices=tuple(PROFILES))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.system), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
