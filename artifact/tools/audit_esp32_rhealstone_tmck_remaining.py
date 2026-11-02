#!/usr/bin/env python3
"""Replay complete original RTEMS Time Checker on native NuttX and Rhino."""
import argparse
import json
from pathlib import Path
import re
import shlex

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_rhealstone_tmck import ROOT, SOURCE, ORIGINAL, REVISION, ITERATIONS, original_outputs
from audit_esp32_rhealstone_tmck_native import machine_paths, render_table
from audit_esp32_rhealstone_calibrated import NUTTX_NATIVE, NUTTX_UPSTREAM, ALIOS_NATIVE, ALIOS_ARCHIVE, ALIOS_UPSTREAM, alios_native_path
from audit_esp32_resources import audit_elf_image, image_length, static_footprint
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_zephyr_isr import rhino_vector_dispatch, irq_archive_member
from collect_esp32_rhealstone_tmck_remaining_control import FUNCTIONS, collector_source

BASE = ROOT / "firmware/bsp/esp32/rhealstone"
PROFILES = {
    "nuttx": {"label": "NuttX", "controller": 110, "worker": 117, "compiler": "GCC13.2 / Os", "noreturn": ("exit", "_exit"),
        "iram": ("esp_clk_cpu_freq",), "init_caller": "rhealstone_main", "loop_register": 5, "backedge": "ff7556 bnez\ta5,",
        "loop_literals": [50000, 100000], "literals": [("rtems_task_start", 13, ["entry"]), ("native_rh_begin", 8, [240000000])],
        "calls": (("rhealstone_main", "sched_setscheduler", 1), ("rtems_task_start", "task_create", 1),
            ("rtems_task_exit", "exit", 1), ("native_rh_begin", "esp_clk_cpu_freq", 1), ("exit", "_exit", 1)),
        "witnesses": {"Init": ("01a0a2 movi\ta10, 1", "5b0c movi.n\ta11, 5", "11cc40 slli\ta12, a12, 12"),
            "rtems_task_create": ("fbc332 addi\ta3, a3, -5", "590c movi.n\ta9, 5", "3899 s32i.n\ta9, a8, 12"),
            "rtems_task_start": ("8b2c movi.n\ta11, 40", "c0bb80 sub\ta11, a11, a8", "41b1b0 srli\ta11, a11, 1",
                "64cbb2 addi\ta11, a11, 100", "11cc40 slli\ta12, a12, 12"),
            "rhealstone_main": ("6ea082 movi\ta8, 110", "01a0b2 movi\ta11, 1", "0189 s32i.n\ta8, a1, 0"),
            "entry": ("1898 l32i.n\ta9, a8, 4", "28a8 l32i.n\ta10, a8, 8", "0009e0 callx8\ta9")}},
    "alios": {"label": "AliOS-Rhino", "controller": 20, "worker": 5, "compiler": "GCC5.2 / Os", "noreturn": (),
        "iram": ("krhino_task_create", "krhino_task_resume", "krhino_task_del", "espos_isr_enter", "espos_isr_exit",
            "krhino_intrpt_enter", "krhino_intrpt_exit"), "init_caller": "init_entry", "loop_register": 4,
        "backedge": "ff7456 bnez\ta4,", "loop_literals": [10000, 50000, 100000],
        "literals": [("Init", 12, [4096]), ("create", 8, ["entry", "stacks"]),
            ("application_start", 8, ["init_entry", "init_stack"]), ("native_rh_begin", 8, [240000000])],
        "calls": (("rtems_task_create", "create", 1), ("create", "krhino_task_create", 1),
            ("application_start", "krhino_task_create", 1), ("application_start", "krhino_task_suspend", 1),
            ("rtems_task_start", "krhino_task_resume", 1), ("rtems_task_exit", "krhino_task_del", 1),
            ("native_rh_begin", "esp_clk_cpu_freq", 1), ("espos_isr_enter", "krhino_intrpt_enter", 1),
            ("espos_isr_exit", "krhino_intrpt_exit", 1)),
        "witnesses": {"Init": ("01a0a2 movi\ta10, 1", "5b0c movi.n\ta11, 5"),
            "Task_1": ("e8a342 movi\ta4, 0x3e8",),
            "check_read_timer": ("e8a392 movi\ta9, 0x3e8", "64a082 movi\ta8, 100", "c1b827 bgeu\ta8, a2, 400d5be4 <check_read_timer+0x1c>"),
            "rtems_task_create": ("fbc332 addi\ta3, a3, -5", "530c movi.n\ta3, 5", "246232 s32i\ta3, a2, 144"),
            "create": ("900ad2 l8ui\ta13, a10, 144", "00a482 movi\ta8, 0x400", "1189 s32i.n\ta8, a1, 4",
                "020c movi.n\ta2, 0", "3129 s32i.n\ta2, a1, 12"),
            "application_start": ("4d1c movi.n\ta13, 20", "00a482 movi\ta8, 0x400", "1189 s32i.n\ta8, a1, 4"),
            "entry": ("2322a2 l32i\ta10, a2, 140", "222282 l32i\ta8, a2, 136", "0008e0 callx8\ta8",)}}}


def directory_for(system):
    return ROOT / ("artifacts/reports/rhealstone-tmck-" + system + "-v1") / system / "tmck"


def markers(system):
    p = PROFILES[system]
    return (f"RHEALSTONE BEGIN TIME CHECKER {p['label']} clock=240 cores=1 tick=100 timer=ccount unit=cycles",
        f"TMCK PROFILE controller={p['controller']} worker={p['worker']} stack=4096 raw=1 samples=100 maximum=1000 loops=1000,10000,50000,100000")


def capture(directory, system, index):
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    if system == "nuttx":
        lines = [line.removeprefix("nsh> ") for line in lines]
    begin, profile = markers(system)
    resets = [row for row in rows if row["line"].startswith("rst:0x")]
    boot_ok = lines.count("NuttShell (NSH)") == lines.count("rhealstone") == 1 if system == "nuttx" else \
        lines.count("bootload image") == 1 and sum("cpu_start: Pro cpu start user code" in line for line in lines) == 1
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or not boot_ok or \
            any(lines.count(line) != 1 for line in (begin, profile, "RHEALSTONE END")) or lines[-1] != "RHEALSTONE END" or \
            any(re.search(r"FAIL|Guru Meditation|panic|ASSERT|Brownout|watchdog|Error ==> ", line, re.I) for line in lines):
        raise ValueError("full tmck remaining physical boot/profile/completion differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], **original_outputs(lines, begin, profile),
        "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def tick_control(directory, system):
    if system == "alios":
        values = hardware_tick_divisors(directory, expected_hz=100)
        # Verify the encoded l32r targets rather than trusting printed addresses.
        text = (directory / "disassembly.txt").read_text()
        with (directory / "application.elf").open("rb") as stream:
            elf = ELFFile(stream)
            for name in values:
                body = re.search(r"^[0-9a-f]+ <" + name + r">:\n(.*?)(?=\n\n|\Z)", text, re.M | re.S)[1]
                row = next(line for line in body.splitlines() if re.search(r"\bl32r\s+a[23],", line))
                match = re.fullmatch(r"([0-9a-f]+):\s+([0-9a-f]+)\s+(.+)", row)
                normalized = f"{match[1]}: {match[2]} {match[3]}"
                register = int(re.search(r"l32r\s+a([23]),", row)[1])
                if literal_word(elf, normalized, register) != 2400000:
                    raise ValueError("full tmck Rhino encoded hardware tick differs")
        return {"hardware_tick_hz": 100, "divisors": values, "native_vector": rhino_vector_dispatch(directory)}
    check_manifest(directory, "tmck-tick-control.sha256")
    expected = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(), system, tick=True)
    if (directory / "collect-tmck-tick-control.py").read_text() != expected:
        raise ValueError("full tmck NuttX frozen tick collector differs")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((directory / "tmck-tick-control-flow.txt").read_text(), "RHEALSTONE IRQ CONTROL",
            elf, symbols, {"up_timer_initialize", "esp32_timerisr"})
        address = symbols.get_symbol_by_name("g_tick_divisor")[0]["st_value"]
        for name, rows in control.items():
            if not any(row.endswith("13f080 wsr.ccompare0\ta8") for row in rows.values()) or \
                    [literal_word(elf, row, 8) for row in rows.values() if " l32r\ta8," in row] != [address]:
                raise ValueError("full tmck NuttX tick comparator/address differs")
        init = control["up_timer_initialize"]
        if [literal_word(elf, row, 9) for row in init.values() if " l32r\ta9," in row] != [2400000] or \
                [literal_word(elf, row, 11) for row in init.values() if " l32r\ta11," in row] != [symbols.get_symbol_by_name("esp32_timerisr")[0]["st_value"]]:
            raise ValueError("full tmck NuttX tick divisor/callback differs")
    return {"hardware_tick_hz": 100, "hardware_tick_divisor": 2400000, "decoded_tick_functions": 2}


def audit(system):
    p = PROFILES[system]
    directory = directory_for(system)
    for name in ("image.sha256", "capture.sha256", "irq-control.sha256"):
        check_manifest(directory, name)
    original_proof_path = ROOT / "artifacts/reports/rhealstone-tmck-freertos-v1/freertos/tmck/official-source.json"
    proof = {row["path"]: row for row in json.loads(original_proof_path.read_text())}
    for name, upstream in ORIGINAL.items():
        if proof[name]["url"] != "https://raw.githubusercontent.com/RTEMS/rtems/" + REVISION + "/" + upstream or \
                digest(directory / name) != proof[name]["sha256"] or (directory / name).read_bytes() != (SOURCE / name).read_bytes():
            raise ValueError("full tmck remaining fixed original source differs")
    version = "v2" if system == "nuttx" else "v1"
    reference = ROOT / f"artifacts/reports/rhealstone-{system}-{version}" / system / "taskswitch"
    recipe = BASE / (system + "_tmck")
    bindings = [(name, recipe / name) for name in ("port.c", "Makefile" if system == "nuttx" else "aos.mk")]
    bindings += [("original.c", SOURCE / "tmck-task1.c"), ("native_rhealstone_port.h", reference / "port.c"),
        ("compiler.txt", reference / "compiler.txt"), ("runner.sh", ROOT / "tools/run_esp32_rhealstone_tmck_remaining.sh"),
        ("capture-uart.py", ROOT / "tools/capture_esp32_uart.py"),
        ("build_esp32_rhealstone_tmck_" + system + ".sh", ROOT / ("tools/build_esp32_rhealstone_tmck_" + system + ".sh"))]
    for folder in ("include", "full_tmck", "full_tmck_remaining"):
        bindings += [(folder + "/" + path.relative_to(BASE / folder).as_posix(), path)
            for path in (BASE / folder).rglob("*") if path.is_file()]
    bindings += [("include/" + name, SOURCE / name) for name in ("timesys.h", "system.h", "tmtests_empty_function.h")]
    bindings += [("full_tmck/include/rtems/btimer.h", SOURCE / "btimer.h")]
    if system == "nuttx":
        bindings += [(name, BASE / "nuttx" / name) for name in ("Kconfig", "Make.defs")]
        configs = [(path / name).read_text().splitlines() for path, name in (
            (reference, "config"), (directory, "native-profile-config"), (directory, "config"))]
        labels = [[line for line in value if line.startswith("CONFIG_BASE_DEFCONFIG=")] for value in configs]
        if any(len(rows) != 1 or not re.fullmatch(r'CONFIG_BASE_DEFCONFIG="esp32-devkitc:nsh(?:-dirty)+"', rows[0]) for rows in labels) or \
                any([line for line in configs[0] if not line.startswith("CONFIG_BASE_DEFCONFIG=")] !=
                    [line for line in value if not line.startswith("CONFIG_BASE_DEFCONFIG=")] for value in configs[1:]):
            raise ValueError("full tmck NuttX profile differs beyond dirty build labels")
        native, upstream = NUTTX_NATIVE, NUTTX_UPSTREAM
    else:
        labels = None
        bindings += [(name, reference / name) for name in ("config", "sdkconfig.h", "k_config.h")]
        bindings += [("Config.in", BASE / "alios/Config.in"), ("examples-Config.in", BASE / "alios/examples-Config.in")]
        board = ROOT / "firmware/bsp/esp32/alios_board"
        bindings += [(name, board / source) for name, source in (("rhino-port-pinned.c", "rhino-port.c"),
            ("rhino-vectors-pinned.S", "rhino-vectors.S"), ("sdkconfig.h", "esp32bench/sdkconfig.h"), ("k_config.h", "esp32bench/k_config.h"))]
        native, upstream = ALIOS_NATIVE, ALIOS_UPSTREAM
    if any((directory / name).read_bytes() != source.read_bytes() for name, source in bindings):
        raise ValueError("full tmck remaining native adapter/profile/source/acquisition differs")
    native_proof_path = ROOT / f"artifacts/reports/rhealstone-{system}-calibrated-v1/official-native-source.json"
    native_proof = json.loads(native_proof_path.read_text())
    expected_native = set(native) | ({ALIOS_ARCHIVE} if system == "alios" else set())
    if {row["path"] for row in native_proof} != expected_native or len(native_proof) != len(expected_native) or any(
            row["url"] != upstream + row["path"] or row["sha256"] != digest(alios_native_path(directory, row["path"]) if system == "alios" else
                directory / "native-source" / row["path"]) for row in native_proof):
        raise ValueError("full tmck remaining fixed native source/archive differs")
    if system == "alios" and (irq_archive_member(alios_native_path(directory, ALIOS_ARCHIVE)) != (directory / "sdk-intr_alloc.o").read_bytes() or
            ALIOS_ARCHIVE not in (directory / "link.opts").read_text() or not re.search(
                r"\.text\.esp_intr_alloc\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*libesp32\.a\(intr_alloc\.o\)", (directory / "application.map").read_text())):
        raise ValueError("full tmck Rhino fixed SDK archive/member linkage differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
        if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    app_sources = ["port.c", "original.c", "tmtests_empty_function.c"]
    required = app_sources + [name for name in native if name.endswith((".c", ".S"))]
    if system == "alios":
        required += ["platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/xtensa_vectors.S"]
    for name in required:
        selected = [args for args in commands if ("app/example/rhealstone/" + name if name in app_sources else name) in args] if system == "alios" else \
            [args for args in commands if any(Path(arg).name == Path(name).name for arg in args if not arg.startswith("-"))]
        if len(selected) != 1 or any(arg.startswith(("-DOPERATION_COUNT", "-DMAXIMUM_DISTRIBUTION", "-DInit", "-DTask_1", "-flto", "-DRHINO_CONFIG_TICKS_PER_SECOND=")) for arg in selected[0]) or \
                (not name.endswith(".S") and [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]) or \
                (system == "alios" and ((not name.endswith(".S") and "-DAOS_NO_WIFI" not in selected[0]) or
                    (name.endswith(".S") and ("-include" not in selected[0] or "out/config/autoconf.h" not in selected[0])))):
            raise ValueError("full tmck remaining original/native actual compile differs: " + name)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    image_length((directory / "bootloader.bin").read_bytes())
    if not (directory / "partitions.bin").read_bytes().startswith(b"\xaa\x50"):
        raise ValueError("full tmck remaining partitions differ")
    flash = (directory / "flash.log").read_text()
    images = (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))
    if flash.count("MAC: 84:1f:e8:8f:55:dc") != 1 or flash.count("Hash of data verified.") != 3 or \
            [(int(n), int(a, 16)) for n, a in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)] != [
                ((directory / name).stat().st_size, address) for name, address in images]:
        raise ValueError("full tmck remaining physical board/image differs")
    frozen = collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text(), system)
    if (directory / "collect-irq-control.py").read_text() != frozen:
        raise ValueError("full tmck remaining frozen collector differs")
    paths = machine_paths(directory, system, {**p, "functions": FUNCTIONS[system]})
    tick = tick_control(directory, system)
    captures = [capture(directory, system, i) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("full tmck remaining independent resets overlap")
    return {"audit": "pass", "scope": p["label"] + " native port of complete original RTEMS Time Checker",
        "original_full_tmck_suite_measured": True, "original_test_body_and_empty_function_unchanged": True,
        "resets": 3, "revision": REVISION, "original_source_files": 6, "native_source_files": len(native),
        "official_prebuilt_sdk_archives": 1 if system == "alios" else 0, "actual_compiled_units_checked": len(required),
        "configured_clock_mhz": 240, "cores": 1, "tick_hz": 100, "compiler": p["compiler"],
        "configuration_build_labels": labels, "original_accepted_samples": 100, "maximum_distribution": 1000,
        "original_empty_function_iterations": list(ITERATIONS[1:]), "unit": "CPU cycles", "captures": captures,
        "machine_paths": paths, "hardware_tick": tick, "raw_mode_requested_by_original": True,
        "average_subtraction_used": False, "measurement_eligible": True, "ranking_eligible": False, "composite_score": None,
        "binary_sha256": digest(directory / "application.bin"), "native_source_proof_sha256": digest(native_proof_path),
        "original_source_proof_sha256": digest(original_proof_path), "installed_flash_bytes": sum((directory / name).stat().st_size for name, _ in images),
        "static_footprint": static_footprint(directory / "application.elf"),
        "boundary": "timer-method validation, not an OS score; original raw mode, no calibrated-mode exercise; compiler/code placement/native priority mapping and console/background differences retained; accepted outliers remain in original histogram; post-endpoint stores can perturb later samples; no ISR/cache attribution, new-image runtime RAM or energy; SDK archive/ROM not source rebuilt"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", choices=tuple(PROFILES))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = json.dumps(audit(args.system), indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
