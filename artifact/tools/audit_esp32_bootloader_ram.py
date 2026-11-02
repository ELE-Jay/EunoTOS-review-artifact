#!/usr/bin/env python3
"""Bind native boot hooks, unchanged application and physical reset observations."""
import argparse
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from audit_esp32_resources import audit_elf_image, static_footprint
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_freertos_startup_stack import verify_trampoline
from measure_esp32_bootloader_ram import MAC, OBSERVER, REFERENCE, observations
from run_esp32_followup import read_raw_capture, sha, verified

ROOT = Path(__file__).resolve().parents[1]


def build(source):
    manifest = json.loads((source / "build.json").read_text())
    if manifest["status"] != "build_pass_not_measured" or manifest["reference"] != REFERENCE or \
            manifest["application_rebuilt"] or manifest["whole_live_ram_peak_measured"] or manifest["ranking_eligible"]:
        raise ValueError("Invalid boot-stage build qualification")
    for name, digest in manifest["files"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source.resolve()) or sha(path) != digest:
            raise ValueError("Boot build source/image changed: " + name)
    reference = ROOT / "artifacts/reports" / REFERENCE
    for name in ("application.elf", "application.bin", "partitions.bin", "config"):
        if (source / name).read_bytes() != (reference / name).read_bytes():
            raise ValueError("Original measured application/configuration changed: " + name)
    if manifest["application_sha256"] != sha(reference / "application.bin"):
        raise ValueError("Application binding differs")
    for name in ("CMakeLists.txt", "entry.S", "observe.c"):
        expected=(ROOT / OBSERVER / name).read_bytes()
        if manifest.get('legacy_rtc_wdt_handoff'):
            from measure_esp32_bootloader_ram import watchdog_observer
            if name=='observe.c':expected=watchdog_observer(expected.decode()).encode()
            elif name=='CMakeLists.txt':expected=expected.replace(
                b'idf_component_register(SRCS "observe.c" "entry.S")',
                b'idf_component_register(SRCS "observe.c" "entry.S" PRIV_REQUIRES hal)')
        if (source / "observer" / name).read_bytes() != expected:
            raise ValueError("Unreviewed boot observer")
    if manifest.get('legacy_rtc_wdt_handoff') and (source/'observer/rhino_watchdog.inc').read_bytes()!= \
            (ROOT/OBSERVER/'rhino_watchdog.inc').read_bytes():
        raise ValueError('Legacy RTC watchdog handoff implementation differs')
    pinned = ROOT / "artifacts/reports/esp32-bootloader-memory-v1/source/sdk"
    for path in (source / "source/sdk").rglob("*"):
        if path.is_file():
            old = pinned / path.relative_to(source / "source/sdk")
            if old.is_file() and path.read_bytes() != old.read_bytes():
                raise ValueError("Native boot source differs from measured pinned SDK")
    compiled = json.loads((source / "compile_commands.json").read_text())
    old_compiled = json.loads((pinned.parent / "build/compile_commands.json").read_text())
    native_units = lambda units: {Path(u["file"]).as_posix().split("/esp-idf-v5.2.5/", 1)[1]
                                  for u in units if "/esp-idf-v5.2.5/" in Path(u["file"]).as_posix()}
    if native_units(compiled) != native_units(old_compiled):
        raise ValueError("Native boot compilation unit set changed")
    for unit in compiled:
        name = Path(unit["file"]).as_posix()
        if manifest.get('legacy_rtc_wdt_handoff') and '/esp-idf-v5.2.5/' not in name and '/work/' not in name:
            relative=[n for n in ('build/project_elf_src_esp32.c',
                'project/bootloader_components/boot_ram/entry.S','project/bootloader_components/boot_ram/observe.c')
                if name.endswith('/'+n)]
            if len(relative)!=1 or not (source/'source/work'/relative[0]).is_file():
                raise ValueError('Unmapped compiled legacy handoff observer source')
            continue
        marker = "/esp-idf-v5.2.5/" if "/esp-idf-v5.2.5/" in name else "/work/"
        if marker not in name:
            raise ValueError("Unmapped compiled boot source")
        prefix = "sdk" if marker.startswith("/esp-idf") else "work"
        if not (source / "source" / prefix / name.split(marker, 1)[1]).is_file():
            raise ValueError("Missing compiled boot source")
    audit_elf_image(source / "bootloader.elf", source / "bootloader.bin")
    with (source / "bootloader.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        state = symbols.get_symbol_by_name("bench_boot_state")[0]
        section = elf.get_section(state["st_shndx"])
        if state["st_size"] != 40 or section["sh_type"] != "SHT_PROGBITS" or \
                struct.unpack_from("<I", section.data(), state["st_value"]-section["sh_addr"])[0] != 0x424c5331:
            raise ValueError("Pre-BSS observation state is not initialized data")
        entry = symbols.get_symbol_by_name("bench_boot_entry")[0]["st_value"]
        if elf["e_entry"] != entry or struct.unpack_from("<I", (source / "bootloader.bin").read_bytes(), 4)[0] != entry:
            raise ValueError("Installed boot entry differs")
        verify_trampoline(elf, symbols, (source / "disassembly.txt").read_text(), "bench_boot_entry",
            [state["st_value"], 0x3ffe0440, 0x3ffe3f20, 0xa5a5a5a5, 0x424c5331], "call_start_cpu0")
        for name in ("observe", "bootloader_after_init", "__wrap_bootloader_console_deinit"):
            symbol = symbols.get_symbol_by_name(name)[0]
            if not 0x40078000 <= symbol["st_value"] < 0x40080000:
                raise ValueError("Boot observer cannot survive application IRAM loading")
    edges = [("call_start_cpu0", "bootloader_after_init"), ("bootloader_after_init", "observe"),
        ("load_image", "__wrap_bootloader_console_deinit"),
        ("__wrap_bootloader_console_deinit", "observe"), ("__wrap_bootloader_console_deinit", "bootloader_console_deinit")]
    if manifest.get('legacy_rtc_wdt_handoff'):
        edges += [('__wrap_bootloader_console_deinit','rhino_watchdog_handoff'),
            ('rhino_watchdog_handoff','wdt_hal_write_protect_disable'),
            ('rhino_watchdog_handoff','wdt_hal_disable'),('rhino_watchdog_handoff','wdt_hal_write_protect_enable')]
    machine = calls(source, edges, require_iram=False, elf_name="bootloader.elf")
    native = (source / "source/sdk/components/bootloader_support/src/bootloader_utility.c").read_text()
    if "bootloader_atexit();" not in native or "(*entry)();" not in native:
        raise ValueError("Native post-observer transfer missing")
    return {"audit": "pass", "compiled_translation_units": len(compiled),
        **({'legacy_rtc_wdt_handoff':True} if manifest.get('legacy_rtc_wdt_handoff') else {}),
        "application_sha256": sha(source / "application.bin"), "application_rebuilt": False,
        "bootloader_sha256": sha(source / "bootloader.bin"), "entry_address": entry,
        "machine_calls": machine, "bootloader_static": static_footprint(source / "bootloader.elf"),
        "application_static": static_footprint(source / "application.elf"),
        "scope": "marked stack from second-stage entry through console-deinit entry; includes observer frames, excludes ROM-first-stage and final transfer"}


def audit(folder, source):
    from audit_esp32_followup import envelope, independent_captures
    from run_esp32_tm_ram_lifetimes import build_proof, read_run
    campaign = envelope(folder)
    proof = build(source)
    plan = json.loads((folder / "plan.json").read_text())
    if campaign["mode"] != "boot-stage-ram" or campaign["board_mac"] != MAC or campaign["independent_resets"] != 5 or \
            plan["resets"] != 5 or plan["seconds"] != 100 or plan["build_manifest_sha256"] != sha(source / "build.json"):
        raise ValueError("Incomplete or changed boot-stage campaign")
    for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin"):
        if (folder / "build" / name).read_bytes() != (source / name).read_bytes():
            raise ValueError("Collected image differs")
    verified(folder / "captures", folder / "build", MAC)
    captures = independent_captures(folder / "captures", range(1, 6))
    app_proof = build_proof(ROOT / "artifacts/reports" / REFERENCE)
    runs = []
    for index, rows in enumerate(captures, 1):
        verified(folder / "captures", folder / "build", MAC, logs=("verify-run%d.log" % index,))
        lines = [row["line"] for row in rows]
        boot = observations(lines)
        if lines.index(next(s for s in lines if s.startswith("BOOT_RAM phase=1 "))) >= \
                lines.index(next(s for s in lines if s.startswith("TM_RAM BEGIN"))):
            raise ValueError("Boot measurement does not precede application benchmark")
        runs.append({"boot_stages": boot, "original_message": read_run(folder / "captures", index, app_proof)})
    from replay_esp32_bootloader_ram import replay
    separate = replay(folder)
    for run, independent in zip(runs, separate["runs"], strict=True):
        original = run["original_message"]
        if run["boot_stages"] != independent["boot_stages"] or any(original[k] != independent[k]
                for k in ("events", "heap_peak_bytes", "heap_final_bytes")) or \
                original["original_message"]["original_window_totals"] != independent["original_counts"]:
            raise ValueError("Separate boot-stage/heap/count byte replay differs")
    return {"audit": "pass", "board_mac": MAC, "independent_resets": 5, "runs": runs, "build": proof,
        "independent_stdlib_replay": True,
        "original_flash_restored": True, "application_binary_unchanged": True,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "remaining": ["first-stage ROM", "final bootloader-to-application transfer", "continuous simultaneous live stacks and unmanaged occupancy"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.campaign, args.source) if args.campaign else build(args.source)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps({k: result[k] for k in ("audit", "independent_resets", "independent_stdlib_replay",
            "original_flash_restored", "whole_live_ram_peak_bytes", "ranking_eligible") if k in result}))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
