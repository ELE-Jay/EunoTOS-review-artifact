#!/usr/bin/env python3
"""Verify a full GCC13 source build with the pinned SDK's legacy C library."""
import argparse
import json
from pathlib import Path
import re
import shlex
import statistics
from elftools.elf.elffile import ELFFile

from audit_esp32_alios_tm import check_conditions, check_native_port
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_report import audit_image_manifest
from audit_esp32_resources import audit_elf_image
from audit_esp32_tm_basic import audit as original
from audit_esp32_tm_reboots import require_self_check
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "artifacts/reports/alios-native-gcc5-v2/message_processing"


def build(folder, case="message_processing"):
    audit_image_manifest(folder, {"application.elf", "application.bin", "config", "compiler.txt", "build.log"})
    if "13.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("Wrong rebuilt compiler")
    baseline = (ROOT / "artifacts/reports/alios-tm-irq-vector-v1" / case if case in
                ("interrupt_processing", "interrupt_preemption_processing") else BASELINE.parent / case)
    for name in ("main.c", "port.c", "test.c", "tm_override.h", "tm_" + case + "_test.c",
                 "sdkconfig.h", "k_config.h", "app-aos.mk", "espos_time.c"):
        if (folder / name).read_bytes() != (baseline / name).read_bytes():
            raise ValueError("Declared compiler control changed workload/profile: " + name)
    native_port = check_native_port(folder, gcc13_noop=True)
    required = {"app/example/thread_metric/main.c", "app/example/thread_metric/port.c", "app/example/thread_metric/test.c",
        "kernel/rhino/k_sched.c", "kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_queue.c",
        "kernel/rhino/k_buf_queue.c", "kernel/rhino/k_mm.c", "platform/arch/xtensa/lx6/port.c"}
    found, compiled_units = set(), 0
    for line in (folder / "build.log").read_text().splitlines():
        if " -c " not in line:
            continue
        args = shlex.split(line)
        if not args or Path(args[0]).name != "xtensa-esp32-elf-gcc":
            continue
        if "iotos-rhino-gcc13-legacy-tools" not in args[0]:
            raise ValueError("A source unit used a different compiler route")
        compiled_units += 1
        for source in required & set(args):
            if source in found or "iotos-rhino-gcc13-legacy-tools" not in args[0] or \
                    [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                    [a for a in args if a.startswith("-DTM_TEST_")] != ["-DTM_TEST_" + case + "=1"]:
                raise ValueError("Rebuilt source/compiler/original selection differs")
            found.add(source)
    if found != required:
        raise ValueError("Incomplete native SDK source build: " + str(required - found))
    compatibility = folder / "compiler-compatibility"
    abi = json.loads((compatibility / "abi.json").read_text())
    wrapper = "xtensa-esp32-elf-gcc-legacy-newlib.sh"
    if abi["abi_size_checks"] != "pass" or abi["board_resets"] or abi["ranking_eligible"] or \
            sha(compatibility / wrapper) != abi["wrapper_sha256"] or \
            (compatibility / wrapper).read_bytes() != (ROOT / "firmware/bsp/esp32/alios_board" / wrapper).read_bytes():
        raise ValueError("Legacy ABI compiler route differs")
    for name, digest in abi["legacy_header_sha256"].items():
        if sha(compatibility / "legacy-headers" / name) != digest:
            raise ValueError("Retained ABI header changed")
    sizes = []
    for item in abi["probes"]:
        obj = compatibility / (item["compiler"] + ".o")
        if sha(obj) != item["object_sha256"]:
            raise ValueError("ABI object changed")
        with obj.open("rb") as stream:
            fields = {s.name:s["st_size"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols() if s.name.startswith("abi_")}
        if fields != item["sizes"]:
            raise ValueError("Compiled public C ABI sizes differ")
        sizes.append(fields)
    if len(sizes) != 2 or sizes[0] != sizes[1] or len(sizes[0]) != 5:
        raise ValueError("Incomplete public C ABI comparison")
    link_map = (folder / "thread_metric@esp32bench.map").read_text()
    if "platform/mcu/esp32//libc.a" not in link_map or "legacy-tools" not in (folder / "build.log").read_text():
        raise ValueError("Pinned SDK libc/link route missing")
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    return {"status": "build_pass_not_measured", "compiler": "GCC13.2 with original GCC5-toolchain newlib headers and pinned SDK libc",
        "full_sdk_source_build_linked": True, "native_source_units_checked": len(found), "native_port": native_port,
        "source_compiled_units": compiled_units, "public_c_abi_sizes": sizes[0],
        "board_resets": 0, "ranking_eligible": False, "energy_measured": False,
        "source_body_unchanged": True, "case": case,
        "images": {name: sha(folder / name) for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin")},
        "boundary": "source-built native units use GCC13; proprietary/precompiled SDK and libc remain legacy, not an all-GCC13 SDK"}


def audit(folder, source):
    campaign = envelope(folder)
    proof = build(source)
    if campaign["kind"] != "message" or campaign["board_mac"] != "34:98:7a:a2:85:28":
        raise ValueError("Wrong native candidate capture/board")
    for name, digest in proof["images"].items():
        if sha(folder / "build" / name) != digest:
            raise ValueError("Measured native image differs from rebuilt candidate")
    verified(folder / "captures", folder / "build", campaign["board_mac"])
    counts = []
    for i, rows in enumerate(independent_captures(folder / "captures"), 1):
        check_conditions(rows)
        require_self_check(rows, "queue")
        counts.append(original(folder / "captures" / ("reset%d.jsonl" % i), "AliOS-Rhino", "message_processing")["original_window_totals"][0])
    return {"audit": "pass", "board": "B1", "board_mac": campaign["board_mac"], "build": proof,
        "independent_resets": 3, "case": "message_processing", "values": counts, "median": statistics.median(counts),
        "unit": "count/30s", "full_legacy_sdk_boot_verified": True, "ranking_eligible": False,
        "comparison_pending": "review same-board original queue path, remaining background tasks and legacy library boundary before main-cohort admission",
        "energy_measured": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--case", default="message_processing")
    args = parser.parse_args()
    result = audit(args.campaign, args.source) if args.campaign else build(args.source, args.case)
    (args.campaign or args.source).joinpath("audit.json" if args.campaign else "build.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
