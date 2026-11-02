#!/usr/bin/env python3
"""Replay the matched peripheral-IRQ cohort, retaining ranking boundaries."""

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from audit_esp32_report import (audit_flash, audit_freertos_no_timeslicing, audit_image_manifest,
                               require_memory_pool_metadata)
from audit_esp32_tm_basic import CASES as ALL_CASES

ROOT = Path(__file__).resolve().parents[1]
CASES = ("interrupt_processing", "interrupt_preemption_processing")
NUTTX_ALIGNED_CASES = ("basic_processing", "preemptive_scheduling", "message_processing",
                       "synchronization_processing", "memory_allocation")
NUTTX_REUSED_CASES = {
    "message_processing": ("esp32-tm-v2/tm-message-selfcheck-nuttx",
                           "esp32-tm-v2/tm-message-selfcheck-nuttx",
                           "esp32-tm-v2/tm-message-selfcheck-nuttx/reset*.jsonl"),
    "synchronization_processing": ("tm-sync-state-build/nuttx",
                                   "tm-sync-power-r3-20261005/nuttx",
                                   "tm-sync-power-r3-20261005/nuttx/reset*/uart.jsonl"),
}
CONFIG_HASHES = {
    "FreeRTOS": "dff62037ee6e0004496fa847f22be71af7ce61009d75ceff233b0784c8206dd2",
    "Zephyr": "c612063e0ed7740d44f1ad1e977e4733f873088a018bfa1ec9645e3f6319e4aa",
    "NuttX": "3e7d1e86e73572aebbaf1b86803edd9a8f5b61f17853246f38b0bfd26c98d255",
}


def audit_image(directory, os, case, require_flash=True, uniform=False):
    cpu2 = case in CASES
    scheduler_control = uniform or (not cpu2 and os == "FreeRTOS")
    if uniform and (os != "FreeRTOS" or case not in ALL_CASES):
        raise ValueError("uniform scheduler cohort supports the eight FreeRTOS cases")
    if not uniform and not cpu2 and not (
            (case == "cooperative_scheduling" and os == "FreeRTOS") or
            (os == "NuttX" and case in ALL_CASES)):
        raise ValueError("unsupported control cohort")
    image = {"FreeRTOS": "iotosbench_tm.elf", "Zephyr": "zephyr.elf", "NuttX": "nuttx"}[os]
    body = f"tm_{case}_test.c"
    required = {image, body, "config", "compiler.txt", "build.log", "port.c", "test.c",
                "tm_override.h", "build_esp32_tm_cooperative_control.sh" if scheduler_control
                else "build_esp32_tm_irq_match.sh"}
    if scheduler_control:
        required |= {"FreeRTOSConfig.h", "FreeRTOSConfig-stock.h", "kernel-config.diff", "kernel-defines.json"}
    required |= {
        "FreeRTOS": {"iotosbench_tm.bin", "bootloader.bin", "partition-table.bin", "main.c",
                     "CMakeLists.txt", "compile_commands.json"},
        "Zephyr": {"zephyr.bin", "main.c", "CMakeLists.txt", "compile_commands.json"},
        "NuttX": {"nuttx.bin", "nuttx.map", "bootloader-esp32.bin", "partition-table-esp32.bin",
                  "iotosbench_main.c", "Makefile"},
    }[os]
    audit_image_manifest(directory, required)
    if hashlib.sha256((directory / "config").read_bytes()).hexdigest() != CONFIG_HASHES[os]:
        raise ValueError(f"{directory}: changed 240-MHz, one-core, 100-Hz reference configuration")
    original = ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / body
    if (directory / body).read_bytes() != original.read_bytes():
        raise ValueError(f"{directory}: changed published original test")
    wrapper = (directory / "test.c").read_text()
    if f'#include "{body}"' not in wrapper or '#pragma GCC optimize("O0")' not in wrapper:
        raise ValueError(f"{directory}: missing original-body include/optimization control")
    if "13.2.0" not in (directory / "compiler.txt").read_text() or \
            b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in (directory / image).read_bytes():
        raise ValueError(f"{directory}: compiler/image provenance mismatch")
    sources = {"main.c", "port.c", "test.c"} if os != "NuttX" else \
              {"iotosbench_main.c", "port.c", "test.c"}
    if os == "NuttX":
        commands = [line for line in (directory / "build.log").read_text().splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc -c ")
                    and any(re.search(r"\s" + re.escape(name) + r"\s+-o\s", line) for name in sources)]
    else:
        application_path = "/idf-freertos-tm-v2/main/" if os == "FreeRTOS" else "/tm-app-v2/src/"
        commands = [row["command"] for row in json.loads((directory / "compile_commands.json").read_text())
                    if application_path in row["file"] and Path(row["file"]).name in sources]
    if len(commands) != 3:
        raise ValueError(f"{directory}: incomplete application compile evidence")
    for command in commands:
        args = shlex.split(command)
        optimizations = [arg for arg in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        flags = {f"-DTM_TEST_{case}=1"}
        if cpu2:
            flags.add("-DTM_IRQ_FROM_CPU2=1")
        if optimizations[-1:] != ["-Os"] or not \
                flags <= set(args):
            raise ValueError(f"{directory}: wrong optimization, test or peripheral IRQ compile flag")
        if uniform and not cpu2 and any(arg.startswith("-DTM_IRQ_FROM_CPU2") for arg in args):
            raise ValueError(f"{directory}: IRQ flag leaked into a non-interrupt test")
        if os == "NuttX" and not cpu2 and any(arg.startswith("-DTM_IRQ_FROM_CPU2") for arg in args):
            raise ValueError(f"{directory}: IRQ flag leaked into a non-interrupt NuttX test")
        if os != "NuttX" and "esp-13.2.0_20230928" not in args[0]:
            raise ValueError(f"{directory}: unexpected application compiler path")
    port = (directory / "port.c").read_text()
    if os == "NuttX" and not cpu2:
        for name in ("port.c", "test.c", "iotosbench_main.c", "tm_override.h", "Makefile"):
            source = ROOT / "firmware/bsp/esp32/nuttx_thread_metric" / name
            if (directory / name).read_bytes() != source.read_bytes():
                raise ValueError(f"{directory}: NuttX adapter {name} differs from maintained source")
        if "pthread_attr_setschedpolicy(&attr, SCHED_FIFO)" not in port or \
                (case == "cooperative_scheduling" and
                 ("cooperative_ready" not in port or "(void)sched_yield();" not in port)):
            raise ValueError(f"{directory}: native FIFO/yield startup contract is not proven")
    if scheduler_control:
        audit_freertos_no_timeslicing(directory, require_preemption="1" if uniform else None)
        if "{ taskYIELD(); }" not in port:
            raise ValueError(f"{directory}: missing native taskYIELD")
        if uniform:
            for name in ("port.c", "main.c", "test.c", "tm_override.h", "CMakeLists.txt"):
                source = ROOT / "firmware/bsp/esp32/freertos_thread_metric/main" / name
                if (directory / name).read_bytes() != source.read_bytes():
                    raise ValueError(f"{directory}: uniform adapter {name} differs from maintained source")
    required_port = {
        "FreeRTOS": ("ETS_FROM_CPU_INTR2_SOURCE == 26", "esp_intr_alloc(source, ESP_INTR_FLAG_LEVEL1",
                     "xPortInIsrContext()", "DPORT_REG_WRITE(DPORT_CPU_INTR_FROM_CPU_2_REG"),
        "Zephyr": ("FROM_CPU_INTR2_SOURCE == 26", "esp_intr_alloc(FROM_CPU_INTR2_SOURCE, ESP_INTR_FLAG_LEVEL1",
                   "k_is_in_isr()", "DPORT_REG_WRITE(DPORT_CPU_INTR_FROM_CPU_2_REG"),
        "NuttX": ("ESP32_PERIPH_CPU_CPU2 == 26", "esp32_setup_irq(0, ESP32_PERIPH_CPU_CPU2, 1, ESP32_CPUINT_LEVEL)",
                  "up_interrupt_context()", "irq_attach(ESP32_IRQ_CPU_CPU2, software_isr"),
    }[os]
    if cpu2 and (any(token not in port for token in required_port) or \
            "if (!irq_context_checked)" not in port or "entered outside ISR" not in port):
        raise ValueError(f"{directory}: native IRQ source/level/context guard not proven")
    if require_flash:
        audit_flash(directory, "flash.log", 1 if os == "Zephyr" else 3)
    return hashlib.sha256((directory / image).read_bytes()).hexdigest()


def audit_cohort(directory, os, case, uniform=False, reuse_identical_image=False):
    if reuse_identical_image and (os != "NuttX" or case not in NUTTX_REUSED_CASES or uniform):
        raise ValueError("only the declared identical NuttX images can reuse historical captures")
    image_hash = audit_image(directory, os, case, uniform=uniform,
                             require_flash=not reuse_identical_image)
    if reuse_identical_image:
        evidence = ROOT / "artifacts/reports"
        image_folder, flash_folder, pattern = NUTTX_REUSED_CASES[case]
        original = evidence / image_folder
        for name in ("nuttx", "nuttx.bin"):
            if (directory / name).read_bytes() != (original / name).read_bytes():
                raise ValueError(f"{directory}: rebuilt {name} differs from the measured image")
        if case == "synchronization_processing":
            if (original / "image.sha256").read_bytes() != (evidence / flash_folder / "image.sha256").read_bytes():
                raise ValueError("synchronization capture manifest differs from the preserved build")
            audit_image_manifest(original, {"nuttx", "nuttx.bin", "config",
                                            "bootloader-esp32.bin", "partition-table-esp32.bin"})
            for name in ("config", "bootloader-esp32.bin", "partition-table-esp32.bin"):
                if (directory / name).read_bytes() != (original / name).read_bytes():
                    raise ValueError(f"{directory}: rebuilt {name} differs from the measured configuration")
        audit_flash(evidence / flash_folder, "flash.log", 3)
        paths = sorted(evidence.glob(pattern))
    else:
        paths = sorted(directory.glob("reset*.jsonl"))
    if len(paths) != 3:
        raise ValueError(f"{directory}: expected exactly three independent resets")
    extra = ["--require-cpu2-interrupt"] if case in CASES else []
    if uniform and case in ("message_processing", "synchronization_processing", "memory_allocation"):
        kind = {"message_processing": "queue", "synchronization_processing": "semaphore",
                "memory_allocation": "memory"}[case]
        extra.append(f"--require-{kind}-self-check")
    elif os == "NuttX" and case in ("message_processing", "synchronization_processing"):
        kind = "queue" if case == "message_processing" else "semaphore"
        extra.append(f"--require-{kind}-self-check")
    result = json.loads(subprocess.check_output([
        sys.executable, str(ROOT / "tools/audit_esp32_tm_reboots.py"), os, case,
        *extra, *map(str, paths),
    ], text=True))
    previous_end = None
    for path in paths:
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        if uniform and case == "memory_allocation":
            require_memory_pool_metadata(raw)
        start = datetime.fromisoformat(raw[0]["utc"])
        end = datetime.fromisoformat(raw[-1]["utc"])
        if start.utcoffset() is None or end.utcoffset() is None or end <= start or \
                (previous_end is not None and start <= previous_end):
            raise ValueError(f"{path}: overlapping reset captures or missing timezone evidence")
        previous_end = end
    result["elf_sha256"] = image_hash
    if reuse_identical_image:
        result["image_binding"] = "rebuilt ELF and BIN byte-identical to the preserved measured image"
        result["reused_capture_pattern"] = pattern
    if case in CASES:
        result["interrupt_source"] = "CPU_FROM_CPU2 peripheral=26 level=1"
    if uniform or (case not in CASES and os == "FreeRTOS"):
        preemption = "1" if "#define configUSE_PREEMPTION                         1" in \
            (directory / "FreeRTOSConfig.h").read_text() else "0"
        result["scheduler"] = f"preemption={preemption}/time-slicing=0; native taskYIELD"
    elif os == "NuttX" and case not in CASES:
        result["scheduler"] = "SCHED_FIFO" + ("; native sched_yield" if case == "cooperative_scheduling" else "")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--images-only", action="store_true")
    parser.add_argument("--cooperative-control", action="store_true")
    parser.add_argument("--cooperative-mode", action="store_true")
    parser.add_argument("--freertos-uniform", action="store_true")
    parser.add_argument("--nuttx-cooperative", action="store_true")
    parser.add_argument("--nuttx-aligned", action="store_true")
    args = parser.parse_args()
    if args.cooperative_mode:
        args.cooperative_control = True
    if args.freertos_uniform and args.cooperative_control:
        parser.error("select either the uniform eight-case cohort or a cooperative control")
    if (args.nuttx_aligned and args.nuttx_cooperative) or \
            ((args.nuttx_cooperative or args.nuttx_aligned) and (args.freertos_uniform or args.cooperative_control)):
        parser.error("select each NuttX cohort separately")
    if args.root is None:
        cohort = "tm-nuttx-native-aligned-v1" if args.nuttx_aligned else \
                 "tm-cooperative-native-nuttx-v1" if args.nuttx_cooperative else \
                 "tm-freertos-native-aligned-v1" if args.freertos_uniform else \
                 "tm-cooperative-mode-v1" if args.cooperative_mode else \
                 "tm-cooperative-no-timeslicing-v1" if args.cooperative_control else "tm-irq-cpu2-v1"
        args.root = ROOT / "artifacts/reports" / cohort
    results = []
    baseline = args.root / "basic_processing"
    for os in ("NuttX",) if args.nuttx_cooperative or args.nuttx_aligned else \
            ("FreeRTOS",) if args.cooperative_control or args.freertos_uniform else CONFIG_HASHES:
        for case in NUTTX_ALIGNED_CASES if args.nuttx_aligned else ALL_CASES if args.freertos_uniform else \
                ("cooperative_scheduling",) if args.cooperative_control or args.nuttx_cooperative else CASES:
            directory = args.root / case if args.freertos_uniform or args.nuttx_aligned else \
                        args.root if args.cooperative_control or args.nuttx_cooperative else args.root / os.lower() / case
            if args.freertos_uniform:
                for name in ("config", "FreeRTOSConfig.h", "port.c", "main.c", "test.c", "tm_override.h"):
                    if (directory / name).read_bytes() != (baseline / name).read_bytes():
                        raise ValueError(f"{directory}: {name} differs between uniform cases")
            if args.nuttx_aligned:
                reference = ROOT / "artifacts/reports/tm-cooperative-native-nuttx-v1"
                for name in ("config", "port.c", "test.c", "tm_override.h", "iotosbench_main.c", "Makefile"):
                    if (directory / name).read_bytes() != (reference / name).read_bytes():
                        raise ValueError(f"{directory}: {name} differs from the measured native NuttX profile")
            if args.images_only:
                results.append({"os": os, "case": case,
                                "elf_sha256": audit_image(directory, os, case, require_flash=False,
                                                          uniform=args.freertos_uniform)})
            else:
                results.append(audit_cohort(directory, os, case, uniform=args.freertos_uniform,
                                           reuse_identical_image=args.nuttx_aligned and case in NUTTX_REUSED_CASES))
    print(json.dumps({"audit": "images_only_pass" if args.images_only else "pass",
                      "ranking_eligible": False, "results": results}, indent=2))
