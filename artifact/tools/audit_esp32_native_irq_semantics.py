#!/usr/bin/env python3
"""Bind B1 native Thread-Metric IRQ counts to real interrupt dispatch paths."""
import json
from pathlib import Path
import re
import shlex
import argparse
from urllib.request import urlopen
import hashlib

from audit_esp32_native_suite_builds import audit_campaign
from audit_esp32_alios_tm_irq import native_calls
from audit_esp32_zephyr_isr import native_dispatch_binding
from audit_esp32_rhealstone_irq_riot import source_urls
from audit_esp32_riot_original import UPSTREAM
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
DESTINATION = REPORTS / "esp32-native-irq-semantics-b1-v1"
CONTEXT = "cpu/esp_common/vendor/xtensa/xtensa_context.S"


def audit():
    source = REPORTS / "esp32-native-irq-suite-b1-v1"
    measured = audit_campaign(source)
    if measured != json.loads((source / "audit.json").read_text()):
        raise ValueError("Native IRQ original/source/runtime replay differs")
    cells = []
    native = ("core/thread.c", "core/sched.c", "cpu/esp32/irq_arch.c",
              "cpu/esp_common/vendor/xtensa/portasm.S", "cpu/esp_common/vendor/xtensa/xtensa_vectors.S")
    pinned = REPORTS / "rhealstone-irq-riot-v3"
    registry = {r["path"]: r for r in json.loads((pinned / "official-native-source.json").read_text())}
    for name in native:
        if registry[name]["url"] != source_urls()[name] or \
                sha(DESTINATION / "native-source" / name) != registry[name]["sha256"] or \
                sha(pinned / "native-source" / name) != registry[name]["sha256"]:
            raise ValueError("RIOT native IRQ source differs from retained fixed official source")
    context = json.loads((DESTINATION / "official-context-source.json").read_text())
    if context["url"] != UPSTREAM + CONTEXT or context["sha256"] != sha(DESTINATION / "native-source" / CONTEXT):
        raise ValueError("RIOT full-context source provenance differs")
    registry[CONTEXT] = context
    native += (CONTEXT,)
    for cell in measured["cells"]:
        system, case = cell["os"], cell["case"]
        build = REPORTS / ("esp32-riot-gcc13-suite-build-v1" if system == "RIOT" else
                           "esp32-rhino-gcc13-suite-build-v1") / case
        if system == "RIOT":
            machine = DESTINATION / case
            if sha(machine / "application.elf") != sha(build / "application.elf"):
                raise ValueError("RIOT IRQ decoding belongs to a different measured image")
            commands = [shlex.split(line) for line in (build / "build.log").read_text().replace("\\\n", " ").splitlines()
                        if "gcc13-legacy-newlib.sh " in line and " -c " in line]
            for name in native:
                selected = [a for a in commands if any(v.endswith("/RIOT-2024.10-devel/" + name) for v in a)]
                if len(selected) != 1 or "-DTM_TEST_" + case + "=1" not in selected[0] or \
                        [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"]:
                    raise ValueError("Native IRQ source compilation/profile missing: " + name)
            proof = native_dispatch_binding(machine, thread_metric=True)
            expected = "tm_interrupt_preemption_handler" if "preemption" in case else "tm_interrupt_handler"
            if proof["callback"] != expected:
                raise ValueError("Wrong original IRQ callback")
            proof["disassembly_sha256"] = sha(machine / "disassembly.txt")
            proof["native_source_sha256"] = {n: registry[n]["sha256"] for n in native}
            profile = "240 MHz / one core / native tickless / GCC13 with GCC12 newlib"
        else:
            proof = native_calls(build, case, gcc13_blocks=True)
            profile = "240 MHz / one core / 100 Hz / GCC13 with legacy SDK libc"
        cells.append({"os": system, "case": case, "profile": profile,
            "elf_sha256": sha(build / "application.elf"), "machine": proof,
            "values": cell["values"], "unit": "count/30s", "independent_resets": 3,
            "hardware_source": "CPU_FROM_CPU2 / peripheral 26 / level 1",
            "original_runtime_checks": "three original 30/60/90 reports per reset; ISR-context guard; no original error output",
            "meaning": "repeated hardware interrupt callback" if case == "interrupt_processing" else
                       "ISR resumes priority-3 worker from priority-10 generator; native exit dispatch and worker self-suspension",
            "interrupt_entry_latency_measured": False, "external_gpio_irq_measured": False,
            "ranking_eligible": False})
    return {"audit": "pass", "board": "B1", "cells": cells, "independent_resets": 12,
        "new_board_measurements": False, "energy_measured": False,
        "boundary": "source/ELF/runtime semantic audit of existing native throughput captures; not a latency experiment or 100 Hz cross-OS admission"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream-context", action="store_true")
    args = parser.parse_args()
    if args.verify_upstream_context:
        with urlopen(UPSTREAM + CONTEXT, timeout=60) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        if digest != sha(DESTINATION / "native-source" / CONTEXT):
            raise ValueError("Actual full-context source differs from fixed official version")
        (DESTINATION / "official-context-source.json").write_text(json.dumps(
            {"path": CONTEXT, "url": UPSTREAM + CONTEXT, "sha256": digest}, indent=2) + "\n")
    result = audit()
    (DESTINATION / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "cells"}))
