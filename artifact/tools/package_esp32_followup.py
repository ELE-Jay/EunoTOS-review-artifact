#!/usr/bin/env python3
"""Package retained evidence and replay tools without private Flash backups."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from run_esp32_followup import CANDIDATES
from run_esp32_b1_message import CASES, sources
from run_esp32_b1_kernel_energy import BASELINES as ENERGY_CASES
from audit_sensys_runtime_tables import HARTSTONE_PH3_SOURCES

DESTINATION = ROOT / "reproduction/esp32-followup-20261019"
REPORTS = ["esp32-irq-ablation-v1", "esp32-irq-ablation-v2", "esp32-irq-ablation-capture-b1-v1",
           "esp32-original-followup-b1-v1", "esp32-original-followup-b1-v2", "esp32-original-followup-b1-v3",
           "riot-yield-zephyr-v1", "riot-yield-zephyr-v2",
           "alios-native-gcc5-v2/basic_processing",
           "zephyr-yield-freertos-v1", "zephyr-yield-nuttx-v1",
           "esp32-message-cohort-b1-v1", "tm-freertos-native-aligned-v1/message_processing",
           "zephyr-gcc13-align/message_processing", "tm-nuttx-native-aligned-v1/message_processing"] + [n for _, _, n in CANDIDATES]
REPORTS += sorted({directory for case in CASES for directory, _ in sources(case).values()})
REPORTS += ["esp32-tm-alignment-v1", "esp32-rhino-gcc13-legacy-v1", "esp32-rhino-gcc13-b1-v1",
            "alios-native-gcc5-v2/message_processing", "esp32-riot-startup-probe-build-v1",
            "esp32-riot-startup-probe-b1-v1", "esp32-riot-gcc13-legacy-v1", "esp32-nuttx-heap-events-v1",
            "esp32-latency-semantics-v1.json", "zephyr-latency-freertos-v2", "zephyr-latency-nuttx-v2",
            "zephyr-original-v1/latency_measure",
            "esp32-network-controlled-idf-v1", "esp32-network-controlled-zephyr-v1", "esp32-network-controlled-nuttx-v2",
            "iperf-original-v1/official-source.json", "zperf-original-v3/official-source.json",
            "nuttx-iperf-original-v5/official-source.json"]
REPORTS += ["esp32-isr-semantics-v1.json", "zephyr-isr-freertos-v1", "zephyr-isr-nuttx-v3"]
REPORTS += ["esp32-riot-gcc13-suite-build-v1", "esp32-rhino-gcc13-suite-build-v1",
            "esp32-native-suite-builds-v1.json", "esp32-usb-interruption-v1",
            "alios-native-gcc5-v2", "alios-tm-irq-vector-v1", "esp32-nuttx-decimal-format-v1"]
REPORTS += ["esp32-native-irq-semantics-b1-v1", "esp32-nuttx-stack-lifetimes-v2"]
REPORTS += ["esp32-nuttx-task-cleanup-v1", "esp32-nuttx-task-cleanup-v2"]
REPORTS += ["esp32-nuttx-retained-owners-v1"]
REPORTS += ["rhealstone-irq-riot-v3/official-native-source.json", "rhealstone-irq-riot-v3/native-source"]
REPORTS += ["esp32-freertos-lifetimes-v4", "hartstone-native-us-fifo-v1/freertos/ph4"]
REPORTS += ["esp32-zephyr-lifetimes-v4", "hartstone-native-us-v1/zephyr/ph4"]
REPORTS += ["esp32-riot-lifetimes-v7", "hartstone-riot-native-v4/ph4"]
REPORTS += ["esp32-rhino-lifetimes-v2", "esp32-rhino-lifetimes-v3", "esp32-rhino-lifetimes-b1-v1", "hartstone-alios-native-v4/ph4"]
REPORTS += ["esp32-rhino-lifetimes-v4", "esp32-rhino-lifetimes-b1-v2"]
REPORTS += ["esp32-riot-native-message-v3"]
REPORTS += ["riot-original-v1/msg_pingpong"]
REPORTS += ["riot-msg-nuttx-v1", "esp32-riot-msg-nuttx-b1-v1"]
REPORTS += ["riot-msg-alios-v1", "riot-msg-alios-v2", "esp32-riot-msg-alios-b1-v1", "esp32-riot-msg-alios-b1-v2",
            "esp32-rhino-message-startup-build-v1", "esp32-rhino-message-startup-b1-v1", "esp32-original-followup-b1-v4"]
REPORTS += ["riot-yield-alios-v1"]
REPORTS += ["esp32-rhino-stack-coverage-v1", "esp32-rhino-stack-coverage-b1-v1", "esp32-rhino-stack-coverage-b1-v2"]
REPORTS += ["esp32-energy-reuse-20261021-v1", "esp32-powerz-readiness-20261021-v1"]
REPORTS += ["esp32-freertos-stack-coverage-v1","esp32-freertos-stack-coverage-b1-v1","esp32-powerz-readiness-20261021-v2"]
REPORTS += ["esp32-riot-stack-coverage-v1","esp32-riot-stack-coverage-b1-v1"]
REPORTS += ["esp32-zephyr-stack-coverage-v1","esp32-zephyr-stack-coverage-b1-v1","esp32-ram-scope-v1.json"]
REPORTS += ["esp32-kernel-energy-reuse-v1"]
REPORTS += [
    "esp32-freertos-message-lifetimes-v1", "esp32-freertos-message-lifetimes-b1-v1",
    "esp32-freertos-message-lifetimes-b1-v2", "esp32-freertos-message-lifetimes-b1-v3",
    "esp32-zephyr-message-lifetimes-v4", "esp32-zephyr-message-lifetimes-b1-v1",
    "esp32-nuttx-message-lifetimes-v2", "esp32-nuttx-message-lifetimes-b1-v2",
    "esp32-message-ram-lifetimes-cohort-v1.json", "zephyr-message-listener-source.json",
    "esp32-message-observer-pairs-b1-v1", "esp32-nuttx-message-identities-v1",
    "esp32-nuttx-message-identities-b1-v1", "esp32-nuttx-address-observer-pairs-b1-v1",
    "esp32-zephyr-message-stack-v1", "esp32-zephyr-message-stack-b1-v1",
    "esp32-zephyr-stack-observer-pairs-b1-v1", "esp32-freertos-message-stack-v1",
    "esp32-freertos-message-stack-b1-v1", "esp32-freertos-stack-observer-pairs-b1-v1",
    "esp32-freertos-message-startup-v1", "esp32-freertos-message-startup-b1-v1",
    "esp32-freertos-startup-observer-pairs-b1-v1", "esp32-freertos-message-startup-replay-v1.json",
    "esp32-freertos-startup-observer-pairs-replay-v1.json",
    "esp32-freertos-message-tick-stacks-v1", "esp32-freertos-message-tick-stacks-b1-v1",
    "esp32-freertos-message-tick-stacks-replay-v1.json", "esp32-freertos-tick-observer-pairs-b1-v1",
    "esp32-freertos-tick-observer-pairs-replay-v1.json",
    "esp32-zephyr-message-tick-stacks-v3", "esp32-zephyr-message-tick-stacks-b1-v1",
    "esp32-zephyr-message-tick-stacks-replay-v1.json", "esp32-zephyr-tick-observer-pairs-b1-v1",
    "esp32-zephyr-tick-observer-pairs-replay-v1.json", "zephyr-tick-source-v1.json",
    "esp32-nuttx-message-tick-stacks-v2", "esp32-nuttx-message-tick-stacks-b1-v2",
    "esp32-nuttx-message-tick-stacks-replay-v1.json", "esp32-nuttx-tick-observer-pairs-b1-v1",
    "esp32-nuttx-tick-observer-pairs-replay-v1.json", "nuttx-tick-source-v1.json",
    "esp32-message-tick-coverage-v1.json",
    "esp32-nuttx-message-tick-control-v1", "esp32-nuttx-tick-control-b1-v1",
    "esp32-nuttx-tick-control-replay-v1.json",
    "esp32-nuttx-message-tick-control-census-b1-v1", "esp32-nuttx-tick-control-census-replay-v1.json",
    "esp32-nuttx-tick-control-observer-pairs-b1-v1", "esp32-nuttx-tick-control-pairs-replay-v1.json",
    "esp32-message-tick-coverage-v2.json",
    "esp32-workbook-sync-v1",
    "esp32-nuttx-message-startup-v5", "esp32-nuttx-message-startup-b1-v1",
    "esp32-nuttx-startup-observer-pairs-b1-v1", "esp32-nuttx-message-startup-replay-v1.json",
    "esp32-nuttx-startup-observer-pairs-replay-v1.json",
    "esp32-zephyr-message-startup-v2", "esp32-zephyr-message-startup-b1-v1",
    "esp32-zephyr-startup-observer-pairs-b1-v1", "esp32-zephyr-message-startup-replay-v1.json",
    "esp32-zephyr-startup-observer-pairs-replay-v1.json",
    "esp32-freertos-message-irq-vector-v1.json", "esp32-message-startup-cohort-v1.json",
    "esp32-message-startup-scope-v1.json", "esp32-message-startup-windows-v1.json",
    "esp32-message-observer-ownership-v1.json", "esp32-message-address-coverage-v1.json", "esp32-network-common-zephyr-v2",
    "esp32-common-tcp-freertos-v2", "esp32-common-tcp-nuttx-v1",
    "esp32-common-udp-freertos-v1", "esp32-common-udp-nuttx-v2",
    "esp32-common-original-tcp-b1-v1", "esp32-common-original-udp-b1-v1",
    "esp32-common-original-udp-b1-v2", "esp32-common-original-udp-b1-v3",
    "alios-iperf-original-v10", "riot-benchmark-udp-original-v2", "riot-network-dependencies-v1",
    "esp32-native-network-rhino-b1-v1", "esp32-native-network-riot-b1-v1",
    "esp32-native-network-riot-b1-v2", "esp32-energy-window-sensitivity-v1.json",
    "sensys-runtime-tables-v1.json",
    "ram-census-v2/alios", "esp32-rhino-message-history-v1", "esp32-rhino-message-history-v2",
    "esp32-rhino-message-history-b1-v1", "esp32-rhino-message-history-b1-v2",
    "esp32-rhino-message-ready-b1-v1", "esp32-rhino-message-boot-reclamation-v1.json",
    "esp32-common-udp-receiver-freertos-v2", "esp32-common-udp-receiver-freertos-v3",
    "esp32-common-udp-receiver-zephyr-v2", "esp32-common-udp-receiver-zephyr-v3",
    "esp32-common-udp-receiver-zephyr-v4", "esp32-common-udp-receiver-zephyr-v5",
    "esp32-common-udp-receiver-nuttx-v1", "esp32-common-udp-receiver-nuttx-v3",
    "esp32-common-original-udp-receiver-b1-v1", "esp32-common-original-udp-receiver-b1-v2",
    "esp32-common-original-udp-receiver-b1-v3", "esp32-common-original-udp-receiver-b1-v4",
    "esp32-common-original-udp-receiver-b1-v5", "esp32-common-udp-source-path-b1-v1",
    "esp32-common-udp-source-queue-control-b1-v1", "esp32-common-udp-source-queue-control-b1-v2",
    "esp32-common-original-udp-receiver-b1-v6",
    "esp32-waitq-oracle-b1-v1", "esp32-waitq-oracle-v1.json",
]
REPORTS += [relative for _, relative, _ in HARTSTONE_PH3_SOURCES]
REPORTS += ["powerz-thread-metric-energy-20261009-corrected"]

CURRENT_RAM_REPORTS = (
    "esp32-boot-handoff-build-v1", "esp32-boot-handoff-b1-v1", "esp32-boot-handoff-b1-v2",
    "esp32-boot-handoff-b1-v2-audit.json", "esp32-boot-handoff-context-union-v1.json",
    "esp32-boot-handoff-observer-pairs-b1-v1", "esp32-boot-handoff-observer-pairs-b1-v2",
    "esp32-boot-handoff-observer-pairs-b1-v2-independent.json",
    "esp32-message-steps-build-v5", "esp32-message-steps-b1-v5",
    "esp32-message-steps-b1-v5-audit.json", "esp32-message-steps-b1-v5-independent.json",
    "esp32-message-runtime-coverage-v1.json", "esp32-message-runtime-coverage-v1-independent.json",
    "esp32-message-steps-observer-pairs-b1-v1",
    "esp32-message-steps-observer-pairs-b1-v1-independent.json",
)


def current_evidence(include):
    # The detailed audit lives with the evidence on leon; retain its archive alias.
    include(ROOT / "artifacts/reports/sensys-runtime-tables-v1.json",
            "paper/sensys2027/review/current-table-audit.json")
    for name in CURRENT_RAM_REPORTS:
        include(ROOT / "artifacts/reports" / name)
    for pattern in ("esp32-message-steps-build-v*", "esp32-message-steps-b1-v*"):
        for source in sorted((ROOT / "artifacts/reports").glob(pattern)):
            if source.is_dir():
                include(source)


def publication_inputs(include, snapshot):
    for record in [*snapshot["inputs"], snapshot["gap_ledger"]]:
        name = PurePosixPath(record["path"])
        if not name.parts or name.is_absolute() or ".." in name.parts or "\\" in record["path"]:
            raise ValueError("Publication input escapes the archive root")
        include(ROOT / name)


def package_entries():
    entries = {}

    def include(source, name=None):
        if source.is_dir():
            for file in source.rglob("*"):
                if file.is_file() and "__pycache__" not in file.parts and file.suffix != ".pyc":
                    include(file, (Path(name) / file.relative_to(source)).as_posix() if name else None)
        else:
            if not source.is_file() or source.is_symlink():
                raise ValueError("Missing or symbolic artifact: " + str(source))
            relative = name or source.relative_to(ROOT).as_posix()
            if source.name == "original-flash.bin":
                raise ValueError("Private full-Flash backup cannot be packaged")
            if relative in entries and entries[relative] != source:
                raise ValueError("Conflicting archive path")
            entries[relative] = source

    include(DESTINATION / "README.md", "README.md")
    include(ROOT / "reproduction/USE_POLICY.md", "USE_POLICY.md")
    include(ROOT / "DATA_STORAGE_POLICY.md")
    include(ROOT / "ESP32_FOLLOWUP_EXPERIMENTS.md")
    include(ROOT / "paper/sensys2027/iotosbench.tex")
    include(ROOT / "paper/sensys2027/build/iotosbench.pdf")
    include(ROOT / "paper/sensys2027/.latexmkrc")
    for name in ("acmart.cls", "acmart.dtx", "acmart.ins", "ACM-Reference-Format.bst"):
        include(ROOT / "paper/sensys2027/template/acmart" / name)
    include(ROOT / "paper/sensys2027/README.md")
    current_evidence(include)
    include(ROOT / "paper/sensys2027/review/nearest-work-matrix.md")
    laboratory_readme = ROOT / "reproduction/esp32-followup-20261019/README.md"
    if DESTINATION.resolve() != laboratory_readme.parent.resolve():
        include(laboratory_readme, "LAB_REPRODUCTION.md")
    include(ROOT / "IOTOS_GENERATIVE_BENCHMARK_PROTOCOL_V1.md")
    include(ROOT / "TENONOS_EVALUATION_AUDIT_V1.md")
    include(ROOT / "registry/tenonos_candidate_v1.json")
    include(ROOT / "artifacts/reports/tenonos-candidate-audit-v1.json")
    include(ROOT / "registry/iotos_evolution_v1.json")
    include(ROOT / "registry/iotos_tasks_v1.json")
    include(ROOT / "artifacts/reports/iotos-task-bank-v1.json")
    include(ROOT / "artifacts/reports/esp32-task-reference-v1")
    include(ROOT / "artifacts/dependency_stage/generative_subjects/ZephyrMCP")
    task_reference=ROOT/"artifacts/reports/esp32-task-reference-b1-v1"
    if task_reference.exists():
        if not (task_reference/"audit.json").is_file():
            raise ValueError("Do not package an unaudited task reference campaign")
        include(task_reference)
    include(ROOT / "registry/iotos_generative_subjects_v1.json")
    include(ROOT / "artifacts/reports/iotos-generative-subjects-v1.json")
    include(ROOT / "artifacts/reports/esp32-generative-reuse-v1.json")
    include(ROOT / "artifacts/reports/esp32-evolution-build-control-v1")
    include(ROOT / "registry/iotos_kconfig_native_resolution_v1.json")
    for task in json.loads((ROOT / "registry/iotos_tasks_v1.json").read_text())["tasks"]:
        version = "v2" if task["id"] in {"A2", "C2"} else "v1"
        generated = ROOT / f"artifacts/reports/esp32-generated-{task['id'].lower()}-{version}"
        if (generated / "audit.json").is_file():
            include(generated)
            retained = ROOT / f"artifacts/reports/esp32-generated-{task['id'].lower()}-source-v1"
            if retained.is_dir():
                include(retained)
    sequence = ROOT / "artifacts/reports/esp32-policy-sequence-v1"
    if (sequence / "audit.json").is_file():
        include(ROOT / "registry/iotos_policy_sequence_v1.json")
        include(sequence)
        retained = ROOT / "artifacts/reports/esp32-policy-sequence-source-v1"
        if retained.is_dir():
            include(retained)
    held_out = ROOT / "artifacts/reports/esp32-policy-holdout-v1"
    if (held_out / "audit.json").is_file():
        include(ROOT / "registry/iotos_policy_holdout_v1.json")
        include(held_out)
        include(ROOT / "artifacts/reports/esp32-policy-holdout-source-v1")
    tenon = ROOT / "artifacts/reports/tenonos-rpi4-v1"
    if (tenon / "formal-v1/audit.json").is_file():
        include(ROOT / "registry/tenonos_tasks_rpi4_v1.json")
        include(ROOT / "TENONOS_RPI4_REPRODUCTION.md")
        include(tenon)
    include(ROOT / "benchmark_esp32.html")
    include(ROOT / "outputs/01a0baf8-de78-7c52-8661-328911f145d0/IoT_OS_Benchmark_合并总表.xlsx")
    include(ROOT / "artifacts/reports/esp32-benchmark-v1.json")
    publication_inputs(include, json.loads((ROOT / "artifacts/reports/esp32-benchmark-v1.json").read_text()))
    include(ROOT / "tools")
    include(ROOT / "host")
    include(ROOT / "firmware")
    for name in ("thread-metric-6.2.1-rel", "hartstone-small-whetstone-sei-derived-2025"):
        include(ROOT / "artifacts/source_snapshots" / name)
    for name in REPORTS:
        include(ROOT / "artifacts/reports" / name)
    compact = ROOT / "artifacts/reports/esp32-freertos-compact-ram-b1-v2"
    if (compact / "audit.json").is_file():
        include(compact)
        include(ROOT / "artifacts/reports/esp32-freertos-compact-ram-build-v2")
        include(ROOT / "artifacts/reports/esp32-freertos-compact-ram-source-v1/README.md")
        include(ROOT / "artifacts/reports/esp32-freertos-compact-ram-b1-v1")
        include(ROOT / "artifacts/reports/esp32-freertos-compact-ram-build-v1")
    handoff = ROOT / "artifacts/reports/esp32-freertos-startup-handoff-b1-v1"
    if (handoff / "audit.json").is_file():
        include(handoff)
        include(ROOT / "artifacts/reports/esp32-freertos-startup-handoff-build-v1")
        include(ROOT / "artifacts/reports/esp32-freertos-startup-handoff-source-v1/README.md")
    inventory = ROOT / "artifacts/reports/esp32-freertos-memory-boundaries-v1"
    if (inventory / "audit.json").is_file():
        include(inventory)
    bootloader = ROOT / "artifacts/reports/esp32-bootloader-memory-v1"
    if (bootloader / "audit.json").is_file():
        include(bootloader)
    boot_stage = ROOT / "artifacts/reports/esp32-boot-stage-b1-v1"
    if (boot_stage / "audit.json").is_file():
        include(boot_stage)
        include(ROOT / "artifacts/reports/esp32-boot-stage-build-v3")
        include(ROOT / "artifacts/reports/esp32-boot-stage-source-v1")
    peak_context = ROOT / "artifacts/reports/esp32-freertos-peak-context-b1-v1"
    if (peak_context / "audit.json").is_file():
        include(peak_context)
        include(ROOT / "artifacts/reports/esp32-freertos-peak-context-build-v1")
        include(ROOT / "artifacts/reports/esp32-freertos-peak-context-source-v1")
    trajectory = ROOT / "artifacts/reports/esp32-policy-trajectory-contrast-v1.json"
    if trajectory.is_file():
        include(trajectory)
    lifecycle = ROOT / "artifacts/reports/esp32-nuttx-task-lifecycle-validation-b1-v3"
    if (lifecycle / "audit.json").is_file():
        include(lifecycle)
        include(ROOT / "artifacts/reports/esp32-nuttx-task-lifecycle-validation-build-v3")
        include(ROOT / "artifacts/reports/esp32-nuttx-task-lifecycle-validation-source-v1")
    for system in ("freertos","zephyr"):
        validation=ROOT/("artifacts/reports/esp32-"+system+"-task-lifecycle-validation-b1-v1")
        if (validation/"audit.json").is_file():
            include(validation)
            include(ROOT/("artifacts/reports/esp32-"+system+"-task-lifecycle-validation-build-v1"))
            include(ROOT/("artifacts/reports/esp32-"+system+"-task-lifecycle-validation-source-v1"))
    energy_folders = [ROOT/"artifacts/reports/esp32-message-energy-b1-v1"]+[
        ROOT/"artifacts/reports"/("esp32-"+case+"-energy-b1-v1") for case in ENERGY_CASES]
    energy_folders += [ROOT/"artifacts/reports"/("esp32-native-"+case+"-energy-b1-v1")
                      for case in ("message_processing",*ENERGY_CASES)]
    for energy in energy_folders:
        if not (energy/"audit.json").exists():
            continue
        include(energy)
        # Preserve any execution cache already sealed by the collector's manifest.
        for name in json.loads((energy/"campaign.json").read_text())["files"]:
            path = (energy/name).resolve()
            if not path.is_relative_to(energy.resolve()) or path.name == "original-flash.bin":
                raise ValueError("Unsafe energy archive member")
            include(path)
    reports = ROOT / "artifacts/reports"
    extra = sorted({*reports.glob("esp32-*-cohort-b1-v*"), *reports.glob("esp32-nuttx-heap-events-b1-v*"),
                    *reports.glob("esp32-riot-gcc13-legacy-b1-v*"), *reports.glob("esp32-network-controlled-b1-v*"),
                    *reports.glob("esp32-network-udp-controlled-b1-v*"), *reports.glob("esp32-nuttx-stack-lifetimes-b1-v*"),
                    *reports.glob("esp32-nuttx-task-cleanup-b1-v*")})
    extra += [p for p in reports.glob("esp32-nuttx-retained-owners-b1-v*") if p not in extra]
    extra += [p for p in reports.glob("esp32-freertos-lifetimes-b1-v*") if (p / "audit.json").exists() and p not in extra]
    extra += [p for p in reports.glob("esp32-zephyr-lifetimes-b1-v*") if (p / "audit.json").exists() and p not in extra]
    extra += [p for p in reports.glob("esp32-riot-lifetimes-b1-v*") if (p / "audit.json").exists() and p not in extra]
    extra += [p for p in reports.glob("esp32-rhino-lifetimes-b1-v*") if (p / "audit.json").exists() and p not in extra]
    extra += [p for p in reports.glob("esp32-riot-native-message-b1-v*") if (p / "audit.json").exists() and p not in extra]
    extra += [p for p in reports.glob("esp32-riot-msg-nuttx-b1-v*") if (p / "audit.json").exists() and p not in extra]
    for folder in extra:
        if (folder / "campaign.json").exists() or (folder / "recovery.json").exists():
            include(folder)
    for name in ("esp32-native-irq-suite-b1-v1", "esp32-native-task-suite-b1-v1"):
        native = reports / name
        if (native / "audit.json").exists():
            include(native)
    ram = ROOT / "artifacts/reports/esp32-ram-followup-b1-v1"
    if ram.exists():
        if not (ram / "audit.json").exists():
            raise ValueError("Do not package an unaudited RAM campaign")
        for name in ("esp32-ram-followup-b1-v1", "ram-hartstone-nuttx-v1/nuttx/ph4",
                     "ram-hartstone-nuttx-v2/nuttx/ph4", "ram-hartstone-nuttx-v4/nuttx/ph4",
                     "ram-hartstone-alios-v1/alios/ph4", "hartstone-native-us-v1/nuttx/ph4",
                     "hartstone-alios-native-v4/ph4"):
            include(ROOT / "artifacts/reports" / name)
    license_root = ROOT / "artifacts/reports/esp32-tm-alignment-v1/source-evidence"
    for name in ("LICENSE.txt", "LICENSED-HARDWARE.txt"):
        include(license_root / "threadx-6.2.1_rel" / name, "licenses/threadx-v6.2.1_rel/" + name)
    include(license_root / "AliOS-Things-bacc144bdc5df8fe8e302e3732675a920aa40bc5/LICENSE", "licenses/AliOS/LICENSE")
    include(license_root / "RIOT-2024.10-devel/LICENSE", "licenses/RIOT/LICENSE")
    return entries


def package():
    entries = package_entries()
    checksum = "".join(hashlib.sha256(source.read_bytes()).hexdigest() + "  " + name + "\n"
                       for name, source in sorted(entries.items()))
    archive = DESTINATION / "IoTOSBench-ESP32-reproduction.zip.pending"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                         strict_timestamps=False) as output:
        for name, source in sorted(entries.items()):
            output.write(source, "IoTOSBench-ESP32-reproduction/" + name)
        output.writestr("IoTOSBench-ESP32-reproduction/SHA256SUMS", checksum)
    with zipfile.ZipFile(archive) as source:
        if source.testzip() is not None:
            raise ValueError("Corrupt archive")
        for line in checksum.splitlines():
            value, name = line.split("  ", 1)
            if hashlib.sha256(source.read("IoTOSBench-ESP32-reproduction/" + name)).hexdigest() != value:
                raise ValueError("Archived bytes differ")
    print(str(archive), len(entries), archive.stat().st_size)
    return archive


def validate_current_stage(root, env):
    """Execute extracted tools, with no fallback import path to this checkout."""
    from audit_esp32_b1_native_energy import equal_observation
    def evaluate(code):
        program="import sys,json;from pathlib import Path;sys.path.insert(0,'tools');"+code
        lines=subprocess.check_output([sys.executable,"-c",program],cwd=root,env=env).splitlines()
        # Audit helpers may print provenance notices before the final JSON record.
        return json.loads(lines[-1])

    def saved(name):
        return json.loads((root/"artifacts/reports"/name/"audit.json").read_text())

    campaigns=[]
    for module,capture,build in (
        ("run_esp32_tm_ram_lifetimes","esp32-freertos-message-lifetimes-b1-v3","esp32-freertos-message-lifetimes-v1"),
        ("run_esp32_zephyr_message_lifetimes","esp32-zephyr-message-lifetimes-b1-v1","esp32-zephyr-message-lifetimes-v4"),
        ("run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-lifetimes-b1-v2","esp32-nuttx-message-lifetimes-v2"),
        ("run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-identities-b1-v1","esp32-nuttx-message-identities-v1"),
        ("run_esp32_zephyr_message_lifetimes","esp32-zephyr-message-stack-b1-v1","esp32-zephyr-message-stack-v1"),
        ("run_esp32_tm_ram_lifetimes","esp32-freertos-message-stack-b1-v1","esp32-freertos-message-stack-v1"),
        ("run_esp32_tm_ram_lifetimes","esp32-freertos-message-startup-b1-v1","esp32-freertos-message-startup-v1"),
        ("run_esp32_tm_ram_lifetimes","esp32-freertos-message-tick-stacks-b1-v1","esp32-freertos-message-tick-stacks-v1"),
        ("run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-startup-b1-v1","esp32-nuttx-message-startup-v5"),
        ("run_esp32_zephyr_message_lifetimes","esp32-zephyr-message-startup-b1-v1","esp32-zephyr-message-startup-v2"),
        ("run_esp32_zephyr_message_lifetimes","esp32-zephyr-message-tick-stacks-b1-v1","esp32-zephyr-message-tick-stacks-v3"),
        ("run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-tick-stacks-b1-v2","esp32-nuttx-message-tick-stacks-v2"),
        ("run_esp32_nuttx_message_lifetimes","esp32-nuttx-message-tick-control-census-b1-v1","esp32-nuttx-message-tick-control-v1"),
        *([("run_esp32_tm_ram_lifetimes","esp32-freertos-compact-ram-b1-v2","esp32-freertos-compact-ram-build-v2")]
          if (root / "artifacts/reports/esp32-freertos-compact-ram-b1-v2/audit.json").is_file() else []),
        *([("run_esp32_tm_ram_lifetimes","esp32-freertos-startup-handoff-b1-v1","esp32-freertos-startup-handoff-build-v1")]
          if (root / "artifacts/reports/esp32-freertos-startup-handoff-b1-v1/audit.json").is_file() else []),
        *([("run_esp32_tm_ram_lifetimes","esp32-freertos-peak-context-b1-v1","esp32-freertos-peak-context-build-v1")]
          if (root / "artifacts/reports/esp32-freertos-peak-context-b1-v1/audit.json").is_file() else []),
        *([("run_esp32_nuttx_message_lifetimes","esp32-nuttx-task-lifecycle-validation-b1-v3","esp32-nuttx-task-lifecycle-validation-build-v3")]
          if (root / "artifacts/reports/esp32-nuttx-task-lifecycle-validation-b1-v3/audit.json").is_file() else []),
        *([("run_esp32_tm_ram_lifetimes","esp32-freertos-task-lifecycle-validation-b1-v1","esp32-freertos-task-lifecycle-validation-build-v1")]
          if (root / "artifacts/reports/esp32-freertos-task-lifecycle-validation-b1-v1/audit.json").is_file() else []),
        *([("run_esp32_zephyr_message_lifetimes","esp32-zephyr-task-lifecycle-validation-b1-v1","esp32-zephyr-task-lifecycle-validation-build-v1")]
          if (root / "artifacts/reports/esp32-zephyr-task-lifecycle-validation-b1-v1/audit.json").is_file() else [])):
        args=f"Path('artifacts/reports/{capture}'),Path('artifacts/reports/{build}')"
        result=evaluate(f"from {module} import audit;print(json.dumps(audit({args})))")
        if result!=saved(capture) or result["independent_resets"]!=5:
            raise ValueError("Extracted current message-RAM evidence differs: "+capture)
        if "freertos-task-lifecycle-validation" in capture:
            if any(r["task_lifecycles"]["completed"]!=4 or r["task_lifecycles"]["separate_replay"]!="pass" for r in result["runs"]):
                raise ValueError("Extracted finite FreeRTOS lifecycle replay differs")
        elif module=="run_esp32_tm_ram_lifetimes":
            if result["build"].get("allocation_peak_context"):
                separate = evaluate(f"from replay_esp32_freertos_message import replay;print(json.dumps(replay({args})))")
                for primary, independent in zip(result["runs"], separate["runs"], strict=True):
                    if primary["allocation_peak_context"]["phases"] != independent["allocation_peak_contexts"] or \
                            primary["heap_peak_bytes"] != independent["heap_peak_bytes"] or \
                            primary["live_tasks"] != independent["live_tasks"]:
                        raise ValueError("Independent native allocation-peak context replay differs")
            if "stack-b1" in capture or "startup-b1" in capture or "tick-stacks-b1" in capture:
                separate=evaluate(f"from replay_esp32_freertos_message import replay;print(json.dumps(replay({args})))")["runs"]
                keys=("heap_peak_bytes","live_tasks","ordinary_irq_stack")
                if "startup-b1" in capture or "tick-stacks-b1" in capture:
                    keys+=("application_startup_stack",)
                if "tick-stacks-b1" in capture:
                    keys+=("native_tick_stack_snapshots",)
            else:
                separate=evaluate("from replay_esp32_freertos_message import history;from replay_esp32_followup import raw_rows;"
                    f"p=Path('artifacts/reports/{capture}/captures');"
                    "print(json.dumps([history([r['line'] for r in raw_rows(p/('reset%d.jsonl'%i))]) for i in range(1,6)]))")
                keys=("heap_peak_bytes","heap_final_bytes","live_tasks")
            if any(any(a[k]!=b[k] for k in keys) for a,b in zip(result["runs"],separate,strict=True)):
                raise ValueError("Extracted FreeRTOS native memory replay differs")
        elif "zephyr-message-stack" in capture or "zephyr-message-startup" in capture or "zephyr-message-tick" in capture:
            separate=evaluate(f"from replay_esp32_message_stack import replay;print(json.dumps(replay({args})))")
            if any(any(a["native_stack_observations"][k]!=b[k] for k in ("irq","tasks"))
                    for a,b in zip(result["runs"],separate["runs"],strict=True)):
                raise ValueError("Extracted Zephyr native memory replay differs")
            if ("zephyr-message-startup" in capture or "zephyr-message-tick" in capture) and any(a["application_startup_stack"]!=b["application_startup_stack"]
                    for a,b in zip(result["runs"],separate["runs"],strict=True)):
                raise ValueError("Extracted inherited startup replay differs")
            if "zephyr-message-tick" in capture and any(a["native_tick_stack_snapshots"]!=b["native_tick_stack_snapshots"]
                    for a,b in zip(result["runs"],separate["runs"],strict=True)):
                raise ValueError("Extracted native IRQ-return pointer replay differs")
        elif "zephyr-task-lifecycle-validation" in capture:
            separate=evaluate("from replay_esp32_message_stack import heap_history;from replay_esp32_followup import raw_rows;"
                f"p=Path('artifacts/reports/{capture}/validation');symbols="+
                repr({k:tuple(v) for k,v in result["build"]["reservations"].items()})+";"
                "print(json.dumps([heap_history([r['line'] for r in raw_rows(p/('reset%d.jsonl'%i))],symbols) for i in range(1,6)]))")
            if any(a["final"]!=b["native_heap_final_bytes"] or a["observed_peak"]>b["native_heap_peak_bytes"]
                   for a,b in zip(result["runs"],separate,strict=True)):
                raise ValueError("Extracted finite Zephyr native heap replay differs")
        elif "task-lifecycle-validation" in capture:
            separate=evaluate("from replay_esp32_followup import raw_rows,native_allocation_addresses;"
                f"p=Path('artifacts/reports/{capture}/validation');"
                "print(json.dumps([native_allocation_addresses([r['line'] for r in raw_rows(p/('reset%d.jsonl'%i))]) for i in range(1,6)]))")
            if any(a["peak"]!=b["native_heap_peak_bytes"] or a["events"]!=b["events"]
                   for a,b in zip(result["runs"],separate,strict=True)):
                raise ValueError("Extracted finite native lifecycle allocation replay differs")
        elif "identities" in capture or "nuttx-message-startup" in capture or "nuttx-message-tick" in capture:
            separate=evaluate(f"from replay_esp32_followup import replay;print(json.dumps(replay({args})))")
            if separate["independent_resets"]!=5:
                raise ValueError("Extracted native memory independent reset count differs")
            if ("nuttx-message-startup" in capture or "nuttx-message-tick" in capture) and any(a["application_startup_stack"]!=b["application_startup_stack"]
                    for a,b in zip(result["runs"],separate["cells"][0]["runs"],strict=True)):
                raise ValueError("Extracted native startup/switch replay differs")
            if "nuttx-message-tick" in capture and any(a['native_tick_stack_snapshots']!=b['native_tick_stack_snapshots']
                    for a,b in zip(result['runs'],separate['cells'][0]['runs'],strict=True)):
                raise ValueError('Extracted native same-stack IRQ snapshot replay differs')
            if 'tick-control-census' in capture and any(a['native_tick_probe_cost']!=b['native_tick_probe_cost']
                    for a,b in zip(result['runs'],separate['cells'][0]['runs'],strict=True)):
                raise ValueError('Extracted default-call cycle witness differs')
        elif "zephyr" in capture:
            separate=evaluate("from replay_esp32_message_stack import heap_history;from replay_esp32_followup import raw_rows;"
                f"p=Path('artifacts/reports/{capture}/captures');symbols="+
                repr({k:tuple(v) for k,v in result["build"]["reservations"].items()})+";"
                "print(json.dumps([heap_history([r['line'] for r in raw_rows(p/('reset%d.jsonl'%i))],symbols) for i in range(1,6)]))")
            if any(a["native_heap_peak_bytes"]!=b["native_heap_peak_bytes"] or
                    a["native_heap_final_bytes"]!=b["native_heap_final_bytes"]
                    for a,b in zip(result["runs"],separate,strict=True)):
                raise ValueError("Extracted historical Zephyr heap replay differs")
        else:
            separate=evaluate("from replay_esp32_followup import raw_rows;import re;"+
                f"p=Path('artifacts/reports/{capture}/captures');out=[]\n"+
                "for i in range(1,6):\n"
                " rows=raw_rows(p/('reset%d.jsonl'%i));used=peak=0;events=[]\n"
                " for row in rows:\n"
                "  m=re.fullmatch(r'TM_N_RAM event=(\\d+) kind=(\\d+) delta=(-?\\d+) occupied=(\\d+) peak=(\\d+)',row['line'])\n"
                "  if m: events.append(tuple(map(int,m.groups())))\n"
                " if not events or events[0]!=(0,0,368,368,368): raise ValueError('Native heap initialization differs')\n"
                " for j,(at,kind,delta,observed,maximum) in enumerate(events):\n"
                "  used+=delta;peak=max(used,peak)\n"
                "  if at!=j or kind not in range(7) or used<368 or (used,peak)!=(observed,maximum): raise ValueError('Native heap event or peak differs')\n"
                " out.append([used,peak])\n"
                "print(json.dumps(out))")
            if separate!=[[r["native_heap_final_bytes"],r["native_heap_peak_bytes"]] for r in result["runs"]]:
                raise ValueError("Extracted historical NuttX heap-byte replay differs")
        campaigns.append({"campaign":capture,"audit":"pass","resets":5,"new_acquisition":False,
                          **({"validation_only":True} if "task-lifecycle-validation" in capture else {})})
    control_name="esp32-nuttx-tick-control-b1-v1"
    if (root/"artifacts/reports"/control_name/"campaign.json").is_file():
        args=f"Path('artifacts/reports/{control_name}'),Path('artifacts/reports/esp32-nuttx-message-tick-control-v1')"
        result=evaluate(f"from run_esp32_nuttx_tick_control import audit;print(json.dumps(audit({args})))")
        separate=evaluate(f"from replay_esp32_nuttx_tick_control import replay;print(json.dumps(replay({args})))")
        if result!=saved(control_name) or result!=separate or result["independent_resets"]!=4:
            raise ValueError("Extracted same-image tick-toggle diagnostic differs")
        campaigns.append({"campaign":control_name,"audit":"pass","resets":4,"diagnostic_only":True,
            "independent_count_replay":True})
    for capture,build in (("esp32-rhino-message-history-b1-v2","esp32-rhino-message-history-v1"),
                          ("esp32-rhino-message-ready-b1-v1","esp32-rhino-message-history-v2")):
        args=f"Path('artifacts/reports/{build}'),Path('artifacts/reports/{capture}')"
        result=evaluate(f"from run_esp32_rhino_message_history import replay;print(json.dumps(replay({args})))")
        separate=evaluate("from replay_esp32_followup import replay;"+
            f"print(json.dumps(replay(Path('artifacts/reports/{capture}'),Path('artifacts/reports/{build}'))))")
        if result!=saved(capture) or result["independent_resets"]!=5:
            raise ValueError("Extracted Rhino message diagnostic differs")
        keys=("events","heap_final_bytes","legacy_heap_final_bytes","heap_peak_bytes","legacy_heap_peak_bytes","fixed_pool_free_bytes")
        if any(any(a[k]!=b[k] for k in keys) or a["original_message"]["original_window_totals"]!=b["original_window_totals"]
                for a,b in zip(result["runs"],separate["cells"][0]["runs"],strict=True)):
            raise ValueError("Independent Rhino message memory/count replay differs")
        campaigns.append({"campaign":capture,"audit":"pass","resets":5,"diagnostic_only":True,"independent_count_replay":True})
    result=evaluate("from audit_esp32_rhino_message_reclamation import audit;print(json.dumps(audit()))")
    if result!=json.loads((root/"artifacts/reports/esp32-rhino-message-boot-reclamation-v1.json").read_text()):
        raise ValueError("Extracted Rhino bootstrap ownership contrast differs")
    for name in ("esp32-message-observer-pairs-b1-v1","esp32-nuttx-address-observer-pairs-b1-v1",
                 "esp32-zephyr-stack-observer-pairs-b1-v1","esp32-freertos-stack-observer-pairs-b1-v1",
                 "esp32-freertos-startup-observer-pairs-b1-v1","esp32-nuttx-startup-observer-pairs-b1-v1",
                 "esp32-zephyr-startup-observer-pairs-b1-v1","esp32-freertos-tick-observer-pairs-b1-v1",
                 "esp32-zephyr-tick-observer-pairs-b1-v1","esp32-nuttx-tick-observer-pairs-b1-v1",
                 "esp32-nuttx-tick-control-observer-pairs-b1-v1",
                 *[name for name in ("esp32-boot-handoff-observer-pairs-b1-v2",
                                     "esp32-message-steps-observer-pairs-b1-v1")
                   if (root / "artifacts/reports" / name / "audit.json").is_file()]):
        argument=f"Path('artifacts/reports/{name}')"
        result=evaluate(f"from run_esp32_message_observer_pairs import audit;print(json.dumps(audit({argument})))")
        separate=evaluate(f"from replay_esp32_followup import replay;print(json.dumps(replay({argument})))")
        if result!=saved(name) or separate["cells"]!=[
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in result["cells"]]:
            raise ValueError("Extracted paired count/source replay differs: "+name)
        campaigns.append({"campaign":name,"audit":"pass","resets":result["independent_resets"]})
    for name,call in (
        ("esp32-common-original-udp-receiver-b1-v1","interrupted_diagnostic"),
        ("esp32-common-original-udp-receiver-b1-v3","clock_diagnostic"),
        ("esp32-common-original-udp-receiver-b1-v4","clock_diagnostic"),
        ("esp32-common-udp-source-path-b1-v1","source_path_diagnostic"),
        ("esp32-common-udp-source-queue-control-b1-v2","source_queue_control")):
        argument=f"Path('artifacts/reports/{name}')"+(",periodic=True" if name.endswith("-v4") else "")
        result=evaluate(f"from run_esp32_common_udp_receiver import {call};print(json.dumps({call}({argument})))")
        if result!=saved(name) or not result["original_flash_restored"] or not result["management_wifi_restored"] or \
                result.get("qualified_resets",0)!=0 or result.get("ranking_eligible",False):
            raise ValueError("Extracted common UDP receiver diagnostic changed or acquired a score")
        campaigns.append({"campaign":name,"audit":result["audit"],"resets":0,
            "diagnostic_only":True,"qualified_resets":0})
    name="esp32-common-original-udp-receiver-b1-v6"
    argument=f"Path('artifacts/reports/{name}')"
    result=evaluate(f"from run_esp32_common_udp_receiver import audit;print(json.dumps(audit({argument})))")
    separate=evaluate(f"from replay_esp32_followup import replay;print(json.dumps(replay({argument})))")
    if result!=saved(name) or result["independent_resets"]!=15 or separate["independent_resets"]!=15 or \
            separate["cells"]!=[{k:c[k] for k in ("system","values_mbit_s","median_mbit_s","range_mbit_s","independent_resets")}
                for c in result["cells"]]:
        raise ValueError("Extracted fixed-load UDP receiver replay differs")
    campaigns.append({"campaign":name,"audit":"pass","resets":15,"independent_count_replay":True})
    for protocol,name in (("tcp","esp32-common-original-tcp-b1-v1"),("udp","esp32-common-original-udp-b1-v3")):
        argument=f"Path('artifacts/reports/{name}')"
        result=evaluate(f"from run_esp32_common_tcp import audit;print(json.dumps(audit({argument},protocol='{protocol}')))")
        separate=evaluate(f"from replay_esp32_followup import replay;print(json.dumps(replay({argument})))")
        if result!=saved(name) or [{k:c[k] for k in ("values_mbit_s","median_mbit_s","range_mbit_s")}
                for c in result["cells"]]!=[{k:c[k] for k in ("values_mbit_s","median_mbit_s","range_mbit_s")}
                for c in separate["cells"]]:
            raise ValueError("Extracted common-network receiver replay differs")
        campaigns.append({"campaign":name,"audit":"pass","resets":result["independent_resets"]})
    for name in ("esp32-native-network-rhino-b1-v1","esp32-native-network-riot-b1-v2"):
        result=evaluate(f"from run_esp32_native_network_b1 import audit;print(json.dumps(audit(Path('artifacts/reports/{name}'))))")
        if result!=saved(name):
            raise ValueError("Extracted original native network source/count replay differs")
        campaigns.append({"campaign":name,"audit":"pass","resets":result["independent_resets"]})
    for case in ("message_processing",*ENERGY_CASES):
        name="esp32-native-"+case+"-energy-b1-v1"
        argument=f"Path('artifacts/reports/{name}')"
        result=evaluate(f"from audit_esp32_b1_native_energy import audit;print(json.dumps(audit({argument})))")
        if not equal_observation(result,saved(name)) or result["independent_resets"]!=6:
            raise ValueError("Extracted native energy evidence differs")
        campaigns.append({"campaign":name,"audit":"pass","resets":6,"independent_energy_replay":True})
    for module,name in (("audit_esp32_message_ram_cohort","esp32-message-ram-lifetimes-cohort-v1.json"),
                        ("audit_esp32_message_startup","esp32-message-startup-cohort-v1.json"),
                        ("audit_esp32_energy_window_sensitivity","esp32-energy-window-sensitivity-v1.json")):
        result=evaluate(f"from {module} import audit;print(json.dumps(audit()))")
        recorded=json.loads((root/"artifacts/reports"/name).read_text())
        agrees=equal_observation(result,recorded) if module=="audit_esp32_energy_window_sensitivity" else result==recorded
        if not agrees:
            raise ValueError("Extracted derived source/window audit differs: "+name)
    result=evaluate("from audit_esp32_message_startup import current_windows;print(json.dumps(current_windows()))")
    if result!=json.loads((root/"artifacts/reports/esp32-message-startup-windows-v1.json").read_text()):
        raise ValueError("Extracted current startup-window boundary replay differs")
    inventory=root/"artifacts/reports/esp32-freertos-memory-boundaries-v1/audit.json"
    if inventory.is_file():
        result=evaluate("from audit_esp32_native_memory_boundaries import audit;print(json.dumps(audit()))")
        if result!=json.loads(inventory.read_text()):
            raise ValueError("Extracted complete native heap inventory differs")
        campaigns.append({"campaign":inventory.parent.name,"audit":"pass","resets":0,
                          "reused_resets":5,"native_heap_inventory_complete":True})
    bootloader = root / "artifacts/reports/esp32-bootloader-memory-v1/audit.json"
    if bootloader.is_file():
        result = evaluate("from audit_esp32_bootloader_memory import audit;print(json.dumps(audit()))")
        if result != json.loads(bootloader.read_text()):
            raise ValueError("Extracted measured bootloader ELF/BIN or physical SRAM union differs")
        campaigns.append({"campaign": bootloader.parent.name, "audit": "pass", "resets": 0,
                          "reused_resets": 5, "bootloader_static_inventory": True})
    boot_stage = root / "artifacts/reports/esp32-boot-stage-b1-v1/audit.json"
    if boot_stage.is_file():
        result = evaluate("from audit_esp32_bootloader_ram import audit;print(json.dumps(audit("
            "Path('artifacts/reports/esp32-boot-stage-b1-v1'),Path('artifacts/reports/esp32-boot-stage-build-v3'))))")
        if result != json.loads(boot_stage.read_text()) or not result["independent_stdlib_replay"]:
            raise ValueError("Extracted boot-stage source/ELF/raw-byte replay differs")
        campaigns.append({"campaign": boot_stage.parent.name, "audit": "pass", "resets": 5,
                          "application_rebuilt": False, "independent_stdlib_replay": True})
    handoff = root / "artifacts/reports/esp32-boot-handoff-b1-v2-audit.json"
    if handoff.is_file():
        result = evaluate("from measure_esp32_boot_handoff_ram import audit;print(json.dumps(audit("
            "Path('artifacts/reports/esp32-boot-handoff-b1-v2'),Path('artifacts/reports/esp32-boot-handoff-build-v1'))))")
        if result != json.loads(handoff.read_text()) or not result["independent_readback_replay"]:
            raise ValueError("Extracted boot handoff/readback differs")
        union = evaluate("from audit_esp32_context_union import audit;print(json.dumps(audit("
            "Path('artifacts/reports/esp32-boot-handoff-build-v1'),Path('artifacts/reports/esp32-boot-handoff-b1-v2'))))")
        if union != json.loads((root / "artifacts/reports/esp32-boot-handoff-context-union-v1.json").read_text()):
            raise ValueError("Extracted simultaneous physical context union differs")
        campaigns.append({"campaign":"esp32-boot-handoff-b1-v2", "audit":"pass", "resets":5,
                          "separate_validation_resets":1, "independent_readback_replay":True,
                          "whole_live_ram_peak_bytes":None, "ranking_eligible":False})
    trajectory=root/"artifacts/reports/esp32-policy-trajectory-contrast-v1.json"
    if trajectory.is_file():
        saved_trajectory=json.loads(trajectory.read_text())
        later=saved_trajectory["experiments"][1:]
        argument="Path("+repr(later[0]["source"])+")" if later else "None"
        result=evaluate("from audit_esp32_policy_trajectory import audit;print(json.dumps(audit("+argument+")))")
        if result!=saved_trajectory:
            raise ValueError("Extracted endpoint/trajectory projection differs")
        campaigns.append({"campaign":trajectory.stem,"audit":"pass","resets":0,
                          "reused_histories":sum(len(e["histories"]) for e in result["experiments"]),
                          "new_model_calls":0})
    result=evaluate("from audit_esp32_ram_scope import observer_ownership;print(json.dumps(observer_ownership()))")
    if result!=json.loads((root/"artifacts/reports/esp32-message-observer-ownership-v1.json").read_text()):
        raise ValueError("Extracted observer static-ownership attribution differs")
    result=evaluate("from audit_esp32_ram_scope import message_coverage;print(json.dumps(message_coverage()))")
    if result!=json.loads((root/"artifacts/reports/esp32-message-address-coverage-v1.json").read_text()):
        raise ValueError("Extracted measured-message physical address coverage differs")
    result=evaluate("from audit_esp32_ram_scope import tick_coverage;print(json.dumps(tick_coverage()))")
    if result!=json.loads((root/'artifacts/reports/esp32-message-tick-coverage-v1.json').read_text()):
        raise ValueError('Extracted native tick-image address coverage differs')
    result=evaluate("from audit_esp32_ram_scope import tick_coverage;print(json.dumps(tick_coverage(True)))")
    if result!=json.loads((root/'artifacts/reports/esp32-message-tick-coverage-v2.json').read_text()):
        raise ValueError('Extracted controlled tick-image address coverage differs')
    result=evaluate("from audit_esp32_workbook_sync import audit,WORKBOOK,REPORT;"
        "print(json.dumps(audit(Path(REPORT/'source.xlsx'),Path(WORKBOOK))))")
    if result!=json.loads((root/'artifacts/reports/esp32-workbook-sync-v1/audit.json').read_text()):
        raise ValueError('Extracted workbook boundary/data-preservation audit differs')
    result=evaluate("from audit_sensys_runtime_tables import audit;print(json.dumps(audit(Path('paper/sensys2027/iotosbench.tex'))))")
    if result!=json.loads((root/"artifacts/reports/sensys-runtime-tables-v1.json").read_text()):
        raise ValueError("Extracted current paper table/source audit differs")
    if "continuous_contexts" in result["reset_level_values"]:
        current = result["reset_level_values"]
        if current["continuous_contexts"]["whole_live_ram_peak_bytes"] is not None or \
                current["continuous_contexts"]["ranking_eligible"] or \
                current["continuous_context_address_coverage"]["whole_live_ram_peak_bytes"] is not None:
            raise ValueError("Incomplete continuous observations acquired a whole-RAM score")
        campaigns.append({"campaign":"esp32-message-steps-b1-v5", "audit":"pass", "resets":5,
                          "separate_validation_resets":1, "reused_validation_resets":1,
                          "continuous_context_and_capacity_replay":True,
                          "whole_live_ram_peak_bytes":None, "ranking_eligible":False})
    display = evaluate("import hashlib;from render_esp32_benchmark import render,validate;"
        "data=json.loads(Path('artifacts/reports/esp32-benchmark-v1.json').read_text());validate(data);"
        "html=render(data);print(json.dumps({'sha256':hashlib.sha256(html.encode('utf-8')).hexdigest(),"
        "'historical_rows':len(data['rows'])}))")
    if display["sha256"] != hashlib.sha256((root / "benchmark_esp32.html").read_bytes()).hexdigest():
        raise ValueError("Extracted HTML does not reproduce from its frozen inputs")
    campaigns.append({"campaign":"desktop-publication-view", "audit":"pass", "resets":0,
                      "html_sha256":display["sha256"], "historical_rows":display["historical_rows"]})
    oracle = root / "artifacts/reports/esp32-waitq-oracle-b1-v1"
    if oracle.is_dir():
        result=evaluate("from esp32_waitq_oracle import audit;print(json.dumps(audit(Path('artifacts/reports/esp32-waitq-oracle-b1-v1'))))")
        if result != saved(oracle.name) or result["independent_resets"] != 10 or \
                result["passed_case_instances"] != 240 or result["generated_task_runs"] != 0 or result["ranking_eligible"]:
            raise ValueError("Extracted original wait-queue functionality replay differs")
        campaigns.append({"campaign":oracle.name, "audit":"pass", "resets":10,
                          "functional_only":True, "original_cases_per_reset":24,
                          "generation_evidence":False, "ranking_eligible":False})
    for task in json.loads((root / "registry/iotos_tasks_v1.json").read_text())["tasks"]:
        version = "v2" if task["id"] in {"A2", "C2"} else "v1"
        name = f"esp32-generated-{task['id'].lower()}-{version}"
        if not (root / "artifacts/reports" / name / "audit.json").is_file():
            continue
        result = evaluate("from run_esp32_generated_task import audit;"
                          f"print(json.dumps(audit(Path('artifacts/reports/{name}'))))")
        if result != saved(name):
            raise ValueError("Extracted generated-configuration evidence differs: " + name)
        resets = sum(len(task["workloads"]) * 3 for t in result["trials"] if t["gates"]["functional"])
        campaigns.append({"campaign": name, "audit": "pass", "resets": resets,
                          "generated_task_physical_resets": resets,
                          "registered_model_calls": result["registered_trials"],
                          "successful_task_trials": result["successes"], "hardware": "ESP32 B1"})
    sequence = root / "artifacts/reports/esp32-policy-sequence-v1"
    if (sequence / "audit.json").is_file():
        result = evaluate("from run_esp32_policy_sequence import audit;"
            "print(json.dumps(audit(Path('artifacts/reports/esp32-policy-sequence-v1'))))")
        if result != saved(sequence.name):
            raise ValueError("Extracted state-linked policy history differs")
        campaigns.append({"campaign": sequence.name, "audit": "pass",
            "resets": result["generated_physical_resets"] + result["initial_state_captures"] + result["recovery_state_captures"],
            "generated_task_physical_resets": result["generated_physical_resets"],
            "registered_model_calls": result["registered_model_calls"],
            "registered_histories": result["registered_histories"], "hardware": "ESP32 B1",
            "prescribed_policy_updates": True, "rsi": False})
    held_out = root / "artifacts/reports/esp32-policy-holdout-v1"
    if (held_out / "audit.json").is_file():
        result=evaluate("from run_esp32_policy_holdout import audit;"
            "print(json.dumps(audit(Path('artifacts/reports/esp32-policy-holdout-v1'))))")
        if result!=saved(held_out.name):
            raise ValueError("Extracted prospective held-out evidence differs")
        histories=result["sequence"]
        campaigns.append({"campaign":held_out.name,"audit":"pass",
            "resets":result["physical_resets"]+histories["generated_physical_resets"]+
                histories["initial_state_captures"]+histories["recovery_state_captures"],
            "generated_task_physical_resets":histories["generated_physical_resets"],
            "registered_model_calls":histories["registered_model_calls"],
            "registered_histories":histories["registered_histories"],"held_out_resets":result["physical_resets"],
            "hardware":"ESP32 B1","rsi":False})
    formal = root / "artifacts/reports/tenonos-rpi4-v1/formal-v1"
    if (formal / "audit.json").is_file():
        result = evaluate("from audit_tenonos_tasks import audit;print(json.dumps(audit("
            "Path('registry/tenonos_tasks_rpi4_v1.json'),"
            "Path('artifacts/reports/tenonos-rpi4-v1/formal-v1'),"
            "Path('artifacts/reports/tenonos-rpi4-v1/rtos-graph/graph.json'))))")
        if result != json.loads((formal / "audit.json").read_text()):
            raise ValueError("Extracted Tenon configuration evidence differs")
        campaigns.append({"campaign": "tenonos-rpi4-v1/formal-v1", "audit": "pass", "resets": 0,
                          "generated_guest_boot_captures": result["raw_guest_captures"],
                          "registered_model_calls": result["registered_trials"],
                          "successful_task_trials": result["accounting"]["successful_runs"],
                          "hardware": "Raspberry Pi 4B / ARM64 KVM"})
    return campaigns


def verify_archive_members(archive):
    prefix = "IoTOSBench-ESP32-reproduction/"
    manifest = prefix + "SHA256SUMS"
    expected = {}
    for line in archive.read(manifest).decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        member = prefix + name
        if member in expected:
            raise ValueError("Duplicate checksum entry: " + name)
        expected[member] = digest
    names = archive.namelist()
    if len(names) != len(set(names)) or set(names) != set(expected) | {manifest} or any(
            not name.startswith(prefix) or ".." in PurePosixPath(name).parts or "\\" in name
            for name in names):
        raise ValueError("Archive member inventory differs from its checksum manifest")
    for name, digest in expected.items():
        if hashlib.sha256(archive.read(name)).hexdigest() != digest:
            raise ValueError("Archived bytes differ: " + name)


def extract_private_archive(archive, destination, minimum_bytes=1024 * 1024):
    """Share only immutable firmware bytes within this fresh extraction."""
    firmware, linked = {}, []
    saved = 0
    for item in archive.infolist():
        target = destination / item.filename
        if item.file_size >= minimum_bytes and target.suffix in (".elf", ".bin", ".map"):
            data = archive.read(item)
            checksum = hashlib.sha256(data).hexdigest()
            key = (len(data), checksum)
            if key in firmware:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(firmware[key], target)
                linked.append((target, checksum))
                saved += len(data)
                continue
            firmware[key] = target
        archive.extract(item, destination)
    return linked, saved


def validate_package(archive):
    from audit_esp32_b1_native_energy import equal_observation
    from render_esp32_benchmark import same_published_evidence
    env = {k:v for k,v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    campaigns = []
    with tempfile.TemporaryDirectory(prefix="iotosbench-package-") as temporary:
        with zipfile.ZipFile(archive) as source:
            verify_archive_members(source)
            linked_firmware, shared_bytes = extract_private_archive(source, Path(temporary))
        root = Path(temporary) / "IoTOSBench-ESP32-reproduction"
        subprocess.run([sys.executable,"tools/test_iotos_evolution.py"],cwd=root,env=env,check=True)
        subprocess.run([sys.executable,"tools/test_esp32_followup_recorder.py"],cwd=root,env=env,check=True)
        subprocess.run([sys.executable,"tools/iotos_evolution.py","check"],cwd=root,env=env,check=True)
        subprocess.run([sys.executable,"tools/iotos_task_benchmark.py","--check"],cwd=root,env=env,check=True)
        subprocess.run([sys.executable,"-c",
            "import sys; sys.path.insert(0,'tools'); from import_iotos_subjects import imported; "
            "f,r,t=imported({'name':'ZephyrMCP','repository':'hakehuang/zephyr_mcp',"
            "'commit':'18d61f7e0bda4204e30aa849c0c2f5e60b5f689f'}); "
            "assert len(r)==6 and 'def generate_text(' in f['src/tools/llm_tools.py']"],
            cwd=root,env=env,check=True)
        task_reference=root/"artifacts/reports/esp32-task-reference-b1-v1"
        if task_reference.is_dir():
            from run_esp32_task_references import audit as audit_references
            replay=audit_references(task_reference,root)
            if replay!=json.loads((task_reference/"audit.json").read_text()):
                raise ValueError("Extracted fixed reference replay differs")
            separate=json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_followup.py",
                str(task_reference)],cwd=root,env=env))
            if separate["independent_resets"]!=replay["independent_resets"] or \
                    {(c["task_id"],c["case"]):c["values"] for c in replay["cells"]} != \
                    {(c["task_id"],c["case"]):c["values"] for c in separate["cells"]}:
                raise ValueError("Extracted fixed reference independent arithmetic differs")
            campaigns.append({"campaign":task_reference.name,"audit":"pass","resets":9,
                              "generation_evidence":False,"independent_count_replay":True})
        reused = json.loads(subprocess.check_output([sys.executable,"tools/run_esp32_b1_energy.py","plan"],cwd=root,env=env))
        if reused != json.loads((root/"artifacts/reports/esp32-energy-reuse-20261021-v1/plan.json").read_text()):
            raise ValueError("Extracted reuse plan differs from admitted B1 evidence")
        subprocess.run([sys.executable,"tools/test_esp32_b1_energy.py"],cwd=root,env=env,check=True)
        reused_kernel = json.loads(subprocess.check_output([sys.executable,"tools/run_esp32_b1_kernel_energy.py","plan"],cwd=root,env=env))
        if reused_kernel != json.loads((root/"artifacts/reports/esp32-kernel-energy-reuse-v1/plan.json").read_text()):
            raise ValueError("Extracted kernel-energy reuse plan differs")
        subprocess.run([sys.executable,"tools/test_esp32_b1_kernel_energy.py"],cwd=root,env=env,check=True)
        energy = root/"artifacts/reports/esp32-message-energy-b1-v1"
        if (energy/"audit.json").exists():
            saved = json.loads((energy/"audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable,"-c",
                "import sys,json;sys.path.insert(0,'tools');from pathlib import Path;from audit_esp32_b1_controlled_energy import audit;"
                "print(json.dumps({k:v for k,v in audit(Path(sys.argv[1])).items() if k not in ('numeric_validation','validator_sha256')}))",
                str(energy)],cwd=root,env=env))
            separate = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_b1_energy.py",str(energy)],cwd=root,env=env))
            if not equal_observation(result,saved) or result["independent_resets"] != separate["independent_resets"] or any(
                    abs(a["medians"][k]-b["medians"][k]) > 1e-8
                    for a,b in zip(result["cells"],separate["cells"]) for k in b["medians"]):
                raise ValueError("Extracted B1 energy primary/independent arithmetic differs")
            campaigns.append({"campaign":energy.name,"audit":"pass","resets":9,"independent_energy_replay":True})
        for case in ENERGY_CASES:
            energy = root/"artifacts/reports"/("esp32-"+case+"-energy-b1-v1")
            if not (energy/"audit.json").exists():
                continue
            saved = json.loads((energy/"audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable,"-c",
                "import sys,json;sys.path.insert(0,'tools');from pathlib import Path;from audit_esp32_b1_controlled_energy import audit;"
                "print(json.dumps({k:v for k,v in audit(Path(sys.argv[1])).items() if k not in ('numeric_validation','validator_sha256')}))",
                str(energy)],cwd=root,env=env))
            separate = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_b1_energy.py",str(energy)],cwd=root,env=env))
            if not equal_observation(result,saved) or result["independent_resets"] != separate["independent_resets"] or any(
                    abs(a["medians"][k]-b["medians"][k])>1e-8 for a,b in zip(result["cells"],separate["cells"]) for k in b["medians"]):
                raise ValueError("Extracted B1 kernel energy primary/independent replay differs")
            campaigns.append({"campaign":energy.name,"audit":"pass","resets":9,"independent_energy_replay":True})
        for name in ("esp32-irq-ablation-capture-b1-v1", "esp32-original-followup-b1-v2",
                     "esp32-original-followup-b1-v3", "esp32-original-followup-b1-v4", "esp32-ram-followup-b1-v1", "esp32-message-cohort-b1-v1"):
            message = name == "esp32-message-cohort-b1-v1"
            args = [sys.executable, "tools/run_esp32_b1_message.py", "audit", "--output", "artifacts/reports/" + name] if message else \
                   [sys.executable, "tools/audit_esp32_followup.py", "artifacts/reports/" + name]
            if "irq-ablation" in name:
                args += ["--prepared", "artifacts/reports/esp32-irq-ablation-v2"]
            result = json.loads(subprocess.check_output(args, cwd=root, env=env))
            if name == "esp32-original-followup-b1-v4":
                independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py",
                    "artifacts/reports/" + name], cwd=root, env=env))
                if result != json.loads((root / "artifacts/reports" / name / "audit.json").read_text()) or \
                        {r["original"]:r["values"] for r in result["cells"]} != {r["original"]:r["values"] for r in independent["cells"]}:
                    raise ValueError("Extracted final Rhino candidate replay differs")
            campaigns.append({"campaign": name, "audit": result["audit"], "resets": result["independent_resets"]})
        stack = root/"artifacts/reports/esp32-freertos-stack-coverage-b1-v1"
        result = json.loads(subprocess.check_output([sys.executable,"tools/audit_esp32_freertos_stack_coverage.py",
            "artifacts/reports/esp32-freertos-stack-coverage-v1","--capture",str(stack)],cwd=root,env=env))
        saved = json.loads((stack/"audit.json").read_text())
        independent = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_followup.py",str(stack)],cwd=root,env=env))["cells"][0]
        if result != saved or [r["touched"] for r in independent["ordinary_irq_stack"]] != [r["touched_watermark_bytes"] for r in result["ordinary_irq_stack_runs"]]:
            raise ValueError("Extracted ordinary-IRQ watermark/source replay differs")
        campaigns.append({"campaign":stack.name,"audit":"pass","resets":3,"independent_stack_replay":True})
        for folder in sorted((root / "artifacts/reports").glob("esp32-*-cohort-b1-v*")):
            if folder.name == "esp32-message-cohort-b1-v1" or not (folder / "audit.json").exists():
                continue
            saved = json.loads((folder / "audit.json").read_text())
            failure = saved.get("result") == "original_correctness_failure"
            command = [sys.executable, "-c", "import sys,json;sys.path.insert(0,'tools');from pathlib import Path;from run_esp32_b1_message import audit_failed_cooperative;print(json.dumps(audit_failed_cooperative(Path(sys.argv[1]))))",
                       str(folder)] if failure else [sys.executable, "tools/run_esp32_b1_message.py", "audit", "--output", str(folder)]
            result = json.loads(subprocess.check_output(command, cwd=root, env=env))
            if result != saved:
                raise ValueError("Extracted native-cohort audit differs")
            campaigns.append({"campaign": folder.name, "audit": result["audit"],
                              "resets": result.get("independent_resets", 0), "correctness_failure": failure})
        commands = [
            ("tools/audit_esp32_rhino_gcc13.py", "esp32-rhino-gcc13-legacy-v1", "esp32-rhino-gcc13-b1-v1", []),
            ("tools/audit_esp32_riot_startup.py", "esp32-riot-startup-probe-build-v1", "esp32-riot-startup-probe-b1-v1", ["--diagnostic"]),
            ("tools/audit_esp32_riot_startup.py", "esp32-riot-gcc13-legacy-v1", "esp32-riot-gcc13-legacy-b1-v1", []),
            ("tools/audit_esp32_nuttx_heap_events.py", "esp32-nuttx-heap-events-v1", "esp32-nuttx-heap-events-b1-v2", []),
            ("tools/audit_esp32_nuttx_heap_events.py", "esp32-nuttx-stack-lifetimes-v2", "esp32-nuttx-stack-lifetimes-b1-v1", []),
            ("tools/audit_esp32_nuttx_heap_events.py", "esp32-nuttx-task-cleanup-v1", "esp32-nuttx-task-cleanup-b1-v1", ["--incomplete"]),
            ("tools/audit_esp32_nuttx_heap_events.py", "esp32-nuttx-task-cleanup-v2", "esp32-nuttx-task-cleanup-b1-v2", []),
            ("tools/audit_esp32_nuttx_heap_events.py", "esp32-nuttx-retained-owners-v1", "esp32-nuttx-retained-owners-b1-v1", [])]
        for script, source, name, options in commands:
            folder = root / "artifacts/reports" / name
            if not (folder / "audit.json").exists():
                continue
            archived = json.loads((folder / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, script, "artifacts/reports/" + source,
                "--campaign", "artifacts/reports/" + name, *options], cwd=root, env=env))
            saved = json.loads((folder / "audit.json").read_text())
            if saved.get("audit") != "pass" or saved != archived:
                raise ValueError("Extracted lifecycle/native audit failed")
            resets = saved.get("independent_resets", saved.get("independent_workload_resets", 0))
            if name in ("esp32-nuttx-stack-lifetimes-b1-v1", "esp32-nuttx-task-cleanup-b1-v2", "esp32-nuttx-retained-owners-b1-v1"):
                replayed = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(folder)],
                                                              cwd=root, env=env))["cells"][0]
                if replayed["values"] != [r["allocated_heap_peak_bytes"] for r in saved["runs"]] or \
                        replayed["stack_lifetimes"] != [r["stacks"][:3] for r in saved["runs"]] or \
                        replayed["allocated_stack_block_peaks"] != [r["stack_ownership"]["peak_allocated_stack_block_bytes"]
                                                                    for r in saved["runs"]]:
                    raise ValueError("Independent allocator/lifetime arithmetic differs")
                if name in ("esp32-nuttx-task-cleanup-b1-v2","esp32-nuttx-retained-owners-b1-v1") and any(
                        any(independent[k] != observed["post_exit_cleanup"][k] for k in
                            ("created","retired","active","allocated_delta_bytes","controller_pid"))
                        for independent,observed in zip(replayed["post_exit_cleanup"],saved["runs"])):
                    raise ValueError("Independent post-exit allocator/lifetime arithmetic differs")
                if name=="esp32-nuttx-retained-owners-b1-v1" and any(
                        independent!={"hash_capacity_delta_bytes":observed["retained_native_ownership"]["pid_table"]["allocated_delta_bytes"],
                            "pending_timer_count":observed["retained_native_ownership"]["pending_native_timers"]["pending"],
                            "pending_timer_block_bytes":observed["retained_native_ownership"]["pending_native_timers"]["allocated_bytes"],
                            "allocated_delta_bytes":observed["post_exit_cleanup"]["allocated_delta_bytes"]}
                        for independent,observed in zip(replayed["retained_native_ownership"],saved["runs"])):
                    raise ValueError("Independent retained-object allocation arithmetic differs")
            campaigns.append({"campaign": name, "audit": "pass", "resets": resets})
        freertos = root / "artifacts/reports/esp32-freertos-lifetimes-b1-v1"
        if (freertos / "audit.json").exists():
            saved = json.loads((freertos / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_freertos_ram_lifetimes.py",
                "artifacts/reports/esp32-freertos-lifetimes-v4", "--capture", str(freertos)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(freertos)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["values"] != [r["allocated_heap_peak_bytes"] for r in saved["runs"]] or \
                    independent["task_lifetimes"] != [[r["tasks"][k] for k in
                        ("created","delete_requested","native_cleanup","retired","active")] for r in saved["runs"]]:
                raise ValueError("Extracted FreeRTOS native allocation/lifecycle replay differs")
            campaigns.append({"campaign": freertos.name, "audit":"pass", "resets":3})
        zephyr = root / "artifacts/reports/esp32-zephyr-lifetimes-b1-v1"
        if (zephyr / "audit.json").exists():
            saved = json.loads((zephyr / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_zephyr_ram_lifetimes.py",
                "artifacts/reports/esp32-zephyr-lifetimes-v4", "--capture", str(zephyr)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(zephyr)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["native_heap_peaks"] != [r["heap_native_peak_bytes"] for r in saved["runs"]] or \
                    independent["worker_lifetimes"] != [r["tasks"]["worker_lifetimes"] for r in saved["runs"]] or \
                    independent["task_lifetimes"] != [[r["tasks"]["final"][k] for k in
                        ("created","dead","joined","retired","active")] for r in saved["runs"]]:
                raise ValueError("Extracted Zephyr native static-resource/lifecycle replay differs")
            campaigns.append({"campaign":zephyr.name,"audit":"pass","resets":3})
        riot = root / "artifacts/reports/esp32-riot-lifetimes-b1-v2"
        if (riot / "audit.json").exists():
            saved = json.loads((riot / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_riot_ram_lifetimes.py",
                "artifacts/reports/esp32-riot-lifetimes-v7", "--capture", str(riot)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(riot)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["native_heap_peaks"] != [r["heap_native_peak_bytes"] for r in saved["runs"]] or \
                    independent["workers_retained_blocked"] != [r["tasks"]["workers_retained_blocked"] for r in saved["runs"]] or \
                    independent["task_lifetimes"] != [[r["tasks"]["final"][k] for k in
                        ("created","stopped","active","workers","native_active")] for r in saved["runs"]] or \
                    independent["retained_records"] != [[[s[k] for k in
                        ("pid","stack","reserved","usable","role","present","status","hwm_measured","spare","gate")]
                        for s in r["tasks"]["records"]] for r in saved["runs"]]:
                raise ValueError("Extracted RIOT allocator/retained-worker replay differs")
            campaigns.append({"campaign":riot.name,"audit":"pass","resets":3})
        stack = root/"artifacts/reports/esp32-riot-stack-coverage-b1-v1"
        result = json.loads(subprocess.check_output([sys.executable,"tools/audit_esp32_riot_stack_coverage.py",
            "artifacts/reports/esp32-riot-stack-coverage-v1","--capture",str(stack)],cwd=root,env=env))
        saved = json.loads((stack/"audit.json").read_text())
        independent = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_followup.py",str(stack)],cwd=root,env=env))["cells"][0]
        if result != saved or independent["native_heap_peaks"] != [r["heap_native_peak_bytes"] for r in saved["runs"]] or \
                independent["stack_coverage"] != [{k:r[k] for k in ("ordinary_irq_stack","current_idle_stack")} for r in saved["native_stack_runs"]]:
            raise ValueError("Extracted RIOT native stack/source replay differs")
        campaigns.append({"campaign":stack.name,"audit":"pass","resets":3,"independent_stack_replay":True})
        subprocess.run([sys.executable,"tools/test_esp32_riot_stack_coverage.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        stack = root/"artifacts/reports/esp32-zephyr-stack-coverage-b1-v1"
        result = json.loads(subprocess.check_output([sys.executable,"tools/audit_esp32_zephyr_stack_coverage.py",
            "artifacts/reports/esp32-zephyr-stack-coverage-v1","--capture",str(stack)],cwd=root,env=env))
        saved = json.loads((stack/"audit.json").read_text())
        independent = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_followup.py",str(stack)],cwd=root,env=env))["cells"][0]
        if result != saved or independent["stack_coverage"] != [{k:r[k] for k in ("ordinary_irq_stack","current_idle_stack")} for r in saved["native_stack_runs"]]:
            raise ValueError("Extracted Zephyr native stack/source replay differs")
        campaigns.append({"campaign":stack.name,"audit":"pass","resets":3,"independent_stack_replay":True})
        subprocess.run([sys.executable,"tools/test_esp32_zephyr_stack_coverage.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        subprocess.run([sys.executable,"tools/test_esp32_ram_scope.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        rhino = root / "artifacts/reports/esp32-rhino-lifetimes-b1-v3"
        if (rhino / "audit.json").exists():
            saved = json.loads((rhino / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_rhino_ram_lifetimes.py",
                "artifacts/reports/esp32-rhino-lifetimes-v4", "--capture", str(rhino)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(rhino)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["native_heap_peaks"] != [r["heap_native_peak_bytes"] for r in saved["runs"]] or \
                    independent["workers_retained_blocked"] != [r["lifetimes"]["workers_retained_blocked"] for r in saved["runs"]] or \
                    independent["thread_records"] != [r["lifetimes"]["records"] for r in saved["runs"]] or \
                    independent["timer_records"] != [r["lifetimes"]["timers"] for r in saved["runs"]] or \
                    independent["heap_samples"] != [r["lifetimes"]["samples"] for r in saved["runs"]]:
                raise ValueError("Extracted Rhino allocator/task/timer lifecycle replay differs")
            campaigns.append({"campaign":rhino.name,"audit":"pass","resets":3})
        stack = root / "artifacts/reports/esp32-rhino-stack-coverage-b1-v2"
        saved = json.loads((stack/"audit.json").read_text())
        result = json.loads(subprocess.check_output([sys.executable,"tools/audit_esp32_rhino_stack_coverage.py",
            "artifacts/reports/esp32-rhino-stack-coverage-v1","--capture",str(stack)],cwd=root,env=env))
        independent = json.loads(subprocess.check_output([sys.executable,"tools/replay_esp32_followup.py",str(stack)],
                                                         cwd=root,env=env))["cells"][0]
        if result != saved or independent["stack_coverage"] != [r["stack_coverage"] for r in saved["runs"]] or \
                independent["native_heap_peaks"] != [r["heap_native_peak_bytes"] for r in saved["runs"]]:
            raise ValueError("Extracted deleted/idle/IRQ stack coverage replay differs")
        campaigns.append({"campaign":stack.name,"audit":"pass","resets":3})
        refused = root/"artifacts/reports/esp32-rhino-stack-coverage-b1-v1"
        result = json.loads(subprocess.check_output([sys.executable,"tools/audit_esp32_rhino_stack_coverage.py",
            "artifacts/reports/esp32-rhino-stack-coverage-v1","--capture",str(refused),"--incomplete"],cwd=root,env=env))
        if result != json.loads((refused/"audit.json").read_text()) or result["completed_workload_resets"]:
            raise ValueError("Validation-only stack boot was promoted")
        campaigns.append({"campaign":refused.name,"audit":"pass","resets":0,"diagnostic_only":True})
        subprocess.run([sys.executable,"tools/test_esp32_rhino_stack_coverage.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        native_message = root / "artifacts/reports/esp32-riot-native-message-b1-v1"
        if (native_message / "audit.json").exists():
            saved = json.loads((native_message / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_riot_native_message.py",
                "artifacts/reports/esp32-riot-native-message-v3", "--capture", str(native_message)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(native_message)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["values"] != saved["original_counts"]:
                raise ValueError("Extracted original native RIOT message count replay differs")
            campaigns.append({"campaign":native_message.name,"audit":"pass","resets":3})
        nuttx_message = root / "artifacts/reports/esp32-riot-msg-nuttx-b1-v2"
        if (nuttx_message / "audit.json").exists():
            saved = json.loads((nuttx_message / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_riot_msg_nuttx.py",
                "artifacts/reports/riot-msg-nuttx-v1", "--capture", str(nuttx_message)], cwd=root, env=env))
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(nuttx_message)],
                                                              cwd=root, env=env))["cells"][0]
            if result != saved or independent["values"] != saved["original_counts"]:
                raise ValueError("Extracted NuttX original-message port replay differs")
            campaigns.append({"campaign":nuttx_message.name,"audit":"pass","resets":3})
        failed_message = root / "artifacts/reports/esp32-riot-msg-nuttx-b1-v1"
        if (failed_message / "audit.json").exists():
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_riot_msg_nuttx.py",
                "artifacts/reports/riot-msg-nuttx-v1", "--failure", str(failed_message)], cwd=root, env=env))
            if result != json.loads((failed_message / "audit.json").read_text()) or result["firmware_write_started"]:
                raise ValueError("Extracted prewrite serial-backup failure was promoted")
            campaigns.append({"campaign":failed_message.name,"audit":"pass","resets":0,"prewrite_backup_failure":True})
        subprocess.run([sys.executable,"tools/test_esp32_riot_msg_nuttx.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        rhino_message = root / "artifacts/reports/esp32-riot-msg-alios-b1-v2"
        saved = json.loads((rhino_message / "audit.json").read_text())
        result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_riot_msg_alios.py",
            "artifacts/reports/riot-msg-alios-v2", "--capture", str(rhino_message)], cwd=root, env=env))
        independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(rhino_message)],
                                                        cwd=root, env=env))["cells"][0]
        if result != saved or independent["values"] != saved["original_counts"] or independent["native_buffered_peaks"] != [0]*3:
            raise ValueError("Extracted Rhino original-message count/direct-copy replay differs")
        campaigns.append({"campaign":rhino_message.name,"audit":"pass","resets":3})
        for source, name, flags in (("riot-msg-alios-v2", "esp32-riot-msg-alios-b1-v1", []),
                ("esp32-rhino-message-startup-build-v1", "esp32-rhino-message-startup-b1-v1", ["--diagnostic"])):
            folder = root / "artifacts/reports" / name
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_rhino_message_startup.py",
                "artifacts/reports/" + source, str(folder), *flags], cwd=root, env=env))
            if result != json.loads((folder / "audit.json").read_text()) or result["completed_workload_resets"] or result["ranking_eligible"]:
                raise ValueError("Startup investigation promoted to a benchmark score")
            campaigns.append({"campaign":name,"audit":"pass","resets":0,"diagnostic_only":True})
        subprocess.run([sys.executable,"tools/test_esp32_riot_msg_alios.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        subprocess.run([sys.executable,"tools/test_esp32_rhino_ram_lifetimes.py"],cwd=root,env=env,check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        network = root / "artifacts/reports/esp32-network-controlled-b1-v6"
        interrupted_network = root / "artifacts/reports/esp32-network-controlled-b1-v2"
        failed_network = root / "artifacts/reports/esp32-network-controlled-b1-v1"
        if (failed_network / "audit.json").exists():
            archived = json.loads((failed_network / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(failed_network), "--failure"], cwd=root, env=env))
            if result != archived or result["ranking_eligible"]:
                raise ValueError("Extracted failed peer qualification differs")
            campaigns.append({"campaign": failed_network.name, "audit": result["audit"], "resets": 0,
                              "host_peer_failure": True})
        if (network / "audit.json").exists() and json.loads((network / "audit.json").read_text()).get("independent_resets") == 18:
            archived = json.loads((network / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(network)], cwd=root, env=env))
            if result != archived:
                raise ValueError("Extracted controlled-network audit differs")
            campaigns.append({"campaign": network.name, "audit": result["audit"], "resets": result["independent_resets"]})
        udp = root / "artifacts/reports/esp32-network-udp-controlled-b1-v1"
        if (udp / "audit.json").exists():
            archived = json.loads((udp / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(udp)], cwd=root, env=env))
            if not same_published_evidence(result,archived) or result["ranking_eligible"] or result["independent_resets"] != 18:
                raise ValueError("Extracted UDP original/session boundaries differ")
            campaigns.append({"campaign": udp.name, "audit": "pass", "resets": 18})
        if (interrupted_network / "audit.json").exists():
            archived = json.loads((interrupted_network / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(interrupted_network), "--interrupted"], cwd=root, env=env))
            if result != archived:
                raise ValueError("Extracted interrupted-network audit differs")
            campaigns.append({"campaign": interrupted_network.name, "audit": result["audit"], "resets": 0,
                              "interruption_not_separate_cohort": True})
        for name in ("esp32-network-controlled-b1-v3", "esp32-network-controlled-b1-v4"):
            folder = root / "artifacts/reports" / name
            archived = json.loads((folder / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(folder), "--failed-resume"], cwd=root, env=env))
            if result != archived or not result["original_flash_restored"] or result["independent_resets"]:
                raise ValueError("Extracted USB interruption/recovery audit differs")
            campaigns.append({"campaign": name, "audit": "pass", "resets": 0, "usb_interruption": True})
        folder = root / "artifacts/reports/esp32-network-controlled-b1-v5"
        if (folder / "audit.json").exists():
            archived = json.loads((folder / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_network_controlled.py",
                "--campaign", str(folder), "--link-failure"], cwd=root, env=env))
            if result != archived:
                raise ValueError("Extracted pre-workload discovery failure differs")
            campaigns.append({"campaign": folder.name, "audit": "pass", "resets": 0, "ap_discovery_failure": True})
        subprocess.run([sys.executable, "tools/audit_esp32_native_suite_builds.py"], cwd=root, env=env, check=True)
        for name in ("esp32-native-irq-suite-b1-v1", "esp32-native-task-suite-b1-v1"):
            native = root / "artifacts/reports" / name
            if not (native / "audit.json").exists():
                continue
            archived = json.loads((native / "audit.json").read_text())
            result = json.loads(subprocess.check_output([sys.executable, "tools/audit_esp32_native_suite_builds.py",
                "--campaign", str(native)], cwd=root, env=env))
            if result != {k: v for k, v in archived.items() if k != "cells"}:
                raise ValueError("Extracted native suite audit differs")
            if json.loads((native / "audit.json").read_text()) != archived:
                raise ValueError("Extracted original native reports differ")
            independent = json.loads(subprocess.check_output([sys.executable, "tools/replay_esp32_followup.py", str(native)],
                                                             cwd=root, env=env))
            if [(c["os"], c["case"], c["values"]) for c in independent["cells"]] != \
                    [(c["os"], c["case"], c["values"]) for c in archived["cells"]]:
                raise ValueError("Independent native IRQ count replay differs")
            campaigns.append({"campaign": native.name, "audit": "pass", "resets": result["independent_resets"],
                              "independent_count_replay": True})
        subprocess.run([sys.executable, "tools/audit_esp32_native_irq_semantics.py"], cwd=root, env=env, check=True)
        subprocess.run([sys.executable, "tools/audit_esp32_latency_semantics.py"], cwd=root, env=env, check=True)
        subprocess.run([sys.executable, "tools/audit_esp32_isr_semantics.py"], cwd=root, env=env, check=True)
        campaigns.extend(validate_current_stage(root,env))
        for path, checksum in linked_firmware:
            if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError("Replay modified a shared firmware input")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_digest:
        raise ValueError("Archive changed during replay")
    result = {"audit": "pass", "archive_sha256": archive_digest,
              "member_checksums_verified": True,
              "isolated_extraction": True, "pythonpath_removed": True, "campaigns": campaigns,
              "identical_firmware_members_shared_inside_isolation": len(linked_firmware),
              "logical_firmware_bytes_shared_inside_isolation": shared_bytes,
              "complete_reset_captures": sum(r["resets"] for r in campaigns),
              "generated_task_physical_resets": sum(r.get("generated_task_physical_resets", 0) for r in campaigns),
              "generated_guest_boot_captures": sum(r.get("generated_guest_boot_captures", 0) for r in campaigns),
              "external_physical_replication": False}
    (DESTINATION / "package-validation.json.pending").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group()
    action.add_argument("--verify-current-stage",action="store_true")
    action.add_argument("--check-inputs",action="store_true",help="Check the exact archive inputs on leon without writing an archive")
    action.add_argument("--verify-archive",type=Path,help="Verify a trusted existing ZIP without rebuilding it; writes a replay receipt beside it unless --output-dir is set")
    parser.add_argument("--output-dir",type=Path,help="Separate release candidate directory containing its own README.md")
    args=parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run evidence replay and packaging on leon, not on the Mac")
    if args.output_dir:
        DESTINATION=args.output_dir.resolve()
        if not (DESTINATION/"README.md").is_file():
            parser.error("--output-dir requires an existing candidate README.md")
    if args.check_inputs:
        entries = package_entries()
        print(json.dumps({"audit":"inputs_present", "files":len(entries),
            "logical_bytes":sum(path.stat().st_size for path in entries.values()),
            "new_physical_measurements":0, "archive_created":False}))
    elif args.verify_archive:
        if not args.output_dir:
            DESTINATION=args.verify_archive.resolve().parent
        validate_package(args.verify_archive.resolve())
        (DESTINATION/"package-validation.json.pending").replace(DESTINATION/"package-validation.json")
    elif args.verify_current_stage:
        env={k:v for k,v in os.environ.items() if k not in ("PYTHONPATH","PYTHONHOME")}
        rows=validate_current_stage(ROOT,env)
        print(json.dumps({"audit":"pass","campaigns":rows,"new_physical_measurements":0},indent=2))
    else:
        pending=package()
        validate_package(pending)
        archive=DESTINATION/"IoTOSBench-ESP32-reproduction.zip"
        pending.replace(archive)
        (DESTINATION/"package-validation.json.pending").replace(DESTINATION/"package-validation.json")
        archive.with_suffix(".zip.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+"  "+archive.name+"\n")
