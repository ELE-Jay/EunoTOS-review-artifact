#!/usr/bin/env python3
"""Reconcile the report's added OS/resource rows with native board evidence."""
import argparse
import hashlib
import json
from pathlib import Path

from audit_esp32_alios_tm import audit_case
from audit_esp32_alios_hartstone import audit_experiment as audit_alios_experiment
from audit_esp32_ram_census import audit_census, audit_suite as audit_ram_suite
from audit_esp32_powerz import audit_sync_suite
from audit_esp32_report import EVIDENCE, REPORT, TM, report_rows
from audit_esp32_resources import audit_cell, primary_directory
from audit_esp32_riot_hartstone import audit_experiment
from audit_esp32_riot_tm import audit_suite
from audit_esp32_tm_energy import audit_suite as audit_energy_suite, render_tables as render_energy_tables
from audit_esp32_alios_tm_irq_ram import audit as audit_irq_ram, render_table as render_irq_ram

PROFILES = (
    ("FreeRTOS", "FreeRTOS / configured resource range", "FreeRTOS / message observation v2", "ram-census-v2/freertos"),
    ("Zephyr", "Zephyr / configured resource range", "Zephyr / message observation v1", "ram-census-v1/zephyr"),
    ("NuttX", "NuttX / configured resource range", "NuttX / message observation v2", "ram-census-v2/nuttx"),
    ("RIOT", "RIOT / native tickless resource range", "RIOT / message observation v1", "ram-census-v1/riot"),
    ("AliOS-Rhino", "AliOS/Rhino / native GCC5 resource range", "AliOS/Rhino / message observation v2", "ram-census-v2/alios"),
)
ADDED_LABELS = (
    "Basic processing control", "Cooperative scheduling", "Preemptive scheduling",
    "Message processing", "Synchronization processing", "Memory allocation",
    "Interrupt processing", "Interrupt preemption processing",
)
RIOT_HARTSTONE = (1, 2, 3, 4)
ALIOS_HARTSTONE = (1, 2, 3, 4)


LICENSE_FILES = {
    "license-threadx": ("eclipse-threadx/threadx", "93387b0a60382a29579bbad5045c68328e3751df", "LICENSE.txt", "9b2b946817048c886bb204cd5d664643053b7e89"),
    "license-rtthread": ("RT-Thread/rt-thread", "c3e94f7b5fd533763a8e577fea0dfbc982eb20e5", "LICENSE", "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"),
    "license-chibios": ("ChibiOS/ChibiOS", "fd2e59c34878b1ef93ef5358f11fb5cc830027ff", "license.txt", "94a9ed024d3859793618152ea559a168bbcbb5e2"),
    "license-chibios-rt-header": ("ChibiOS/ChibiOS", "fd2e59c34878b1ef93ef5358f11fb5cc830027ff", "os/rt/include/ch.h", "60d0693b9996183c032924108a12fe7ac73587fe"),
    "license-alios": ("alibaba/AliOS-Things", "bacc144bdc5df8fe8e302e3732675a920aa40bc5", "LICENSE", "8dada3edaf50dbc082c9a125058f25def75e625a"),
    "license-liteos": ("openharmony/kernel_liteos_m", "bca80e0bc4b4925ac3c14819bcf3ba7ae04c590c", "LICENSE", "208b4cd3556ada5a8fa98bcf0fade1795fa982c6"),
    "license-rtx": ("ARM-software/CMSIS-RTX", "161e285b9e10e79cd6ac6d7ed7bd7a41ba57493b", "LICENSE", "8dada3edaf50dbc082c9a125058f25def75e625a"),
    "rtx-readme-pinned": ("ARM-software/CMSIS-RTX", "161e285b9e10e79cd6ac6d7ed7bd7a41ba57493b", "README.md", "3d97a86440a51cc79491a75acad295b2a0b0d796"),
    "license-idf": ("espressif/esp-idf", "v5.2.5", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
    "license-zephyr": ("zephyrproject-rtos/zephyr", "v3.7.0", "LICENSE", "8f71f43fee3f78649d238238cbde51e6d7055c82"),
    "license-riot": ("RIOT-OS/RIOT", "dd06b3727c41c2c44bf93f47ff7831fdd501d68b", "LICENSE", "8000a6faacf471c537530805ab29523c7732e11a"),
    "license-nuttx": ("apache/nuttx", "nuttx-12.2.1", "LICENSE", "df19b7ccc7af0e005a2fc182e6dc6eb293bda33f"),
    "license-ucos-pinned": ("weston-embedded/uC-OS3", "9a3fc5f45d75c0b4c3b6eaecf903720c74329747", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
    "license-freertos": ("espressif/esp-idf", "v5.2.5", "components/freertos/FreeRTOS-Kernel/LICENSE.md", "9cf106272ac3b56b0c4c80218e8fc10a664ca5f4"),
    "license-contiki": ("contiki-ng/contiki-ng", "735e87c3e5060e9c427b214e55c372967f595c04", "LICENSE.md", "f4b1a054c4b61db9688bf7607400933e7a4761df"),
}
LICENSE_ROWS = (
    ("FreeRTOS / license", "license-freertos", "MIT (kernel); Apache-2.0 (ESP-IDF root)", "license-idf"),
    ("Zephyr / license", "license-zephyr", "Apache-2.0 (root)"),
    ("RIOT / license", "license-riot", "LGPL v2.1 (root license text)"),
    ("NuttX / license", "license-nuttx", "Apache-2.0; bundled notices retained"),
    ("ThreadX / license", "license-threadx", "MIT"),
    ("CMSIS-RTX / license", "license-rtx", "Apache-2.0"),
    ("RT-Thread / license", "license-rtthread", "Apache-2.0"),
    ("ChibiOS/RT / license", "license-chibios", "GPL v3 (RT kernel)", "license-chibios-rt-header"),
    ("uC/OS-III / license", "license-ucos-pinned", "Apache-2.0"),
    ("AliOS/Rhino / license", "license-alios", "Apache-2.0 (root)"),
    ("LiteOS-M / license", "license-liteos", "BSD-3-Clause"),
    ("Contiki-NG / license", "license-contiki", "BSD-3-Clause"),
)


def audit_licenses(text, records=None):
    snapshot = Path(__file__).resolve().parents[1] / "artifacts/source_snapshots/thread-metric-6.2.1-rel"
    for name, digest in (
            ("LICENSE.txt", "4ae1a05e03184b46ff7def8750b73d7f124538c458de22f91ce882b81f5274a3"),
            ("LICENSED-HARDWARE.txt", "c7dd0825700d50c93335e7ec7c536b9f2eae7a6a6720e802e922c1b89a673165")):
        if hashlib.sha256((snapshot / name).read_bytes()).hexdigest() != digest:
            raise ValueError("original Thread-Metric release license bytes differ")
    if "6.2.1 uses\nthe retained legacy Microsoft Azure RTOS terms" not in text:
        raise ValueError("original benchmark license revision is not distinguished from current kernel notices")
    if records is None:
        records = json.loads((EVIDENCE / "esp32-support-audit-v1/official-evidence.json").read_text())["records"]
    by_key = {record["key"]: record for record in records}
    if len(by_key) != len(records):
        raise ValueError("duplicate official source record")
    for key, (repo, ref, path, sha) in LICENSE_FILES.items():
        record = by_key[key]
        payload = record["content"].encode("utf-8")
        blob = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        if (record["repo"], record["ref"], record["path"], record["sha"]) != (repo, ref, path, sha) or blob != sha:
            raise ValueError(f"{key}: pinned license/source bytes or identity differ")
    rows = report_rows(text)
    for row in LICENSE_ROWS:
        label, key, notice, *extra = row
        links = []
        for source in (key, *extra):
            repo, ref, path, _ = LICENSE_FILES[source]
            version = ref[:12] if len(ref) == 40 else ref
            links.append(f"[{version}: {path}](https://github.com/{repo}/blob/{ref}/{path})")
        if rows[label][1:] != [notice, "; ".join(links)]:
            raise ValueError(f"{label}: license table differs from pinned notices")
    return len(LICENSE_ROWS)


def audit_liteos_source(records=None, readme=None):
    if records is None:
        records = json.loads((EVIDENCE / "esp32-support-audit-v1/official-evidence.json").read_text())["records"]
    if readme is None:
        readme = json.loads((EVIDENCE / "esp32-support-audit-v1/liteos-esp32-readme.json").read_text())
    record = next(item for item in records if item["key"] == "liteos-esp32")
    entries = json.loads(record["structuredContent"]["content"])
    entry = next(item for item in entries if item["path"] == "esp32/README.md")
    payload = readme["content"].encode("utf-8")
    digest = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    if ((readme["repo"], readme["path"], readme["retrieved_ref"], readme["blob_sha"]) !=
            ("openharmony/device_qemu", "esp32/README.md", "master",
             "a3b159875d67b4e52cbf32b5cabc8535d5a1271c") or
            digest != entry["sha"] or digest != readme["blob_sha"] or len(payload) != entry["size"]):
        raise ValueError("LiteOS-M device README identity/content differs from official inventory")
    return {"blob_sha": digest, "device_commit_pinned": False,
            "documented_validation": "QEMU; not a physical-board qualification"}


def audit_ram_rows(text, suite=None):
    if suite is None:
        suite = audit_ram_suite(EVIDENCE / "ram-thread-metric-v1")
    if (suite["status"], suite["observation_cells"], suite["independent_resets"]) != ("PASS", 40, 120):
        raise ValueError("full original-workload RAM coverage is incomplete")
    rows = report_rows(text)
    cells = {(cell["os"], cell["original_case"]): cell for cell in suite["cells"]}
    if len(cells) != 40:
        raise ValueError("full original-workload RAM identities differ")
    for cell in suite["cells"]:
        if cell["os"] == "NuttX" and (cell.get("native_heap_control", {}).get("native_heap_control_bytes") != 368 or
                cell["runtime_whole_ram_peak_bytes"] != cell.get("historical_static_plus_managed_heap_median_bytes", -1) + 368):
            raise ValueError("NuttX report requires separately audited native heap-control accounting")
    for (case, _, _), label in zip(TM, ADDED_LABELS):
        expected = [f'{cells[os, case]["runtime_whole_ram_peak_bytes"]:,}' for os, *_ in PROFILES]
        if rows[f"RAM / {label}"][1:] != expected:
            raise ValueError(f"{case}: workload RAM table differs from native observer evidence")
    for os, label, *_ in PROFILES:
        peaks = [cells[os, case]["runtime_whole_ram_peak_bytes"] for case, _, _ in TM]
        if rows[label][3:] != [f"{min(peaks):,}-{max(peaks):,}"]:
            raise ValueError(f"{os}: eight-workload RAM range differs from native observer evidence")
    if "40 workload cells and 120 independent\nresets" not in text:
        raise ValueError("full RAM coverage summary drift")
    return suite


def audit_power_rows(text, suite=None):
    if suite is None:
        suite = audit_sync_suite(EVIDENCE / "powerz-native-sync-20261009-positive-assumption-v1", -1,
                                "Operator requested positive current; reversed meter direction is assumed, sole-board supply path is unverified")
    rows = report_rows(text)
    for profile in suite["profiles"]:
        label = "AliOS/Rhino" if profile["os"] == "AliOS-Rhino" else profile["os"]
        expected = [f'{profile["steady_average_power_w_median"] * 1000:.1f}',
                    f'{profile["steady_average_power_w_min"] * 1000:.1f}-{profile["steady_average_power_w_max"] * 1000:.1f}',
                    *[f"{energy:.3f}" for energy in profile["interval_energy_j_medians"]], "3"]
        if rows.get(f"Power / {label} native sync", [])[1:] != expected:
            raise ValueError(f"{label}: power table differs from signed raw-packet/phase replay")
    if ("15 independent power reset captures" not in text or
            "assumed fixed polarity -1" not in text or
            "not accepted whole-board energy" not in text):
        raise ValueError("power observation count/direction/boundary summary drift")
    return suite


def audit_whole_board_power_rows(text, suite=None):
    if suite is None:
        suite = audit_sync_suite(EVIDENCE / "powerz-native-sync-20261009-whole-board-v2", require_whole_board=True)
    if not suite["whole_board_eligible"] or suite["ranking_eligible"]:
        raise ValueError("whole-board report requires accepted observations, without automatic cross-cohort ranking")
    rows = report_rows(text)
    for profile in suite["profiles"]:
        label = "AliOS/Rhino" if profile["os"] == "AliOS-Rhino" else profile["os"]
        if any(run["supply_evidence_type"] != "operator_text_confirmation" for run in profile["runs"]):
            raise ValueError("whole-board report's operator-evidence type differs from retained records")
        expected = [f'{profile["steady_average_power_w_median"] * 1000:.1f}',
                    f'{profile["steady_average_power_w_min"] * 1000:.1f}-{profile["steady_average_power_w_max"] * 1000:.1f}',
                    *[f"{energy:.3f}" for energy in profile["interval_energy_j_medians"]], "3"]
        if rows.get(f"Whole-board power / {label} native sync", [])[1:] != expected:
            raise ValueError(f"{label}: whole-board power table differs from capture-bound supply/packet/phase replay")
    if "15 operator-confirmed whole-board reset captures" not in text or \
            "no independent electrical isolation test" not in text:
        raise ValueError("whole-board count or physical-verification scope drift")
    return suite


def audit_energy_rows(text, suite=None):
    if suite is None:
        suite = audit_energy_suite(EVIDENCE / "powerz-thread-metric-energy-20261009-corrected")
    if not suite["whole_board_eligible"] or suite["ranking_eligible"]:
        raise ValueError("active energy requires supply-bound observations without an unrestricted rank")
    if render_energy_tables(suite).strip() not in text:
        raise ValueError("energy tables/order/ranges differ from independent original-workload replay")
    if "40 original-workload energy cells and 120 independent power reset captures" not in text:
        raise ValueError("energy coverage summary drift")
    return suite


def audit_report(text):
    license_scopes = audit_licenses(text)
    liteos_source = audit_liteos_source()
    ram_suite = audit_ram_rows(text)
    power_suite = audit_power_rows(text)
    whole_board_suite = audit_whole_board_power_rows(text)
    energy_suite = audit_energy_rows(text)
    irq_ram = audit_irq_ram(EVIDENCE / "alios-tm-irq-ram-v1")
    if render_irq_ram(irq_ram) not in text or irq_ram["replacement_of_old_matrix"] or \
            irq_ram["uninstrumented_firmware_peak_eligible"] or irq_ram["performance_or_energy_score_eligible"]:
        raise ValueError("corrected Rhino RAM report differs from separate instrumented-image evidence")
    rows = report_rows(text)
    added = {
        "RIOT": audit_suite(EVIDENCE / "riot-native-gcc12-v3")["cells"],
        "AliOS-Rhino": [audit_case(EVIDENCE / "alios-native-gcc5-v3" / case, case)
                        for case, _, _ in TM],
    }
    for os, cells in added.items():
        prefix = "AliOS" if os == "AliOS-Rhino" else os
        for label, cell in zip(ADDED_LABELS, cells):
            if rows[f"{prefix} {label}"][1:] != [f'{cell["first_window_median"]:,}']:
                raise ValueError(f"{os} original-test report value differs from UART")
    resets = 0
    for os, footprint_label, ram_label, folder in PROFILES:
        if os in added:
            cells = added[os]
        else:
            cells = [audit_cell(primary_directory(os, case), os, case) for case, _, _ in TM]
        expected = []
        for field in ("installed_flash_bytes", "static_sram_bytes"):
            expected.append(f'{min(cell[field] for cell in cells):,}-{max(cell[field] for cell in cells):,}')
        if rows[footprint_label][1:3] != expected:
            raise ValueError(f"{os} resource range differs from archived ELF/installed images")
        ram = audit_census(EVIDENCE / folder, os)
        heap = ram["runs"][0]["dynamic_heap_peak_bytes"] + ram.get("native_heap_control", {}).get("native_heap_control_bytes", 0)
        expected = [f'{ram["static_sram_bytes"]:,}',
                    "0 (heaps already reserved above)" if os == "Zephyr" else f"{heap:,}",
                    f'{ram["runtime_whole_ram_peak_bytes"]:,}']
        if rows[ram_label][1:] != expected:
            raise ValueError(f"{os} RAM report differs from native observer evidence")
        resets += len(ram["runs"])
    for label, cohort, experiments, auditor in (
            ("RIOT / native tickless", "hartstone-riot-native-v4", RIOT_HARTSTONE, audit_experiment),
            ("AliOS / native GCC5", "hartstone-alios-native-v4", ALIOS_HARTSTONE, audit_alios_experiment)):
        for experiment in experiments:
            result = auditor(EVIDENCE / cohort / f"ph{experiment}", experiment)
            expected = [" / ".join(str(run[field]) for run in result["runs"])
                        for field in ("first_loss_step", "best_step")]
            expected += [" / ".join(f'{run["raw_speed_kwips"]:,}' for run in result["runs"]),
                         str(result["independent_resets"])]
            if rows[f"{label} PH{experiment}"][1:] != expected:
                raise ValueError(f"{label} PH{experiment} report differs from full first-loss series")
    if "40 original-test cells" not in text or "15 independent" not in text or \
            "before original\n`tm_main`" not in text:
        raise ValueError("resource count/window summary drift")
    return {"status": "PASS", "resource_cells": 40, "license_scopes": license_scopes,
            "assumed_direction_power_os_profiles": power_suite["os_profiles"],
            "assumed_direction_power_independent_resets": power_suite["independent_resets"],
            "whole_board_power_os_profiles": whole_board_suite["os_profiles"],
            "whole_board_power_independent_resets": whole_board_suite["independent_resets"],
            "power_whole_board_eligible": whole_board_suite["whole_board_eligible"],
            "original_workload_energy_cells": energy_suite["cells_count"],
            "original_workload_energy_independent_resets": energy_suite["independent_resets"],
            "original_workload_energy_observed_order_cases": energy_suite["observed_order_cases"],
            "liteos_device_source": liteos_source,
            "ram_profiles": len(PROFILES),
            "ram_workload_cells": ram_suite["observation_cells"],
            "ram_workload_independent_resets": ram_suite["independent_resets"],
            "native_heap_control_corrected_ram_cells": sum(cell["os"] == "NuttX" for cell in ram_suite["cells"]),
            "separate_corrected_rhino_irq_ram_cells": len(irq_ram["cells"]),
            "separate_corrected_rhino_irq_ram_independent_resets": irq_ram["independent_resets"],
            "ram_independent_resets": resets, "added_thread_metric_cells": 16,
            "added_thread_metric_resets": 48, "riot_complete_hartstone_experiments": list(RIOT_HARTSTONE),
            "alios_complete_hartstone_experiments": list(ALIOS_HARTSTONE),
            "unrestricted_product_ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = args.report.read_text()
    result = audit_report(text)
    result["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")
