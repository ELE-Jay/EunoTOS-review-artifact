#!/usr/bin/env python3
"""One offline replay entry for the public native benchmark extensions."""
import argparse
import json
from datetime import datetime
from pathlib import Path
from audit_esp32_zephyr_original import audit as zephyr, BENCHMARKS
from audit_esp32_riot_original import audit as riot, CASES as RIOT_CASES, digest
from audit_esp32_riot_yield_freertos import audit as riot_yield_freertos_build
from audit_esp32_riot_yield_nuttx import audit as riot_yield_nuttx_build
from audit_esp32_riot_yield_zephyr import audit as riot_yield_zephyr_build
from audit_esp32_riot_yield_alios import audit as riot_yield_alios_build
from audit_esp32_riot_flags_freertos import audit as riot_flags_freertos_build
from audit_esp32_riot_flags_alios import audit as riot_flags_alios_build
from audit_esp32_riot_flags_zephyr import audit as riot_flags_zephyr_build
from audit_esp32_riot_flags_nuttx import audit as riot_flags_nuttx_build
from audit_esp32_riot_msg_freertos import audit as riot_msg_freertos_build
from audit_esp32_riot_msg_zephyr import audit as riot_msg_zephyr_build
from audit_esp32_rhealstone import audit as rhealstone, CASES as RHEAL_CASES
from audit_esp32_iperf_original import audit as iperf
from audit_esp32_freertos_original_performance import audit as freertos
from audit_esp32_hartstone_ram import audit as lifecycle_ram
from audit_esp32_hartstone_ram_zephyr import audit as zephyr_lifecycle_ram, render_table as zephyr_lifecycle_ram_table
from audit_esp32_hartstone_ram_riot import audit as riot_lifecycle_ram, render_table as riot_lifecycle_ram_table
from audit_esp32_hartstone_ram_nuttx import pilot as nuttx_ram_setup_pilot, interrupted as nuttx_ram_interrupted
from audit_esp32_hartstone_ram_nuttx_freelist import audit as nuttx_ram_freelist_build
from audit_esp32_nuttx_ram_context import audit as nuttx_ram_context, report_table as nuttx_ram_context_table
from audit_esp32_hartstone_ram_alios import build as alios_ram_build, machine as alios_ram_machine
from audit_esp32_raw_uart_clock import audit as raw_uart_clock
from audit_esp32_hartstone_ram_controls import audit as ram_controls
from audit_esp32_rhealstone_zephyr import audit as zephyr_rhealstone
from audit_esp32_freertos_original_isr import audit as native_isr
from audit_esp32_freertos_corrected_isr import audit as corrected_isr
from audit_esp32_rhealstone_nuttx import audit as nuttx_rhealstone
from audit_esp32_rhealstone_alios import audit as alios_rhealstone
from audit_esp32_rhealstone_riot import audit as riot_rhealstone, CASES as RIOT_RHEAL_CASES
from audit_esp32_zperf_original import audit as zperf, render_tables as zperf_tables
from audit_esp32_nuttx_iperf_original import audit as nuttx_iperf, render_table as nuttx_iperf_table
from audit_esp32_riot_udp_readiness import audit as riot_network_readiness
from audit_esp32_riot_udp_original import audit as riot_udp, render_table as riot_udp_table
from audit_esp32_alios_iperf_readiness import audit as alios_network_readiness
from audit_esp32_alios_iperf_original import audit as alios_network_corrected, render_table as alios_network_table
from audit_esp32_zephyr_latency_freertos import audit as freertos_latency_port, render_table as freertos_latency_table
from audit_esp32_zephyr_latency_nuttx import audit as nuttx_latency_port
from audit_esp32_zephyr_latency_riot import audit as riot_latency_port
from audit_esp32_zephyr_latency_alios import audit as alios_latency_port
from audit_esp32_zephyr_heap import audit as heap_subset, render_table as heap_table
from audit_esp32_zephyr_thread import audit as lifecycle_subset, render_table as lifecycle_table, COHORTS as LIFECYCLE_COHORTS
from audit_esp32_zephyr_yield import audit as yield_subset, render_table as yield_table, COHORTS as YIELD_COHORTS
from audit_esp32_zephyr_condvar import audit as condvar_subset, render_table as condvar_table, COHORTS as CONDVAR_COHORTS
from audit_esp32_zephyr_condvar_freertos import audit as freertos_condvar_subset
from audit_esp32_zephyr_condvar_alios import audit as alios_condvar_subset
from audit_esp32_zephyr_events import audit as event_subset, render_table as event_table, COHORTS as EVENT_COHORTS, riot_compatibility_candidate, nuttx_driver_candidate
from audit_esp32_zephyr_isr import audit as software_irq_subset, render_table as software_irq_table
from audit_esp32_alios_tm_irq import audit as corrected_rhino_tm_irq, render_table as corrected_rhino_tm_irq_table
from audit_esp32_alios_tm_irq_ram import audit as corrected_rhino_tm_irq_ram, render_table as corrected_rhino_tm_irq_ram_table
from audit_esp32_zephyr_stack import audit as stack_subset, render_table as stack_table
from audit_esp32_zephyr_slab import audit as slab_subset, render_table as slab_table
from audit_esp32_zephyr_slab_alios import audit as alios_slab_subset, render_table as alios_slab_table
from audit_esp32_zephyr_slab_nuttx import audit as nuttx_slab_subset, render_table as nuttx_slab_table
from audit_esp32_zephyr_syskernel_sema import audit as syskernel_sema_subset, render_table as syskernel_sema_table
from audit_esp32_zephyr_syskernel_sema_nuttx import audit as nuttx_syskernel_sema_subset, render_table as nuttx_syskernel_sema_table
from audit_esp32_zephyr_syskernel_sema_riot import audit as riot_syskernel_sema_subset, render_table as riot_syskernel_sema_table
from audit_esp32_zephyr_syskernel_sema_alios import audit as alios_syskernel_sema_subset, render_table as alios_syskernel_sema_table
from audit_esp32_zephyr_syskernel_stack import audit as syskernel_stack_subset, render_table as syskernel_stack_table
from audit_esp32_rhealstone_irq import audit as rhealstone_irq_port, render_table as rhealstone_irq_table
from audit_esp32_rhealstone_irq_zephyr import audit as zephyr_rhealstone_irq_port, render_table as zephyr_rhealstone_irq_table
from audit_esp32_rhealstone_irq_nuttx import audit as nuttx_rhealstone_irq_port, render_table as nuttx_rhealstone_irq_table
from audit_esp32_rhealstone_irq_riot import audit as riot_rhealstone_irq_port, render_table as riot_rhealstone_irq_table
from audit_esp32_rhealstone_irq_alios import audit as alios_rhealstone_irq_port, render_table as alios_rhealstone_irq_table
from audit_esp32_rhealstone_iram import audit as rhealstone_iram_control, render_table as rhealstone_iram_table
from audit_esp32_rhealstone_calibrated import audit as rhealstone_calibrated_port, render_table as rhealstone_calibrated_table
from audit_esp32_rhealstone_tmck import audit as full_tmck_port, render_table as full_tmck_table
from audit_esp32_rhealstone_tmck_native import audit as native_full_tmck_port, render_table as native_full_tmck_table
from audit_esp32_rhealstone_tmck_remaining import audit as remaining_full_tmck_port
from audit_esp32_rhealstone_baselines import audit as baseline_interpretation, render_table as baseline_table

ROOT = Path(__file__).resolve().parents[1]


def audit():
    uart_clock = raw_uart_clock(manifest=ROOT / "artifacts/reports/esp32-raw-uart-clock-binding-audit.json")
    if uart_clock["new_board_boots"] or uart_clock["new_metric_created"] or any(
            row["per_line_byte_binding_verified"] for row in uart_clock["clock_only_legacy_captures"]):
        raise ValueError("clock replay promoted legacy byte proof or added fabricated measurements")
    evidence = ROOT / "artifacts/reports"
    riot_event_candidate = riot_compatibility_candidate()
    nuttx_event_candidate = nuttx_driver_candidate()
    nuttx_freelist = nuttx_ram_freelist_build()
    riot_yield_build = riot_yield_freertos_build()
    nuttx_yield_build = riot_yield_nuttx_build()
    zephyr_yield_build = riot_yield_zephyr_build()
    alios_yield_build = riot_yield_alios_build()
    flags_build = riot_flags_freertos_build()
    alios_flags_build = riot_flags_alios_build()
    zephyr_flags_build = riot_flags_zephyr_build()
    nuttx_flags_build = riot_flags_nuttx_build()
    msg_build = riot_msg_freertos_build()
    zephyr_msg_build = riot_msg_zephyr_build()
    if any(zephyr_msg_build[n] for n in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured",
            "physical_positive_validation_complete", "payload_correctness_validated")) or not zephyr_msg_build["original_test_body_unchanged"] or \
            not zephyr_msg_build["capture_pipeline_prepared"]:
        raise ValueError("Zephyr original message build promoted to a board result or lost prepared capture auditing")
    if any(msg_build[n] for n in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured", "native_unbuffered_rendezvous_implemented",
            "payload_correctness_validated")) or not msg_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured buffered original message candidate promoted to a board/native-rendezvous score")
    if any(nuttx_flags_build[n] for n in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or not nuttx_flags_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured NuttX original RIOT flags build promoted to a board score")
    if any(zephyr_flags_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or not zephyr_flags_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured Zephyr original RIOT flags build promoted to a board score")
    if any(alios_flags_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or not alios_flags_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured Rhino original RIOT flags build promoted to a board score")
    if any(flags_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible", "board_boots",
            "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or not flags_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured original RIOT flags build promoted to a board score")
    if any(alios_yield_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible",
            "board_boots", "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or \
            not alios_yield_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured Rhino original RIOT yield build promoted to a board score")
    if any(zephyr_yield_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible",
            "board_boots", "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or \
            not zephyr_yield_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured Zephyr original RIOT yield build promoted to a board score")
    if any(nuttx_yield_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible",
            "board_boots", "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or \
            not nuttx_yield_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured NuttX original RIOT yield build promoted to a board score")
    if any(riot_yield_build[name] for name in ("measured", "measurement_eligible", "ranking_eligible",
            "board_boots", "new_metric_created", "energy_measured", "runtime_ram_peak_measured")) or \
            not riot_yield_build["original_test_body_unchanged"]:
        raise ValueError("unmeasured original RIOT yield build promoted to a board score")
    full_tmck = full_tmck_port()
    if not full_tmck["original_full_tmck_suite_measured"] or not full_tmck["measurement_eligible"] or \
            full_tmck["ranking_eligible"] or full_tmck["composite_score"] is not None or \
            full_tmck_table(full_tmck) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("full original tmck validation/report/score boundary differs")
    native_full_tmck = {system: native_full_tmck_port(system) for system in ("zephyr", "riot")}
    native_full_tmck.update({system: remaining_full_tmck_port(system) for system in ("nuttx", "alios")})
    for result in native_full_tmck.values():
        if not result["original_full_tmck_suite_measured"] or not result["measurement_eligible"] or \
                result["ranking_eligible"] or result["composite_score"] is not None or \
                native_full_tmck_table(result) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
            raise ValueError("native full original tmck validation/report/score boundary differs")
    riot_slab = slab_subset()
    if riot_slab["ranking_eligible"] or riot_slab["full_original_suite_measured"] or \
            riot_slab["native_pool_concurrency_protection"] or riot_slab["original_tick_phase_synchronization_preserved"] or \
            slab_table(riot_slab) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original fixed-block subset report/native concurrency/timer boundary differs")
    rhino_slab = alios_slab_subset()
    if rhino_slab["ranking_eligible"] or rhino_slab["full_original_suite_measured"] or \
            not rhino_slab["native_pool_concurrency_protection"] or not rhino_slab["original_one_native_tick_preparation_preserved"] or \
            alios_slab_table(rhino_slab) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Rhino original fixed-block subset report/native critical-section boundary differs")
    nuttx_slab = nuttx_slab_subset()
    if nuttx_slab["ranking_eligible"] or nuttx_slab["full_original_suite_measured"] or \
            not nuttx_slab["native_pool_concurrency_protection"] or nuttx_slab["original_tick_phase_synchronization_preserved"] or \
            nuttx_slab_table(nuttx_slab) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX original fixed-block subset report/native pool/timer boundary differs")
    syskernel_sema = syskernel_sema_subset()
    if syskernel_sema["ranking_eligible"] or syskernel_sema["full_original_suite_measured"] or \
            syskernel_sema["native_per_thread_cooperative_priority_class"] or \
            syskernel_sema_table(syskernel_sema) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original semaphore scenario report/native scheduling boundary differs")
    nuttx_syskernel_sema = nuttx_syskernel_sema_subset()
    if nuttx_syskernel_sema["ranking_eligible"] or nuttx_syskernel_sema["full_original_suite_measured"] or \
            nuttx_syskernel_sema["native_per_thread_cooperative_priority_class"] or \
            nuttx_syskernel_sema["native_semaphore_limit_one_enforced"] or \
            nuttx_syskernel_sema_table(nuttx_syskernel_sema) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX original semaphore scenario report/native counting/scheduling boundary differs")
    riot_syskernel_sema = riot_syskernel_sema_subset()
    if riot_syskernel_sema["ranking_eligible"] or riot_syskernel_sema["full_original_suite_measured"] or \
            riot_syskernel_sema["native_per_thread_cooperative_priority_class"] or \
            riot_syskernel_sema["native_semaphore_limit_one_enforced"] or \
            riot_syskernel_sema["original_tick_phase_synchronization_preserved"] or \
            riot_syskernel_sema_table(riot_syskernel_sema) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("RIOT original semaphore scenario report/native counting/scheduling/timer boundary differs")
    alios_syskernel_sema = alios_syskernel_sema_subset()
    if alios_syskernel_sema["ranking_eligible"] or alios_syskernel_sema["full_original_suite_measured"] or \
            alios_syskernel_sema["native_per_thread_cooperative_priority_class"] or \
            alios_syskernel_sema["native_semaphore_limit_one_enforced"] or \
            not alios_syskernel_sema["original_one_native_tick_preparation_preserved"] or \
            alios_syskernel_sema_table(alios_syskernel_sema) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Rhino original semaphore scenario report/native counting/scheduling/timer boundary differs")
    syskernel_stack = syskernel_stack_subset()
    if syskernel_stack["ranking_eligible"] or syskernel_stack["full_original_suite_measured"] or \
            syskernel_stack["native_per_thread_cooperative_priority_class"] or \
            not syskernel_stack["native_queue_front_copy_mapping"] or \
            syskernel_stack_table(syskernel_stack) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original two-slot stack report/native copy/scheduling boundary differs")
    rhealstone_calibrated = rhealstone_calibrated_port()
    if rhealstone_calibrated["ranking_eligible"] or not rhealstone_calibrated["original_timer_overhead_contract_restored"] or \
            rhealstone_calibrated["original_full_tmck_suite_measured"] or \
            any(row["measurement_eligible"] for row in rhealstone_calibrated["cells"]) or \
            rhealstone_calibrated_table(rhealstone_calibrated) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original calibrated timer report or directive-baseline boundary differs")
    zephyr_calibrated = rhealstone_calibrated_port(evidence / "rhealstone-zephyr-calibrated-v1", "zephyr")
    if zephyr_calibrated["ranking_eligible"] or not zephyr_calibrated["original_timer_overhead_contract_restored"] or \
            zephyr_calibrated["original_full_tmck_suite_measured"] or \
            any(row["measurement_eligible"] for row in zephyr_calibrated["cells"]) or \
            rhealstone_calibrated_table(zephyr_calibrated) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Zephyr calibrated timer report or original negative/cache boundary differs")
    riot_calibrated = rhealstone_calibrated_port(evidence / "rhealstone-riot-calibrated-v2", "riot")
    if riot_calibrated["ranking_eligible"] or not riot_calibrated["original_timer_overhead_contract_restored"] or \
            riot_calibrated["original_full_tmck_suite_measured"] or \
            any(row["measurement_eligible"] for row in riot_calibrated["cells"]) or \
            any(row["board_boots"] for row in riot_calibrated["excluded_failed_builds"]) or \
            rhealstone_calibrated_table(riot_calibrated) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("RIOT calibrated timer report or failed-build/native-baseline boundary differs")
    nuttx_calibrated = rhealstone_calibrated_port(evidence / "rhealstone-nuttx-calibrated-v1", "nuttx")
    if nuttx_calibrated["ranking_eligible"] or not nuttx_calibrated["original_timer_overhead_contract_restored"] or \
            nuttx_calibrated["original_full_tmck_suite_measured"] or \
            any(row["measurement_eligible"] for row in nuttx_calibrated["cells"]) or \
            rhealstone_calibrated_table(nuttx_calibrated) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX calibrated timer report or unsigned-baseline/cache boundary differs")
    alios_calibrated = rhealstone_calibrated_port(evidence / "rhealstone-alios-calibrated-v1", "alios")
    if alios_calibrated["ranking_eligible"] or not alios_calibrated["original_timer_overhead_contract_restored"] or \
            alios_calibrated["original_full_tmck_suite_measured"] or \
            any(row["measurement_eligible"] for row in alios_calibrated["cells"]) or \
            rhealstone_calibrated_table(alios_calibrated) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Rhino calibrated timer report or cold-sample/native-baseline boundary differs")
    calibrated_ports = (rhealstone_calibrated, zephyr_calibrated, riot_calibrated, nuttx_calibrated, alios_calibrated)
    baseline_review = baseline_interpretation(dict(zip(("freertos", "zephyr", "riot", "nuttx", "alios"), calibrated_ports)))
    if baseline_table(baseline_review) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original subtraction interpretation table differs")
    calibrated_cells = [cell for port in calibrated_ports for cell in port["cells"]]
    calibrated_captures = sorted([capture for cell in calibrated_cells for capture in cell["captures"]],
        key=lambda row: datetime.fromisoformat(row["start_utc"]))
    if len({(cell["os"], cell["case"]) for cell in calibrated_cells}) != 25 or len(calibrated_captures) != 75 or any(
            datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"])
            for a, b in zip(calibrated_captures, calibrated_captures[1:])):
        raise ValueError("five-port original timer-calibration coverage or shared-board reset chronology differs")
    calibration_phases = [phase for capture in calibrated_captures for phase in capture["calibration_phases"]]
    calibration_coverage = {"native_ports": 5, "original_program_cells": 25, "independent_boots": 75,
        "calibration_raw_readings": sum(phase["attempts"] for phase in calibration_phases),
        "original_rule_rejected_readings": sum(phase["attempts"] - phase["accepted"] for phase in calibration_phases),
        "missing_timer_interface_remeasurement_cells": 0, "ranking_eligible": False,
        "boundary": "timer-interface records complete; native baseline/cache/API semantic comparison remains unresolved"}
    rhealstone_iram = rhealstone_iram_control()
    if rhealstone_iram["ranking_eligible"] or rhealstone_iram["original_timer_overhead_contract_restored"] or \
            any(row["measurement_eligible"] for row in rhealstone_iram["cells"]) or \
            rhealstone_iram_table(rhealstone_iram) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original IRAM diagnostic report or raw-timer boundary differs")
    alios_rhealstone_irq = alios_rhealstone_irq_port(evidence / "rhealstone-irq-alios-v1")
    if alios_rhealstone_irq["ranking_eligible"] or alios_rhealstone_irq["unmodified_official_source"] or \
            alios_rhealstone_irq["external_gpio_interrupt_entry_measured"] or alios_rhealstone_irq["original_iterations"] != 1 or \
            alios_rhealstone_irq["prebuilt_native_irq_archive_source_rebuilt"] or \
            alios_rhealstone_irq_table(alios_rhealstone_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Rhino original one-shot IRQ report or native archive boundary differs")
    riot_rhealstone_irq = riot_rhealstone_irq_port(evidence / "rhealstone-irq-riot-v3")
    if riot_rhealstone_irq["ranking_eligible"] or riot_rhealstone_irq["unmodified_official_source"] or \
            riot_rhealstone_irq["external_gpio_interrupt_entry_measured"] or riot_rhealstone_irq["original_iterations"] != 1 or \
            riot_rhealstone_irq["tick_hz"] is not None or riot_rhealstone_irq["matrix_route_restoration_verified"] or \
            riot_rhealstone_irq_table(riot_rhealstone_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("RIOT original one-shot IRQ report or tickless/restoration boundary differs")
    nuttx_rhealstone_irq = nuttx_rhealstone_irq_port(evidence / "rhealstone-irq-nuttx-v4")
    if nuttx_rhealstone_irq["ranking_eligible"] or nuttx_rhealstone_irq["unmodified_official_source"] or \
            nuttx_rhealstone_irq["external_gpio_interrupt_entry_measured"] or nuttx_rhealstone_irq["original_iterations"] != 1 or \
            nuttx_rhealstone_irq_table(nuttx_rhealstone_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX original one-shot IRQ report or native ABI boundary differs")
    zephyr_rhealstone_irq = zephyr_rhealstone_irq_port(evidence / "rhealstone-irq-zephyr-v1")
    if zephyr_rhealstone_irq["ranking_eligible"] or zephyr_rhealstone_irq["unmodified_official_source"] or \
            zephyr_rhealstone_irq["external_gpio_interrupt_entry_measured"] or zephyr_rhealstone_irq["original_iterations"] != 1 or \
            zephyr_rhealstone_irq_table(zephyr_rhealstone_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Zephyr original one-shot IRQ report or platform-adapted boundary differs")
    rhealstone_irq = rhealstone_irq_port(evidence / "rhealstone-irq-freertos-v1")
    if rhealstone_irq["ranking_eligible"] or rhealstone_irq["unmodified_official_source"] or \
            rhealstone_irq["external_gpio_interrupt_entry_measured"] or rhealstone_irq["original_iterations"] != 1 or \
            rhealstone_irq_table(rhealstone_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original one-shot IRQ report or platform-adapted boundary differs")
    groups = {
        "zephyr_native": [zephyr(evidence / "zephyr-original-v1" / case) for case in BENCHMARKS],
        "riot_native": [riot(evidence / "riot-original-v1" / case) for case in RIOT_CASES],
        "freertos_native": [freertos(evidence / "freertos-original-performance-v1")],
        "rhealstone_diagnostic_port": [rhealstone(evidence / "rhealstone-v2/freertos" / case)
                                      for case in RHEAL_CASES],
        "rhealstone_zephyr_port": [zephyr_rhealstone(evidence / "rhealstone-zephyr-v3/zephyr" / case)
                                   for case in RHEAL_CASES],
        "rhealstone_nuttx_port": [nuttx_rhealstone(evidence / "rhealstone-nuttx-v2/nuttx" / case)
                                  for case in RHEAL_CASES],
        "rhealstone_alios_port": [alios_rhealstone(evidence / "rhealstone-alios-v1/alios" / case)
                                  for case in RHEAL_CASES],
        "rhealstone_riot_port": [riot_rhealstone(evidence /
                                 ("rhealstone-riot-v4" if case in RIOT_RHEAL_CASES[:2] else "rhealstone-riot-v5") /
                                 "riot" / case) for case in RIOT_RHEAL_CASES],
        "iperf_native_network": [iperf(evidence / "iperf-original-v1")],
        "zperf_native_network": [zperf(evidence / "zperf-original-v3")],
        "nuttx_iperf_native_network": [nuttx_iperf(evidence / "nuttx-iperf-original-v5")],
        "riot_udp_native_network": [riot_udp(evidence / "riot-benchmark-udp-original-v2", evidence / "riot-network-dependencies-v1")],
    }
    for name, group in groups.items():
        if not name.startswith("rhealstone_"):
            continue
        for row in group:
            row["original_arithmetic_positive"] = row["measurement_eligible"]
            row["original_timer_overhead_contract_restored"] = False
            row["measurement_eligible"] = False
            row["median_us"] = row["range_us"] = None
            row["measurement_reason"] = "raw timer adapter lacks original average-overhead removal; arithmetic positivity is not qualified latency"
            for capture in row["captures"]:
                capture["original_arithmetic_positive"] = capture["measurement_eligible"]
                capture["measurement_eligible"] = False
                if capture["original_arithmetic_positive"]:
                    capture["measurement_reason"] = row["measurement_reason"]
    if any(row["audit"] != "pass" or row.get("ranking_eligible", False)
           for group in groups.values() for row in group):
        raise ValueError("native results failed replay or acquired an unsupported cross-OS rank")
    if zperf_tables(groups["zperf_native_network"][0]) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("native zperf report values differ from original endpoint/wire evidence")
    if nuttx_iperf_table(groups["nuttx_iperf_native_network"][0]) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("native NuttX iPerf report values differ from original endpoint evidence")
    if riot_udp_table(groups["riot_udp_native_network"][0]) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("native RIOT UDP report values differ from original wire/arithmetic evidence")
    count = sum(row["resets"] for group in groups.values() for row in group)
    ram = lifecycle_ram(evidence / "ram-hartstone-lifecycle-v2/freertos/ph4")
    ram_iram = lifecycle_ram(evidence / "ram-hartstone-iram-control-v1/freertos/ph4", "hartstone_lifecycle_iram")
    zephyr_ram = zephyr_lifecycle_ram()
    if zephyr_ram["ranking_eligible"] or zephyr_ram["uninstrumented_peak_measured"] or \
            zephyr_ram["stack_live_bytes_high_water_measured"] or zephyr_ram["dynamic_heap_added_to_static_bytes"] != 0 or \
            zephyr_lifecycle_ram_table(zephyr_ram) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Zephyr PH4 static reservation/table/double-count or measurement-scope boundary differs")
    riot_ram = riot_lifecycle_ram()
    if any(riot_ram[key] for key in ("ranking_eligible", "uninstrumented_peak_measured", "stack_live_bytes_high_water_measured",
            "pre_kernel_transient_peak_measured", "allocator_internal_transient_peak_measured", "energy_measured", "new_metric_created")) or \
            riot_ram["resets"] != 3 or not riot_ram["reference_worker_cohort_covered"] or \
            riot_lifecycle_ram_table(riot_ram) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("RIOT PH4 native occupation/report/reference workers or measurement-scope boundary differs")
    nuttx_ram_pilot = nuttx_ram_setup_pilot()
    if any(nuttx_ram_pilot[name] for name in ("measured", "complete_first_loss_measured", "runtime_peak_reportable",
            "ranking_eligible", "uninstrumented_peak_measured", "energy_measured", "new_metric_created")) or \
            nuttx_ram_pilot["native_heap_control_context"][1] != 368:
        raise ValueError("NuttX incomplete RAM pilot promoted or native heap-control ownership lost")
    nuttx_ram_diagnostic = nuttx_ram_interrupted()
    if nuttx_ram_diagnostic["complete_resets"] != 1 or nuttx_ram_diagnostic["attempted_resets"] != 2 or any(
            nuttx_ram_diagnostic[key] for key in ("runtime_peak_reportable", "reference_worker_cohort_covered", "ranking_eligible")):
        raise ValueError("NuttX interrupted, reference-short RAM cohort promoted to a complete score")
    nuttx_ram_correction = nuttx_ram_context()
    if nuttx_ram_correction["new_board_boots"] or nuttx_ram_correction["original_cases"] != 8 or \
            nuttx_ram_context_table(nuttx_ram_correction) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX historical per-image RAM correction/table differs")
    alios_ram = alios_ram_build()
    alios_ram["machine_control"] = alios_ram_machine()
    if alios_ram["board_boots"] or any(alios_ram[key] for key in (
            "measured", "runtime_peak_reportable", "ranking_eligible", "energy_measured", "new_metric_created")) or \
            not alios_ram["completion_requires_original_first_loss_marker"]:
        raise ValueError("Rhino PH4 unmeasured native RAM build promoted to a board result")
    controls = ram_controls()
    isr = native_isr(evidence / "freertos-original-isr-diagnostics-v1")
    corrected = corrected_isr(evidence / "freertos-original-isr-corrected-v1")
    latency_port = freertos_latency_port(evidence / "zephyr-latency-freertos-v2")
    if latency_port["ranking_eligible"] or latency_port["unmodified_official_native_suite"]:
        raise ValueError("selected native-adapter latency port promoted into an official full-suite/ranking claim")
    if freertos_latency_table(latency_port) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original latency subset table differs from captured average inputs")
    nuttx_latency = nuttx_latency_port(evidence / "zephyr-latency-nuttx-v2")
    if nuttx_latency["ranking_eligible"] or nuttx_latency["unmodified_official_native_suite"]:
        raise ValueError("native NuttX subset port promoted into full-suite/ranking claim")
    if freertos_latency_table(nuttx_latency, "NuttX") not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX original latency subset table differs from captured average inputs")
    riot_latency = riot_latency_port(evidence / "zephyr-latency-riot-v2")
    alios_latency = alios_latency_port(evidence / "zephyr-latency-alios-v2")
    for name, result in (("RIOT", riot_latency), ("AliOS-Rhino", alios_latency)):
        if result["ranking_eligible"] or result["unmodified_official_native_suite"]:
            raise ValueError("native subset port promoted into full-suite/ranking claim")
        if freertos_latency_table(result, name) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
            raise ValueError(name + " original latency subset table differs from captured average inputs")
    heaps = [heap_subset(evidence / ("zephyr-heap-" + os + "-" + version), os)
             for os, version in (("freertos", "v2"), ("nuttx", "v1"), ("riot", "v1"), ("alios", "v1"))]
    if any(row["ranking_eligible"] or row["unmodified_official_native_suite"] for row in heaps) or \
            heap_table(heaps) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original native heap subset table or comparison boundary differs")
    stack = stack_subset(evidence / "zephyr-stack-freertos-v2")
    if stack["ranking_eligible"] or stack["unmodified_official_native_suite"] or stack["native_dedicated_k_stack_implementation"] or \
            stack_table(stack) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original bounded-stack table or native queue-adapter boundary differs")
    lifecycles = [lifecycle_subset(evidence / ("zephyr-thread-" + os + "-" + version), os) for os, version in LIFECYCLE_COHORTS]
    if any(row["ranking_eligible"] or row["unmodified_official_native_suite"] for row in lifecycles) or \
            lifecycle_table(lifecycles) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original native lifecycle subset table or comparison boundary differs")
    yields = [yield_subset(evidence / ("zephyr-yield-" + os + "-" + version), os) for os, version in YIELD_COHORTS]
    if any(row["ranking_eligible"] or row["unmodified_official_native_suite"] for row in yields) or \
            yield_table(yields) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original native preemptive yield subset table or comparison boundary differs")
    condvars = [condvar_subset(evidence / ("zephyr-condvar-" + os + "-" + version), os) for os, version in CONDVAR_COHORTS]
    if any(row["ranking_eligible"] or row["unmodified_official_native_suite"] or row["original_subtracts_timestamp_overhead"]
           or row["general_object_cleanup_claim_eligible"] for row in condvars) or \
            condvar_table(condvars) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original native condition-variable table or method/cleanup boundary differs")
    freertos_condvar = freertos_condvar_subset()
    if any(freertos_condvar[key] for key in ("ranking_eligible", "unmodified_official_native_suite",
            "native_pthread_workers_used", "original_subtracts_timestamp_overhead", "general_object_cleanup_claim_eligible")) or \
            not freertos_condvar["official_pthread_condition_variable_objects_used"] or \
            condvar_table([freertos_condvar]) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("official pthread/original condition-variable table or SDK boundary differs")
    alios_condvar = alios_condvar_subset()
    if any(alios_condvar[key] for key in ("ranking_eligible", "unmodified_official_native_suite",
            "native_pthread_workers_used", "full_posix_component_profile_used", "original_subtracts_timestamp_overhead",
            "general_object_cleanup_claim_eligible")) or not alios_condvar["official_posix_condition_variable_objects_used"] or \
            not alios_condvar["post_timing_internal_condition_lock_retained"] or \
            condvar_table([alios_condvar]) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("official Rhino POSIX/original condition-variable table or cleanup boundary differs")
    events = [event_subset(evidence / ("zephyr-events-" + os + "-" + version), os) for os, version in EVENT_COHORTS]
    if any(row["ranking_eligible"] or row["unmodified_official_native_suite"] or row["full_zephyr_event_semantics_implemented"]
           for row in events) or event_table(events) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original native event table or scoped semantics boundary differs")
    software_irq = software_irq_subset(evidence / "zephyr-isr-freertos-v1")
    if software_irq["ranking_eligible"] or software_irq["external_gpio_interrupt_entry_measured"] or \
            software_irq["unadjusted_accumulator_separately_captured"] or \
            software_irq_table(software_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("original software-IRQ subset table or measurement boundary differs")
    rhino_software_irq = software_irq_subset(evidence / "zephyr-isr-alios-v4", os="alios")
    if rhino_software_irq["ranking_eligible"] or rhino_software_irq["external_gpio_interrupt_entry_measured"] or \
            rhino_software_irq["unadjusted_accumulator_separately_captured"] or \
            software_irq_table(rhino_software_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("Rhino original software-IRQ subset table or measurement boundary differs")
    rhino_tm_irq = corrected_rhino_tm_irq(evidence / "alios-tm-irq-vector-v1")
    rhino_tm_irq_ram = corrected_rhino_tm_irq_ram(evidence / "alios-tm-irq-ram-v1")
    if rhino_tm_irq_ram["ranking_eligible"] or rhino_tm_irq_ram["replacement_of_old_matrix"] or \
            rhino_tm_irq_ram["uninstrumented_firmware_peak_eligible"] or rhino_tm_irq_ram["performance_or_energy_score_eligible"] or \
            corrected_rhino_tm_irq_ram_table(rhino_tm_irq_ram) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("corrected Rhino original IRQ RAM table or observer-image boundary differs")
    riot_software_irq = software_irq_subset(evidence / "zephyr-isr-riot-v2", os="riot")
    if riot_software_irq["ranking_eligible"] or riot_software_irq["external_gpio_interrupt_entry_measured"] or \
            riot_software_irq["original_one_native_tick_synchronization_preserved"] or \
            riot_software_irq["matrix_route_restoration_verified"] or \
            software_irq_table(riot_software_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("RIOT software-IRQ table or tickless preparation boundary differs")
    nuttx_software_irq = software_irq_subset(evidence / "zephyr-isr-nuttx-v3", os="nuttx")
    if nuttx_software_irq["ranking_eligible"] or nuttx_software_irq["external_gpio_interrupt_entry_measured"] or \
            nuttx_software_irq["original_one_native_tick_synchronization_preserved"] or \
            not nuttx_software_irq["native_preparation_one_tick_timeout_requested"] or \
            software_irq_table(nuttx_software_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("NuttX software-IRQ table or native preparation boundary differs")
    if rhino_tm_irq["ranking_eligible"] or rhino_tm_irq["replacement_of_old_matrix"] or \
            corrected_rhino_tm_irq_table(rhino_tm_irq) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("corrected Rhino original IRQ table or cohort separation differs")
    riot_network = riot_network_readiness(evidence / "riot-benchmark-udp-original-v2", evidence / "riot-network-dependencies-v1")
    alios_network = alios_network_readiness(evidence / "alios-iperf-original-v10")
    alios_corrected = alios_network_corrected(evidence / "alios-iperf-original-v10")
    if alios_corrected["unmodified_official_measurement_method"] or alios_corrected["ranking_eligible"]:
        raise ValueError("corrected native network adapter acquired an unsupported original-method/ranking claim")
    if alios_network_table(alios_corrected) not in (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text():
        raise ValueError("corrected AliOS network report differs from original counters/packet/peer replay")
    if riot_network["network_performance_measured"] or riot_network["ranking_eligible"]:
        raise ValueError("network admission probe promoted into performance results")
    if alios_network["network_performance_measured"] or alios_network["ranking_eligible"]:
        raise ValueError("native AliOS startup/CLI probe promoted into network performance")
    if any(row["reference_workload_peak_eligible"] or row["ranking_eligible"] for row in (ram, ram_iram)):
        raise ValueError("observer-altered memory diagnostics promoted into the original cohort")
    return {"audit": "pass", "scope": "native original extensions, not all existing IoT benchmarks",
            "selected_independent_boot_captures": count, "groups": groups,
            "excluded_network_pilot_captures": 3,
            "excluded_zperf_network_runs": groups["zperf_native_network"][0]["excluded"],
            "excluded_nuttx_network_runs": groups["nuttx_iperf_native_network"][0]["excluded"],
            "excluded_riot_udp_network_runs": groups["riot_udp_native_network"][0]["excluded"],
            "excluded_riot_rhealstone_initial_priority_diagnostic_boots": 4,
            "separate_lifecycle_ram_diagnostics": ram,
            "separate_lifecycle_ram_iram_observations": ram_iram,
            "separate_zephyr_hartstone_ph4_static_ram_observation": zephyr_ram,
            "separate_riot_hartstone_ph4_native_heap_ram_observation": riot_ram,
            "separate_nuttx_hartstone_ph4_native_ram_setup_pilot": nuttx_ram_pilot,
            "separate_nuttx_hartstone_ph4_interrupted_ram_diagnostic": nuttx_ram_diagnostic,
            "separate_nuttx_hartstone_ph4_freelist_ram_build": nuttx_freelist,
            "separate_nuttx_thread_metric_native_heap_context_correction": nuttx_ram_correction,
            "separate_alios_hartstone_ph4_native_ram_build": alios_ram,
            "separate_raw_uart_clock_binding_validation": uart_clock,
            "separate_calibration_prefix_controls": controls,
            "separate_vendor_ignored_isr_diagnostics": isr,
            "separate_corrected_original_method_isr": corrected,
            "separate_freertos_original_zephyr_latency_subset": latency_port,
            "separate_nuttx_original_zephyr_latency_subset": nuttx_latency,
            "excluded_nuttx_latency_initial_version_boots": 3,
            "separate_riot_original_zephyr_latency_subset": riot_latency,
            "excluded_riot_latency_initial_printf_boots": 3,
            "separate_alios_original_zephyr_latency_subset": alios_latency,
            "excluded_alios_latency_initial_assembler_tick_boots": 3,
            "separate_original_zephyr_heap_subsets": heaps,
            "separate_original_zephyr_bounded_stack_subset": stack,
            "separate_original_zephyr_fixed_block_riot_subset": riot_slab,
            "separate_original_zephyr_fixed_block_alios_subset": rhino_slab,
            "separate_original_zephyr_fixed_block_nuttx_subset": nuttx_slab,
            "separate_original_zephyr_syskernel_semaphore_freertos_subset": syskernel_sema,
            "separate_original_zephyr_syskernel_semaphore_nuttx_subset": nuttx_syskernel_sema,
            "separate_original_zephyr_syskernel_semaphore_riot_subset": riot_syskernel_sema,
            "separate_original_zephyr_syskernel_semaphore_alios_subset": alios_syskernel_sema,
            "separate_original_zephyr_syskernel_stack_freertos_subset": syskernel_stack,
            "separate_original_rtems_full_tmck_freertos_validation": full_tmck,
            "separate_original_rtems_full_tmck_zephyr_validation": native_full_tmck["zephyr"],
            "separate_original_rtems_full_tmck_riot_validation": native_full_tmck["riot"],
            "separate_original_rtems_full_tmck_nuttx_validation": native_full_tmck["nuttx"],
            "separate_original_rtems_full_tmck_alios_validation": native_full_tmck["alios"],
            "separate_rhealstone_original_single_irq_port": rhealstone_irq,
            "separate_zephyr_rhealstone_original_single_irq_port": zephyr_rhealstone_irq,
            "separate_nuttx_rhealstone_original_single_irq_port": nuttx_rhealstone_irq,
            "separate_riot_rhealstone_original_single_irq_port": riot_rhealstone_irq,
            "separate_alios_rhealstone_original_single_irq_port": alios_rhealstone_irq,
            "separate_original_rhealstone_iram_placement_controls": rhealstone_iram,
            "separate_original_rhealstone_calibrated_freertos_port": rhealstone_calibrated,
            "separate_original_rhealstone_calibrated_zephyr_port": zephyr_calibrated,
            "separate_original_rhealstone_calibrated_riot_port": riot_calibrated,
            "separate_original_rhealstone_calibrated_nuttx_port": nuttx_calibrated,
            "separate_original_rhealstone_calibrated_alios_port": alios_calibrated,
            "separate_original_rhealstone_baseline_interpretation": baseline_review,
            "separate_original_rhealstone_calibration_coverage": calibration_coverage,
            "separate_original_zephyr_lifecycle_subsets": lifecycles,
            "separate_original_zephyr_yield_subsets": yields,
            "separate_original_riot_yield_freertos_build": riot_yield_build,
            "separate_original_riot_yield_nuttx_build": nuttx_yield_build,
            "separate_original_riot_yield_zephyr_build": zephyr_yield_build,
            "separate_original_riot_yield_alios_build": alios_yield_build,
            "separate_original_riot_thread_flags_freertos_build": flags_build,
            "separate_original_riot_thread_flags_alios_build": alios_flags_build,
            "separate_original_riot_thread_flags_zephyr_build": zephyr_flags_build,
            "separate_original_riot_thread_flags_nuttx_build": nuttx_flags_build,
            "separate_original_riot_msg_freertos_build": msg_build,
            "separate_original_riot_msg_zephyr_build": zephyr_msg_build,
            "separate_original_zephyr_condvar_subsets": condvars,
            "separate_freertos_original_zephyr_condvar_pthread_subset": freertos_condvar,
            "separate_alios_original_zephyr_condvar_posix_subset": alios_condvar,
            "separate_original_zephyr_event_subsets": events,
            "separate_riot_official_event_compatibility_candidate": riot_event_candidate,
            "separate_nuttx_official_driver_event_candidate": nuttx_event_candidate,
            "separate_original_zephyr_software_irq_subset": software_irq,
            "separate_alios_original_zephyr_software_irq_subset": rhino_software_irq,
            "separate_riot_original_zephyr_software_irq_subset": riot_software_irq,
            "separate_nuttx_original_zephyr_software_irq_subset": nuttx_software_irq,
            "separate_alios_original_tm_irq_vector_corrected": rhino_tm_irq,
            "separate_alios_original_tm_irq_vector_ram_observations": rhino_tm_irq_ram,
            "separate_riot_network_admission": riot_network,
            "separate_alios_network_admission": alios_network,
            "separate_alios_corrected_clock_network": alios_corrected,
            "cross_os_ranking_eligible": False, "composite_score": None,
            "gap_ledger": "ESP32_BENCHMARK_GAPS.md", "gap_ledger_sha256": digest(ROOT / "ESP32_BENCHMARK_GAPS.md"),
            "report_sha256": digest(ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md"),
            "remaining": ["remaining applicable native latency cases and matched network profiles",
                          "all original Rhealstone native directive baseline, API semantics and cache interpretation; timer-calibrated captures exist for five ports",
                          "valid external interrupt-entry latency", "zperf RX comparable loss percentage",
                          "original network idle/transaction/sleep energy",
                          "other OS lifecycle RAM, uninstrumented-image and pre-heap/transient peaks"],
            "boundary": "original APIs, statistics and profiles stay separate; diagnostics do not create scores"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
