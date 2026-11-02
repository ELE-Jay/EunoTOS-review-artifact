#!/usr/bin/env python3
"""Report matched message-task RAM evidence, retaining observer and scope limits."""
import argparse
import json
from pathlib import Path

from run_esp32_followup import sha
from run_esp32_tm_ram_lifetimes import audit as freertos
from run_esp32_zephyr_message_lifetimes import audit as zephyr
from run_esp32_nuttx_message_lifetimes import audit as nuttx

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
SPECS = [("FreeRTOS",freertos,"esp32-freertos-message-lifetimes-b1-v3","esp32-freertos-message-lifetimes-v1"),
         ("Zephyr",zephyr,"esp32-zephyr-message-lifetimes-b1-v1","esp32-zephyr-message-lifetimes-v4"),
         ("NuttX",nuttx,"esp32-nuttx-message-lifetimes-b1-v2","esp32-nuttx-message-lifetimes-v2")]


def followup_validation():
    from run_esp32_message_observer_pairs import audit as pairs_audit
    name="esp32-message-observer-pairs-b1-v1"
    paired=pairs_audit(REPORTS/name)
    if paired!=json.loads((REPORTS/name/"audit.json").read_text()) or paired["independent_resets"]!=30:
        raise ValueError("Existing paired observer evidence changed")
    validations=[]
    for system,fn,campaign,build in (
        ("FreeRTOS",freertos,"esp32-freertos-task-lifecycle-validation-b1-v1","esp32-freertos-task-lifecycle-validation-build-v1"),
        ("Zephyr",zephyr,"esp32-zephyr-task-lifecycle-validation-b1-v1","esp32-zephyr-task-lifecycle-validation-build-v1"),
        ("NuttX",nuttx,"esp32-nuttx-task-lifecycle-validation-b1-v3","esp32-nuttx-task-lifecycle-validation-build-v3")):
        folder=REPORTS/campaign
        if not (folder/"audit.json").is_file():
            validations.append({"os":system,"status":"pending","evidence":"artifacts/reports/"+campaign})
            continue
        result=fn(folder,REPORTS/build)
        if json.loads(json.dumps(result))!=json.loads((folder/"audit.json").read_text()) or \
                result["independent_resets"]!=5 or not result["original_flash_restored"] or result["benchmark_result"]:
            raise ValueError("Finite native lifecycle validation changed: "+system)
        lifetimes=[r["task_lifecycles"] for r in result["runs"]]
        if any(r["completed"]!=4 for r in lifetimes):
            raise ValueError("Incomplete finite native lifecycle validation")
        reused="reused_static_address_pairs" if system=="Zephyr" else "reused_address_pairs"
        validations.append({"os":system,"status":"complete","evidence":"artifacts/reports/"+campaign+"/audit.json",
            "independent_resets":5,"completed_lifetimes":sum(r["completed"] for r in lifetimes),
            "reused_tcb_stack_address_pairs":sum(r[reused] for r in lifetimes),
            "storage":"static reservations retained after join" if system=="Zephyr" else "native dynamic allocations reclaimed",
            "benchmark_result":False,"ranking_eligible":False})
    native_inventory={"status":"pending","os":"FreeRTOS"}
    inventory=REPORTS/"esp32-freertos-memory-boundaries-v1"
    if (inventory/"audit.json").is_file():
        from audit_esp32_native_memory_boundaries import audit as boundary_audit
        boundary=boundary_audit()
        if json.loads(json.dumps(boundary))!=json.loads((inventory/"audit.json").read_text()):
            raise ValueError("Native memory inventory replay changed")
        native_inventory={"status":"complete","os":"FreeRTOS","evidence":inventory.relative_to(ROOT).as_posix()+"/audit.json",
            "reused_workload_resets":boundary["reused_workload_resets"],"new_board_resets":0,
            "native_heap_pools":len(boundary["expected_native_heaps"]),"ranking_eligible":False,
            "scope":"Complete compiled native heap inventory; ROM/cache/RTC occupancy and continuous live-stack peak remain unresolved"}
    peak_context = {"status": "pending", "os": "FreeRTOS"}
    peak_folder = REPORTS / "esp32-freertos-peak-context-b1-v1"
    if (peak_folder / "audit.json").is_file():
        peak_build = REPORTS / "esp32-freertos-peak-context-build-v1"
        result = freertos(peak_folder, peak_build)
        if json.loads(json.dumps(result)) != json.loads((peak_folder / "audit.json").read_text()):
            raise ValueError("Allocation-peak context evidence changed")
        from replay_esp32_freertos_message import replay as independent_peak_replay
        separate = independent_peak_replay(peak_folder, peak_build)
        if any(r["allocation_peak_context"]["phases"] != s["allocation_peak_contexts"]
               for r, s in zip(result["runs"], separate["runs"], strict=True)):
            raise ValueError("Independent allocation-peak context replay differs")
        peak_context = {"status": "complete", "os": "FreeRTOS", "independent_resets": 5,
            "evidence": peak_folder.relative_to(ROOT).as_posix() + "/audit.json",
            "native_heap_peak_bytes": [r["heap_peak_bytes"] for r in result["runs"]],
            "static_sram_bytes": result["build"]["static_sram_bytes"],
            "original_flash_restored": result["original_flash_restored"], "ranking_eligible": False,
            "scope": "Same-instant native contexts at phase allocation high-water; not a continuous whole-live peak"}
    return {"observer_impact":{"status":"complete","evidence":"artifacts/reports/"+name+"/audit.json",
                "independent_resets":30,"scope":paired["scope"]},
            "finite_task_lifecycles":validations,"native_memory_inventory":native_inventory,
            "allocation_peak_context": peak_context,
            "scope":"Separate validation of native retirement/reclamation and storage reuse; no change to original message results or whole-live-RAM qualification"}


def audit():
    cells = []
    for os,fn,campaign,build in SPECS:
        result = fn(REPORTS/campaign,REPORTS/build)
        if result["audit"] != "pass" or result["independent_resets"] != 5 or not result["original_flash_restored"]:
            raise ValueError("Incomplete lifecycle campaign")
        proof = result["build"]
        static = proof["static_sram_bytes"]
        key = "heap_peak_bytes" if os == "FreeRTOS" else "native_heap_peak_bytes"
        heaps = [r[key] for r in result["runs"]]
        totals = [static+(0 if os == "Zephyr" else h) for h in heaps]
        cells.append({"os":os,"evidence":"artifacts/reports/"+campaign,"build":"artifacts/reports/"+build,
            "campaign_sha256":sha(REPORTS/campaign/"campaign.json"), "elf_sha256":sha(REPORTS/build/"application.elf"),
            "static_sram_bytes":static,"baseline_static_sram_bytes":proof["baseline_static_sram_bytes"],
            "observer_static_delta_bytes":static-proof["baseline_static_sram_bytes"],
            "native_heap_peak_bytes":heaps,"observed_allocated_software_bytes":totals,
            "heap_inside_static":os == "Zephyr","independent_resets":5,
            "original_counts":[r["original_message"]["original_window_totals"] for r in result["runs"]]})
    return {"audit":"pass","board_mac":"34:98:7a:a2:85:28","clock_mhz":240,"cores":1,"tick_hz":100,
        "compiler":"GCC13.2","workload":"original Thread-Metric message_processing",
        "workload_resets":15,"cells":cells,"whole_live_ram_peak_bytes":None,"ranking_eligible":False,
        "old_results_replaced":False,"scope":"native heap initialization through third original message report; observer-inclusive static reservations plus nonoverlapping allocated heaps",
        "followup_validation":followup_validation(),
        "remaining":["pre-allocator and unmanaged memory boundaries","exact simultaneous live stack use"],
        "limitations":["native heap counters include different allocator metadata scopes; do not rank heap subcounts",
                       "NuttX replays byte deltas and stack identities, not all allocation-pointer identities",
                       "original infinite tasks remain alive; finite native-task lifecycle validation is reported separately",
                       "historical stack watermarks are not summed; static heap pools are not added twice"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path)
    a = p.parse_args()
    result = audit()
    if a.output: a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps(result,ensure_ascii=False,indent=2))
