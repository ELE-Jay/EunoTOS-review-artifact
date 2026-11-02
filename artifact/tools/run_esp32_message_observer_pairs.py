#!/usr/bin/env python3
"""Measure the complete RAM observer's impact with frozen, paired original TM runs."""
import argparse
from datetime import datetime, timezone
import fcntl
import importlib
import json
from pathlib import Path
import shutil
import signal
import statistics
import subprocess

from run_esp32_followup import Board, sha, monotonic_interval
from run_esp32_b1_message import CASE, SOURCES, source_proof, window_durations

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"
MAC = "34:98:7a:a2:85:28"
BOOT_PROFILES = ("freertos-message-boot-handoff-v1", "freertos-message-steps-v1", "freertos-message-boundaries-v1", "freertos-message-combined-stacks-v1", "freertos-message-native-sp-v1")
NUTTX_LOADER_PROFILE = "nuttx-compact-loader-v1"
NUTTX_COMMON_LOADER = "esp32-boot-handoff-build-v1/paired-bootloader"
MONOTONIC_PROFILES = (*BOOT_PROFILES, "zephyr-message-ownership-v1", NUTTX_LOADER_PROFILE)
OBSERVERS = {
    "FreeRTOS": ("run_esp32_tm_ram_lifetimes", "esp32-freertos-message-lifetimes-v1", "TM_RAM END"),
    "Zephyr": ("run_esp32_zephyr_message_lifetimes", "esp32-zephyr-message-lifetimes-v4", "TM_Z_RAM END"),
    "NuttX": ("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-message-lifetimes-v2", "NUTTX_MESSAGE_RAM END"),
}


def observers(profile="native-v1"):
    if profile == "native-v1":
        return OBSERVERS
    if profile == "nuttx-addresses-v1":
        return {"NuttX":("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-message-identities-v1", "NUTTX_MESSAGE_RAM END")}
    if profile == NUTTX_LOADER_PROFILE:
        return {"NuttX":("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-compact-startup-v1", "NUTTX_MESSAGE_RAM END")}
    if profile == "zephyr-message-stack-v1":
        return {"Zephyr":("run_esp32_zephyr_message_lifetimes", "esp32-zephyr-message-stack-v1", "TM_Z_RAM END")}
    if profile == "freertos-message-stack-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-freertos-message-stack-v1", "TM_RAM END")}
    if profile == "freertos-message-startup-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-freertos-message-startup-v1", "TM_RAM END")}
    if profile == "freertos-message-tick-stacks-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-freertos-message-tick-stacks-v1", "TM_RAM END")}
    if profile == "freertos-message-boot-handoff-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-boot-handoff-build-v1", "TM_RAM END")}
    if profile == "freertos-message-steps-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-message-steps-build-v5", "TM_RAM END")}
    if profile == "freertos-message-boundaries-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-message-boundary-build-v5", "TM_RAM END")}
    if profile == "freertos-message-combined-stacks-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-message-native-sp-combined-build-v1", "TM_RAM END")}
    if profile == "freertos-message-native-sp-v1":
        return {"FreeRTOS":("run_esp32_tm_ram_lifetimes", "esp32-message-native-sp-build-v1", "TM_RAM END")}
    if profile == "nuttx-message-startup-v1":
        return {"NuttX":("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-message-startup-v5", "NUTTX_MESSAGE_RAM END")}
    if profile == "nuttx-message-tick-stacks-v1":
        return {"NuttX":("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-message-tick-stacks-v2", "NUTTX_MESSAGE_RAM END")}
    if profile == "nuttx-message-tick-control-v1":
        return {"NuttX":("run_esp32_nuttx_message_lifetimes", "esp32-nuttx-message-tick-control-v1", "NUTTX_MESSAGE_RAM END")}
    if profile == "zephyr-message-startup-v1":
        return {"Zephyr":("run_esp32_zephyr_message_lifetimes", "esp32-zephyr-message-startup-v2", "TM_Z_RAM END")}
    if profile == "zephyr-message-ownership-v1":
        return {"Zephyr":("run_esp32_zephyr_message_lifetimes", "esp32-zephyr-message-ownership-v1", "TM_Z_RAM END")}
    if profile == "zephyr-message-tick-stacks-v1":
        return {"Zephyr":("run_esp32_zephyr_message_lifetimes", "esp32-zephyr-message-tick-stacks-v3", "TM_Z_RAM END")}
    raise ValueError("Unknown frozen observer profile")


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def schedule(profile="native-v1"):
    systems = list(observers(profile))
    return [{"round": r+1, "os": os, "variant": variant}
            for r in range(5) for os in systems[r%len(systems):]+systems[:r%len(systems)]
            for variant in (("baseline", "observer") if (r+systems.index(os))%2 == 0
                            else ("observer", "baseline"))]


def image_sources(system, variant, profile="native-v1"):
    directory, names = SOURCES[system]
    origin = REPORTS / (directory if variant == "baseline" else observers(profile)[system][1])
    mapping = names if variant == "baseline" else {n:n for n in (
        "application.elf", "application.bin", "bootloader.bin", "partitions.bin")}
    result = {saved:origin/name for name,saved in mapping.items()}
    if profile == NUTTX_LOADER_PROFILE:
        result["bootloader.bin"] = REPORTS / NUTTX_COMMON_LOADER / "bootloader.bin"
    return result


def build_proofs(profile="native-v1"):
    result = {}
    for os, (module, name, _) in observers(profile).items():
        observer = importlib.import_module(module).build_proof(REPORTS/name)
        if profile in BOOT_PROFILES:
            from measure_esp32_boot_handoff_ram import build_proof as paired_proof
            paired = paired_proof(REPORTS / name)
            if observer != paired["application"]:
                raise ValueError("Paired bootloader/application qualification differs")
        images = {p.name: sha(p) for p in (REPORTS/name).iterdir()
                  if p.name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin")}
        result[os] = {"baseline": source_proof(os), "observer": observer,
                      "observer_images": images, "observer_manifest_sha256": sha(REPORTS/name/"build.json")}
        if profile == NUTTX_LOADER_PROFILE:
            from audit_esp32_bootloader_ram import build as loader_proof
            boot = REPORTS / NUTTX_COMMON_LOADER
            if not observer.get("compact_observer") or not observer.get("application_startup_stack_coverage"):
                raise ValueError("Requires the exact compact native-startup observer")
            installed = {variant:{n:sha(p) for n,p in image_sources(os,variant,profile).items()}
                         for variant in ("baseline", "observer")}
            if installed["baseline"]["partitions.bin"] != installed["observer"]["partitions.bin"] or \
                    installed["baseline"]["bootloader.bin"] != installed["observer"]["bootloader.bin"]:
                raise ValueError("Matched NuttX loader/partition identity differs")
            result[os].update(installed_images=installed,
                common_loader={"source":boot.relative_to(ROOT).as_posix(), "manifest_sha256":sha(boot/"build.json"),
                    "proof":loader_proof(boot),
                    "scope":"Both variants use the same diagnostic loader; baseline application is native. Not the historical native-loader performance/energy cohort."})
    return result


def read_run(folder, system, variant, proof, profile="native-v1"):
    from audit_esp32_tm_basic import audit as original
    from audit_esp32_tm_reboots import require_self_check
    from audit_esp32_zephyr_thread import read_raw_capture
    rows = read_raw_capture(folder, 1)
    clock = monotonic_interval(rows) if profile in MONOTONIC_PROFILES else None
    if profile in MONOTONIC_PROFILES and clock is None:
        raise ValueError("New paired campaign requires boot-scoped monotonic chronology")
    resets = [r for r in rows if r["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2:
        raise ValueError("Missing independent physical reset")
    require_self_check(rows, "queue")
    value = original(folder/"reset1.jsonl", system, CASE)
    if len(value["original_window_totals"]) != 3 or any(not 25 < n < 40 for n in window_durations(value)):
        raise ValueError("Incomplete original thirty-second windows")
    observer = None
    boot = {}
    if profile == NUTTX_LOADER_PROFILE:
        from measure_esp32_bootloader_ram import observations
        from replay_esp32_bootloader_ram import boot_rows
        lines = [r["line"] for r in rows]
        stages = observations(lines)
        if stages != boot_rows(lines):
            raise ValueError("Common loader replayers disagree")
        phases = [i for i,s in enumerate(lines) if s.startswith("BOOT_RAM phase=")]
        native = [i for i,s in enumerate(lines) if s == "Thread-Metric NuttX ESP32 boot"]
        if len(native) != 1 or max(phases) >= native[0]:
            raise ValueError("Common loader observation must precede native test")
        boot = {"boot_stages":stages}
    if variant == "observer":
        observer = importlib.import_module(observers(profile)[system][0]).read_run(folder, 1, proof["observer"])
        if observer["original_message"] != value:
            raise ValueError("Observer replay and original workload disagree")
        if profile in BOOT_PROFILES:
            from measure_esp32_boot_handoff_ram import observations
            from replay_esp32_bootloader_ram import handoff_row
            from replay_esp32_followup import raw_rows
            address = proof["observer"]["boot_readback_state_address"]
            handoff = observations([r["line"] for r in rows], address)
            separate = [r["line"] for r in raw_rows(folder / "reset1.jsonl")]
            if handoff != handoff_row(separate, address) or handoff["app_sp"] != \
                    observer["application_startup_stack"]["application_entry_sp"]:
                raise ValueError("Paired boot readback differs")
            observer["boot_handoff"] = handoff
        if profile == "freertos-message-steps-v1":
            from measure_esp32_message_steps import step_observations
            steps = step_observations([r["line"] for r in rows])
            if steps["unclassified_sp_observations"]:
                raise ValueError("Paired continuous observer has unclassified contexts")
            observer["continuous_stack"] = steps
    return {"original_message": value, "observer": observer,
            **boot,
            "start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"],
            **({"monotonic_interval": clock} if clock is not None else {}),
            "raw_sha256": sha(folder/"reset1.raw")}


def run_schedule(board, output, proofs, campaign, profile="native-v1"):
    # Always restore once a verified backup exists, including timeout/SIGTERM paths.
    board.backup()
    try:
        order = schedule(profile)
        selected = observers(profile)
        for item in order:
            os, variant, round_ = item["os"], item["variant"], item["round"]
            folder = output/"runs"/("round%d" % round_)/os/variant
            folder.mkdir(parents=True)
            pairs = board.flash(folder, output/"builds"/os/variant)
            seconds = (150 if profile in ("freertos-message-steps-v1", "freertos-message-boundaries-v1", "freertos-message-combined-stacks-v1") else 110) if variant == "observer" else 95
            board.capture(folder, 1, seconds,
                          stop=selected[os][2] if variant == "observer" else None,
                          send="iotosbench" if os == "NuttX" else None,
                          **({"monotonic_clock": True} if profile in MONOTONIC_PROFILES else {}))
            board.verify(pairs, folder/"verify-after.log")
            result = read_run(folder, os, variant, proofs[os], profile)
            write_json(folder/"result.json", result)
            campaign["completed_resets"] += 1
            write_json(output/"progress.json", {**item, "completed_resets": campaign["completed_resets"],
                                               "total_resets": len(order), "completed_utc": result["end_utc"]})
            print("PAIR", round_, os, variant, result["original_message"]["original_window_totals"], flush=True)
        campaign["status"] = "collection_complete_audit_pending"
    finally:
        board.restore()
        campaign["original_flash_restored"] = True


def collect(root, output, port, profile="native-v1"):
    if shutil.disk_usage(output.parent).free < 128 * 1024**2:
        raise ValueError("Insufficient persistent evidence space")
    device = subprocess.check_output(["udevadm", "info", "-q", "property", "-n", port]).decode()
    if not {"ID_VENDOR_ID=1a86", "ID_MODEL_ID=7523", "ID_USB_DRIVER=ch341"} <= set(device.splitlines()):
        raise ValueError("Unexpected ESP32 serial bridge")
    proofs = build_proofs(profile)
    selected = observers(profile)
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        write_json(output/"proofs.json", proofs)
        write_json(output/"plan.json", {"schedule": schedule(profile), "primary": "first original 30-second count B/A",
            "pairs_per_os": 5, "board_mac": MAC, "case": CASE, "source_proof_sha256": sha(output/"proofs.json"),
            **({"chronology": "host-boot-scoped-monotonic-ns-v1"} if profile in MONOTONIC_PROFILES else {}),
            **({"profile":profile} if profile != "native-v1" else {})})
        (output/"device.log").write_text(device, encoding="utf-8")
        for file, saved in ((Path(__file__), "runner.py"),
                            (Path(__file__).with_name("run_esp32_followup.py"), "board-helper.py"),
                            (root/"capture_esp32_uart.py", "capture_esp32_uart.py")):
            shutil.copyfile(file, output/saved)
        for os in selected:
            for variant in ("baseline", "observer"):
                target = output/"builds"/os/variant
                target.mkdir(parents=True)
                for saved, origin in image_sources(os,variant,profile).items():
                    shutil.copyfile(origin, target/saved)
        campaign = {"mode": "message-observer-pairs", "status": "incomplete", "board_mac": MAC,
            "completed_resets": 0, "started_utc": datetime.now(timezone.utc).isoformat(),
            "original_flash_restored": False, "old_cohort_modified": False, "energy_measured": False,
            "external_independent_replication": False}
        try:
            run_schedule(Board(root, output, MAC, port), output, proofs, campaign, profile)
        finally:
            campaign["completed_utc"] = datetime.now(timezone.utc).isoformat()
            campaign["files"] = {p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file()}
            write_json(output/"campaign.json", campaign)


def audit(output):
    from audit_esp32_followup import envelope, verified
    campaign = envelope(output)
    plan = json.loads((output/"plan.json").read_text())
    profile = plan.get("profile","native-v1")
    selected, proofs, order = observers(profile), build_proofs(profile), schedule(profile)
    if campaign["mode"] != "message-observer-pairs" or campaign["board_mac"] != MAC or campaign["completed_resets"] != len(order):
        raise ValueError("Incomplete paired experiment")
    if json.loads((output/"proofs.json").read_text()) != json.loads(json.dumps(proofs)) or json.loads(
            (output/"plan.json").read_text()) != {"schedule": order, "primary": "first original 30-second count B/A",
            "pairs_per_os": 5, "board_mac": MAC, "case": CASE, "source_proof_sha256": sha(output/"proofs.json"),
            **({"chronology": "host-boot-scoped-monotonic-ns-v1"} if profile in MONOTONIC_PROFILES else {}),
            **({"profile":profile} if profile != "native-v1" else {})}:
        raise ValueError("Frozen configuration/protocol changed")
    for os in selected:
        _, mapping = SOURCES[os]
        for variant in ("baseline", "observer"):
            expected = ({saved:proofs[os]["baseline"]["images"][name] for name,saved in mapping.items()}
                        if variant == "baseline" else proofs[os]["observer_images"])
            if profile == NUTTX_LOADER_PROFILE:
                expected = proofs[os]["installed_images"][variant]
            if {p.name:sha(p) for p in (output/"builds"/os/variant).iterdir()} != expected:
                raise ValueError("Paired installed image differs from source")
    records, previous, previous_domain = {}, None, None
    for item in order:
        os, variant, round_ = item["os"], item["variant"], item["round"]
        folder = output/"runs"/("round%d" % round_)/os/variant
        verified(folder, output/"builds"/os/variant, MAC)
        result = read_run(folder, os, variant, proofs[os], profile)
        if json.loads(json.dumps(result)) != json.loads((folder/"result.json").read_text()):
            raise ValueError("Saved statistics differ from original capture")
        if profile in MONOTONIC_PROFILES:
            clock = result["monotonic_interval"]
            domain, start, end = clock["host_boot_id"], clock["start_ns"], clock["end_ns"]
        else:
            domain = "UTC"
            start, end = (datetime.fromisoformat(result[k]) for k in ("start_utc", "end_utc"))
        if start >= end or previous is not None and (domain != previous_domain or previous >= start):
            raise ValueError("Declared paired chronology differs")
        previous, previous_domain = end, domain
        records[os, round_, variant] = result["original_message"]["original_window_totals"]
    cells = []
    for os in selected:
        pairs = [{"round": r, "baseline_counts": records[os,r,"baseline"],
                  "observer_counts": records[os,r,"observer"],
                  "first_window_ratio": records[os,r,"observer"][0]/records[os,r,"baseline"][0]}
                 for r in range(1,6)]
        ratios = [p["first_window_ratio"] for p in pairs]
        cells.append({"os": os, "pairs": pairs, "median_ratio": statistics.median(ratios),
                      "ratio_range": [min(ratios),max(ratios)], "independent_resets": 10,
                      "observer_static_delta_bytes": proofs[os]["observer"]["static_sram_bytes"]-
                          proofs[os]["observer"]["baseline_static_sram_bytes"]})
    return {"audit": "pass", "board_mac": MAC, "independent_resets": len(order), "cells": cells,
            **({"chronology": "host-boot-scoped-monotonic-ns-v1", "host_boot_id": previous_domain}
               if profile in MONOTONIC_PROFILES else {}),
            "original_flash_restored": True, "energy_measured": False, "ranking_eligible": False,
            "whole_live_ram_peak_bytes": None, "scope": (
                "Native application versus compact RAM observer under the same diagnostic loader and partition table; not historical native-loader performance/energy or isolated hook cost."
                if profile == NUTTX_LOADER_PROFILE else
                "whole observer-image intervention including code layout; not isolated hook cost or inferred uninstrumented RAM")}


def ownership_paper_text(value):
    if value['independent_resets']!=10 or len(value['cells'])!=1 or value['cells'][0]['os']!='Zephyr' or \
            value.get('chronology')!='host-boot-scoped-monotonic-ns-v1':
        raise ValueError('Entry-vector control requires the exact ten-reset Zephyr cohort')
    cell=value['cells'][0];low,high=[(r-1)*100 for r in cell['ratio_range']]
    return ('Five alternating baseline/entry-vector-observer pairs add ten independent Zephyr '
        f'resets. The first original-window count changes by a median of {(cell["median_ratio"]-1)*100:+.6f}\\% '
        f'(range {low:+.6f}\\% to {high:+.6f}\\%). Both replayers agree, with host-monotonic '
        'chronology and restored original Flash. This control belongs to the new vector-readback '
        'image and includes layout and all observer code; it does not estimate isolated hook '
        'cost or justify subtracting instrumentation from allocated RAM.')


def nuttx_loader_paper_text(value):
    if value['independent_resets']!=10 or len(value['cells'])!=1 or value['cells'][0]['os']!='NuttX' or \
            value.get('chronology')!='host-boot-scoped-monotonic-ns-v1' or 'same diagnostic loader' not in value['scope']:
        raise ValueError('Compact NuttX control requires the matched-loader ten-reset cohort')
    c=value['cells'][0];low,high=[(r-1)*100 for r in c['ratio_range']]
    return ('Five alternating native/compact-observer NuttX pairs add ten independent resets. '
        'Both applications retain the same diagnostic IDF~5.2.5 loader and identical partition table. '
        f'The first original-window count changes by a median of {(c["median_ratio"]-1)*100:+.6f}\\% '
        f'(range {low:+.6f}\\% to {high:+.6f}\\%). The static application difference is '
        f'{c["observer_static_delta_bytes"]:,}\\,B. Both replayers agree, host-monotonic chronology '
        'is retained, and original Flash is restored. The contrast includes application layout and '
        'all observer code; it neither replaces native-loader performance/energy nor estimates '
        'uninstrumented RAM by subtracting the static difference.')


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("proof", "collect", "audit"))
    p.add_argument("--root", type=Path, default=Path.home()/"esp32-pilot")
    p.add_argument("--output", type=Path)
    p.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    p.add_argument("--profile", choices=("native-v1","nuttx-addresses-v1","zephyr-message-stack-v1","freertos-message-stack-v1","freertos-message-startup-v1","freertos-message-tick-stacks-v1","freertos-message-boot-handoff-v1","freertos-message-steps-v1","freertos-message-boundaries-v1","freertos-message-combined-stacks-v1","freertos-message-native-sp-v1","nuttx-message-startup-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1","zephyr-message-startup-v1","zephyr-message-tick-stacks-v1","zephyr-message-ownership-v1",NUTTX_LOADER_PROFILE),default="native-v1")
    a = p.parse_args()
    if a.mode != "proof" and a.output is None:
        p.error("--output required")
    def interrupted(signum, frame):
        signal.alarm(0)
        raise InterruptedError("Collection interrupted; restoring original Flash")
    signal.signal(signal.SIGTERM, interrupted)
    if a.mode == "collect":
        if a.profile in ("freertos-message-tick-stacks-v1",*MONOTONIC_PROFILES,"zephyr-message-tick-stacks-v1","nuttx-message-tick-stacks-v1","nuttx-message-tick-control-v1"):
            signal.signal(signal.SIGALRM, interrupted)
            signal.alarm(2400)
        try:
            collect(a.root, a.output, a.port, a.profile)
        finally:
            signal.alarm(0)
    else:
        result = build_proofs(a.profile) if a.mode == "proof" else audit(a.output)
        if a.mode == "audit":
            write_json(a.output/"audit.json", result)
        print(json.dumps(result, indent=2))
