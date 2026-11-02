#!/usr/bin/env python3
"""Audit the new TCP cohort with the original endpoint-specific arithmetic."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import statistics
import shlex

from audit_esp32_followup import envelope, verified
from audit_esp32_iperf_original import capture as idf_capture
from audit_esp32_nuttx_iperf_original import capture as nuttx_capture
from audit_esp32_zperf_original import capture as zephyr_capture, native_image
from audit_esp32_report import audit_image_manifest
from audit_esp32_resources import audit_elf_image
from run_esp32_followup import sha
from run_esp32_network_controlled import SOURCES, SCHEDULE, RESUME_TASKS, RETAINED, configuration
from audit_esp32_zephyr_thread import read_raw_capture

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "artifacts/reports"
PROFILES = {"FreeRTOS": ("idf", "iperf-original-v1"), "Zephyr": ("zephyr", "zperf-original-v3"),
            "NuttX": ("nuttx", "nuttx-iperf-original-v5")}


def build(system, protocol="tcp"):
    short, reference = PROFILES[system]
    folder = EVIDENCE / ("esp32-network-controlled-" + short + ("-v2" if system == "NuttX" else "-v1"))
    configuration(system, folder)
    audit_image_manifest(folder, {"config", "compiler.txt", "build.log"}, allow_nested=True)
    originals = json.loads((EVIDENCE / reference / "official-source.json").read_text())
    for row in originals:
        if sha(folder / row["path"]) != row["sha256"]:
            raise ValueError("Original network source changed: " + row["path"])
    if system == "Zephyr":
        native_image(folder)
    else:
        audit_elf_image(folder / ("iperf.elf" if system == "FreeRTOS" else "nuttx"),
                        folder / ("iperf.bin" if system == "FreeRTOS" else "nuttx.bin"))
    commands = (folder / ("compile_commands.json" if system != "NuttX" else "build.log")).read_text()
    if system == "NuttX":
        for name in ("iperf.c", "iperf_main.c"):
            found = [shlex.split(line) for line in commands.splitlines() if line.startswith("xtensa-esp32-elf-gcc -c ") and
                     " " + name + " -o " in line and ".apps.netutils.iperf.o" in line]
            if len(found) != 1 or "-O2" not in found[0] or "-Os" in found[0]:
                raise ValueError("Original NuttX program -O2 compilation missing")
    else:
        rows = json.loads(commands)
        wanted = ("cmd_wifi.c", "iperf_example_main.c", "iperf.c") if system == "FreeRTOS" else \
                 ("main.c", "zperf_" + protocol + "_receiver.c", "zperf_" + protocol + "_uploader.c")
        for name in wanted:
            found = [r for r in rows if Path(r["file"]).name == name]
            if not found or not any(" -O2 " in r["command"] for r in found):
                raise ValueError("Original TCP program -O2 compilation missing: " + name)
    return {"audit": "pass", "source_files": len(originals), "compiler": "GCC13.2", "optimization": "-O2",
            "images": {saved: sha(folder / name) for name, saved in SOURCES[system][2].items()},
            "config_sha256": sha(folder / "config"),
            "boundary": "native networking stacks and RF/SDK versions retained"}


def default_route_path(record):
    raw = record["routes"]["output"]
    if raw.lstrip().startswith("["):
        rows = [{k: v for k, v in r.items() if k != "metric"}
                for r in json.loads(raw) if r.get("dst") == "default"]
    else:
        rows = []
        for line in raw.splitlines():
            parts = line.split()
            if parts[:1] != ["default"]:
                continue
            if "metric" in parts:
                at = parts.index("metric")
                del parts[at:at + 2]
            rows.append(parts)
    if not rows:
        raise ValueError("No default-route witness")
    return rows


def host_restored(folder):
    before, after = [json.loads((folder / ("host-" + stage + ".json")).read_text()) for stage in ("before", "after")]
    if any(r["radio"]["output"].strip() != "disabled" or r["radio"]["returncode"] for r in (before, after)):
        raise ValueError("Host radio state was not restored")
    if default_route_path(before) != default_route_path(after):
        raise ValueError("Host default gateway/interface changed")
    return {"gateway_interface_restored": True, "radio_disabled": True,
            "route_metric_changed": before["routes"]["output"] != after["routes"]["output"],
            "boundary": "NetworkManager may temporarily add a connectivity metric penalty; private AP traffic uses the direct subnet route, not the default route"}


def audit(folder):
    campaign = envelope(folder)
    udp = campaign["mode"] == "network-controlled-udp"
    cases = ("udp_tx", "udp_rx") if udp else ("tcp_tx", "tcp_rx")
    if campaign["mode"] not in ("network-controlled", "network-controlled-resume", "network-controlled-udp") or campaign["board_mac"] != "34:98:7a:a2:85:28" or \
            campaign["schedule"] != [list(order) for order in SCHEDULE] or campaign["ranking_eligible"]:
        raise ValueError("Controlled cohort identity/schedule differs")
    if campaign["protocol"]["directions"] != list(cases) or any(campaign["protocol"][k] != v for k, v in
            (("cores", 1), ("clock_mhz", 240), ("tick_hz", 100), ("seconds", 60))):
        raise ValueError("Controlled protocol/window differs")
    if udp and campaign["protocol"]["payload_bytes"] != {"FreeRTOS": 1472, "NuttX": 1472, "Zephyr": 1024}:
        raise ValueError("Controlled original UDP payload sizes differ")
    parent = None
    parent_proof = None
    if campaign["mode"] == "network-controlled-resume":
        expected = RESUME_TASKS
        relation = campaign["parent"]
        parent = folder.parent / relation["directory"]
        if relation["directory"] != "esp32-network-controlled-b1-v2" or \
                sha(parent / "campaign.json") != relation["campaign_sha256"] or \
                campaign["selected_os_rounds"] != expected or relation["replaced_os_rounds"] != expected or \
                relation["retained_closed_os_rounds"] != RETAINED:
            raise ValueError("Resume selection differs from the sealed interruption protocol")
        parent_proof = audit_interrupted(parent)
    host = json.loads((EVIDENCE / "esp32-network-controlled-zephyr-v1/dependencies/provenance.json").read_text())
    if sha(folder / "iperf-host") != host["iperf_binary_sha256"]:
        raise ValueError("Native iPerf 2.0.5 peer differs")
    host_proof = host_restored(folder)
    parsers = {"FreeRTOS": idf_capture, "Zephyr": zephyr_capture, "NuttX": nuttx_capture}
    cells, sequence = [], []
    for system in SOURCES:
        proof = build(system, "udp" if udp else "tcp")
        build_dir = folder / system / "build"
        if any(sha(build_dir / name) != digest for name, digest in proof["images"].items()) or \
                sha(folder / system / "config") != proof["config_sha256"]:
            raise ValueError("Acquired network image/config differs from qualified build")
        runs = {case: [] for case in cases}
        for index in (1, 2, 3):
            origin = parent if parent is not None and [index, system] not in campaign["selected_os_rounds"] else folder
            base = origin / system / ("run%d" % index)
            selected_build = origin / system / "build"
            if any(sha(selected_build / n) != value for n, value in proof["images"].items()):
                raise ValueError("Resume candidate image differs from parent")
            verified(base, selected_build, campaign["board_mac"])
            for case in runs:
                result = parsers[system](base / case, case, controlled=True)
                actions = json.loads((base / case / "actions.json").read_text())
                if sum(r.get("peer_port_ready") is True for r in actions) != 1 or \
                        (case.endswith("tx") and sum(r.get("peer_listener_ready") is True for r in actions) != 1):
                    raise ValueError("Controlled peer port/listener readiness not witnessed")
                if udp:
                    ports = [r for r in actions if r.get("peer_port_ready")]
                    listeners = [r for r in actions if r.get("peer_listener_ready")]
                    if ports[0].get("protocol") != "udp" or case.endswith("tx") and listeners[0]["state"]["arguments"] != \
                            ["ss", "-lun", "sport", "=", ":5001"]:
                        raise ValueError("UDP peer readiness used a TCP socket check")
                if (origin.name == "esp32-network-controlled-b1-v6" or udp) and \
                        sum(r.get("controlled_ap_ready") is True for r in actions) != 1:
                    raise ValueError("Resumed AP discovery barrier not witnessed")
                if "bind failed" in (base / case / "host.log").read_text():
                    raise ValueError("Original peer did not bind its declared address")
                runs[case].append(result)
                result["evidence_campaign"] = origin.name
                sequence.append((datetime.fromisoformat(result["start_utc"]),
                                 datetime.fromisoformat(result["end_utc"]), index, system, case))
                if system == "FreeRTOS":
                    uart = (base / case / "uart.jsonl").read_text()
                    if "ELF file SHA256:  " + proof["images"]["application.elf"][:9] + "..." not in uart:
                        raise ValueError("Native image fingerprint missing")
        for case, captures in runs.items():
            values = [r["receiver_decimal_mbit_s"] for r in captures]
            cells.append({"os": system, "case": case, "values": values,
                          "median": statistics.median(values) if all(v is not None for v in values) else None,
                          "unit": "Mbit/s", "captures": captures, "build": proof, "independent_resets": 3,
                          "receiver_durations_s": [r["receiver_duration_s"] for r in captures],
                          "nominal_duration_guard_passed": all(r["nominal_duration_guard_passed"] for r in captures),
                          "ranking_eligible": False})
            if udp and system == "Zephyr":
                folder_source = EVIDENCE / "esp32-network-controlled-zephyr-v1/zperf-library"
                if any("k_uptime_ticks()" not in (folder_source / name).read_text() for name in
                       ("zperf_udp_receiver.c", "zperf_udp_uploader.c")):
                    raise ValueError("Original zperf UDP timestamp source differs")
                cells[-1]["original_jitter_timestamp_quantum_us"] = 10000
                cells[-1]["jitter_scope"] = "original estimator includes 100-Hz sender/receiver tick quantization; not a sub-millisecond pure network jitter measurement"
    sequence.sort()
    expected = [(i, system, case) for i, order in enumerate(SCHEDULE, 1) for system in order for case in cases]
    if parent is not None:
        expected = [(i, system, case) for i, system in RETAINED + RESUME_TASKS for case in ("tcp_tx", "tcp_rx")]
    if [row[2:] for row in sequence] != expected or any(a[1] >= b[0] for a, b in zip(sequence, sequence[1:])):
        raise ValueError("Independent network captures overlap or acquisition order differs")
    result = {"audit": "pass", "board": "B1", "independent_resets": len(sequence), "cells": cells,
            "protocol": campaign["protocol"], "controlled": ["board", "CPU clock", "cores", "tick", "compiler",
                "optimization", "channel", "peer", "direction", "radio buffer counts"],
            "ranking_eligible": False, "energy_measured": False,
            "remaining": ["zperf 1024 B and explicit yield versus iPerf 16384 B",
                          "native TCP/RF stack and buffer-byte/window policies differ",
                          "RF environment is shared laboratory air, not shielded or attenuator-controlled",
                          "UDP loss/jitter not recollected in this TCP cohort",
                          "original receiver connection duration can exceed nominal 60 s; extended captures remain ineligible for fixed-window comparison"],
            "fixed_receiver_window_comparison_eligible": False,
            "host_restoration": host_proof, "resumed_parent": parent_proof,
            "rotation_interrupted_and_resumed": parent is not None}
    if udp:
        result["remaining"] = ["zperf 1024 B versus iPerf 1472 B",
            "NuttX TX is unpaced; IDF and zperf request 10 Mbit/s",
            "requested sender rates are configuration values, not proof of equal actual emission",
            "IDF/NuttX lack a complete original UDP final handshake; missing loss/jitter are not synthesized",
            "zperf RX first-packet omission and sequence-gap/tail convention retained",
            "zperf uses 100-Hz uptime ticks here: original jitter includes 10-ms timestamp quantization",
            "native RF/stack policies and shared laboratory air; no common OS network ranking"]
    return result


def audit_interrupted(folder):
    campaign = envelope(folder, allow_incomplete=True)
    if campaign["status"] != "incomplete" or campaign["mode"] != "network-controlled" or \
            campaign["board_mac"] != "34:98:7a:a2:85:28" or campaign.get("error") != "Error: Timeout expired (35 seconds)\n":
        raise ValueError("Not the retained WPA-timeout interruption")
    parsers = {"FreeRTOS": idf_capture, "Zephyr": zephyr_capture, "NuttX": nuttx_capture}
    completed = []
    for index, order in enumerate(SCHEDULE, 1):
        for system in order:
            if [index, system] not in RETAINED:
                continue
            proof = build(system)
            image = folder / system / "build"
            if sha(folder / system / "config") != proof["config_sha256"] or \
                    any(sha(image / n) != value for n, value in proof["images"].items()):
                raise ValueError("Interrupted campaign's candidate differs")
            base = folder / system / ("run%d" % index)
            verified(base, image, campaign["board_mac"])
            for case in ("tcp_tx", "tcp_rx"):
                completed.append({"os": system, "round": index, "case": case,
                                  "capture": parsers[system](base / case, case, controlled=True)})
    failed = folder / "NuttX/run3/tcp_rx"
    read_raw_capture(failed, "", prefix="uart")
    actions = json.loads((failed / "actions.json").read_text())
    if any(r.get("host_command") or r.get("capture_complete") for r in actions) or \
            not any(r.get("returncode") == 3 and r.get("output") == campaign["error"] for r in actions):
        raise ValueError("WPA timeout was not before the throughput workload")
    try:
        diagnostic = nuttx_capture(folder / "NuttX/run3/tcp_tx", "tcp_tx", controlled=True)
    except ValueError as error:
        if str(error) != "peer observations/aggregate incomplete":
            raise
        diagnostic = {"status": "not_a_valid_result", "error": str(error),
                      "raw_sha256": sha(folder / "NuttX/run3/tcp_tx/uart.raw"),
                      "host_sha256": sha(folder / "NuttX/run3/tcp_tx/host.log")}
    verified(folder / "NuttX/run3", folder / "NuttX/build", campaign["board_mac"],
             logs=("identity.log", "flash.log", "verify-before.log"))
    if (folder / "NuttX/run3/verify-after.log").exists():
        raise ValueError("Interruption no longer matches the missing post-round verification")
    excluded = []
    for system, parser in (("FreeRTOS", idf_capture), ("NuttX", nuttx_capture)):
        base = folder / system / "run2"
        verified(base, folder / system / "build", campaign["board_mac"])
        try:
            parser(base / "tcp_tx", "tcp_tx", controlled=True)
        except ValueError as error:
            if str(error) not in ("TCP peer final aggregate missing", "peer observations/aggregate incomplete"):
                raise
            excluded.append({"os": system, "round": 2, "reason": str(error),
                             "unused_valid_rx": parser(base / "tcp_rx", "tcp_rx", controlled=True)})
        else:
            raise ValueError("Excluded round no longer has the declared missing receiver aggregate")
    return {"audit": "pass", "status": "incomplete_wpa_timeout", "closed_direction_captures": 10,
            "completed": completed, "unclosed_diagnostic_tx": diagnostic,
            "excluded_rounds": excluded,
            "failed_direction": "NuttX tcp_rx round3", "cohort_resets": 0, "ranking_eligible": False,
            "original_flash_restored": True, "host_restoration": host_restored(folder)}


def audit_failure(folder):
    campaign = envelope(folder, allow_incomplete=True)
    if campaign["status"] != "incomplete" or campaign["mode"] != "network-controlled" or \
            campaign["board_mac"] != "34:98:7a:a2:85:28":
        raise ValueError("Not the retained failed network acquisition")
    completed = []
    for system, parser in (("FreeRTOS", idf_capture), ("Zephyr", zephyr_capture)):
        proof = build(system)
        build_dir = folder / system / "build"
        if any(sha(build_dir / n) != digest for n, digest in proof["images"].items()):
            raise ValueError("Failed campaign's completed candidate differs")
        verified(folder / system / "run1", build_dir, campaign["board_mac"])
        for case in ("tcp_tx", "tcp_rx"):
            completed.append({"os": system, "case": case,
                              "capture": parser(folder / system / "run1" / case, case, controlled=True)})
    failed = folder / "NuttX/run1/tcp_tx"
    rows = read_raw_capture(failed, "", prefix="uart")
    if "bind failed: Address already in use" not in (failed / "host.log").read_text() or \
            not any("tcp client connect error" in r["line"] for r in rows):
        raise ValueError("Declared peer-bind failure is not witnessed")
    actions = json.loads((failed / "actions.json").read_text())
    if any(r.get("capture_complete") for r in actions):
        raise ValueError("Failed direction was declared complete")
    return {"audit": "pass", "status": "incomplete_host_peer_failure", "completed_direction_captures": len(completed),
            "completed": completed, "failed_direction": "NuttX tcp_tx reset1",
            "cause": "host peer bind failed; board client refused; no NuttX throughput result",
            "original_flash_restored": True, "cohort_resets": 0, "ranking_eligible": False}


def audit_failed_resume(folder):
    campaign = json.loads((folder / "campaign.json").read_text())
    if campaign["status"] != "incomplete" or campaign["mode"] != "network-controlled-resume" or \
            campaign["board_mac"] != "34:98:7a:a2:85:28":
        raise ValueError("Not a sealed failed resume attempt")
    recovery = None
    if campaign["original_flash_restored"]:
        envelope(folder, allow_incomplete=True)
    else:
        if set(campaign["files"]) != {p.relative_to(folder).as_posix() for p in folder.rglob("*")
                if p.is_file() and p.name not in ("campaign.json", "audit.json")} or \
                any(not (folder / n).resolve().is_relative_to(folder.resolve()) or sha(folder / n) != value
                    for n, value in campaign["files"].items()):
            raise ValueError("Unrestored attempt's sealed evidence changed")
        recovery_folder = folder.parent / (folder.name + "-recovery")
        recovery = json.loads((recovery_folder / "recovery.json").read_text())
        if not recovery["original_flash_restored"] or recovery["board_mac"] != campaign["board_mac"] or \
                recovery["parent_campaign_sha256"] != sha(folder / "campaign.json") or \
                any(sha(recovery_folder / n) != value for n, value in recovery["files"].items()):
            raise ValueError("Separate recovery proof changed")
        text = (recovery_folder / "restore-verify.log").read_text()
        if "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in text or \
                "-- verify OK (digest matched)" not in text or ("MAC: " + campaign["board_mac"]) not in text:
            raise ValueError("Recovery lacks complete same-board restoration")
    trials = sorted(folder.glob("*/run*/*/actions.json"))
    if len(trials) != 1:
        raise ValueError("Failed resume attempt changed its attempted workload count")
    actions = json.loads(trials[0].read_text())
    rows = read_raw_capture(trials[0].parent, "", prefix="uart")
    if any(r.get("host_command") or r.get("capture_complete") for r in actions) or \
            any("NuttShell (NSH)" in r["line"] for r in rows):
        raise ValueError("Attempt unexpectedly entered the benchmark or shell")
    journal = EVIDENCE / "esp32-usb-interruption-v1/host-journal.log"
    if "ch341-uart converter now disconnected" not in journal.read_text() or \
            "ch341-uart converter now attached to ttyUSB1" not in journal.read_text():
        raise ValueError("USB re-enumeration is not witnessed")
    return {"audit": "pass", "status": "usb_interrupted_before_workload", "independent_resets": 0,
            "attempt": trials[0].parent.relative_to(folder).as_posix(), "ranking_eligible": False,
            "original_flash_restored": True, "original_failed_campaign_unmodified": True,
            "separate_recovery": recovery, "usb_journal_sha256": sha(journal),
            "boundary": "USB disconnection and missing NSH startup are observed; physical/electrical cause not established; no OS throughput inferred"}


def audit_link_failure(folder):
    campaign = envelope(folder, allow_incomplete=True)
    if campaign["status"] != "incomplete" or campaign["mode"] != "network-controlled-resume" or \
            "not compatible with connection" not in campaign.get("error", ""):
        raise ValueError("Not the retained pre-workload AP discovery failure")
    trial = folder / "NuttX/run2/tcp_tx"
    rows = read_raw_capture(trial, "", prefix="uart")
    actions = json.loads((trial / "actions.json").read_text())
    activation = [r for r in actions if "up" in r.get("arguments", [])]
    scans = [r for r in actions if "list" in r.get("arguments", [])]
    if len(activation) != 2 or any(r["returncode"] != 4 for r in activation) or not scans or \
            any("IoTOSBench-B1" in r["output"] for r in scans) or \
            any(r.get("host_command") or r.get("capture_complete") for r in actions) or \
            sum("NuttShell (NSH)" in r["line"] for r in rows) != 1:
        raise ValueError("Declared missing-AP activation failure is not witnessed")
    return {"audit": "pass", "status": "target_ap_not_discovered_before_workload", "independent_resets": 0,
            "ranking_eligible": False, "original_flash_restored": True,
            "host_restoration": host_restored(folder),
            "boundary": "NSH boot succeeded; target AP was absent in host discovery; no throughput workload or score"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--failure", action="store_true")
    parser.add_argument("--interrupted", action="store_true")
    parser.add_argument("--failed-resume", action="store_true")
    parser.add_argument("--link-failure", action="store_true")
    args = parser.parse_args()
    method = audit
    if args.failed_resume:
        method = audit_failed_resume
    elif args.link_failure:
        method = audit_link_failure
    elif args.interrupted:
        method = audit_interrupted
    elif args.failure:
        method = audit_failure
    result = method(args.campaign) if args.campaign else {s: build(s) for s in SOURCES}
    if args.campaign:
        (args.campaign / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
