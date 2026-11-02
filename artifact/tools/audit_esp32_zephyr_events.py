#!/usr/bin/env python3
"""Replay unchanged original event cases and their case-specific formulas."""
import argparse
import json
from pathlib import Path
from urllib.request import urlopen
from audit_esp32_zephyr_thread import audit as native_audit, capture, digest, ROOT, EVENT_TAGS

COHORTS = (("freertos", "v1"), ("alios", "v2"))
ADMISSION = "EVENTS NATIVE ADMISSION post_or=1 set_replace=1 wait_nonconsuming=1 reset_before_wait=1 single_waiter=1"
NUTTX_CANDIDATE_SOURCES = {
    "altmdm_event.c": ("https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/drivers/modem/alt1250/altmdm_event.c",
        "bb731f7b1034ebf01c0c0134ac178940a506970f85dc601c13cd6b482e9e8169"),
    "altmdm_event.h": ("https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/drivers/modem/alt1250/altmdm_event.h",
        "98d6b01d66bc2b06287407e9e0abeeab3054b8d864dfe893130147a5e1da9f4f"),
    "zephyr-kernel-events.c": ("https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/kernel/events.c",
        "51eeaabe518f47f2b5b98210d8faf2e9ea5168a9a897a684abc30233c0d5496d"),
}


def nuttx_driver_candidate(directory=None, verify_upstream=False):
    directory = directory or ROOT / "artifacts/reports/zephyr-events-native-eligibility-v1/nuttx"
    proof = []
    for name, (url, sha) in NUTTX_CANDIDATE_SOURCES.items():
        source = directory / name
        if digest(source) != sha:
            raise ValueError("fixed official NuttX/Zephyr event candidate source changed: " + name)
        if verify_upstream and urlopen(url, timeout=60).read() != source.read_bytes():
            raise ValueError("event candidate differs from its pinned official source: " + name)
        proof.append({"path": name, "official_source_url": url, "sha256": sha})
    original = ROOT / "artifacts/reports/zephyr-original-v1/latency_measure/source/src/events.c"
    if digest(original) != "c162941387b040ef61f71f8a2dc5adaf7ca5d475349248866eb5d2c459533140":
        raise ValueError("original Zephyr event test changed")
    return {"audit": "pass", "os": "NuttX", "version": "12.2.1", "candidate": "ALT1250 modem-driver event flags",
        "sources": proof, "original_test_sha256": digest(original), "candidate_usable": False,
        "reason": "direct mapping lacks all-bits wait; set ORs rather than replaces; with_clear consumes after matching rather than resetting before waiting",
        "semantic_differences": {"wait_all": "native match != 0, not match == desired",
            "set_replace": "native event |= input, not replacement",
            "reset_before_wait": "native with_clear removes matched bits after a successful match",
            "no_wait": "native timeout_ms=0 means infinite wait, not polling"},
        "original_event_case_coverage_added": 0, "board_boots": 0, "new_metric_created": False,
        "ranking_eligible": False, "measurement_eligible": False,
        "scope": "rejects this direct fixed-version driver-object mapping; no assertion that every NuttX event mapping or an untested subset is impossible"}


def riot_compatibility_candidate(directory=None, verify_upstream=False):
    directory = directory or ROOT / "artifacts/reports/zephyr-events-native-eligibility-v1/riot"
    source = directory / "event_groups.c"
    url = "https://raw.githubusercontent.com/RIOT-OS/RIOT/dd06b3727c41c2c44bf93f47ff7831fdd501d68b/cpu/esp_common/freertos/event_groups.c"
    if digest(source) != "64ff3cde1f2ea15b6ae4a60f71b945728a97d90f08cd5341a983b9b84dfa0739":
        raise ValueError("fixed official RIOT ESP32 event-group candidate changed")
    if verify_upstream and urlopen(url, timeout=60).read() != source.read_bytes():
        raise ValueError("RIOT candidate differs from its pinned official source")
    return {"audit": "pass", "os": "RIOT", "candidate": "official ESP32 FreeRTOS-compatibility event groups",
        "official_source_url": url, "source_sha256": digest(source), "candidate_usable": False,
        "reason": "create returns NULL; delete/set/clear/wait only print unsupported, set/clear/wait return zero",
        "original_event_case_coverage_added": 0, "board_boots": 0, "ranking_eligible": False,
        "scope": "rejects this fixed-version compatibility candidate; other native mappings remain unresolved"}


def capture_events(directory, index, os):
    result = capture(directory, index, os, events_subset=True)
    lines = [json.loads(line)["line"] for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    mask = 0xffffff if os == "freertos" else 0xffffffff
    objects = [line for line in lines if line.startswith("EVENTS ORIGINAL OBJECT ")]
    if lines.count(ADMISSION) != 1 or objects != [f"EVENTS ORIGINAL OBJECT bits=4660 native_mask={mask}"] * 2:
        raise ValueError("native original event admission/retained bits differs")
    result["final_retained_bits"] = 0x1234
    result["native_event_mask"] = mask
    return result


def audit(directory, os, verify_upstream=False):
    result = native_audit(directory, os, verify_upstream, events_subset=True)
    result["captures"] = [capture_events(directory, index, os) for index in (1, 2, 3)]
    result.update(benchmark="Zephyr 3.7.0 original event kernel subset",
                  timestamp_subtracted_cases=list(EVENT_TAGS[4:6]),
                  timestamp_not_subtracted_cases=list(EVENT_TAGS[:4] + EVENT_TAGS[6:]),
                  native_event_bits=24 if os == "freertos" else 32,
                  event_control_flow_sha256=digest(directory / "event-control-flow-v3.txt"),
                  event_control_flow_version=3,
                  full_zephyr_event_semantics_implemented=False,
                  original_reset_before_wait=True, original_clear_on_exit=False,
                  boundary="unchanged original eight cases, 1000 loops and integer means; only any-wait/set-wake blocking halves subtract original timestamp overhead; native nonconsuming any/all bit waits; native clear+post composes replacement and retains its cost; preclear-before-block is restricted to the original single higher-priority waiter, lower-priority producer and no ISR event writer; FreeRTOS has 24 usable event bits and maps original all-clear sentinel to its native mask, Rhino has 32; no generic multiwaiter/broadcast or full native Zephyr suite claim, and no cross-OS rank")
    return result


def render_table(results):
    lines = ["| Original Zephyr event subset / OS | Original case | Original means, ns (three boots) |", "| --- | --- | --- |"]
    for result in results:
        for tag in EVENT_TAGS:
            lines.append(f"| Original event port / {result['os']} / {tag} | {tag} | " +
                         " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("os", choices=("freertos", "alios"))
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.os, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
