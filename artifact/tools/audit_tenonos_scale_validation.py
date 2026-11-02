#!/usr/bin/env python3
"""Replay source, configuration and original-output scale-validation evidence."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import statistics

from audit_tenonos_policy_sequence import guest_checks
from audit_tenonos_tasks import require, configuration
from tenonos_kvm_reproduce import sha
from tenonos_scale_validation import retained_profiles

NAMES = ("average_task_switch_time, in cpu cycles", "average_multi_task_switch_time, in cpu cycles",
         "average_task_preempt_time, in cpu cycles", "average_semaphore_shuffle_time, in cpu cycles",
         "interrupt_latency_time, in cpu cycles", "timer_deviation_under_interrupt_interference, in count of generic timer")


def source_change(before, after, originals, scaled):
    require(set(before) == set(after) == set(scaled), "Tracked source coverage differs")
    require([n for n in before if before[n] != after[n]] == ["include/rst_cfg.h"], "Changed more than the iteration header")
    for name, raw in originals.items():
        require(hashlib.sha256(raw).hexdigest() == before[name], "Source snapshot differs from pinned upstream/adapter")
        expected = raw
        if name == "include/rst_cfg.h":
            require(raw.count(b"#define RST_BENCHMARKS_COUNT 500\n") == 1, "Original iteration setting differs")
            expected = raw.replace(b"#define RST_BENCHMARKS_COUNT 500\n", b"#define RST_BENCHMARKS_COUNT 2000\n")
        require(scaled[name] == expected and sha_bytes(expected) == after[name], "Scaled compiled source differs")


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def audit(folder, root):
    plan = json.loads((folder / "protocol.json").read_text())
    campaign = json.loads((folder / "campaign.json").read_text())
    require(campaign["status"] == "complete" and campaign["model_calls"] == 0 and campaign["governor_restored"] and
            campaign["host_after_restore"]["governor"] == campaign["host_initial"]["governor"] and
            sha(folder / "protocol.json") == campaign["plan_sha256"], "Scale validation incomplete or changed")
    require(datetime.fromisoformat(plan["frozen_utc"]) <= datetime.fromisoformat(campaign["registered_utc"]) and
            campaign["prospective_before_generation"] is False, "Incorrect registration chronology")
    require(plan["parameter"] == {"file": "include/rst_cfg.h", "macro": "RST_BENCHMARKS_COUNT", "original": 500, "validation": 2000},
            "Different validation workload parameter")
    profiles = retained_profiles(root, plan)
    require(profiles == campaign["profiles"] and [v["id"] for v in profiles] == [r["id"] for r in campaign["completed"]],
            "Retained profile or alias coverage differs")
    for name, digest in campaign["source_sha256"].items():
        require(sha(folder / "sources" / name) == digest, "Frozen collection helper changed")
    originals = {}
    dependency = root / "artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark"
    inventory = json.loads((dependency / "manifest.json").read_text())
    require(inventory["commit"] == "0b71b8e722acfab4733eb99b07b67fbe8472c31d" and
            inventory["tree_sha"] == "cfa0345c54d4c9dbd269ca83fc2ccb91cc1df9b6" and not inventory["truncated"],
            "Upstream source inventory is not the pinned complete tree")
    tree = {v["path"]: v for v in inventory["files"]}
    for path in dependency.glob("*.source.json"):
        record = json.loads(path.read_text())
        raw = record["content"].encode()
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == record["git_blob_sha"],
                "Pinned original Git blob changed")
        originals[record["path"]] = raw
    require(all(n in originals for n in ("main.c", "Makefile.uk", "include/rst_cfg.h")), "Original sources missing")
    summaries, total_guests = [], 0
    for profile, completed in zip(profiles, campaign["completed"]):
        p = folder / profile["id"]
        transfer = json.loads((p / "runtime-transfer-check.json").read_text())
        require(transfer["all_equal"] and transfer["remote_returncode"] == 0, "Pi evidence transfer incomplete")
        for name, digest in transfer["files"].items():
            file = (p / name).resolve()
            file.relative_to(p.resolve())
            require(sha(file) == digest, "Retained Pi bytes changed")
        proof = json.loads((p / "source-proof.json").read_text())
        before, after = proof["original_sha256"], proof["scaled_sha256"]
        source = p / "source/app-rtos-benchmark-scale"
        current = {n: (source / n).read_bytes() for n in before}
        require(set(current) == set(tree), "Separate source copy does not cover the tracked upstream tree")
        expected = {n: raw for n, raw in originals.items() if n in before}
        patches = proof["upstream_and_adapter_identity"]["rtos_adapter_patch"]["files"]
        require(patches == {"adapter/os/tenonos/rst_isr.c": "738792173125d862712cf17d40640a3f1c3488a761d2ac321cfe537982d1a707",
                            "adapter/os/tenonos/rst_task.c": "71c41a94f0ccdf644b0afb0f266afe072e3048df42816bf2a8893dcece304bed"},
                "Native adapter profile differs")
        for name, digest in patches.items():
            require(sha(source / name) == digest, "Patched native adapter changed")
            expected[name] = current[name]
        for name, raw in current.items():
            if name in patches:
                continue
            original = raw.replace(b"#define RST_BENCHMARKS_COUNT 2000\n", b"#define RST_BENCHMARKS_COUNT 500\n") \
                if name == "include/rst_cfg.h" else raw
            require(len(original) == tree[name]["size"] and hashlib.sha1(
                b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest() == tree[name]["sha"],
                "Compiled source does not reconstruct its pinned Git blob")
        source_change(before, after, expected, current)
        require(all(sha_bytes(raw) == after[n] for n, raw in current.items()), "Scaled source manifest differs")
        require(sha(p / "input.config") == profile["config_sha256"], "Wrong retained parent configuration")
        initial, scaled = configuration(p / "input.config"), configuration(p / "build/.config")
        diff = {n: [initial.get(n), scaled.get(n)] for n in initial.keys() | scaled.keys() if initial.get(n) != scaled.get(n)}
        require(set(diff) == {"UK_APP"} and diff["UK_APP"][0] == '"/home/pi/tenonos-benchmark-v1/apps/app-rtos-benchmark-abi"' and
                diff["UK_APP"][1].endswith('/source/app-rtos-benchmark-scale"'), "Native policy changed, not only source path")
        build = json.loads((p / "build/build-result.json").read_text())
        require(build["source_commits"] == {k: v for k, v in proof["upstream_and_adapter_identity"].items()
                                           if k != "rtos_adapter_patch"}, "Build kernel sources differ from the reviewed profile")
        require(sha(p / "build/runtime-image") == build["image_sha256"] and sha(p / "build/.config") == build["config_sha256"] and
                build["iterations"] == 2000 and build["source_profile_sha256"] == sha(p / "source-proof.json"), "Linked profile differs")
        require(all(json.loads((p / ("build/" + n + ".json")).read_text())["returncode"] == 0
                    for n in ("compiler", "configure", "build")), "Native build step failed")
        outcomes, complete = guest_checks(p / "boots", build["image_sha256"])
        require(complete and len(outcomes) == 3, "Original suite did not complete in three fresh guests")
        values = {n: [] for n in NAMES}
        for i, outcome in enumerate(outcomes, 1):
            pairs = {name: (int(v), unit) for name, v, unit in outcome["values"]}
            require(set(pairs) == set(NAMES), "Original metric coverage differs")
            for name in NAMES:
                value, unit = pairs[name]
                require(unit == ("count" if name.startswith("timer_deviation") else "cycle"), "Original timer/cycle units interchanged")
                values[name].append(value)
            step = json.loads((p / ("boots/boot%d.json" % i)).read_text())
            argv = step["argv"]
            require(step["recorder_sha256"] == campaign["source_sha256"]["tenonos_kvm_reproduce.py"] and
                    all(argv[argv.index(k) + 1] == v for k, v in (("-accel", "kvm"), ("-smp", "1"), ("-m", "128M"))),
                    "Actual guest envelope differs")
        for phase in ("host_before", "host_after"):
            state = completed[phase]
            require(state["serial"] == campaign["host_initial"]["serial"] and state["governor"] == "performance" and
                    state["throttled"] == "throttled=0x0" and not state["qemu_running"], "Pi host envelope changed")
        total_guests += 3
        summaries.append({"profile": profile["id"], "config_sha256": profile["config_sha256"], "aliases": len(profile["aliases"]),
                          "fresh_guests": 3, "passed": True, "values": values,
                          "medians": {n: statistics.median(v) for n, v in values.items()}})
    return {"pass": True, "id": plan["id"], "profiles": summaries, "distinct_configurations": len(profiles),
            "retained_state_aliases": sum(len(p["aliases"]) for p in profiles), "fresh_guest_boots": total_guests,
            "native_builds": len(profiles), "model_calls": 0, "original_iterations": 500, "validation_iterations": 2000,
            "prospective_before_generation": False, "ranking_eligible": False, "runtime_counter_fidelity_proven": False,
            "interpretation": plan["interpretation"], "campaign_sha256": sha(folder / "campaign.json"),
            "source_audit_sha256": sha(Path(__file__)), "whole_live_ram_peak_bytes": None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.folder, Path(__file__).resolve().parents[1])
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
