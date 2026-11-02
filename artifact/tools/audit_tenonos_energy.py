#!/usr/bin/env python3
"""Replay signed sensor bytes, covered activation windows and original guest gates."""
import argparse
import json
from pathlib import Path
import statistics

from audit_tenonos_policy_sequence import parent_check
from audit_tenonos_tasks import require
from replay_esp32_b1_energy import interval_energy, trace
from run_tenonos_energy import references, SOURCES
from tenonos_kvm_reproduce import sha


def audit(folder, root):
    campaign = json.loads((folder / "campaign.json").read_text())
    plan = json.loads((folder / "protocol.json").read_text())
    setup = json.loads((folder / "operator-setup.json").read_text())
    variants = references(plan, root)
    require(sha(folder / "protocol.json") == campaign["protocol_sha256"] and
            campaign["status"] == "complete" and campaign["model_calls"] == campaign["rebuilds"] == 0,
            "Protocol or completion differs")
    require(setup["confirmation_source"] == "direct_user_message" and setup["sole_board_supply_through_meter"] is True and
            setup["answers_pi_only_supply_request"] is True and setup["operator_confirmation"] and setup["target"] == "Raspberry Pi 4B",
            "Pi supply-path confirmation missing")
    require(campaign["governor_restored"] and campaign["host_after_restore"]["governor"] == setup["initial_host"]["governor"],
            "Pi governor restoration incomplete")
    require(set(campaign["source_sha256"]) == set(SOURCES), "Collector source coverage differs")
    for name, digest in campaign["source_sha256"].items():
        require(sha(folder / "sources" / name) == digest, "Captured source changed")
    probe, _ = trace(folder / "meter-preflight", setup["polarity"])
    require(probe["meter_serial"] == setup["meter_serial"] == "086477" and probe["port"] is None and
            probe["sample_count"] >= 20, "Read-only preflight differs")
    expected = ["R%d-%s" % (i, v) for i, row in enumerate(plan["schedule"], 1) for v in row]
    require([v["id"] for v in campaign["trials"]] == expected, "Missing, extra or reordered activation")
    require(sorted(p.name for p in folder.glob("R*-*") if p.is_dir()) == sorted(expected), "Unaccounted trial folder")
    rows, guests = [], 0
    for record in campaign["trials"]:
        directory = folder / record["id"]
        require(record == json.loads((directory / "activation.json").read_text()) and record["status"] == "complete",
                "Activation outcome or campaign row differs")
        value = variants[record["variant"]]
        guests += parent_check(directory / "runtime", root / value["build"], campaign["source_commits"])
        for index in (1, 2, 3):
            step = json.loads((directory / ("runtime/boots/boot%d.json" % index)).read_text())
            argv = step["argv"]
            require(step["recorder_sha256"] == campaign["source_sha256"]["tenonos_kvm_reproduce.py"] and
                    argv.count("qemu-system-aarch64") == 1 and all(argv.count(flag) == 1 and
                    argv[argv.index(flag) + 1] == setting for flag, setting in
                    (("-accel", "kvm"), ("-smp", "1"), ("-m", "128M"), ("-nic", "none"))),
                    "Actual guest invocation differs from the frozen envelope")
        require(record["runtime"] == {"image_sha256": value["image_sha256"], "fresh_guest_boots": 3, "passed": True},
                "Activation runtime summary differs")
        for phase in ("host_before", "host_after"):
            host = record[phase]
            require(host["governor"] == "performance" and host["throttled"] == "throttled=0x0" and
                    host["serial"] == setup["initial_host"]["serial"] and not host["qemu_running"], "Host state changed")
        metadata, powers = trace(directory, setup["polarity"])
        require(metadata["meter_serial"] == setup["meter_serial"], "Trial meter identity differs")
        start, end = record["start_s"], record["end_s"]
        duration, energy = end - start, interval_energy(powers, start, end)
        require(duration > 1 and record["duration_s"] == duration and abs(record["energy_j"] - energy) < 1e-9 and
                abs(record["average_power_w"] - energy / duration) < 1e-9, "Activation arithmetic differs")
        rows.append({"id": record["id"], "variant": record["variant"], "duration_s": duration, "energy_j": energy,
                     "average_power_w": energy / duration, "samples": len(powers),
                     "max_sample_gap_s": max(b[0] - a[0] for a, b in zip(powers, powers[1:]))})
    summary = []
    for name in variants:
        values = [r for r in rows if r["variant"] == name]
        require(len(values) == 3, "Three independent activations per image required")
        summary.append({"variant": name, "n": 3, **{key: {"median": statistics.median(r[key] for r in values),
                        "min": min(r[key] for r in values), "max": max(r[key] for r in values)}
                        for key in ("energy_j", "duration_s", "average_power_w")}})
    return {"pass": True, "id": plan["id"], "activation_trials": len(rows), "fresh_guest_boots": guests,
            "model_calls": 0, "rebuilds": 0, "rows": rows, "summary": summary, "boundary": plan["boundary"],
            "interpretation": plan["interpretation"], "ranking_eligible": False,
            "campaign_sha256": sha(folder / "campaign.json"), "protocol_sha256": sha(folder / "protocol.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.folder, Path(__file__).resolve().parents[1])
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
