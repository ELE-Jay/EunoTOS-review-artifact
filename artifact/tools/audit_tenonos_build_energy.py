#!/usr/bin/env python3
"""Independently check rebuilt configurations, native runs and signed energy."""
import argparse
import json
from pathlib import Path
import statistics

from audit_tenonos_tasks import configuration, require
from audit_tenonos_policy_sequence import guest_checks
from replay_esp32_b1_energy import trace, interval_energy
from tenonos_kvm_reproduce import sha


def window_energy(powers, value):
    duration = value["end_s"] - value["start_s"]
    energy = interval_energy(powers, value["start_s"], value["end_s"])
    require(duration > 0 and value["duration_s"] == duration and abs(value["energy_j"] - energy) < 1e-9 and
            abs(value["average_power_w"] - energy / duration) < 1e-9, "Window energy or duration differs")
    return {"duration_s": duration, "energy_j": energy, "average_power_w": energy / duration}


def audit(root, folder):
    plan = json.loads((folder / "protocol.json").read_text())
    campaign = json.loads((folder / "campaign.json").read_text())
    refs = json.loads((folder / "references.json").read_text())
    setup_path = root / "artifacts/reports/tenonos-rpi4-activation-energy-v1/operator-setup.json"
    setup = json.loads(setup_path.read_text())
    require(campaign["status"] == "complete" and campaign["model_calls"] == 0 and
            campaign["protocol_sha256"] == sha(folder / "protocol.json") and
            sha(folder / "references.json") == sha(root / plan["reference_registry"]) and
            campaign["governor_restored"] and campaign["host_after_restore"]["governor"] == campaign["initial_host"]["governor"],
            "Incomplete or changed build-energy campaign")
    require(setup["sole_board_supply_through_meter"] and setup["confirmation_source"] == "direct_user_message" and
            setup["meter_serial"] == "086477" and setup["initial_host"]["serial"] == campaign["initial_host"]["serial"],
            "Prior supply-path confirmation or target identity differs")
    for name, digest in campaign["source_sha256"].items():
        require(sha(folder / "sources" / name) == digest, "Frozen collector/helper changed")
    metadata, powers = trace(folder / "meter-preflight", campaign["polarity"])
    require(metadata["meter_serial"] == "086477" and metadata["port"] is None and len(powers) >= 20 and
            any(p > 0 for _, p in powers), "Fresh signed instrument check incomplete")
    variants = {v["id"]: v for v in refs["variants"]}
    expected = ["R%d-%s" % (i, name) for i, names in enumerate(plan["schedule"], 1) for name in names]
    require(len(expected) == 9 and [r["id"] for r in campaign["trials"]] == expected, "Build trial coverage differs")
    rows = []
    for row in campaign["trials"]:
        trial = folder / row["id"]
        require(json.loads((trial / "trial.json").read_text()) == row and row["status"] == "complete", "Trial outcome differs")
        runtime = trial / "runtime"
        transfer = json.loads((trial / "runtime-transfer.json").read_text())
        require(transfer["all_equal"], "Runtime transfer incomplete")
        for name, digest in transfer["files"].items():
            p = (runtime / name).resolve()
            p.relative_to(runtime.resolve())
            require(sha(p) == digest, "Returned runtime bytes changed")
        reference = variants[row["variant"]]
        build = runtime / "build"
        proof = json.loads((build / "build-result.json").read_text())
        original = root / reference["build"]
        old = json.loads((original / "build-result.json").read_text())
        require(sha(original / ".config") == reference["config_sha256"] and
                sha(trial / "input.config") == sha(runtime / "input.config") == reference["config_sha256"] and
                configuration(build / ".config") == configuration(original / ".config") and
                sha(build / ".config") == proof["config_sha256"] and
                sha(build / "runtime-image") == proof["image_sha256"], "Rebuilt input/config/image differs")
        require(proof["source_commits"] == old["source_commits"] and proof["source_worktrees_unchanged"] and
                proof["application"] == "app-rtos-benchmark-abi" and proof["c11_timer_fix"] and
                sha(build / "compiler.stdout") == proof["compiler_version_stdout_sha256"] == old["compiler_version_stdout_sha256"],
                "Native source, adapter or compiler differs")
        for phase in ("compiler", "configure", "build"):
            step = json.loads((build / (phase + ".json")).read_text())
            require(step["state"] == "finished" and step["returncode"] == 0, "Native build step failed")
            if phase == "build":
                require(step["argv"][-1] == "-j2" and "900" in step["argv"], "Build concurrency or time limit differs")
        linked = json.loads((build / "linked-inputs.json").read_text())
        require(linked["measured_image_sha256"] == proof["image_sha256"] and linked["retained_before_guest_execution"] and
                all(sha(build / name) == digest for name, digest in linked["files"].items()), "Native ELF inputs missing")
        outcomes, complete = guest_checks(runtime / "boots", proof["image_sha256"])
        require(complete and len(outcomes) == 3, "Original outputs incomplete")
        for i in (1, 2, 3):
            step = json.loads((runtime / ("boots/boot%d.json" % i)).read_text())
            args = step["argv"]
            require(step["recorder_sha256"] == campaign["source_sha256"]["tenonos_kvm_reproduce.py"] and
                    all(args[args.index(k) + 1] == v for k, v in (("-accel", "kvm"), ("-smp", "1"), ("-m", "128M"), ("-nic", "none"))),
                    "Actual guest envelope differs")
        for phase in ("host_before", "host_after"):
            h = row[phase]
            require(h["serial"] == campaign["initial_host"]["serial"] and h["governor"] == "performance" and
                    not h["qemu_running"] and h["throttled"] == "throttled=0x0", "Host envelope changed")
        meta, samples = trace(trial, campaign["polarity"])
        require(meta["meter_serial"] == "086477", "Instrument changed")
        a, b = row["subwindows"]["build"], row["subwindows"]["boot"]
        require(row["start_s"] <= a["start_s"] < a["end_s"] <= b["start_s"] < b["end_s"] <= row["end_s"] and
                a["returncode"] == b["returncode"] == 0, "Subwindow order or operation differs")
        rows.append({"id": row["id"], "variant": row["variant"], **window_energy(samples, row),
                     "build": window_energy(samples, a), "boot": window_energy(samples, b),
                     "max_sample_gap_s": max(right[0] - left[0] for left, right in zip(samples, samples[1:]))})
    summary = []
    for name in variants:
        values = [r for r in rows if r["variant"] == name]
        require(len(values) == 3, "Three fresh builds per configuration required")
        summary.append({"variant": name, "n": 3,
            **{key: {"median": statistics.median(v[key] for v in values), "min": min(v[key] for v in values),
                     "max": max(v[key] for v in values)} for key in ("energy_j", "duration_s", "average_power_w")},
            "build_energy_j_median": statistics.median(v["build"]["energy_j"] for v in values),
            "boot_energy_j_median": statistics.median(v["boot"]["energy_j"] for v in values)})
    return {"pass": True, "trials": 9, "native_builds": 9, "fresh_guest_boots": 27, "model_calls": 0,
        "rows": rows, "summary": summary, "boundary": plan["boundary"], "polarity": campaign["polarity"],
        "prior_operator_setup_sha256": sha(setup_path), "campaign_sha256": sha(folder / "campaign.json"),
        "protocol_sha256": sha(folder / "protocol.json"), "ranking_eligible": False, "whole_live_ram_peak_bytes": None}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not root.is_relative_to(Path("/home/reviewer/esp32-pilot/audit-workspace")):
        p.error("Audit real raw evidence on leon")
    result = audit(root, a.folder.resolve())
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("rows", "summary")}))
