#!/usr/bin/env python3
"""Reuse scale observations only for identical audited retained configurations."""
import argparse
from datetime import datetime
import json
from pathlib import Path

from audit_tenonos_tasks import configuration
from audit_tenonos_policy_budget import audit as history_audit
from audit_tenonos_scale_validation import audit as scale_audit
from tenonos_kvm_reproduce import sha


def same_profile(config, build, profile):
    return config == profile["config"] and build["source_commits"] == profile["source"] and \
        build["compiler_version_stdout_sha256"] == profile["compiler_sha256"]


def bind(root, pipeline, campaign, underlying, scale):
    history = history_audit(root, pipeline, campaign, underlying)
    checked = scale_audit(scale, root)
    if checked != json.loads((scale / "audit.json").read_text()):
        raise ValueError("Reused scale observations differ from their source/guest replay")
    protocol = json.loads((scale / "protocol.json").read_text())
    registered = json.loads((campaign / "registration.json").read_text())
    if datetime.fromisoformat(protocol["frozen_utc"]) >= datetime.fromisoformat(registered["registered_utc"]):
        raise ValueError("External workload specification was not frozen before new generation")
    profiles = {p["profile"]: {"config": configuration(scale / p["profile"] / "input.config"), "result": p,
        "source": json.loads((scale / p["profile"] / "source-proof.json").read_text())["upstream_and_adapter_identity"],
        "compiler_sha256": sha(scale / p["profile"] / "build/compiler.stdout")} for p in checked["profiles"]}
    aliases, unmatched = [], []
    histories = json.loads((campaign / "campaign.json").read_text())["histories"]
    for h in histories:
        for record in h["rounds"]:
            for phase, name in (("parent", "parent_build"), ("retained", "retained_build")):
                build = root / record[name]
                proof = json.loads((build / "build-result.json").read_text())
                if sha(build / ".config") != proof["config_sha256"] or sha(build / "runtime-image") != proof["image_sha256"]:
                    raise ValueError("Retained build identity changed")
                actual = configuration(build / ".config")
                matches = [key for key, p in profiles.items() if same_profile(actual, proof, p)]
                alias = {"history": h["id"], "round": record["round"], "phase": phase,
                         "build": record[name], "config_sha256": proof["config_sha256"], "image_sha256": proof["image_sha256"]}
                if len(matches) > 1:
                    raise ValueError("Ambiguous reused profile")
                if matches:
                    aliases.append({**alias, "profile": matches[0]})
                else:
                    unmatched.append(alias)
    used = {a["profile"] for a in aliases}
    return {"pass": not unmatched and len(aliases) == 24, "retained_state_aliases": len(aliases),
        "aliases": aliases, "unmatched": unmatched, "profiles": [p["result"] for k, p in profiles.items() if k in used],
        "distinct_configurations": len(used), "reused_guest_boots": sum(profiles[k]["result"]["fresh_guests"] for k in used),
        "new_guest_boots": 0, "new_model_calls": 0, "external_workload_spec_frozen_before_this_generation": True,
        "new_hardware_collection": False, "history_audit_sha256": sha(underlying),
        "scale_audit_sha256": sha(scale / "audit.json"), "scale_campaign_sha256": sha(scale / "campaign.json"),
        "scope": "Existing 2000-iteration original-test observations reused only after exact full-configuration, source/adapter and compiler identity checks. Repeated state aliases are not independent samples. The old scale campaign remains post-trajectory for the old histories; no optimization, generalization improvement, timing-rank or RSI claim.",
        "history_model_calls": history["model_calls"], "whole_live_ram_peak_bytes": None}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("pipeline", "campaign", "underlying", "scale", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace"):
        p.error("Bind real evidence on leon")
    result = bind(root, args.pipeline.resolve(), args.campaign.resolve(), args.underlying.resolve(), args.scale.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("aliases", "profiles", "unmatched")}))
