#!/usr/bin/env python3
"""Bind the budget-only variant to a completed independent task/runtime replay."""
import argparse
from datetime import datetime
import json
from pathlib import Path

from prepare_tenonos_budget_profile import SOURCES, CAMPAIGN_SOURCES, budget_variant, campaign_variant
from tenonos_kvm_reproduce import sha


def request_limit(method, stage, cap, used):
    if type(cap) is not int or type(used) is not int or not 0 <= used < 1152:
        raise ValueError("Invalid budget accounting")
    if stage == "configurations":
        expected = 1152 - used
    elif method == "graph" and stage in ("objective", "paths"):
        expected = min(288, 1152 - used)
    else:
        raise ValueError("Unexpected model stage")
    if cap != expected:
        raise ValueError("Actual request does not use the frozen stage/aggregate budget")


def audit(root, pipeline, campaign, underlying_path):
    plan = json.loads((pipeline / "protocol.json").read_text())
    proof = json.loads((pipeline / "source-variant.json").read_text())
    registration = json.loads((campaign / "registration.json").read_text())
    replay = json.loads(underlying_path.read_text())
    if not (replay["generation_interface_admissible"] and replay["runtime_audit"]["registered_task_outcomes_audited"]) or \
            (replay["registered_trials"], registration["aggregate_completion_tokens_per_trial"]) != (18, 1152) or \
            datetime.fromisoformat(proof["prepared_utc"]) > datetime.fromisoformat(registration["registered_utc"]):
        raise ValueError("Campaign is incomplete, inadmissible or precedes its frozen variant")
    for name in SOURCES + CAMPAIGN_SOURCES:
        original = root / "tools" / name
        if sha(original) != proof["original_sha256"][name] or sha(pipeline / name) != proof["variant_sha256"][name]:
            raise ValueError("Original or isolated source changed: " + name)
        expected = original.read_bytes()
        if name == "tenonos_paper_orchestrator.py":
            expected = budget_variant(expected, {"objective": 288, "paths": 288})
        elif name in ("run_tenonos_paper_tasks.py", "audit_tenonos_paper_tasks.py"):
            expected = campaign_variant(expected, name)
        if (pipeline / name).read_bytes() != expected:
            raise ValueError("Source variant changes algorithm or judge: " + name)
    base_bank = root / plan["base_task_bank"]
    original, bank = json.loads(base_bank.read_text()), json.loads((pipeline / "task-bank.json").read_text())
    allowed = {"id", "maximum_output_tokens", "model", "model_metadata", "scope", "base_task_bank_sha256"}
    if {k: v for k, v in original.items() if k not in allowed} != {k: v for k, v in bank.items() if k not in allowed} or \
            bank["base_task_bank_sha256"] != sha(base_bank) or replay["actual_model"] != plan["model"]:
        raise ValueError("Frozen task requirements or model changed")
    for name, digest in replay["campaign_evidence_manifest"].items():
        p = (campaign / name).resolve()
        p.relative_to(campaign.resolve())
        if sha(p) != digest:
            raise ValueError("Underlying replay no longer binds actual bytes")
    count, tokens = 0, 0
    for trial in registration["trials"]:
        folder = campaign / trial["id"] / "candidate"
        calls = json.loads((folder / "model-calls.json").read_text())
        order = [c["stage"] for c in calls]
        expected = ["configurations"] if trial["method"] == "direct" else ["objective", "paths", "configurations"]
        if order != expected[:len(order)] or len(order) > len(expected):
            raise ValueError("Extra attempts or out-of-order stages")
        used = 0
        for call in calls:
            count += 1
            payload = json.loads((folder / (call["stage"] + "-request.json")).read_text())
            request_limit(trial["method"], call["stage"], payload["max_tokens"], used)
            context = json.loads(payload["messages"][1]["content"])
            allowed_context = {"objective", "paths"} if call["stage"] == "paths" else {
                "task", "allowed_configuration_metadata", "parsed_objective", "selected_paths", "permitted_controls"}
            if set(context) - allowed_context:
                raise ValueError("Private judge/held-out fields exposed to the model")
            response = folder / (call["stage"] + "-response.json")
            if response.exists():
                used += json.loads(response.read_text())["usage"]["completion_tokens"]
        if used > 1152:
            raise ValueError("Trial exceeded aggregate output budget")
        tokens += used
    if count != replay["model_attempts"] or tokens != replay["completion_tokens"] or \
            count > plan["maximum_model_calls"] or tokens > plan["maximum_completion_tokens"]:
        raise ValueError("Campaign API accounting exceeds its authorization")
    return {"pass": True, "scope": "Equal-output-budget sensitivity; independent paper reconstruction, not author engine or RSI",
            "registered_trials": 18, "aggregate_output_cap": 1152, "graph_stage_caps": plan["graph_stage_token_caps"],
            "model_calls": count, "completion_tokens": tokens, "model": replay["actual_model"],
            "groups": replay["runtime_audit"]["groups"], "finish_reasons": replay["finish_reasons"],
            "failure_types": replay["failure_types"], "raw_guest_captures": replay["runtime_audit"]["raw_guest_captures"],
            "underlying_audit_sha256": sha(underlying_path), "source_variant_sha256": sha(pipeline / "source-variant.json"),
            "protocol_sha256": sha(pipeline / "protocol.json"), "author_engine": False,
            "whole_ram_peak_measured": False, "new_energy_measured": False, "new_model_calls_by_audit": 0}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pipeline", type=Path, required=True)
    p.add_argument("--campaign", type=Path, required=True)
    p.add_argument("--underlying", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace"):
        p.error("Audit evidence on leon")
    result = audit(root, a.pipeline.resolve(), a.campaign.resolve(), a.underlying.resolve())
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k != "groups"}))
