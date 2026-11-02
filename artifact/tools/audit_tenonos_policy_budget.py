#!/usr/bin/env python3
"""Bind the larger-budget history variant to independent native/runtime replay."""
import argparse
from datetime import datetime
import json
from pathlib import Path

from audit_tenonos_budget_sensitivity import request_limit
from prepare_tenonos_budget_profile import (SOURCES, CAMPAIGN_SOURCES, POLICY_SOURCES,
    budget_variant, campaign_variant, policy_variant)
from tenonos_kvm_reproduce import sha
from audit_tenonos_tasks import configuration


def check_plan(base, plan):
    excluded = {"id", "maximum_output_tokens_per_round", "maximum_completion_tokens"}
    if any(plan[k] != value for k, value in base.items() if k not in excluded) or \
            (plan["maximum_output_tokens_per_round"], plan["maximum_completion_tokens"]) != (1152, 13824):
        raise ValueError("History protocol changes more than its output budget")


def inherited_choice_conflict(task, submitted, resolved):
    return task["starting_options"].get("LIBUKBOOT_INITTLSF") == "y" and \
        submitted.get("LIBUKBOOT_INITBBUDDY") == "y" and "LIBUKBOOT_INITTLSF" not in submitted and \
        resolved.get("LIBUKBOOT_INITTLSF") == "y" and resolved.get("LIBUKBOOT_INITBBUDDY") == "n"


def audit(root, pipeline, campaign, underlying):
    plan = json.loads((pipeline / "protocol.json").read_text())
    base = json.loads((root / plan["base_protocol"]).read_text())
    proof = json.loads((pipeline / "source-variant.json").read_text())
    registration = json.loads((campaign / "registration.json").read_text())
    result = json.loads(underlying.read_text())
    if result["audit"] != "pass" or (result["registered_histories"], result["registered_rounds"]) != (6, 12) or \
            plan != json.loads((campaign / "protocol.json").read_text()) or \
            sha(pipeline / "protocol.json") != proof["protocol_sha256"]:
        raise ValueError("Incomplete or changed policy campaign")
    if proof["protocol_sha256"] != registration["plan_sha256"] or \
            datetime.fromisoformat(proof["prepared_utc"]) > datetime.fromisoformat(registration["registered_utc"]):
        raise ValueError("Variant was not frozen before collection")
    check_plan(base, plan)
    for name in SOURCES + CAMPAIGN_SOURCES + POLICY_SOURCES:
        raw = (root / "tools" / name).read_bytes()
        if sha(root / "tools" / name) != proof["original_sha256"][name] or \
                sha(pipeline / name) != proof["variant_sha256"][name]:
            raise ValueError("Original or isolated source changed")
        if name == "tenonos_paper_orchestrator.py":
            raw = budget_variant(raw, plan["graph_stage_token_caps"])
        elif name in ("run_tenonos_paper_tasks.py", "audit_tenonos_paper_tasks.py"):
            raw = campaign_variant(raw, name)
        elif name in POLICY_SOURCES:
            raw = policy_variant(raw, name)
        if raw != (pipeline / name).read_bytes():
            raise ValueError("History variant changes prompts, selection or judge")
    for name, digest in result["evidence_manifest"].items():
        p = (campaign / name).resolve()
        p.relative_to(campaign.resolve())
        if sha(p) != digest:
            raise ValueError("Captured history no longer matches its independent replay")
    histories = json.loads((campaign / "campaign.json").read_text())["histories"]
    calls, tokens, choice_conflict_rounds = 0, 0, []
    for history in histories:
        for index in (1, 2):
            folder = campaign / history["id"] / ("R" + str(index)) / "candidate"
            used = 0
            for call in json.loads((folder / "model-calls.json").read_text()):
                payload = json.loads((folder / (call["stage"] + "-request.json")).read_text())
                request_limit(history["method"], call["stage"], payload["max_tokens"], used)
                context = json.loads(payload["messages"][1]["content"])
                allowed = {"objective", "paths"} if call["stage"] == "paths" else {
                    "task", "allowed_configuration_metadata", "parsed_objective", "selected_paths", "permitted_controls"}
                if set(context) - allowed:
                    raise ValueError("Unexpected model context or hidden measurement feedback")
                response = folder / (call["stage"] + "-response.json")
                if response.exists():
                    used += json.loads(response.read_text())["usage"]["completion_tokens"]
                calls += 1
            if used > 1152:
                raise ValueError("Per-round output budget exceeded")
            tokens += used
            task = json.loads((folder / "task.json").read_text())
            generated = json.loads((folder / "generation.json").read_text())
            for prior in folder.glob("validation-*/.config"):
                candidate_index = prior.parent.name.removeprefix("validation-")
                submitted = json.loads((folder / ("candidate-" + candidate_index + ".json")).read_text())["options"]
                resolved = configuration(prior)
                if not generated["valid_candidate"] and inherited_choice_conflict(task, submitted, resolved):
                    choice_conflict_rounds.append(history["id"] + "/R" + str(index))
                    break
    if (calls, tokens) != (result["model_calls"], result["completion_tokens"]) or calls > 24 or tokens > 13824:
        raise ValueError("Batch exceeds its registered API bounds")
    return {"pass": True, "scope": "Budget-only state-linked Tenon reconstruction histories, not author engine or RSI",
        "histories": result["histories"], "groups": result["groups"], "model": result["model"],
        "registered_histories": 6, "registered_rounds": 12, "model_calls": calls, "completion_tokens": tokens,
        "finish_reasons": result["finish_reasons"], "candidate_guest_captures": result["candidate_guest_captures"],
        "parent_check_guest_captures": result["parent_check_guest_captures"], "aggregate_output_cap": 1152,
        "graph_stage_caps": plan["graph_stage_token_caps"], "underlying_audit_sha256": sha(underlying),
        "source_variant_sha256": sha(pipeline / "source-variant.json"), "protocol_sha256": sha(pipeline / "protocol.json"),
        "inherited_tlsf_choice_conflict_rounds": choice_conflict_rounds,
        "new_model_calls_by_audit": 0, "author_engine": False, "rsi": False, "whole_live_ram_peak_bytes": None}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("pipeline", "campaign", "underlying", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace"):
        p.error("Audit raw evidence on leon")
    result = audit(root, args.pipeline.resolve(), args.campaign.resolve(), args.underlying.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("histories", "groups")}))
