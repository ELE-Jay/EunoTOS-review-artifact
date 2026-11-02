#!/usr/bin/env python3
"""Bind expanded trials to replayed native records and qualified behavior profiles."""
import argparse
import json
from pathlib import Path
import sys

from audit_tenonos_runtime_oracle import audit as observer_audit
from audit_tenonos_tasks import configuration, require
from bind_tenonos_runtime_candidates import build_identity, identity
from prepare_tenonos_expanded_tasks import numeric_pipeline_source, runner_metadata
from tenonos_kvm_reproduce import save, sha

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_CAPTURE = "artifacts/reports/tenonos-expanded-reference-feasibility-v1"
OLD_CAPTURE = "artifacts/reports/tenonos-runtime-oracle-rpi4-v6"


def known_profiles(root):
    known = {}
    sources = [(root / REFERENCE_CAPTURE / "behavior", root / REFERENCE_CAPTURE / "behavior-protocol.json"),
               (root / OLD_CAPTURE, None),
               (root / "artifacts/reports/tenonos-runtime-candidate-profile-v1", root / "registry/tenonos_runtime_candidates_v1.json")]
    for folder, plan in sources:
        report = observer_audit(root, folder, plan)
        for profile in report["profiles"]:
            source = folder / profile["profile"]
            proof = json.loads((source / "source-proof.json").read_text())
            key = identity(configuration(source / "input.config"), proof["identity"], sha(source / "build/compiler.stdout"))
            if key in known:
                require(known[key]["admitted"] == profile["admitted"], "Conflicting known behavioral profiles")
                continue
            known[key] = {"identity": key, "profile": profile["profile"], "capture": str(folder.relative_to(root)),
                          "admitted": profile["admitted"], "guests": len(profile["guests"])}
    return known


def inventory(root, pipeline, campaign, native_report):
    spec = json.loads((pipeline / "protocol.json").read_text())
    source = json.loads((pipeline / "source-variant.json").read_text())
    base = root / spec["base_pipeline"]
    require(source["specification_sha256"] == sha(pipeline / "protocol.json") and
            source["base_proof_sha256"] == sha(base / "source-variant.json"), "Pipeline identity changed")
    for name, digest in source["variant_sha256"].items():
        raw = (base / name).read_bytes()
        require(sha(base / name) == source["base_source_sha256"][name], "Base reconstruction changed")
        if source.get("numeric_adapter_repaired"):
            raw = numeric_pipeline_source(raw, name, source["runner_previous_id"], spec["id"])
        elif name == "run_tenonos_paper_tasks.py":
            raw = runner_metadata(raw, spec["id"])
        require(sha(pipeline / name) == digest and (pipeline / name).read_bytes() == raw, "Generator or judge changed")
    checked = json.loads(native_report.read_text())
    require(checked["generation_interface_admissible"] and checked["runtime_audit"]["registered_task_outcomes_audited"],
            "Native/request replay is incomplete")
    registration = json.loads((campaign / "registration.json").read_text())
    require(checked["campaign_registration_sha256"] == sha(campaign / "registration.json") and
            checked["campaign_results_sha256"] == sha(campaign / "results.json") and
            checked["registered_trials"] == source["registered_trials"] == len(registration["trials"]) and
            registration["aggregate_completion_tokens_per_trial"] == spec["maximum_output_tokens"] and
            checked["model_attempts"] <= spec["maximum_model_calls"] and
            checked["completion_tokens"] <= spec["maximum_completion_tokens"], "Native replay or budget binding differs")
    for name, digest in checked["campaign_evidence_manifest"].items():
        path = (campaign / name).resolve()
        path.relative_to(campaign.resolve())
        require(sha(path) == digest, "Audited native evidence changed")
    known, groups, rows, missing = known_profiles(root), {}, [], []
    results = json.loads((campaign / "results.json").read_text())
    for trial in registration["trials"]:
        row = next(r for r in results["records"] if r["id"] == trial["id"])
        if not row["gates"]["functional"]:
            rows.append({"trial": trial["id"], "original_task_pass": row["end_to_end_pass"],
                         "profile": None, "boundary": "No complete native runtime; no semantic success assigned."})
            continue
        build = campaign / trial["id"] / "evaluation/build"
        key, proof = build_identity(build)
        if key not in groups:
            if key in known:
                groups[key] = known[key]
            else:
                name = "expanded-config-%d" % (len(missing) + 1)
                missing.append({"id": name, "build": str(build.relative_to(root)),
                                "config_sha256": proof["config_sha256"], "image_sha256": proof["image_sha256"]})
                groups[key] = {"identity": key, "profile": name, "capture": None, "admitted": None}
        rows.append({"trial": trial["id"], "original_task_pass": row["end_to_end_pass"],
                     "identity": key, "profile": groups[key]["profile"]})
    return {"scope": "Separate post-generation behavioral qualification; no new model trials or reassigned timing/RAM/energy.",
            "native_report_sha256": sha(native_report), "pipeline_proof_sha256": sha(pipeline / "source-variant.json"),
            "campaign_results_sha256": sha(campaign / "results.json"), "rows": rows, "groups": list(groups.values()),
            "variants": missing, "registered_trials": len(rows), "distinct_runtime_configurations": len(groups),
            "model_calls": 0, "source_sha256": sha(Path(__file__))}


def bind(root, inventory_path, extra=None, plan=None):
    frozen = json.loads(inventory_path.read_text())
    known = known_profiles(root)
    fresh = 0
    if frozen["variants"]:
        require(extra is not None and plan is not None, "Missing configurations still need behavioral collection")
        protocol = json.loads(plan.read_text())
        require(protocol["reference_registry_sha256"] == sha(inventory_path), "Additional inventory differs")
        result = observer_audit(root, extra, plan)
        for profile in result["profiles"]:
            folder = extra / profile["profile"]
            proof = json.loads((folder / "source-proof.json").read_text())
            key = identity(configuration(folder / "input.config"), proof["identity"], sha(folder / "build/compiler.stdout"))
            require(key not in known, "Redundant new behavioral configuration")
            known[key] = {"identity": key, "profile": profile["profile"], "capture": str(extra.relative_to(root)),
                          "admitted": profile["admitted"], "guests": len(profile["guests"])}
            fresh += len(profile["guests"])
    rows, reused = [], set()
    for row in frozen["rows"]:
        if row["profile"] is None:
            rows.append({**row, "behavior_qualified": False, "qualified_task_pass": False})
            continue
        profile = known.get(row["identity"])
        require(profile is not None, "Candidate has no matching full configuration/source/compiler profile")
        if extra is None or profile["capture"] != str(extra.relative_to(root)):
            reused.add(row["identity"])
        rows.append({**row, "behavior_qualified": profile["admitted"],
                     "qualified_task_pass": row["original_task_pass"] and profile["admitted"],
                     "behavior_capture": profile["capture"]})
    return {"audit": "pass", "registered_trials": len(rows), "rows": rows,
            "qualified_task_passes": sum(r["qualified_task_pass"] for r in rows),
            "reused_behavior_guests": sum(known[key]["guests"] for key in reused), "new_behavior_guests": fresh,
            "inventory_sha256": sha(inventory_path), "new_model_calls": 0,
            "boundary": "Aliases reuse configuration-level observer evidence, not independent runtime observations. Original attempt durations and denominators remain unchanged. Expanded RAM/energy evidence remains separate."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "bind"))
    for name in ("output", "pipeline", "campaign", "native-report", "inventory", "extra", "plan"):
        parser.add_argument("--" + name, type=Path, required=name == "output")
    args = parser.parse_args()
    if sys.platform == "darwin" or args.output.exists():
        parser.error("Use leon and a new persistent output file")
    if args.action == "inventory":
        if not all((args.pipeline, args.campaign, args.native_report)):
            parser.error("Inventory needs pipeline, campaign and native report")
        value = inventory(ROOT, args.pipeline.resolve(), args.campaign.resolve(), args.native_report.resolve())
    else:
        if args.inventory is None:
            parser.error("Bind needs a frozen inventory")
        value = bind(ROOT, args.inventory.resolve(), args.extra.resolve() if args.extra else None,
                     args.plan.resolve() if args.plan else None)
    save(args.output, value)
    print(json.dumps({k: v for k, v in value.items() if k not in ("rows", "groups", "variants")}, indent=2))
