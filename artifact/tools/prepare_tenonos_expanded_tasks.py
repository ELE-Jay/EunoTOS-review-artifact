#!/usr/bin/env python3
"""Freeze new tasks against qualified references and an unchanged reconstruction."""
import argparse
import json
from pathlib import Path
import shutil
import sys

from audit_tenonos_tasks import configuration
from prepare_tenonos_budget_profile import SOURCES, CAMPAIGN_SOURCES
from prepare_tenonos_expanded_references import audit, reference_options
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
SPEC = "registry/tenonos_expanded_composition_v1.json"


def runner_metadata(raw, identifier):
    replacements = {
        b"tenon-paper-v4-equal-budget-v1": identifier.encode(),
        b"Three fresh calls per task and method; median/range, no P95; retain all failures.":
        b"Five fresh calls per task and method; median/range, no P95; retain all failures."
    }
    for before, after in replacements.items():
        if raw.count(before) != 1:
            raise ValueError("Expected only existing runner metadata")
        raw = raw.replace(before, after)
    return raw


def numeric_pipeline_source(raw, name, previous_id, identifier):
    if name == "tenonos_orchestrator.py":
        old = b'        node = known.get(name)\n'
        new = old + (b'        if node is not None and node["type"] in ("int", "hex") and type(raw) is int:\n'
                     b'            raw = str(raw) if node["type"] == "int" else hex(raw)\n')
        if raw.count(old) != 1:
            raise ValueError("Expected exactly one native-option type boundary")
        return raw.replace(old, new)
    if name == "run_tenonos_paper_tasks.py":
        if raw.count(previous_id.encode()) != 1:
            raise ValueError("Expected exactly one previous protocol identifier")
        return raw.replace(previous_id.encode(), identifier.encode())
    return raw


def prepare_numeric(root, base, output):
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Prepare a new isolated numeric-interface batch on leon")
    output.relative_to(root / "artifacts/reports")
    proof = json.loads((base / "source-variant.json").read_text())
    plan = json.loads((base / "protocol.json").read_text())
    bank = json.loads((base / "task-bank.json").read_text())
    previous_id = plan["id"]
    identifier = "tenon-expanded-numeric-interface-v1"
    output.mkdir(parents=True)
    hashes = {}
    for name, digest in proof["variant_sha256"].items():
        if sha(base / name) != digest:
            raise ValueError("Original frozen composition pipeline changed")
        (output / name).write_bytes(numeric_pipeline_source((base / name).read_bytes(), name, previous_id, identifier))
        hashes[name] = sha(output / name)
    plan.update(id=identifier, base_pipeline=str(base.relative_to(root)),
                interface_repair="Normalize exact JSON integers only for declared native int/hex options. Reject bool, float and unknown symbols. No prompt, task, model, budget, retrieval, selection, reference or runtime-judge change; old strict-string batch retained.")
    save(output / "protocol.json", plan)
    bank.update(id=identifier, specification_sha256=sha(output / "protocol.json"))
    save(output / "task-bank.json", bank)
    save(output / "source-variant.json", {"prepared_utc": utc(), "specification_sha256": sha(output / "protocol.json"),
        "base_pipeline": str(base.relative_to(root)), "base_proof_sha256": sha(base / "source-variant.json"),
        "base_source_sha256": proof["variant_sha256"], "variant_sha256": hashes,
        "numeric_adapter_repaired": True, "runner_previous_id": previous_id,
        "registered_tasks": len(bank["tasks"]), "registered_trials": proof["registered_trials"], "model_calls": 0})
    shutil.copyfile(Path(__file__), output / "preparer-source.py")
    return {"prepared": str(output.relative_to(root)), "tasks": len(bank["tasks"]),
            "trials": proof["registered_trials"], "model_calls": 0}


def prepare(root, output):
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Use leon and a new persistent frozen pipeline directory")
    output.relative_to(root / "artifacts/reports")
    spec = json.loads((root / SPEC).read_text())
    audited = {}
    for task in spec["tasks"]:
        path = task.get("reference_campaign", spec["reference_campaign"])
        if path not in audited:
            audited[path] = audit(root / path)
        if not any(r["id"] == task["reference"] and r["feasible"] for r in audited[path]["references"]):
            raise ValueError("A new task lacks a qualified feasible reference")
    base = root / spec["base_pipeline"]
    proof = json.loads((base / "source-variant.json").read_text())
    graph = root / spec["graph"]
    if sha(graph) != spec["graph_sha256"] or sha(root / spec["index"] / "run.json") != spec["index_run_sha256"]:
        raise ValueError("Original graph or index changed")
    symbols = {n["name"] for n in json.loads(graph.read_text())["nodes"] if n["kind"] == "config"}
    if not set(spec["candidate_controls"]) <= symbols:
        raise ValueError("Requested new controls are absent from source-bound graph")
    output.mkdir(parents=True)
    shutil.copyfile(root / SPEC, output / "protocol.json")
    hashes = {}
    for name in SOURCES + CAMPAIGN_SOURCES:
        source = base / name
        if sha(source) != proof["variant_sha256"][name]:
            raise ValueError("Previously qualified pipeline changed")
        raw = source.read_bytes()
        if name == "run_tenonos_paper_tasks.py":
            raw = runner_metadata(raw, spec["id"])
        (output / name).write_bytes(raw)
        hashes[name] = sha(output / name)
    tasks = []
    for task in spec["tasks"]:
        references = root / task.get("reference_campaign", spec["reference_campaign"])
        old_plan = json.loads((references / "protocol.json").read_text())
        profiles = {p["id"]: p for p in old_plan["profiles"]}
        name = task["reference"]
        folder = references / name
        build = folder / "evaluation/build"
        options = {**reference_options(old_plan, profiles[name]), **task["additional_required_options"]}
        actual = configuration(build / ".config")
        if any(actual.get(k, "n") != v for k, v in options.items()):
            raise ValueError("Reference misses frozen requirement: " + task["id"])
        fixed = {**old_plan["fixed_options"], "LIBUKLOCK": "y", "LIBUKLOCK_MUTEX": "n", "LIBUKLOCK_RWLOCK": "n"}
        files = [p for base_folder in (folder, references / "behavior" / name)
                 for p in base_folder.rglob("*") if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts]
        tasks.append({"id": task["id"], "family": "configuration_composition", "objective": task["objective"],
                      "application": "app-rtos-benchmark-abi", "fixed_options": fixed,
                      "candidate_controls": spec["candidate_controls"], "required_options": options,
                      "generation_budget_s": spec["generation_budget_s"], "maximum_attempts": 1,
                      "reference_profile": name, "reference_files": [
                          {"path": str(p.relative_to(root)), "sha256": sha(p)} for p in sorted(set(files))]})
    bank = {k: spec[k] for k in ("id", "scope", "maximum_output_tokens", "generation_budget_s", "wall_budget_s",
                                 "attempts_per_trial", "independent_guest_boots_per_candidate", "statistics", "model")}
    bank.update(seeds=list(range(42, 42 + spec["fresh_requests_per_task_method"])),
                seed_interpretation="Repetition labels only; official API transmits no seed.",
                tasks=tasks, specification_sha256=sha(root / SPEC), feasible_reference_audit=audited)
    save(output / "task-bank.json", bank)
    save(output / "source-variant.json", {"prepared_utc": utc(), "specification_sha256": sha(root / SPEC),
        "base_pipeline": spec["base_pipeline"], "base_proof_sha256": sha(base / "source-variant.json"),
        "variant_sha256": hashes, "base_source_sha256": {n: proof["variant_sha256"][n] for n in hashes},
        "changes": "Task bank and runner descriptive metadata only. Generator, retrieval, token caps, corrected native serializer, runtime and audit code unchanged.",
        "model_calls": 0, "registered_tasks": len(tasks), "registered_trials": len(tasks) * 2 * spec["fresh_requests_per_task_method"]})
    return {"prepared": str(output.relative_to(root)), "tasks": len(tasks), "trials": len(tasks) * 10, "model_calls": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--numeric-base", type=Path)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Prepare evidence-dependent tasks on leon")
    print(json.dumps(prepare_numeric(ROOT, args.numeric_base.resolve(), args.output.resolve())
                     if args.numeric_base else prepare(ROOT, args.output.resolve())))
