#!/usr/bin/env python3
"""Prepare a source-bound token-budget variant, without model or hardware calls."""
import argparse
import ast
import json
from pathlib import Path
import shutil

from tenonos_kvm_reproduce import sha, save, utc

SOURCES = ("tenonos_paper_orchestrator.py", "tenonos_config_validation.py", "tenonos_lib_graph.py",
           "tenonos_lightrag_runtime.py", "tenonos_model_service.py", "tenonos_orchestrator.py",
           "tenonos_kvm_reproduce.py", "import_iotos_subjects.py")
CAMPAIGN_SOURCES = ("run_tenonos_paper_tasks.py", "audit_tenonos_paper_tasks.py", "audit_tenonos_tasks.py", "iotos_task_benchmark.py")
POLICY_SOURCES = ("run_tenonos_policy_sequence.py", "audit_tenonos_policy_sequence.py")


def budget_variant(raw, limits):
    if limits != {"objective": 288, "paths": 288}:
        raise ValueError("Only the frozen stage-budget profile is supported")
    tree = ast.parse(raw)
    locations = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "call" and \
                node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in limits:
            stage, cap = node.args[0].value, node.args[-1]
            if stage in locations or len(node.args) != 4 or not isinstance(cap, ast.Constant) or cap.value != 96 or cap.lineno != cap.end_lineno:
                raise ValueError("Original token-cap call structure changed")
            locations[stage] = cap
    if set(locations) != set(limits):
        raise ValueError("Both original graph-stage caps must be present exactly once")
    lines = raw.splitlines(keepends=True)
    for stage, cap in sorted(locations.items(), key=lambda pair: (pair[1].lineno, pair[1].col_offset), reverse=True):
        row = lines[cap.lineno - 1]
        lines[cap.lineno - 1] = row[:cap.col_offset] + str(limits[stage]).encode() + row[cap.end_col_offset:]
        cap.value = limits[stage]
    modified = b"".join(lines)
    if ast.dump(ast.parse(modified), include_attributes=False) != ast.dump(tree, include_attributes=False):
        raise ValueError("Budget variant changes more than the two cap literals")
    return modified


def campaign_variant(raw, name):
    expected = 3 if name == "run_tenonos_paper_tasks.py" else 1
    tree = ast.parse(raw)
    locations = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and type(n.value) is int and n.value == 384]
    if len(locations) != expected:
        raise ValueError("Frozen aggregate-budget locations differ")
    lines = raw.splitlines(keepends=True)
    for n in sorted(locations, key=lambda n: (n.lineno, n.col_offset), reverse=True):
        row = lines[n.lineno - 1]
        lines[n.lineno - 1] = row[:n.col_offset] + b"1152" + row[n.end_col_offset:]
        n.value = 1152
    changed = b"".join(lines)
    if ast.dump(ast.parse(changed), include_attributes=False) != ast.dump(tree, include_attributes=False):
        raise ValueError("Aggregate variant changed more than budget constants")
    if name == "run_tenonos_paper_tasks.py":
        old = b'root = Path(__file__).resolve().parents[1]'
        new = b'root = Path("/home/reviewer/esp32-pilot/audit-workspace")'
        protocol = b'tenon-paper-v4-paired-v2'
        if changed.count(old) != 1 or changed.count(protocol) != 1:
            raise ValueError("Frozen runner root or registration differs")
        changed = changed.replace(old, new).replace(protocol, b'tenon-paper-v4-equal-budget-v1')
    return changed


def policy_variant(raw, name):
    count = 3 if name == "run_tenonos_policy_sequence.py" else 1
    tree = ast.parse(raw)
    locations = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and type(n.value) is int
                 and n.value in (384, 4608)]
    if any(sum(n.value == v for n in locations) != count for v in (384, 4608)):
        raise ValueError("Frozen policy-budget locations differ")
    lines = raw.splitlines(keepends=True)
    for n in sorted(locations, key=lambda n: (n.lineno, n.col_offset), reverse=True):
        row = lines[n.lineno - 1]
        value = {384: 1152, 4608: 13824}[n.value]
        lines[n.lineno - 1] = row[:n.col_offset] + str(value).encode() + row[n.end_col_offset:]
        n.value = value
    changed = b"".join(lines)
    if ast.dump(ast.parse(changed), include_attributes=False) != ast.dump(tree, include_attributes=False):
        raise ValueError("Policy variant changed more than budget constants")
    bindings = ({b'ROOT = Path(__file__).resolve().parents[1]': b'ROOT = Path("/home/reviewer/esp32-pilot/audit-workspace")',
                 b'source = ROOT / "tools" / name': b'source = Path(__file__).with_name(name)',
                 b'sha(ROOT / "tools" / n)': b'sha(Path(__file__).with_name(n))'}
                if name == "run_tenonos_policy_sequence.py" else
                {b'sha(root / "tools" / name)': b'sha(Path(__file__).with_name(name))'})
    for old, new in bindings.items():
        if changed.count(old) != 1:
            raise ValueError("Frozen policy source binding differs")
        changed = changed.replace(old, new)
    return changed


def prepare_policy(root, output):
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Prepare on leon in a new persistent source-variant folder")
    output.resolve().relative_to((root / "artifacts/reports").resolve())
    plan_path = root / "registry/tenonos_policy_budget_v1.json"
    plan = json.loads(plan_path.read_text())
    if (plan["maximum_output_tokens_per_round"], plan["maximum_model_calls"], plan["maximum_completion_tokens"]) != (1152, 24, 13824):
        raise ValueError("Frozen policy budget differs")
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output / "protocol.json")
    before, after = {}, {}
    for name in SOURCES + CAMPAIGN_SOURCES + POLICY_SOURCES:
        source = root / "tools" / name
        raw = source.read_bytes()
        if name == "tenonos_paper_orchestrator.py":
            raw = budget_variant(raw, plan["graph_stage_token_caps"])
        elif name in ("run_tenonos_paper_tasks.py", "audit_tenonos_paper_tasks.py"):
            raw = campaign_variant(raw, name)
        elif name in POLICY_SOURCES:
            raw = policy_variant(raw, name)
        (output / name).write_bytes(raw)
        before[name], after[name] = sha(source), sha(output / name)
    proof = {"prepared_utc": utc(), "protocol_sha256": sha(plan_path), "original_sha256": before,
             "variant_sha256": after, "changed_files": [n for n in before if before[n] != after[n]],
             "stage_caps": plan["graph_stage_token_caps"], "model_calls": 0, "trial_results": None}
    save(output / "source-variant.json", proof)
    print(json.dumps(proof))


def prepare(root, output, plan_path, campaign=False):
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Prepare on leon in a new persistent source-variant folder")
    output.resolve().relative_to((root / "artifacts/reports").resolve())
    plan = json.loads(plan_path.read_text())
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output / "protocol.json")
    before, after = {}, {}
    for name in SOURCES + (CAMPAIGN_SOURCES if campaign else ()):
        source, destination = root / "tools" / name, output / name
        raw = source.read_bytes()
        if name == "tenonos_paper_orchestrator.py":
            raw = budget_variant(raw, plan["graph_stage_token_caps"])
        elif name in ("run_tenonos_paper_tasks.py", "audit_tenonos_paper_tasks.py"):
            raw = campaign_variant(raw, name)
        destination.write_bytes(raw)
        before[name], after[name] = sha(source), sha(destination)
    proof = {"prepared_utc": utc(), "original_sha256": before, "variant_sha256": after,
             "changed_files": [n for n in before if before[n] != after[n]],
             "stage_caps": plan["graph_stage_token_caps"], "model_calls": 0,
             "trial_results": None, "paid_batch_authorized_by_preparation": False}
    save(output / "source-variant.json", proof)
    if campaign:
        if plan["status"] != "authorized_not_executed":
            raise ValueError("Campaign preparation needs recorded authorization")
        bank_path = root / plan["base_task_bank"]
        bank = json.loads(bank_path.read_text())
        bank.update(id="tenon-paper-v4-equal-budget-v1", maximum_output_tokens=1152, model=plan["model"],
                    scope="Equal-output-budget sensitivity of the independently reconstructed Tenon paper pipeline; task requirements and references unchanged.",
                    base_task_bank_sha256=sha(bank_path))
        bank.pop("model_metadata", None)
        save(output / "task-bank.json", bank)
    print(json.dumps(proof))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-ready", action="store_true")
    parser.add_argument("--policy-ready", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.policy_ready:
        if args.campaign_ready:
            parser.error("Choose one campaign type")
        prepare_policy(root, args.output)
    else:
        prepare(root, args.output, root / "registry/tenonos_budget_sensitivity_v1.json", args.campaign_ready)
