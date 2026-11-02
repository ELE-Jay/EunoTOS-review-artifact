#!/usr/bin/env python3
"""Replay saved generation, native configuration and guest evidence; no model calls."""
import argparse
from collections import Counter
import contextlib
import io
import json
from pathlib import Path
import re
import statistics
import sys

from audit_tenonos_tasks import configuration, require
from iotos_task_benchmark import summarize_accounting
from tenonos_config_validation import submitted_options, validate
from tenonos_kvm_reproduce import sha
from tenonos_paper_orchestrator import parse_objective, retrieved_paths, select_paths, strict_object


def request_violations(payload):
    issues = []
    if payload.get("response_format") == {"type": "json_object"} and not any(
            "json" in str(m.get("content", "")).lower() for m in payload.get("messages", [])):
        issues.append("json_mode_without_json_instruction")
    if "seed" in payload or "provider" in payload:
        issues.append("unsupported_official_route_parameters")
    if payload.get("thinking") != {"type": "disabled"}:
        issues.append("thinking_mode_differs")
    return issues


def audit(folder):
    registration = json.loads((folder / "registration.json").read_text())
    report = json.loads((folder / "results.json").read_text())
    if not report["finished"] or len(report["records"]) != len(registration["trials"]):
        raise ValueError("Campaign is incomplete")
    for name, expected in registration["source_sha256"].items():
        if sha(folder / "sources" / name) != expected:
            raise ValueError("Captured source differs: " + name)
    by_id = {r["id"]: r for r in report["records"]}
    if len(by_id) != len(report["records"]) or set(by_id) != {r["id"] for r in registration["trials"]}:
        raise ValueError("Registered trial coverage differs")
    attempts, successful, tokens, prompt_tokens = 0, 0, 0, 0
    issues, finishes, failures, fingerprints = Counter(), Counter(), Counter(), set()
    rows = []
    for trial in registration["trials"]:
        root = folder / trial["id"] / "candidate"
        generated = json.loads((root / "generation.json").read_text())
        if sha(root / "task.json") != registration["task_sha256"][trial["task"]]:
            raise ValueError("Task differs from registration")
        calls = json.loads((root / "model-calls.json").read_text())
        if len(calls) != len(list(root.glob("*-request.json"))):
            raise ValueError("Request coverage differs")
        used = 0
        for call in calls:
            attempts += 1
            payload = json.loads((root / (call["stage"] + "-request.json")).read_text())
            if payload["model"] != registration["model"] or not 0 < payload["max_tokens"] <= 384 - used:
                raise ValueError("Model or aggregate token budget differs")
            context = json.loads(payload["messages"][1]["content"])
            if "task" in context and set(context["task"]) - {"objective", "fixed_options", "candidate_controls", "starting_options"}:
                raise ValueError("Private judge fields were exposed")
            issues.update(request_violations(payload))
            response_path = root / (call["stage"] + "-response.json")
            if response_path.exists() != call["response_received"]:
                raise ValueError("Response presence differs")
            if response_path.exists():
                response = json.loads(response_path.read_text())
                count = response["usage"]["completion_tokens"]
                if response["model"] != registration["model"] or type(count) is not int or not 0 <= count <= payload["max_tokens"]:
                    raise ValueError("Actual model or response usage differs")
                used += count
                tokens += count
                prompt_tokens += response["usage"]["prompt_tokens"]
                successful += 1
                choice = response["choices"][0]
                finishes[choice["finish_reason"]] += 1
                if response.get("system_fingerprint"):
                    fingerprints.add(response["system_fingerprint"])
        if used != generated["completion_tokens"]:
            raise ValueError("Generation token summary differs")
        failure = generated.get("failure") or {}
        failures[failure.get("type", "none")] += 1
        rows.append({"id": trial["id"], "attempts": len(calls), "completion_tokens": used,
                     "valid_candidate": generated["valid_candidate"], "failure_type": failure.get("type")})
    raw_boots = list(folder.glob("*/evaluation/boots/boot*.stdout"))
    return {"scope": "Saved generation-interface evidence only; native dependency and runtime audit remain separate.",
        "registered_trials": len(rows), "actual_model": registration["model"], "model_attempts": attempts,
        "responses_received": successful, "completion_tokens": tokens, "prompt_tokens": prompt_tokens,
        "request_protocol_issues": dict(issues), "finish_reasons": dict(finishes), "failure_types": dict(failures),
        "fingerprints": sorted(fingerprints), "raw_guest_captures": len(raw_boots), "trials": rows,
        "generation_interface_admissible": not issues,
        "full_benchmark_admission_proven": False, "author_engine": False, "new_model_calls": 0}


def guest_outcome(stdout, stderr, returncode):
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", stdout)
    names = ["average_task_switch_time, in cpu cycles", "average_multi_task_switch_time, in cpu cycles",
             "average_task_preempt_time, in cpu cycles", "average_semaphore_shuffle_time, in cpu cycles",
             "interrupt_latency_time, in cpu cycles", "timer_deviation_under_interrupt_interference, in count of generic timer"]
    headings = ["task switch benchmark", "50 task switch benchmark", "task preempt benchmark",
                "semaphore shuffle benchmark", "interrupt latency benchmark", "timer deviation under interrupt interference"]
    values = re.findall(r"R-Rhealstone: ([^\r\n]+?) - (-?[0-9]+) (cycle|count)", text)
    complete = (returncode == 0 and len(values) == 6 and {v[0] for v in values} == set(names) and
                all(text.count("RST: " + h) == 1 for h in headings) and
                not re.search(r"panic|unhandled exception|assertion.*fail|\[E/RST\]", text + stderr, re.I))
    return {"booted": "powered by tenonos" in text.lower(), "complete": complete, "values": values}


def constraint_outcome(task, actual, image_bytes, baseline=None):
    checks = [actual.get(k, "n") == v for k, v in task["required_options"].items()]
    if "maximum_image_bytes" in task:
        checks.append(image_bytes <= task["maximum_image_bytes"])
    if task.get("preserve_reference"):
        require(baseline is not None, "Missing starting configuration")
        changed = {k for k in actual.keys() | baseline.keys() if actual.get(k, "n") != baseline.get(k, "n")}
        checks.append(not (changed - set(task["preserve_reference"]["allowed_changes"])))
    return all(checks)


def published_rows(report):
    runtime = report["runtime_audit"]
    require(runtime["registered_task_outcomes_audited"], "Runtime outcomes have not been replayed")
    groups = runtime["groups"]
    labels = {"TC-A": "Composition", "TC-B": "Image budget", "TC-C": "Modification"}
    require(len(groups) == 6 and {(g["task"], g["method"]) for g in groups} ==
            {(t, m) for t in labels for m in ("direct", "graph")}, "Paired group coverage differs")
    rows = []
    for task, label in labels.items():
        for method in ("direct", "graph"):
            counts = next(g["accounting"] for g in groups if g["task"] == task and g["method"] == method)
            n = counts["applicable_runs"]
            require(n == counts["registered_runs"] == 3, "Published task denominator differs")
            stages = counts["unconditional_stage_success_rates"]
            values = [round(stages[k] * n) for k in ("generated", "built", "functional")] + [counts["successful_runs"]]
            rows.append(label + " / " + method + " & " + " & ".join(str(v) + "/" + str(n) for v in values))
    return rows


def require_published_table(source, rows):
    tables = [t for t in re.findall(r"\\begin\{table\}.*?\\end\{table\}", source, re.S)
              if "\\label{tab:tenonpaired}" in t]
    require(len(tables) == 1, "Missing or duplicate paired table")
    actual = [line.strip() for line in tables[0].splitlines()
              if " & " in line and re.search(r"\d", line.split(" & ", 1)[1])]
    require(sorted(actual) == sorted(row + r" \\" for row in rows), "Paired manuscript row differs")


def audit_runtime(folder, bank_path, graph_path, workspace, replay):
    registration = json.loads((folder / "registration.json").read_text())
    report = json.loads((folder / "results.json").read_text())
    bank, graph = json.loads(bank_path.read_text()), json.loads(graph_path.read_text())
    require(sha(bank_path) == registration["historical_task_bank_sha256"] and
            sha(graph_path) == registration["graph_sha256"], "Bank or graph differs")
    for name, expected in registration["source_sha256"].items():
        if name != "run_tenonos_paper_tasks.py":
            require(sha(Path(__file__).with_name(name)) == expected, "Replay source differs: " + name)
    for task in bank["tasks"]:
        for item in task["reference_files"]:
            require(sha(Path(item["path"])) == item["sha256"], "Feasible reference changed")
    replay.mkdir(parents=True, exist_ok=False)
    receipts, checked = [], []
    for planned in registration["trials"]:
        run = folder / planned["id"]
        candidate = run / "candidate"
        record = json.loads((run / "trial.json").read_text())
        require(record == next(r for r in report["records"] if r["id"] == planned["id"]), "Trial/result disagreement")
        task = next(t for t in bank["tasks"] if t["id"] == planned["task"])
        require(json.loads((candidate / "task.json").read_text()) ==
                {**task, "protocol_id": bank["id"], "bank_sha256": sha(bank_path)}, "Frozen task changed")
        generated = json.loads((candidate / "generation.json").read_text())
        require(generated["task_sha256"] == sha(candidate / "task.json") and
                generated["graph_sha256"] == sha(graph_path) and
                generated["source_sha256"] == {n: registration["source_sha256"][n] for n in generated["source_sha256"]},
                "Generation identity changed")
        allowed = set(task["candidate_controls"])
        if (candidate / "selected-paths.json").exists():
            parsed = parse_objective(json.loads((candidate / "objective-response.json").read_text())["choices"][0]["message"]["content"])
            require(parsed == json.loads((candidate / "objective.json").read_text()), "Parsed objective differs")
            paths = retrieved_paths(graph, json.loads((candidate / "retrieval/retrieval.json").read_text()),
                                    registration["reconstruction"]["maximum_paths"])
            selected = select_paths(json.loads((candidate / "paths-response.json").read_text())["choices"][0]["message"]["content"],
                                    paths, registration["reconstruction"]["path_threshold"])
            require(selected == json.loads((candidate / "selected-paths.json").read_text()), "Selected paths differ")
            allowed &= {n["name"] for p in selected for n in p["nodes"] if n["kind"] == "config"}
        valid = []
        if (candidate / "candidate-validations.json").exists():
            raw = json.loads((candidate / "configurations-response.json").read_text())
            proposed = strict_object(raw["choices"][0]["message"]["content"])["candidates"]
            for row in json.loads((candidate / "candidate-validations.json").read_text()):
                index = row["candidate"]
                value = proposed[index]
                path = candidate / ("candidate-" + str(index) + ".json")
                if "validation_sha256" not in row:
                    require(not row["dependency_valid"] and row.get("input_failure"), "Missing input rejection evidence")
                    try:
                        options, _ = submitted_options(graph, json.dumps({"options": value["options"]}), task)
                        require(set(options) <= allowed, "Outside permitted graph controls")
                    except (ValueError, TypeError, KeyError):
                        continue
                    raise ValueError("Rejected candidate has no independently reproduced input failure")
                require(json.loads(path.read_text()) == {"options": value["options"]}, "Candidate answer changed")
                prior = candidate / ("validation-" + str(index))
                proof = json.loads((prior / "validation.json").read_text())
                require(sha(prior / "validation.json") == row["validation_sha256"] and
                        sha(prior / ".config") == proof["native_config_sha256"] and
                        sha(prior / "candidate.defconfig") == proof["input_defconfig_sha256"], "Native validation bytes changed")
                target = replay / planned["id"] / str(index)
                with contextlib.redirect_stdout(io.StringIO()):
                    result = validate(workspace, graph_path, path, candidate / "task.json", target)
                require(result["dependency_valid"] == row["dependency_valid"] and
                        configuration(target / ".config") == configuration(prior / ".config"), "Native dependency replay differs")
                options, _ = submitted_options(graph, path.read_text(), task)
                require(set(options) <= allowed, "Candidate outside selected paths")
                if result["dependency_valid"]:
                    valid.append((value["utility"], index, options, prior))
        require(bool(valid) == generated["valid_candidate"], "Selected candidate validity differs")
        raw_gates = {"generated": bool(valid), "built": False, "booted": False, "functional": False, "constraints": False}
        if valid:
            best = max(valid, key=lambda item: (item[0], -item[1]))
            require(best[1] == generated["selected_candidate"] and best[2] == generated["options"] and
                    sha(best[3] / "candidate.defconfig") == sha(candidate / "candidate.defconfig") == generated["candidate_sha256"],
                    "Utility selection or selected fragment differs")
            transfer = json.loads((run / "runtime-transfer-check.json").read_text())
            require(transfer["all_equal"], "Runtime transfer incomplete")
            for name, expected in transfer["files"].items():
                path = (run / transfer.get("file_overrides", {}).get(name, name)).resolve()
                path.relative_to(run.resolve())
                require(sha(path) == expected, "Returned runtime file changed: " + name)
            if transfer.get("serialization_reconciliation"):
                original = run / transfer["file_overrides"]["candidate/evaluation.json"]
                require(json.loads(original.read_text()) == json.loads((candidate / "evaluation.json").read_text()) and
                        sha(candidate / "evaluation.json") == transfer["serialization_reconciliation"]["local_replay_sha256"],
                        "Serialization reconciliation changed")
            built = run / "evaluation/build"
            if (built / "build-result.json").exists():
                proof = json.loads((built / "build-result.json").read_text())
                require(proof["source_commits"] == registration["source_commits"]["source_commits"] and
                        proof["source_worktrees_unchanged"], "Runtime source changed")
                require(sha(built / "input.defconfig") == proof["input_defconfig_sha256"] == generated["candidate_sha256"] and
                        sha(built / ".config") == proof["config_sha256"] and
                        sha(built / "runtime-image") == proof["image_sha256"], "Compiled artifact changed")
                require(sha(built / "compiler.stdout") == proof["compiler_version_stdout_sha256"] and
                        "10.2.1" in (built / "compiler.stdout").read_text(), "Native compiler version differs")
                raw_gates["built"] = True
                boots = run / "evaluation/boots"
                verdict = json.loads((boots / "boot-result.json").read_text())
                require(verdict["image_sha256"] == proof["image_sha256"] and
                        verdict["guest_memory_bytes"] == 134217728 and verdict["accelerator"] == "kvm" and
                        not verdict["reused_boot_indices"], "Guest identity or repetition differs")
                outcomes = []
                for index in range(1, len(verdict["runs"]) + 1):
                    step = json.loads((boots / ("boot" + str(index) + ".json")).read_text())
                    require(step["state"] == "finished" and
                            sha(boots / ("boot" + str(index) + ".stdout")) == step["stdout_sha256"] and
                            sha(boots / ("boot" + str(index) + ".stderr")) == step["stderr_sha256"], "Raw guest capture changed")
                    outcome = guest_outcome((boots / ("boot" + str(index) + ".stdout")).read_text(),
                                            (boots / ("boot" + str(index) + ".stderr")).read_text(), step["returncode"])
                    outcomes.append(outcome)
                    receipts.append({"trial": planned["id"], "boot": index, **outcome})
                raw_gates["booted"] = bool(outcomes) and outcomes[0]["booted"]
                raw_gates["functional"] = len(outcomes) == 3 and all(o["complete"] for o in outcomes)
                baseline = None
                if task.get("preserve_reference"):
                    baseline_path = candidate / "starting-reference.config"
                    require(sha(baseline_path) == task["preserve_reference"]["sha256"], "Starting reference changed")
                    baseline = configuration(baseline_path)
                raw_gates["constraints"] = constraint_outcome(task, configuration(built / ".config"),
                                                             (built / "runtime-image").stat().st_size, baseline)
            else:
                step = json.loads((built / "build.json").read_text())
                require(step["state"] == "finished" and step["returncode"] != 0 and
                        sha(built / "build.stdout") == step["stdout_sha256"] and
                        sha(built / "build.stderr") == step["stderr_sha256"], "Missing build failure evidence")
        gates, previous = {}, True
        for name, value in raw_gates.items():
            gates[name] = previous and value
            previous = gates[name]
        serialization_repair = run / "runtime-transfer-repair/collection-reconciliation.json"
        if serialization_repair.exists():
            repair = json.loads(serialization_repair.read_text())
            require(sha(run / "trial.json") == repair["original_trial_sha256"] and
                    record.get("failure") == "ValueError: Returned runtime evidence differs: candidate/evaluation.json" and
                    repair["new_model_calls"] == repair["new_builds"] == repair["new_boots"] == 0 and
                    all(gates.values()), "Unrecognized collection repair")
            record = {**record, "gates": gates, "raw_gates": raw_gates, "end_to_end_pass": not record["timed_out"],
                      "collection_failure": record["failure"], "collector_error_reconciled": True,
                      "duration_boundary": "Original observation bounds pre-error runtime verification; offline evidence replay excluded."}
            del record["failure"]
        else:
            require(gates == record["gates"] and (not valid or raw_gates == record["raw_gates"]), "Recorded stage gate differs")
        require(record["end_to_end_pass"] == (all(gates.values()) and not record["timed_out"]) and
                record["timed_out"] == (record["observed_wall_s"] > bank["wall_budget_s"]) and
                not record["infrastructure_invalid"], "Budget, success or infrastructure verdict differs")
        checked.append(record)
    groups = []
    for task in bank["tasks"]:
        for method in ("direct", "graph"):
            rows = [r for r in checked if r["task_id"] == task["id"] and r["method"] == method]
            groups.append({"task": task["id"], "method": method, "accounting": summarize_accounting(rows),
                           "observed_wall_median_s": statistics.median(r["observed_wall_s"] for r in rows),
                           "observed_wall_range_s": [min(r["observed_wall_s"] for r in rows), max(r["observed_wall_s"] for r in rows)]})
    require(report["accounting"] == {m: summarize_accounting([r for r in report["records"] if r["method"] == m]) for m in ("direct", "graph")},
            "Registered denominator changed")
    return {"registered_task_outcomes_audited": True, "native_dependency_replayed": True,
            "groups": groups, "raw_guest_captures": len(receipts), "guest_outcomes": receipts,
            "audited_records": checked,
            "audited_accounting": {m: summarize_accounting([r for r in checked if r["method"] == m]) for m in ("direct", "graph")},
            "boundary": "Frozen task output/constraint gates; not proof of original timing counter fidelity, MCU equivalence or full RAM coverage."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bank", type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Audit evidence on leon, not this Mac")
    result = audit(args.folder)
    optional = (args.bank, args.graph, args.workspace, args.replay)
    if any(optional):
        if not all(optional):
            parser.error("Full task replay requires bank, graph, workspace and a new replay directory")
        result["runtime_audit"] = audit_runtime(args.folder, *optional)
    result["campaign_registration_sha256"] = sha(args.folder / "registration.json")
    result["campaign_results_sha256"] = sha(args.folder / "results.json")
    result["audit_code_sha256"] = sha(Path(__file__))
    result["campaign_evidence_manifest"] = {str(p.relative_to(args.folder)): sha(p)
                                            for p in args.folder.rglob("*") if p.is_file() and not p.is_symlink()}
    if args.source:
        require_published_table(args.source.read_text(), published_rows(result))
        result["manuscript_sha256"] = sha(args.source)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    brief = {k: v for k, v in result.items() if k not in ("trials", "fingerprints", "runtime_audit", "campaign_evidence_manifest")}
    if "runtime_audit" in result:
        brief["runtime_audit"] = {k: v for k, v in result["runtime_audit"].items()
                                  if k not in ("guest_outcomes", "audited_records", "audited_accounting", "groups")}
    print(json.dumps(brief))
