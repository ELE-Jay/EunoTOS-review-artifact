#!/usr/bin/env python3
"""Replay Tenon history lineage, budget, native resolution and raw guest gates."""
import argparse
from collections import Counter
import contextlib
import io
import json
from pathlib import Path
import statistics
import sys

from audit_tenonos_tasks import configuration, require
from audit_tenonos_paper_tasks import constraint_outcome, guest_outcome, request_violations
from run_tenonos_policy_sequence import configuration_feedback, round_task
from tenonos_config_validation import submitted_options, validate
from tenonos_kvm_reproduce import sha
from tenonos_paper_orchestrator import parse_objective, retrieved_paths, select_paths, strict_object, visible_task


def transferred(folder):
    proof = json.loads((folder / "runtime-transfer-check.json").read_text())
    require(proof["all_equal"], "Runtime transfer incomplete")
    for name, digest in proof["files"].items():
        p = (folder / proof.get("file_overrides", {}).get(name, name)).resolve()
        p.relative_to(folder.resolve())
        require(sha(p) == digest, "Transferred runtime bytes changed")
    if proof.get("serialization_reconciliation"):
        first = folder / proof["file_overrides"]["candidate/evaluation.json"]
        second = folder / "candidate/evaluation.json"
        require(json.loads(first.read_text()) == json.loads(second.read_text()) and
                sha(second) == proof["serialization_reconciliation"]["local_replay_sha256"], "Serialized checker differs")


def guest_checks(folder, image_sha):
    proof = json.loads((folder / "boot-result.json").read_text())
    require(proof["image_sha256"] == image_sha and proof["accelerator"] == "kvm" and
            proof["guest_memory_bytes"] == 134217728 and not proof["reused_boot_indices"], "Guest identity differs")
    outcomes = []
    for index in range(1, len(proof["runs"]) + 1):
        name = "boot" + str(index)
        step = json.loads((folder / (name + ".json")).read_text())
        require(step["state"] == "finished" and sha(folder / (name + ".stdout")) == step["stdout_sha256"] and
                sha(folder / (name + ".stderr")) == step["stderr_sha256"], "Guest capture changed")
        outcomes.append(guest_outcome((folder / (name + ".stdout")).read_text(),
                                     (folder / (name + ".stderr")).read_text(), step["returncode"]))
    complete = len(outcomes) == 3 and all(o["complete"] for o in outcomes)
    require(complete == proof["all_three_pass"], "Guest summary differs from raw output")
    return outcomes, complete


def parent_check(folder, parent, source_ids):
    transferred(folder)
    original = json.loads((folder / "build/origin-build-result.json").read_text())
    current = json.loads((folder / "build/build-result.json").read_text())
    require(sha(folder / "build/origin-build-result.json") == sha(parent / "build-result.json") and
            {k: v for k, v in original.items() if k != "image"} == {k: v for k, v in current.items() if k != "image"},
            "Parent activation changes more than the temporary image path")
    require(current["source_commits"] == source_ids and sha(folder / "build/runtime-image") ==
            sha(parent / "runtime-image") == current["image_sha256"] and
            sha(folder / "build/.config") == sha(parent / ".config") == current["config_sha256"], "Parent bytes changed")
    outcomes, complete = guest_checks(folder / "boots", current["image_sha256"])
    require(complete, "Retained parent does not pass the original suite")
    return len(outcomes)


def generation_check(candidate, task_path, graph_path, workspace, replay, method, model):
    task, graph = json.loads(task_path.read_text()), json.loads(graph_path.read_text())
    value = json.loads((candidate / "generation.json").read_text())
    require(sha(candidate / "task.json") == sha(task_path) == value["task_sha256"] and
            value["graph_sha256"] == sha(graph_path) and value["method"] == method, "Round generation identity differs")
    calls = json.loads((candidate / "model-calls.json").read_text())
    expected = ["configurations"] if method == "direct" else ["objective", "paths", "configurations"]
    require([c["stage"] for c in calls] == expected[:len(calls)] and 0 < len(calls) <= len(expected) and
            len(list(candidate.glob("*-request.json"))) == len(calls), "Unexpected retry or omitted model call")
    used, finishes = 0, Counter()
    for call in calls:
        payload = json.loads((candidate / (call["stage"] + "-request.json")).read_text())
        require(not request_violations(payload) and payload["model"] == model and payload["temperature"] == 0 and
                0 < payload["max_tokens"] <= 384 - used, "API contract differs")
        context = json.loads(payload["messages"][1]["content"])
        if "task" in context:
            require(context["task"] == visible_task(task), "Model task includes hidden or changed fields")
        path = candidate / (call["stage"] + "-response.json")
        require(path.exists() == call["response_received"], "Response coverage differs")
        if path.exists():
            response = json.loads(path.read_text())
            count = response["usage"]["completion_tokens"]
            require(response["model"] == model and type(count) is int and 0 <= count <= payload["max_tokens"], "Model usage differs")
            used += count
            finishes[response["choices"][0]["finish_reason"]] += 1
    require(used == value["completion_tokens"] and calls == value["model_calls"], "Generation accounting differs")
    allowed = set(task["candidate_controls"])
    if (candidate / "selected-paths.json").exists():
        parsed = parse_objective(json.loads((candidate / "objective-response.json").read_text())["choices"][0]["message"]["content"])
        paths = retrieved_paths(graph, json.loads((candidate / "retrieval/retrieval.json").read_text()))
        selected = select_paths(json.loads((candidate / "paths-response.json").read_text())["choices"][0]["message"]["content"], paths, 0.5)
        require(parsed == json.loads((candidate / "objective.json").read_text()) and
                selected == json.loads((candidate / "selected-paths.json").read_text()), "Objective or path filtering differs")
        allowed &= {n["name"] for p in selected for n in p["nodes"] if n["kind"] == "config"}
    valid = []
    if (candidate / "candidate-validations.json").exists():
        answer = json.loads((candidate / "configurations-response.json").read_text())["choices"][0]["message"]["content"]
        proposed = strict_object(answer)["candidates"]
        for item in json.loads((candidate / "candidate-validations.json").read_text()):
            index = item["candidate"]
            raw = proposed[index]
            if "validation_sha256" not in item:
                require(not item["dependency_valid"] and item.get("input_failure"), "Missing candidate rejection")
                try:
                    options, _ = submitted_options(graph, json.dumps({"options": raw["options"]}), task)
                    require(set(options) <= allowed, "Outside graph controls")
                except (ValueError, TypeError, KeyError):
                    continue
                raise ValueError("Candidate rejection cannot be independently reproduced")
            p = candidate / ("candidate-" + str(index) + ".json")
            prior = candidate / ("validation-" + str(index))
            proof = json.loads((prior / "validation.json").read_text())
            require(json.loads(p.read_text()) == {"options": raw["options"]} and sha(prior / "validation.json") ==
                    item["validation_sha256"] and sha(prior / ".config") == proof["native_config_sha256"] and
                    sha(prior / "candidate.defconfig") == proof["input_defconfig_sha256"], "Native candidate record changed")
            with contextlib.redirect_stdout(io.StringIO()):
                checked = validate(workspace, graph_path, p, task_path, replay / str(index))
            require(checked["dependency_valid"] == item["dependency_valid"] and
                    configuration(replay / str(index) / ".config") == configuration(prior / ".config"), "Native replay differs")
            options, _ = submitted_options(graph, p.read_text(), task)
            require(set(options) <= allowed, "Native candidate outside selected controls")
            if checked["dependency_valid"]:
                valid.append((raw["utility"], index, options, prior))
    require(bool(valid) == value["valid_candidate"], "Native-valid generation gate differs")
    if valid:
        chosen = max(valid, key=lambda t: (t[0], -t[1]))
        require(chosen[1] == value["selected_candidate"] and chosen[2] == value["options"] and
                sha(chosen[3] / "candidate.defconfig") == sha(candidate / "candidate.defconfig") == value["candidate_sha256"],
                "Candidate utility selection differs")
    return value, len(calls), used, finishes


def audit(folder, root, graph_path, workspace, replay):
    plan = json.loads((folder / "protocol.json").read_text())
    registration = json.loads((folder / "registration.json").read_text())
    campaign = json.loads((folder / "campaign.json").read_text())
    bank = json.loads((folder / "task-bank.json").read_text())
    require(campaign["status"] == "collection_complete" and sha(folder / "protocol.json") == registration["plan_sha256"] and
            sha(folder / "task-bank.json") == registration["bank_sha256"] == plan["task_bank_sha256"] and
            sha(graph_path) == registration["graph_sha256"], "Incomplete or changed sequence registration")
    for name, expected in registration["source_sha256"].items():
        require(sha(folder / "sources" / name) == expected and sha(root / "tools" / name) == expected,
                "Captured or replay sequence source changed")
    expected = ["H%d-%s" % (i, m) for i in (1, 2, 3) for m in (("direct", "graph") if i % 2 else ("graph", "direct"))]
    require([h["id"] for h in campaign["histories"]] == expected, "History coverage differs")
    replay.mkdir(parents=True, exist_ok=False)
    base = next(t for t in bank["tasks"] if t["id"] == "TC-C")
    graph = json.loads(graph_path.read_text())
    source_ids = registration["source_commits"]["source_commits"]
    calls, tokens, parent_boots, candidate_boots = 0, 0, 0, 0
    finishes, histories = Counter(), []
    for history in campaign["histories"]:
        directory = folder / history["id"]
        parent = root / plan["initial_reference"] / "build"
        parent_boots += parent_check(directory / "initial", parent, source_ids)
        feedback, accepted_count, costs = {"accepted": None, "gates": None, "required_configuration": []}, 0, []
        require(len(history["rounds"]) == 2, "Missing sequence round")
        for index, record in enumerate(history["rounds"], 1):
            run = directory / ("R" + str(index))
            require(json.loads((run / "round.json").read_text()) == record and record["round"] == index and
                    record["parent_build"] == str(parent.relative_to(root)) and record["parent_image_sha256"] ==
                    sha(parent / "runtime-image") and record["parent_config_sha256"] == sha(parent / ".config"), "Wrong retained parent")
            require(registration["registered_utc"] <= record["started_utc"] < record["finished_utc"], "Unregistered or reversed round timing")
            task = json.loads((run / "task.json").read_text())
            require(task == round_task(base, parent / ".config", graph, feedback, index) and record["feedback"] == feedback,
                    "Task or prior configuration feedback changed")
            generated, n, used, reasons = generation_check(run / "candidate", run / "task.json", graph_path, workspace,
                                                          replay / history["id"] / str(index), history["method"], plan["model"])
            calls += n
            tokens += used
            finishes.update(reasons)
            require((n, used) == (record["model_calls"], record["completion_tokens"]), "Round call accounting differs")
            raw = {"generated": generated["valid_candidate"], "built": False, "booted": False, "functional": False, "constraints": False}
            evaluation = {}
            if generated["valid_candidate"]:
                transferred(run)
                built = run / "evaluation/build"
                require(sha(run / "candidate/starting-reference.config") == sha(parent / ".config"), "Preservation reference differs")
                if (built / "build-result.json").exists():
                    proof = json.loads((built / "build-result.json").read_text())
                    require(proof["source_commits"] == source_ids and proof["source_worktrees_unchanged"] and
                            sha(built / "runtime-image") == proof["image_sha256"] and sha(built / ".config") == proof["config_sha256"] and
                            sha(built / "input.defconfig") == generated["candidate_sha256"] == proof["input_defconfig_sha256"], "Compiled candidate differs")
                    require(sha(built / "compiler.stdout") == proof["compiler_version_stdout_sha256"] and
                            "10.2.1" in (built / "compiler.stdout").read_text(), "Native compiler differs")
                    outcomes, complete = guest_checks(run / "evaluation/boots", proof["image_sha256"])
                    candidate_boots += len(outcomes)
                    raw.update(built=True, booted=bool(outcomes) and outcomes[0]["booted"], functional=complete,
                               constraints=constraint_outcome(task, configuration(built / ".config"),
                                                              (built / "runtime-image").stat().st_size, configuration(parent / ".config")))
                    evaluation = json.loads((run / "candidate/evaluation.json").read_text())
                    require(all(raw[k] == evaluation[k] for k in raw), "Candidate checker differs from raw replay")
                else:
                    failure = json.loads((built / "build.json").read_text())
                    require(failure["state"] == "finished" and failure["returncode"] != 0, "Missing build failure")
            gates, previous = {}, True
            for name, value in raw.items():
                gates[name] = previous and value
                previous = gates[name]
            require(gates == record["gates"], "Sequence stage gate differs")
            accepted = all(gates.values()) and record["decision_wall_s"] <= 1800
            require(accepted == record["accepted"] and 0 <= record["decision_wall_s"] <= record["observed_wall_s"], "Acceptance or time boundary differs")
            before = parent
            if accepted:
                parent = run / "evaluation/build"
                require(configuration(parent / ".config") != configuration(before / ".config"), "Accepted modification is a no-op")
                accepted_count += 1
            else:
                parent_boots += parent_check(run / "recovery", parent, source_ids)
            require(record["retained_build"] == str(parent.relative_to(root)) and record["retained_image_sha256"] ==
                    sha(parent / "runtime-image") and record["retained_config_sha256"] == sha(parent / ".config") and
                    record["policy_changed"] == (configuration(parent / ".config") != configuration(before / ".config")), "Retention or rollback differs")
            feedback = configuration_feedback(gates, accepted, evaluation)
            require(feedback == record["next_feedback"], "Feedback contains altered or extra measurements")
            costs.append(record["observed_wall_s"])
        require(history["final_image_sha256"] == sha(parent / "runtime-image") and
                history["final_config_sha256"] == sha(parent / ".config") and sum(costs) <= history["total_round_wall_s"] and
                history["within_history_budget"] == (history["total_round_wall_s"] <= 3600), "Final state or cumulative cost differs")
        histories.append({"id": history["id"], "method": history["method"], "accepted_rounds": accepted_count,
                          "rejected_rounds": 2 - accepted_count, "round_wall_s": costs,
                          "total_round_wall_s": history["total_round_wall_s"],
                          "endpoint_equals_initial_config": configuration(parent / ".config") ==
                          configuration(root / plan["initial_reference"] / "build/.config"),
                          "within_history_budget": history["within_history_budget"]})
    require((calls, tokens) == (campaign["model_calls"], campaign["completion_tokens"]) and calls <= 24 and tokens <= 4608,
            "Global model budget or denominator differs")
    return {"audit": "pass", "histories": histories, "registered_histories": 6, "registered_rounds": 12,
            "model": registration["model"], "author_engine": False, "rsi": False,
            "model_calls": calls, "completion_tokens": tokens, "finish_reasons": dict(finishes),
            "candidate_guest_captures": candidate_boots, "parent_check_guest_captures": parent_boots,
            "protocol_sha256": sha(folder / "protocol.json"), "campaign_sha256": sha(folder / "campaign.json"),
            "audit_code_sha256": sha(Path(__file__)), "new_model_calls": 0, "new_guest_boots": 0,
            "groups": [{"method": m, "accepted_rounds": sum(h["accepted_rounds"] for h in histories if h["method"] == m),
                        "total_round_wall_median_s": statistics.median(h["total_round_wall_s"] for h in histories if h["method"] == m)}
                       for m in ("direct", "graph")],
            "boundary": "Prescribed configuration lineage and original output/requirement gates in KVM; no autonomous optimization, held-out certification, timing-counter equivalence or RSI claim."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("folder", "root", "graph", "workspace", "replay", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Replay real records on leon")
    result = audit(args.folder.resolve(), args.root.resolve(), args.graph.resolve(), args.workspace.resolve(), args.replay.resolve())
    result["evidence_manifest"] = {str(p.relative_to(args.folder)): sha(p)
                                   for p in args.folder.rglob("*") if p.is_file() and not p.is_symlink()}
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("histories", "evidence_manifest")}))
