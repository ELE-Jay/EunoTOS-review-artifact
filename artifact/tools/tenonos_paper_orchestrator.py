#!/usr/bin/env python3
"""Independent reconstruction of TenonOS section 4.5; not the author engine."""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import time

from tenonos_config_validation import submitted_options, validate, verify_sources
from tenonos_lib_graph import digest, lightrag_input, validate_graph
from tenonos_lightrag_runtime import check_context
from tenonos_model_service import DEFAULT_KEY, DEEPSEEK_KEY, MODELS, model_status, official_status, read_key, request

RECONSTRUCTION = {
    "paper": "https://arxiv.org/html/2512.00400v2#S4.SS5",
    "author_engine": False,
    "objective_format": "goals/resources/security string lists",
    "path_scoring": "LLM relevance in [0,1] for source-bound root-to-entity DAG paths",
    "path_threshold": 0.5,
    "maximum_paths": 12,
    "maximum_candidates": 2,
    "utility_selection": "Highest LLM-estimated utility among native-valid candidates; input order breaks ties",
    "unknown_author_settings": ["model and checkpoint", "prompts", "embedding model and quantization",
                                "LightRAG version", "path scoring and threshold", "utility scoring",
                                "original fourteen application tasks"],
}


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def strict_object(content):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON key: " + name)
            result[name] = value
        return result
    result = json.loads(content, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("Model must return a JSON object")
    return result


def visible_task(task):
    return {key: task[key] for key in ("objective", "fixed_options", "candidate_controls", "starting_options")
            if key in task}


def parse_objective(content):
    result = strict_object(content)
    if set(result) != {"goals", "resources", "security"}:
        raise ValueError("Expected goals/resources/security only")
    if any(not isinstance(v, list) or any(not isinstance(x, str) or not x.strip() for x in v)
           for v in result.values()) or not result["goals"]:
        raise ValueError("Objective entities must be nonempty strings, with at least one goal")
    return result


def retrieved_paths(graph, retrieval, maximum=12):
    check_context(graph, retrieval["result"], retrieval["vector_hits"])
    by_id = {node["id"]: node for node in graph["nodes"]}
    names = {row["entity_name"]: json.loads(row["description"])["id"]
             for row in lightrag_input(graph)["entities"]}
    parents = {e["target"]: e["source"] for e in graph["edges"]}
    paths = []
    for hit in retrieval["vector_hits"][:maximum]:
        current = names[hit["entity_name"]]
        chain = [current]
        while current != "root":
            current = parents[current]
            chain.append(current)
        paths.append({"id": "P" + str(len(paths)), "nodes": [by_id[x] for x in reversed(chain)]})
    if not paths:
        raise ValueError("Retrieval produced no source-bound paths")
    return paths


def finite_score(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("Expected finite score in [0,1]")
    return value


def select_paths(content, paths, threshold):
    result = strict_object(content)
    if set(result) != {"paths"} or not isinstance(result["paths"], (list, dict)):
        raise ValueError("Expected path scores")
    if isinstance(result["paths"], dict):
        result["paths"] = [{"id": name, "score": value} for name, value in result["paths"].items()]
    by_id = {p["id"]: p for p in paths}
    seen, selected = set(), []
    for row in result["paths"]:
        if not isinstance(row, dict) or set(row) != {"id", "score"} or row["id"] not in by_id or row["id"] in seen:
            raise ValueError("Unknown or duplicate selected path")
        seen.add(row["id"])
        score = finite_score(row["score"])
        if score >= threshold:
            selected.append({**by_id[row["id"]], "score": score})
    if not selected:
        raise ValueError("No path reached the frozen threshold")
    return selected


class Budget:
    def __init__(self, seconds, tokens, clock=time.monotonic):
        self.clock, self.started = clock, clock()
        self.seconds, self.tokens = seconds, tokens
        self.used_tokens, self.calls = 0, []

    def remaining(self, require_tokens=True):
        seconds = self.seconds - (self.clock() - self.started)
        tokens = self.tokens - self.used_tokens
        if seconds <= 0 or (require_tokens and tokens <= 0):
            raise TimeoutError("Aggregate generation budget exhausted")
        return seconds, tokens

    def charge(self, response, cap):
        count = response.get("usage", {}).get("completion_tokens")
        if type(count) is not int or not 0 <= count <= cap:
            self.used_tokens += cap
            raise ValueError("Missing/invalid completion-token accounting; remaining request budget charged")
        self.used_tokens += count
        if self.clock() - self.started > self.seconds:
            raise TimeoutError("Generation wall budget exceeded")


def generate(task_path, graph_path, index, workspace, output, profile, provider, seed, tokens, key_file, method,
             service="openrouter"):
    preflight_started = time.monotonic()
    key = read_key(key_file, "DEEPSEEK_API_KEY") if service == "deepseek" else read_key(key_file)
    if not key:
        raise ValueError("Configure the private model-service key on leon before generation")
    if service == "deepseek":
        if provider not in (None, "deepseek"):
            raise ValueError("Official credentials may only use the official DeepSeek route")
        provider = "deepseek"
        status = official_status(key, profile)
        if not status["listed"] or not status["balance_available"]:
            raise ValueError("Exact official model must be listed and the balance available")
        endpoint = None
    elif service == "openrouter":
        status = model_status(profile)
        endpoint = next((p for p in status["endpoint_catalog"].get("data", {}).get("endpoints", [])
                         if p.get("tag") == provider), None)
        if not status["weight_identity_matches_catalog"] or endpoint is None:
            raise ValueError("Choose an explicit endpoint with a matching model catalog identity")
    else:
        raise ValueError("Unknown model service")
    preflight_wall_s = time.monotonic() - preflight_started
    task = json.loads(task_path.read_text())
    graph = json.loads(graph_path.read_text())
    validate_graph(graph)
    verify_sources(graph, graph_path, workspace)
    index_record = json.loads((index / "run.json").read_text())
    if not index_record["complete"] or index_record["graph_sha256"] != digest(graph_path):
        raise ValueError("Index does not belong to this graph")
    output.mkdir(parents=True, exist_ok=False)
    sources = ["tenonos_paper_orchestrator.py", "tenonos_config_validation.py", "tenonos_lib_graph.py",
               "tenonos_lightrag_runtime.py", "tenonos_model_service.py", "tenonos_orchestrator.py",
               "tenonos_kvm_reproduce.py", "import_iotos_subjects.py"]
    (output / "sources").mkdir()
    hashes = {}
    for name in sources:
        source = Path(__file__).with_name(name)
        hashes[name] = digest(source)
        shutil.copyfile(source, output / "sources" / name)
    shutil.copyfile(task_path, output / "task.json")
    save(output / "model-status.json", status)
    save(output / "registration.json", {"registered_utc": datetime.now(timezone.utc).isoformat(),
        "method": method, "reconstruction": RECONSTRUCTION, "source_sha256": hashes,
        "task_sha256": digest(task_path), "graph_sha256": digest(graph_path),
        "index_run_sha256": digest(index / "run.json"),
        "generation_budget_s": task["generation_budget_s"], "aggregate_completion_token_budget": tokens,
        "seed": seed if service == "openrouter" else None, "seed_transmitted": service == "openrouter",
        "service": service, "thinking": "disabled" if service == "deepseek" else "provider default",
        "preflight_wall_s": preflight_wall_s, "model": status["requested_model"], "provider": provider,
        "benchmark_trial": False, "campaign_registration_required": True})
    budget = Budget(task["generation_budget_s"], tokens)
    record = {"subject": "TenonOS-paper-pipeline-independent-reconstruction", "author_orchestrator": False,
        "method": method, "generator_invoked": False, "valid_candidate": False,
        "model_response_received": False, "benchmark_trial": False, "ranking_eligible": False,
        "task_sha256": digest(task_path), "graph_sha256": digest(graph_path),
        "generator_code_sha256": digest(Path(__file__)), "source_sha256": hashes,
        "started_utc": datetime.now(timezone.utc).isoformat(), "model": status["requested_model"],
        "service": service, "preflight_wall_s": preflight_wall_s}

    def call(stage, instruction, context, token_cap):
        seconds, remaining_tokens = budget.remaining()
        cap = min(token_cap, remaining_tokens)
        payload = {"model": status["requested_model"], "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)}],
            "max_tokens": cap, "temperature": 0, "seed": seed, "stream": False,
            "response_format": {"type": "json_object"},
            "provider": {"order": [provider], "allow_fallbacks": False, "data_collection": "deny"}}
        if service == "deepseek":
            del payload["seed"]
            del payload["provider"]
            payload["thinking"] = {"type": "disabled"}
        save(output / (stage + "-request.json"), payload)
        attempt = {"stage": stage, "attempted": True, "response_received": False, "max_tokens": cap}
        budget.calls.append(attempt)
        save(output / "model-calls.json", budget.calls)
        record["generator_invoked"] = True
        before = time.monotonic()
        try:
            kwargs = {"timeout": seconds}
            if service == "deepseek":
                kwargs["service"] = service
            response = request("/chat/completions", payload, key, **kwargs)
            save(output / (stage + "-response.json"), response)
            attempt["response_received"] = True
            record["model_response_received"] = True
            attempt.update(usage=response.get("usage"), returned_model=response.get("model"),
                           system_fingerprint=response.get("system_fingerprint"),
                           finish_reason=response.get("choices", [{}])[0].get("finish_reason"))
            budget.charge(response, cap)
            if response.get("model") != status["requested_model"] or (endpoint is not None and response.get("provider") != endpoint["provider_name"]):
                raise ValueError("Returned model/provider differs from the fixed route")
            return response["choices"][0]["message"]["content"]
        finally:
            attempt["wall_s"] = time.monotonic() - before
            save(output / "model-calls.json", budget.calls)

    try:
        metadata = [n for n in graph["nodes"] if n["kind"] == "config" and n["name"] in task["candidate_controls"]]
        context = {"task": visible_task(task), "allowed_configuration_metadata": metadata}
        allowed = set(task["candidate_controls"])
        if method == "graph":
            parsed = parse_objective(call("objective", "Parse the task into one line of compact JSON with exactly goals, resources, security. Each is a list of very brief noun phrases, not sentences. Do not propose options or explain.", context, 96))
            save(output / "objective.json", parsed)
            seconds, _ = budget.remaining()
            with (output / "retrieval.log").open("xb") as log:
                subprocess.run([sys.executable, str(Path(__file__).with_name("tenonos_lightrag_runtime.py")),
                    "query", "--index", str(index), "--query", json.dumps(parsed),
                    "--output", str(output / "retrieval")], stdout=log, stderr=subprocess.STDOUT,
                    check=True, timeout=seconds)
            paths = retrieved_paths(graph, json.loads((output / "retrieval/retrieval.json").read_text()),
                                    RECONSTRUCTION["maximum_paths"])
            selected = select_paths(call("paths", 'Score relevant supplied paths using relation semantics and task context. Return one line of compact JSON: {"paths":{"P0":0.9}}; map relevant supplied IDs to scores in [0,1], omit irrelevant IDs. No explanation.',
                {"objective": parsed, "paths": paths}, 96), paths, RECONSTRUCTION["path_threshold"])
            save(output / "selected-paths.json", selected)
            allowed &= {n["name"] for p in selected for n in p["nodes"] if n["kind"] == "config"}
            if not allowed:
                raise ValueError("Selected paths contain no permitted configuration controls")
            context.update(parsed_objective=parsed, selected_paths=selected)
        content = call("configurations", 'Return compact JSON: {"candidates":[{"options":{"CONFIG_NAME":"value"},"utility":0.9}]}. Propose one or two configurations for the task; utility is expected task suitability in [0,1]. Set only supplied permitted controls and never fixed options. No code or explanation.',
                       {**context, "permitted_controls": sorted(allowed)}, tokens)
        candidates = strict_object(content)
        if set(candidates) != {"candidates"} or not isinstance(candidates["candidates"], list) or not 1 <= len(candidates["candidates"]) <= RECONSTRUCTION["maximum_candidates"]:
            raise ValueError("Expected one or two candidate configurations")
        validations, valid = [], []
        for i, candidate in enumerate(candidates["candidates"]):
            response_path = output / ("candidate-" + str(i) + ".json")
            try:
                if not isinstance(candidate, dict) or set(candidate) != {"options", "utility"}:
                    raise ValueError("Malformed candidate")
                utility = finite_score(candidate["utility"])
                save(response_path, {"options": candidate["options"]})
                proposed, _ = submitted_options(graph, response_path.read_text(), task)
                if set(proposed) - allowed:
                    raise ValueError("Candidate changes controls outside selected paths")
            except (ValueError, TypeError, KeyError) as error:
                validations.append({"candidate": i, "dependency_valid": False,
                                    "input_failure": str(error)})
                save(output / "candidate-validations.json", validations)
                continue
            seconds, _ = budget.remaining(require_tokens=False)
            folder = output / ("validation-" + str(i))
            result = validate(workspace, graph_path, response_path, task_path, folder, min(90, seconds))
            validations.append({"candidate": i, "utility": utility, "dependency_valid": result["dependency_valid"],
                                "validation_sha256": digest(folder / "validation.json")})
            save(output / "candidate-validations.json", validations)
            if result["dependency_valid"]:
                valid.append((utility, i, proposed, folder))
        if time.monotonic() - budget.started > budget.seconds:
            raise TimeoutError("Generation including retrieval and validation exceeded wall budget")
        save(output / "candidate-validations.json", validations)
        if not valid:
            raise ValueError("All proposed configurations failed native dependency validation")
        chosen = max(valid, key=lambda item: (item[0], -item[1]))
        shutil.copyfile(chosen[3] / "candidate.defconfig", output / "candidate.defconfig")
        record.update(valid_candidate=True, options=chosen[2], selected_candidate=chosen[1],
                      candidate_sha256=digest(output / "candidate.defconfig"))
    except Exception as error:
        record["failure"] = {"type": type(error).__name__, "message": str(error)}
        if hasattr(error, "code"):
            record["failure"]["http_status"] = error.code
        if hasattr(error, "redacted_response"):
            save(output / "model-error.json", {"http_status": error.code, "redacted_response": error.redacted_response})
    finally:
        record.update(generation_wall_s=time.monotonic() - budget.started,
                      completion_tokens=budget.used_tokens, model_calls=budget.calls,
                      finished_utc=datetime.now(timezone.utc).isoformat())
        save(output / "generation.json", record)
    print(json.dumps(record, indent=2))
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("task", "graph", "index", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--service", choices=("openrouter", "deepseek"), default="openrouter")
    parser.add_argument("--model", help="OpenRouter profile or exact official model ID")
    parser.add_argument("--provider")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--tokens", type=int, default=384)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--method", choices=("direct", "graph"), default="graph")
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run model calls and retain evidence on leon")
    if args.tokens <= 0:
        parser.error("--tokens must be positive")
    if args.service == "openrouter":
        args.model = args.model or "v3"
        if args.model not in MODELS or not args.provider:
            parser.error("Specify an OpenRouter profile and explicit provider")
    elif not args.model:
        parser.error("Specify an exact official model; no automatic fallback")
    args.key_file = args.key_file or (DEEPSEEK_KEY if args.service == "deepseek" else DEFAULT_KEY)
    generate(args.task.resolve(), args.graph.resolve(), args.index.resolve(), args.workspace.resolve(),
             args.output.resolve(), args.model, args.provider, args.seed, args.tokens, args.key_file, args.method,
             args.service)
