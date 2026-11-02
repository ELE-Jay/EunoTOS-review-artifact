#!/usr/bin/env python3
"""Independent paper-inspired Tenon configuration prototype, not author code."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
import urllib.request

from tenonos_kvm_reproduce import boot, build, save, sha, utc


def kconfig(workspace, application, scratch):
    import kconfiglib as kc
    base = workspace / "tenon-c11"
    scratch.mkdir(parents=True, exist_ok=True)
    env = {"UK_BASE": str(base), "UK_APP": str(workspace / "apps" / application),
           "UK_ARCH": "arm64", "HOST_ARCH": "arm64", "UK_NAME": application,
           "UK_FULLVERSION": "0.1.0~756aa1c-custom", "TN_FULLVERSION": "0.3.0",
           "UK_CODENAME": "", "KCONFIG_DIR": str(scratch),
           "KCONFIG_LIB_BASE": str(base / "lib"), "KCONFIG_PLAT_BASE": str(base / "plat"),
           "KCONFIG_DRIV_BASE": str(base / "drivers"), "KCONFIG_ELIB_BASE": "",
           "KCONFIG_ELIB_DIRS": "", "KCONFIG_EPLAT_DIRS": "", "KCONFIG_EDRIV_DIRS": "",
           "KCONFIG_EAPP_DIR": str(workspace / "apps" / application), "KCONFIG_EXCLUDEDIRS": ""}
    os.environ.update(env)
    if application.startswith("app-rtos-benchmark"):
        os.environ.update(KCONFIG_ELIB_BASE=str(workspace / "libs"),
                          KCONFIG_ELIB_DIRS=str(workspace / "libs/lib-tlsf"))
    return kc.Kconfig(str(base / "Config.uk"), warn_to_stderr=False)


def export_graph(workspace, output, application="app-helloworld"):
    output.mkdir(parents=True, exist_ok=False)
    kc = kconfig(workspace, application, output / "kconfig")
    import kconfiglib
    nodes, edges = [], []
    for symbol in kc.unique_defined_syms:
        prompts = [node.prompt[0] for node in symbol.nodes if node.prompt]
        descriptions = [node.help for node in symbol.nodes if node.help]
        refs = sorted({s.name for s in symbol.referenced if s.name and s.name != symbol.name})
        nodes.append({"name": symbol.name, "type": kconfiglib.TYPE_TO_STR[symbol.type],
                      "prompt": " ".join(prompts), "help": "\n".join(descriptions),
                      "depends": kconfiglib.expr_str(symbol.direct_dep), "references": refs,
                      "sources": [{"file": str(Path(n.filename).resolve().relative_to(workspace)),
                                   "line": n.linenr} for n in symbol.nodes]})
        edges.extend({"from": symbol.name, "to": ref, "relation": "references"} for ref in refs)
    paths = {n.filename for s in kc.unique_defined_syms for n in s.nodes}
    save(output / "graph.json", {"subject": "Tenon-Kconfig-independent-prototype",
        "created_utc": utc(), "application": application, "nodes": nodes, "edges": edges,
        "source_files": {str(Path(p).resolve().relative_to(workspace)): sha(Path(p)) for p in sorted(paths)},
        "parser": "kconfiglib 14.1.0", "retrieval": "lexical plus referenced-symbol closure",
        "paper": "https://arxiv.org/html/2512.00400v2#S4.SS5",
        "not_implemented": ["LightRAG embeddings and paper path scoring", "runtime adaptation", "RSI"]})
    print(json.dumps({"symbols": len(nodes), "edges": len(edges)}))


def retrieve(graph, objective, limit=12):
    stop = set("a an the for of in on and or to from with then do not rather than keep existing supplied unchanged configure application prerequisites".split())
    def words(text):
        return set(re.findall(r"[a-z][a-z0-9]+", text.lower().replace("_", " "))) - stop
    query = words(objective)
    documents = {n["name"]: words(n["name"] + " " + n["prompt"] + " " + n["help"]) for n in graph["nodes"]}
    weights = {w: math.log(1 + len(documents) / (1 + sum(w in d for d in documents.values()))) for w in query}
    def score(node):
        title = words(node["name"] + " " + node["prompt"])
        return sum(weights[w] * (3 if w in title else 1) for w in query & documents[node["name"]])
    ranked = sorted(graph["nodes"], key=lambda n: (-score(n), n["name"]))
    selected = {n["name"] for n in ranked[:limit] if score(n)}
    initial = selected.copy()
    for node in graph["nodes"]:
        if node["name"] in initial:
            selected.update(node["references"])
    return [n for n in graph["nodes"] if n["name"] in selected]


def options_from_response(content, graph):
    value = json.loads(content)
    if not isinstance(value, dict) or set(value) != {"options"} or not isinstance(value["options"], dict):
        raise ValueError("Expected one JSON object with an options mapping")
    known = {n["name"]: n for n in graph["nodes"]}
    options = {}
    for key, raw in value["options"].items():
        name = key.removeprefix("CONFIG_")
        node = known.get(name)
        if node is None or node["type"] not in ("bool", "tristate", "int", "hex") or type(raw) is not str:
            raise ValueError("Unknown or unsupported configuration option: " + str(key))
        if node["type"] in ("bool", "tristate") and raw not in ("y", "n", "m"):
            raise ValueError("Invalid boolean configuration")
        if node["type"] == "int" and not re.fullmatch(r"-?[0-9]+", raw):
            raise ValueError("Invalid integer configuration")
        if node["type"] == "hex" and not re.fullmatch(r"0x[0-9a-fA-F]+", raw):
            raise ValueError("Invalid hexadecimal configuration")
        if name in options:
            raise ValueError("Duplicate configuration option")
        options[name] = raw
    return options


def request_payload(graph, task, model, seed=42):
    """Keep acquisition and offline request binding on the same unchanged prompt."""
    context = retrieve(graph, task["objective"])
    if task.get("candidate_controls"):
        names = set(task["candidate_controls"]) | {n["name"] for n in context}
        context = [n for n in graph["nodes"] if n["name"] in names]
    compact = [{k: n[k] for k in ("name", "type", "prompt", "help", "depends")} for n in context]
    prompt = "Requirement:\n" + task["objective"] + "\nKconfig metadata:\n" + json.dumps(compact) + \
        '\nReturn only {"options":{"CONFIG_NAME":"value"}}. Set only options needed by the requirement. Do not repeat the metadata.'
    if task.get("starting_options"):
        prompt += "\nStarting configuration, to be preserved except requested changes:\n" + json.dumps(task["starting_options"])
    properties = {}
    for node in context:
        if node["name"] not in task["fixed_options"] and node["type"] in ("bool", "tristate", "int", "hex") and \
                (not task.get("candidate_controls") or node["name"] in task["candidate_controls"]):
            prop = {"type": "string"}
            if node["type"] in ("bool", "tristate"):
                prop["enum"] = ["y", "n"] + (["m"] if node["type"] == "tristate" else [])
            properties["CONFIG_" + node["name"]] = prop
    schema = {"type": "object", "properties": {"options": {"type": "object",
              "properties": properties, "additionalProperties": False}},
              "required": ["options"], "additionalProperties": False}
    return {"model": model, "messages": [
        {"role": "system", "content": "Configure a " + task.get("target_system", "Tenon LibOS") +
         " from its Kconfig metadata. Return only the requested JSON object."},
        {"role": "user", "content": prompt}],
        "temperature": 0, "seed": seed, "max_tokens": 384,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "tenon_configuration", "strict": True, "schema": schema}}}


def generate(graph_path, task_path, output, endpoint, model, seed=42):
    graph, task = json.loads(graph_path.read_text()), json.loads(task_path.read_text())
    output.mkdir(parents=True, exist_ok=False)
    before = time.monotonic()
    payload = request_payload(graph, task, model, seed)
    save(output / "request.json", payload)
    save(output / "task.json", task)
    record = {"subject": task.get("subject", "Tenon-Kconfig-independent-prototype"), "author_orchestrator": False,
              "started_utc": utc(), "model": model, "graph_sha256": sha(graph_path),
              "task_sha256": sha(task_path), "generator_invoked": False,
              "model_response_received": False, "valid_candidate": False,
              "build_pass": None, "boot_pass": None, "functional_pass": None,
              "constraint_pass": None, "ranking_eligible": False}
    try:
        request = urllib.request.Request(endpoint.rstrip("/") + "/chat/completions",
            json.dumps(payload).encode(), {"Content-Type": "application/json"})
        record["generator_invoked"] = True
        with urllib.request.urlopen(request, timeout=task["generation_budget_s"]) as response:
            raw = response.read()
        (output / "response.json").write_bytes(raw)
        response = json.loads(raw)
        record["model_response_received"] = True
        content = response["choices"][0]["message"]["content"]
        (output / "candidate-response.txt").write_text(content)
        options = options_from_response(content, graph)
        locked = set(task["fixed_options"])
        if locked.intersection(options):
            raise ValueError("Candidate may not change fixed platform or prerequisite options")
        if task.get("candidate_controls") and set(options) - set(task["candidate_controls"]):
            raise ValueError("Candidate changed an option outside the frozen interface")
        lines = [f"CONFIG_{k}={v}" for k, v in {**task.get("starting_options", {}), **task["fixed_options"], **options}.items()]
        (output / "candidate.defconfig").write_text("\n".join(lines) + "\n")
        record.update(valid_candidate=True, options=options,
                      candidate_sha256=sha(output / "candidate.defconfig"), usage=response.get("usage"))
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        record.update(finished_utc=utc(), generation_wall_s=time.monotonic() - before,
                      generator_code_sha256=sha(Path(__file__)))
        save(output / "generation.json", record)
    print(json.dumps(record, indent=2))
    return record


def check_resolved(candidate_dir, build_dir, boot_dir):
    task = json.loads((candidate_dir / "task.json").read_text())
    generation = json.loads((candidate_dir / "generation.json").read_text())
    build = json.loads((build_dir / "build-result.json").read_text())
    if not generation["valid_candidate"] or build["input_defconfig_sha256"] != generation["candidate_sha256"]:
        raise ValueError("Build does not consume this generated candidate")
    config = dict(re.findall(r"^CONFIG_([A-Z0-9_]+)=(.*)$", (build_dir / ".config").read_text(), re.M))
    if sha(build_dir / ".config") != build["config_sha256"] or sha(candidate_dir / "candidate.defconfig") != generation["candidate_sha256"]:
        raise ValueError("Candidate or resolved configuration changed")
    checks = [{"option": k, "required": v, "actual": config.get(k, "n"), "pass": config.get(k, "n") == v}
              for k, v in task["required_options"].items()]
    requested = [{"option": k, "requested": v, "actual": config.get(k, "n"), "pass": config.get(k, "n") == v}
                 for k, v in generation["options"].items()]
    boots = json.loads((boot_dir / "boot-result.json").read_text())
    if boots["image_sha256"] != build["image_sha256"]:
        raise ValueError("Booted image differs from the candidate build")
    runtime_checks = []
    if "APPHELLOWORLD_PRINTARGS" in task["required_options"]:
        expected = task["required_options"]["APPHELLOWORLD_PRINTARGS"] != "n"
        for run in boots["runs"]:
            text = (boot_dir / ("boot" + str(run["index"]) + ".stdout")).read_text()
            observed = bool(re.search(r"^Arguments:", text, re.M))
            runtime_checks.append({"boot": run["index"], "gate": "argument_output",
                                   "expected": expected, "observed": observed, "pass": observed == expected})
    if "maximum_image_bytes" in task:
        image = build_dir / build["retained_image"]
        if sha(image) != build["image_sha256"]:
            raise ValueError("Retained image changed")
        runtime_checks.append({"gate": "image_bytes", "actual": image.stat().st_size,
                               "limit": task["maximum_image_bytes"], "pass": image.stat().st_size <= task["maximum_image_bytes"]})
    if task.get("preserve_reference"):
        baseline = Path(task["preserve_reference"]["config"])
        if not baseline.is_absolute():
            baseline = candidate_dir / baseline
        if sha(baseline) != task["preserve_reference"]["sha256"]:
            raise ValueError("Starting reference configuration changed")
        old = dict(re.findall(r"^CONFIG_([A-Z0-9_]+)=(.*)$", baseline.read_text(), re.M))
        changes = {k: [old.get(k, "n"), config.get(k, "n")] for k in old.keys() | config.keys()
                   if old.get(k, "n") != config.get(k, "n")}
        allowed = set(task["preserve_reference"]["allowed_changes"])
        runtime_checks.append({"gate": "preserve_unrelated_configuration", "changes": changes,
                               "pass": not (set(changes) - allowed)})
    first_console = (boot_dir / "boot1.stdout").read_text()
    result = {"subject": generation["subject"], "task_id": task["id"], "author_orchestrator": False,
              "generated": True, "built": True, "booted": "powered by tenonos" in first_console.lower(),
              "functional": boots["all_three_pass"],
              "constraints": all(c["pass"] for c in checks + runtime_checks),
              "required_checks": checks, "requested_configuration_checks": requested,
              "runtime_checks": runtime_checks, "checker_sha256": sha(Path(__file__)),
              "all_requested_options_preserved": all(c["pass"] for c in requested),
              "candidate_sha256": generation["candidate_sha256"], "image_sha256": build["image_sha256"],
              "execution_group": "Raspberry Pi 4B Linux-hosted ARM64 KVM guest",
              "ranking_eligible": False, "formal_task_bank_member": False,
              "experiment_protocol": task.get("protocol_id"),
              "boundary": "Independent Tenon-Kconfig baseline; original RTOS output gates or hello probe as declared by the task. Not author TenonOS generator results or ESP32 scores."}
    result["end_to_end_pass"] = all(result[k] for k in ("generated", "built", "booted", "functional", "constraints"))
    save(candidate_dir / "evaluation.json", result)
    print(json.dumps(result, indent=2))
    return result


def evaluate(workspace, candidate_dir, output):
    output.mkdir(parents=True, exist_ok=False)
    before = time.monotonic()
    generation = json.loads((candidate_dir / "generation.json").read_text())
    task = json.loads((candidate_dir / "task.json").read_text())
    record = {"subject": generation["subject"], "task_id": task["id"], "started_utc": utc(),
              "generated": generation["valid_candidate"], "built": False, "booted": False,
              "functional": False, "constraints": False, "end_to_end_pass": False}
    try:
        if not generation["valid_candidate"]:
            raise ValueError("Generation failed; no candidate is eligible for execution")
        build(workspace, output / "build", candidate_dir / "candidate.defconfig",
              c11_timer_fix=True, application=task["application"])
        record["built"] = True
        boot(workspace, output / "build", output / "boots", "kvm")
        record.update(check_resolved(candidate_dir, output / "build", output / "boots"))
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        record.update(finished_utc=utc(), build_and_three_boot_wall_s=time.monotonic() - before,
                      generation_wall_s=generation["generation_wall_s"],
                      evaluator_code_sha256=sha(Path(__file__)))
        save(output / "pipeline.json", record)
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("graph", "generate", "check", "evaluate"))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--task", type=Path)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--boot-dir", type=Path)
    parser.add_argument("--endpoint", default="http://127.0.0.1:18089/v1")
    parser.add_argument("--model", default="qwen2.5-0.5b-instruct-q4_k_m")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--application", default="app-helloworld")
    args = parser.parse_args()
    if args.action == "graph":
        export_graph(args.workspace.resolve(), args.output.resolve(), args.application)
    elif args.action == "generate":
        generate(args.graph, args.task, args.output, args.endpoint, args.model, args.seed)
    elif args.action == "check":
        check_resolved(args.candidate_dir, args.build_dir, args.boot_dir)
    else:
        evaluate(args.workspace.resolve(), args.candidate_dir.resolve(), args.output.resolve())
