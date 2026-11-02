#!/usr/bin/env python3
"""Validate candidates with Tenon's native Kconfig; never generate or run an OS."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import time

from import_iotos_subjects import config_text
from tenonos_kvm_reproduce import command
from tenonos_lib_graph import digest, validate_graph
from tenonos_orchestrator import kconfig, options_from_response


def submitted_options(graph, response, task):
    symbols = {"nodes": [n for n in graph["nodes"] if n["kind"] == "config"]}
    options = options_from_response(response, symbols)
    if set(options) & set(task["fixed_options"]):
        raise ValueError("Candidate writes fixed platform/prerequisite options")
    if set(options) - set(task["candidate_controls"]):
        raise ValueError("Candidate writes outside the frozen interface")
    combined = {**task.get("starting_options", {}), **task["fixed_options"], **options}
    # Validate supplied defaults too; an unknown '=n' must not appear to succeed.
    combined = options_from_response(json.dumps({"options": combined}), symbols)
    return options, combined


def requested_differences(graph, requested, resolved):
    types = {n["name"]: n["type"] for n in graph["nodes"] if n["kind"] == "config"}
    differences = {}
    for name, expected in requested.items():
        actual = resolved.get("CONFIG_" + name, "n")
        equal = actual == expected
        if types[name] in ("int", "hex"):
            try:
                base = 16 if types[name] == "hex" else 10
                equal = int(actual, base) == int(expected, base)
            except ValueError:
                equal = False
        if not equal:
            differences[name] = {"requested": expected, "resolved": actual}
    return differences


def resolution_checks(graph, task, proposed, resolved):
    return {
        "requested_differences": requested_differences(
            graph, {**task["fixed_options"], **proposed}, resolved),
        "inherited_differences": requested_differences(
            graph, task.get("starting_options", {}), resolved),
    }


def verify_sources(graph, graph_path, workspace):
    for name, expected in graph["source_files"].items():
        prefix, relative = name.split("/", 1)
        if prefix == "source":
            root = workspace
        elif prefix == "generated-kconfig":
            root = graph_path.parent / "kconfig"
        else:
            raise ValueError("Unknown graph source origin")
        source = (root / relative).resolve()
        source.relative_to(root.resolve())
        if digest(source) != expected:
            raise ValueError("Graph source changed: " + name)


def validate(workspace, graph_path, response_path, task_path, output, timeout_s=90):
    import kconfiglib as kc

    graph = json.loads(graph_path.read_text())
    validate_graph(graph)
    task = json.loads(task_path.read_text())
    verify_sources(graph, graph_path, workspace)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    record = {"schema": "tenon-native-config-validation-v1", "complete": False,
              "dependency_valid": False, "benchmark_trial": False,
              "generator_invoked": False, "author_engine": False,
              "graph_sha256": digest(graph_path), "task_sha256": digest(task_path),
              "response_sha256": digest(response_path), "code_sha256": digest(Path(__file__)),
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "boundary": "Configuration consistency only; no build, boot, functional or task-constraint verdict."}
    for source, name in ((response_path, "response.json"), (task_path, "task.json"),
                         (Path(__file__), Path(__file__).name)):
        shutil.copyfile(source, output / name)
    try:
        proposed, requested = submitted_options(graph, response_path.read_text(), task)
        (output / "candidate.defconfig").write_text("".join(
            "CONFIG_" + k + "=" + v + "\n" for k, v in requested.items()))
        record.update(proposed_options=proposed, input_options=requested,
                      requested_options={**task["fixed_options"], **proposed},
                      input_defconfig_sha256=digest(output / "candidate.defconfig"))
        configured = command(output, "native-configure", [
            "timeout", "--kill-after=5", str(timeout_s), "make", "-C", workspace / "tenon-c11",
            "A=" + str(workspace / "apps" / task["application"]),
            "L=" + str(workspace / "libs"), "O=" + str(output / "build"),
            "C=" + str(output / ".config"), "ARCH=arm64",
            "UK_DEFCONFIG=" + str(output / "candidate.defconfig"), "defconfig"])
        record["native_returncode"] = configured["returncode"]
        if configured["returncode"]:
            raise RuntimeError("Native Kconfig infrastructure failed; inspect configure logs")
        resolved, duplicates = config_text((output / ".config").read_text())
        if duplicates:
            raise ValueError("Duplicate entries in native configuration")
        checks = resolution_checks(graph, task, proposed, resolved)
        parsed = kconfig(workspace, task["application"], output / "parsed-kconfig")
        parsed.load_config(str(output / ".config"))
        violations = {}
        for symbol in parsed.unique_defined_syms:
            value = resolved.get("CONFIG_" + symbol.name, "n")
            if symbol.type in (kc.BOOL, kc.TRISTATE) and value in ("y", "m"):
                if {"m": 1, "y": 2}[value] > kc.expr_value(symbol.direct_dep):
                    violations[symbol.name] = kc.expr_str(symbol.direct_dep)
        verify_sources(graph, graph_path, workspace)
        record.update(complete=True, native_config_sha256=digest(output / ".config"),
                      **checks, dependency_violations=violations,
                      parser_warnings=parsed.warnings,
                      dependency_valid=not checks["requested_differences"] and not violations)
    except Exception as error:
        record["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        record["wall_s"] = time.monotonic() - started
        (output / "validation.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("workspace", "graph", "response", "task", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout-s", type=float, default=90)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run native configuration validation and retain evidence on leon")
    if not 0 < args.timeout_s <= 90:
        parser.error("--timeout-s must be positive and no greater than 90")
    validate(args.workspace.resolve(), args.graph.resolve(), args.response.resolve(),
             args.task.resolve(), args.output.resolve(), args.timeout_s)
