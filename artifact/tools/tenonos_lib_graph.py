#!/usr/bin/env python3
"""Reconstruct TenonOS section 4.5's Kconfig graph; not the author engine."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_graph(graph):
    nodes = graph["nodes"]
    lookup = {node["id"]: node for node in nodes}
    if len(lookup) != len(nodes) or lookup.get("root", {}).get("kind") != "root":
        raise ValueError("Duplicate node or missing root")
    parents = {}
    for edge in graph["edges"]:
        source, target = edge["source"], edge["target"]
        if source not in lookup or target not in lookup or target == "root" or target in parents:
            raise ValueError("Missing endpoint, multiple parent, or edge to root")
        if edge["relation"] == "describes":
            if lookup[target]["kind"] != "help" or lookup[source]["kind"] != "config":
                raise ValueError("Help must describe a configuration entry")
        elif edge["relation"] == "parent_of":
            if lookup[target]["kind"] == "help":
                raise ValueError("Help requires a descriptive edge")
        else:
            raise ValueError("Unknown structural relation")
        parents[target] = source
    if set(parents) != set(lookup) - {"root"}:
        raise ValueError("Orphan node")
    for name in parents:
        seen = set()
        current = name
        while current != "root":
            if current in seen:
                raise ValueError("Cycle in structural graph")
            seen.add(current)
            current = parents[current]
    for node in nodes:
        if node["kind"] == "config" and node["has_help"]:
            help_id = node["id"] + ":help"
            if lookup.get(help_id, {}).get("kind") != "help" or parents.get(help_id) != node["id"]:
                raise ValueError("Configuration help was not preserved separately")
    return {"nodes": len(nodes), "edges": len(graph["edges"]),
            "config_entries": sum(n["kind"] == "config" for n in nodes),
            "help_entities": sum(n["kind"] == "help" for n in nodes)}


def lightrag_input(graph):
    validate_graph(graph)
    names = {n["id"]: n.get("name", n["id"]) + " [" + n["id"] + "]"
             for n in graph["nodes"]}
    chunks, entities, relationships = [], [], []
    for node in graph["nodes"]:
        description = json.dumps(node, ensure_ascii=False, sort_keys=True)
        path = node.get("source", "Tenon Kconfig graph root")
        chunks.append({"content": description, "source_id": node["id"], "file_path": path})
        entities.append({"entity_name": names[node["id"]], "entity_type": node["kind"],
                         "description": description, "source_id": node["id"], "file_path": path})
    for edge in graph["edges"]:
        relationships.append({"src_id": names[edge["source"]], "tgt_id": names[edge["target"]],
            "description": edge["source"] + " -> " + edge["target"] + ": " + edge["relation"],
            "keywords": edge["relation"], "source_id": edge["target"]})
    return {"chunks": chunks, "entities": entities, "relationships": relationships}


def export(workspace, application, output):
    import kconfiglib as kc
    from tenonos_orchestrator import kconfig

    output.mkdir(parents=True, exist_ok=False)
    workspace = workspace.resolve()
    config = kconfig(workspace, application, output / "kconfig")
    entries = list(config.node_iter())
    ids = {id(node): "entry:" + str(index) for index, node in enumerate(entries)}
    nodes = [{"id": "root", "kind": "root", "name": "Tenon Kconfig"}]
    edges, sources = [], {}
    for entry in entries:
        item = entry.item
        identifier = ids[id(entry)]
        path = Path(entry.filename).resolve()
        if path.is_relative_to(workspace):
            relative = "source/" + path.relative_to(workspace).as_posix()
        else:
            relative = "generated-kconfig/" + path.relative_to((output / "kconfig").resolve()).as_posix()
        sources[relative] = digest(path)
        parent = entry.parent
        while parent is not None and id(parent) not in ids:
            parent = parent.parent
        edges.append({"source": ids[id(parent)] if parent else "root",
                      "target": identifier, "relation": "parent_of"})
        node = {"id": identifier, "source": relative, "line": entry.linenr,
                "prompt": entry.prompt[0] if entry.prompt else "",
                "depends": kc.expr_str(entry.dep)}
        if isinstance(item, kc.Symbol):
            node.update(kind="config", name=item.name,
                        type=kc.TYPE_TO_STR[item.type], has_help=bool(entry.help),
                        symbol_dependencies=kc.expr_str(item.direct_dep),
                        referenced_symbols=sorted({s.name for s in item.referenced
                                                   if s.name and not s.is_constant}))
            if entry.help:
                nodes.append({"id": identifier + ":help", "kind": "help",
                              "name": item.name + " help", "text": entry.help,
                              "source": relative, "line": entry.linenr})
                edges.append({"source": identifier, "target": identifier + ":help",
                              "relation": "describes"})
        else:
            node.update(kind="choice" if isinstance(item, kc.Choice) else "menu",
                        name=getattr(item, "name", None) or node["prompt"])
        nodes.append(node)
    graph = {"schema": "tenonos-paper-lib-graph-component-v1",
             "paper": "https://arxiv.org/html/2512.00400v2#S4.SS5",
             "implementation": "independent_reconstruction_of_graph_component",
             "author_engine": False, "application": application,
             "generator_invoked": False, "nodes": nodes, "edges": edges,
             "source_files": dict(sorted(sources.items())),
             "parser": "kconfiglib " + importlib.metadata.version("kconfiglib"),
             "code_sha256": digest(Path(__file__)),
             "kconfig_environment_helper_sha256": digest(Path(__file__).with_name("tenonos_orchestrator.py")),
             "boundary": "Structural parent/help DAG only. Symbol references and dependency "
                         "expressions remain metadata, not a claim of solved constraints.",
             "remaining_engine_components": ["LightRAG semantic retrieval", "path scoring and threshold",
                 "candidate generation", "dependency pruning and utility selection",
                 "author model/checkpoint/prompts and original application tasks"]}
    stats = validate_graph(graph)
    defined = {s.name for s in config.unique_defined_syms}
    if {n["name"] for n in nodes if n["kind"] == "config"} != defined:
        raise ValueError("Graph did not cover every defined symbol")
    graph["coverage"] = {**stats, "unique_defined_symbols": len(defined)}
    with (output / "lib-graph.json").open("x") as stream:
        json.dump(graph, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    with (output / "lightrag-input.json").open("x") as stream:
        json.dump(lightrag_input(graph), stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"component": "Kconfig Lib-Graph", "coverage": graph["coverage"],
                      "author_engine": False, "generator_invoked": False,
                      "output": str(output / "lib-graph.json")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--application", default="app-rtos-benchmark-abi")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Generate evidence on leon; do not write experiment data on this Mac")
    export(args.workspace, args.application, args.output)


if __name__ == "__main__":
    main()
