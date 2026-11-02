#!/usr/bin/env python3
"""Real embedding/index retrieval component, not a completed TenonOS engine."""
import argparse
import asyncio
from datetime import datetime, timezone
import importlib.metadata
import json
from numbers import Integral, Real
import os
from pathlib import Path
import sys
import time
import xml.etree.ElementTree as ET

from tenonos_lib_graph import digest, lightrag_input, validate_graph

MODEL = "BAAI/bge-small-en-v1.5"
VERSIONS = {"lightrag-hku": "1.4.9.8", "fastembed": "0.7.3"}


def json_number(value):
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, Real):
        return float(value)
    raise TypeError("Unsupported JSON value: " + type(value).__name__)


def check_context(graph, result, hits):
    payload = lightrag_input(graph)
    names = {row["entity_name"]: json.loads(row["description"])
             for row in payload["entities"]}
    by_id = {row["id"]: row for row in graph["nodes"]}
    relations = {frozenset((row["src_id"], row["tgt_id"])) for row in payload["relationships"]}
    if result.get("status") != "success":
        raise ValueError("LightRAG returned no successful retrieval")
    found = {}
    for row in result["data"].get("entities", []) + hits:
        name = row["entity_name"]
        if name not in names:
            raise ValueError("Retrieved entity has no source binding")
        found[names[name]["id"]] = names[name]
    for row in result["data"].get("relationships", []):
        if frozenset((row["src_id"], row["tgt_id"])) not in relations:
            raise ValueError("Retrieved relation has no source binding")
    for row in result["data"].get("chunks", []):
        node = json.loads(row["content"])
        if by_id.get(node.get("id")) != node:
            raise ValueError("Retrieved chunk differs from the input configuration metadata")
        found[node["id"]] = node
    owners = {e["target"]: e["source"] for e in graph["edges"] if e["relation"] == "describes"}
    symbols = set()
    for identifier, node in found.items():
        if identifier in owners:
            node = by_id[owners[identifier]]
        if node["kind"] == "config":
            symbols.add(node["name"])
    return {"bound_entities_and_chunks": len(found), "configuration_symbols": sorted(symbols),
            "returned_entity_count": len(result["data"].get("entities", [])),
            "returned_relation_count": len(result["data"].get("relationships", [])),
            "returned_chunk_count": len(result["data"].get("chunks", []))}


def graphml_audit(directory, graph):
    files = list(directory.rglob("*.graphml"))
    if len(files) != 1:
        raise ValueError("Expected one persisted LightRAG graph")
    root = ET.parse(files[0]).getroot()
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    persisted = root.find("g:graph", ns)
    payload = lightrag_input(graph)
    names = {row["entity_name"] for row in payload["entities"]}
    nodes = {row.attrib["id"] for row in persisted.findall("g:node", ns)}
    edges = [frozenset((row.attrib["source"], row.attrib["target"]))
             for row in persisted.findall("g:edge", ns)]
    expected = {frozenset((row["src_id"], row["tgt_id"])) for row in payload["relationships"]}
    if nodes != names or len(edges) != len(expected) or set(edges) != expected:
        raise ValueError("Persisted graph coverage differs from the input")
    return {"nodes": len(nodes), "edges": len(edges), "graphml_sha256": digest(files[0]),
            "storage_edge_default": persisted.attrib.get("edgedefault"),
            "boundary": "LightRAG default storage is undirected. The original parent/help DAG "
                        "is retained separately; this audit does not establish directed path scoring."}


async def execute(args, record):
    import numpy as np
    from fastembed import TextEmbedding
    from lightrag import LightRAG, QueryParam
    from lightrag.utils import EmbeddingFunc

    installed = {name: importlib.metadata.version(name) for name in VERSIONS}
    if installed != VERSIONS:
        raise ValueError("Retrieval dependency versions differ from this component protocol")
    record["versions"] = installed
    if args.command == "query":
        original = json.loads((args.index / "run.json").read_text())
        if not original["complete"] or original["runtime_code_sha256"] != digest(Path(__file__)):
            raise ValueError("Index is incomplete or was created with different code")
        if original["graph_helper_sha256"] != digest(Path(__file__).with_name("tenonos_lib_graph.py")):
            raise ValueError("Index graph helper changed")
        graph_path = Path(original["graph_path"])
        if digest(graph_path) != original["graph_sha256"]:
            raise ValueError("Indexed graph changed")
        model_dir = Path(original["model_directory"])
        model_manifest = Path(original["model_manifest"])
        if digest(model_manifest) != original["model_manifest_sha256"]:
            raise ValueError("Indexed embedding manifest changed")
        index_dir = args.index / "rag"
    else:
        graph_path, model_dir, model_manifest = args.graph, args.model_directory, args.model_manifest
        index_dir = args.output / "rag"
    graph = json.loads(graph_path.read_text())
    validate_graph(graph)
    manifest = json.loads(model_manifest.read_text())
    if manifest["model_name"] != MODEL:
        raise ValueError("Wrong embedding model")
    for name, expected in manifest["files"].items():
        if digest(model_dir / name) != expected["sha256"]:
            raise ValueError("Embedding file changed: " + name)
    record.update(graph_path=str(graph_path.resolve()), graph_sha256=digest(graph_path),
                  model_directory=str(model_dir.resolve()), model_manifest=str(model_manifest.resolve()),
                  model_manifest_sha256=digest(model_manifest), model_name=MODEL,
                  embedding_window_tokens=512, author_embedding_model_confirmed=False)
    os.environ["TIKTOKEN_CACHE_DIR"] = str(model_dir.parent / "tiktoken-cache")
    model = TextEmbedding(model_name=MODEL, specific_model_path=str(model_dir),
                          cache_dir=str(model_dir.parent / "fastembed-cache"), threads=2,
                          providers=["CPUExecutionProvider"], local_files_only=True)
    count = {"calls": 0, "texts": 0}

    async def embed(texts, **kwargs):
        values = await asyncio.to_thread(lambda: np.asarray(list(model.embed(texts, batch_size=16))))
        if values.shape != (len(texts), 384) or not np.isfinite(values).all():
            raise ValueError("Invalid real-model embedding output")
        count["calls"] += 1
        count["texts"] += len(texts)
        return values

    async def no_generation(*unused, **kwargs):
        raise RuntimeError("This retrieval component must not invoke a generative LLM")

    rag = LightRAG(working_dir=str(index_dir), workspace="tenon-paper-graph",
        embedding_func=EmbeddingFunc(embedding_dim=384, max_token_size=512, func=embed),
        embedding_batch_num=16, embedding_func_max_async=1, default_embedding_timeout=180,
        llm_model_func=no_generation, llm_model_name="generation-not-connected",
        enable_llm_cache=False, max_parallel_insert=1)
    try:
        await rag.initialize_storages()
        if args.command == "index":
            payload = lightrag_input(graph)
            await rag.ainsert_custom_kg(payload)
            expected = sum(len(payload[k]) for k in ("entities", "relationships", "chunks"))
            if count["texts"] != expected:
                raise ValueError("Not every graph item was embedded in the fresh index")
        else:
            params = QueryParam(mode="local", ll_keywords=[args.query], enable_rerank=False)
            result = await rag.aquery_data(args.query, params)
            hits = await rag.entities_vdb.query(args.query, top_k=params.top_k)
            record["retrieval_audit"] = check_context(graph, result, hits)
            record.update(query=args.query, structured_keywords_provided=True,
                          query_mode=params.mode, top_k=params.top_k,
                          cosine_threshold=rag.cosine_better_than_threshold)
            with (args.output / "retrieval.json").open("x") as stream:
                json.dump({"result": result, "vector_hits": hits}, stream,
                          default=json_number, allow_nan=False, ensure_ascii=False, indent=2)
    finally:
        await rag.finalize_storages()
        record["real_embedding_work"] = count
    record["graph_audit"] = graphml_audit(index_dir, graph)
    record["complete"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("index", "query"))
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--model-directory", type=Path)
    parser.add_argument("--model-manifest", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--query")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run real embedding and retain evidence on leon")
    required = (args.graph, args.model_directory, args.model_manifest) if args.command == "index" else (args.index, args.query)
    if not all(required):
        parser.error("Index needs graph/model directory/manifest; query needs index/query text")
    args.output.mkdir(parents=True, exist_ok=False)
    for name in (Path(__file__).name, "tenonos_lib_graph.py"):
        (args.output / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    record = {"command": args.command, "complete": False, "benchmark_trial": False,
              "author_engine": False, "generator_invoked": False,
              "runtime_code_sha256": digest(Path(__file__)),
              "graph_helper_sha256": digest(Path(__file__).with_name("tenonos_lib_graph.py")),
              "started_utc": datetime.now(timezone.utc).isoformat()}
    before = time.monotonic()
    try:
        asyncio.run(execute(args, record))
    except Exception as error:
        record["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        record["wall_s"] = time.monotonic() - before
        with (args.output / "run.json").open("w") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(record, ensure_ascii=False))


if __name__ == "__main__":
    main()
