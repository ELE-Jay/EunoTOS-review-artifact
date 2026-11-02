#!/usr/bin/env python3
"""Inspect pinned public artifacts without executing subjects or generating code."""
import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.parse import quote
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry/iotos_generative_subjects_v1.json"
REPORT = "artifacts/reports/iotos-generative-subjects-v1.json"
CAPTURES = ROOT / "artifacts/dependency_stage/generative_subjects"


def fetch(subject_id=None):
    """Fetch immutable public sources; never read repository credential files."""
    registry = json.loads((ROOT / REGISTRY).read_text())
    for subject in registry["subjects"]:
        if "commit" not in subject or (subject_id and subject["id"] != subject_id):
            continue
        gitee = subject.get("provider") == "gitee"
        base = ("https://gitee.com/api/v5/repos/" if gitee else "https://api.github.com/repos/") + subject["repository"]
        with urlopen(base + "/git/trees/" + subject.get("tree_sha", subject["commit"]) + "?recursive=1", timeout=30) as response:
            tree = json.load(response)
        if tree["truncated"]:
            raise ValueError("Incomplete upstream tree")
        files = [{"path": f["path"], "sha": f["sha"], "size": f["size"]} for f in tree["tree"] if f["type"] == "blob"]
        folder = CAPTURES / subject["name"]
        folder.mkdir(parents=True, exist_ok=True)
        for f in files:
            path = f["path"]
            selected = (path.startswith("optimized_result/") or path in ("README.md", "append.py", "init_env.sh")) if subject["id"] == "autoos" else (
                bool(re.fullmatch(r"core/userstudy/[^/]+/(base|generated_code)\.c", path)) or path in (
                    "README.md", "core/start.py", "core/llmselfdebug.py", "datasets/app.csv", "datasets/output.csv"))
            if gitee:
                selected = path in ("README.md", "COPYING.md", "Config.uk", "Makefile") or (
                    path.startswith("arch/") and path.endswith("Config.uk"))
            if not selected:
                continue
            if f["size"] > 1024 * 1024:
                raise ValueError("Unexpected source size")
            if gitee:
                with urlopen(base + "/git/blobs/" + f["sha"], timeout=30) as response:
                    blob_data = json.load(response)
                if blob_data["encoding"] != "base64":
                    raise ValueError("Unknown Gitee blob encoding")
                raw = base64.b64decode(blob_data["content"])
            else:
                url = "https://raw.githubusercontent.com/" + subject["repository"] + "/" + subject["commit"] + "/" + quote(path)
                with urlopen(url, timeout=30) as response:
                    raw = response.read(1024 * 1024 + 1)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if len(raw) != f["size"] or blob != f["sha"]:
                raise ValueError("Downloaded source differs from pinned Git blob")
            content = {"repository": subject["repository"], "commit": subject["commit"],
                       "path": path, "git_blob_sha": blob, "content": raw.decode("utf-8")}
            (folder / (path.replace("/", "__") + ".source.json")).write_text(json.dumps(content) + "\n")
        manifest = {"repository": subject["repository"], "commit": subject["commit"],
                    "truncated": False, "tree_sha": tree["sha"], "files": files}
        (folder / "manifest.json").write_text(json.dumps(manifest) + "\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def imported(subject):
    folder = CAPTURES / subject["name"]
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest["repository"] != subject["repository"] or manifest["commit"] != subject["commit"] or manifest["truncated"]:
        raise ValueError("Unpinned or incomplete repository inventory")
    tree = {f["path"]: f for f in manifest["files"]}
    contents, records = {}, []
    for path in sorted(folder.glob("*.source.json")):
        entry = json.loads(path.read_text())
        raw = entry["content"].encode("utf-8")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if entry["repository"] != subject["repository"] or entry["commit"] != subject["commit"] or \
                blob != entry["git_blob_sha"] or blob != tree[entry["path"]]["sha"] or len(raw) != tree[entry["path"]]["size"]:
            raise ValueError("Imported bytes differ from upstream Git blob: " + entry["path"])
        contents[entry["path"]] = entry["content"]
        records.append({"path": entry["path"], "git_blob_sha": blob, "sha256": sha(raw), "bytes": len(raw),
            "url": ("https://gitee.com/" if subject.get("provider") == "gitee" else "https://github.com/") + subject["repository"] + "/blob/" + subject["commit"] + "/" + entry["path"]})
    return contents, records, tree


def config_text(text):
    """Textual assignments only; no Linux Kconfig dependency resolution claim."""
    values, duplicates = {}, []
    for line in text.splitlines():
        assigned = re.fullmatch(r"(CONFIG_[A-Za-z0-9_]+)=(.*)", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
        if assigned or disabled:
            name, value = (assigned[1], assigned[2]) if assigned else (disabled[1], "n")
            if name in values:
                duplicates.append(name)
            values[name] = value
    if not values:
        raise ValueError("Not a Linux configuration text")
    return values, sorted(set(duplicates))


def inspect():
    registry = json.loads((ROOT / REGISTRY).read_text())
    subjects = []
    for subject in registry["subjects"]:
        result = {**subject, "runtime_measurements_imported": 0, "complete_evolution_histories": 0,
                  "ranking_eligible": False, "source_artifacts": []}
        files, records, tree = imported(subject)
        if subject["id"] == "tenonos":
            result.update(state="pinned_source_platforms_imported_no_runtime_admission", artifact_pairs=[], source_artifacts=records,
                architecture_configs=[p for p in tree if p.startswith("arch/") and p.endswith("Config.uk")],
                esp32_or_xtensa_named_paths=[p for p in tree if re.search(r"(?:^|/)(?:esp32|xtensa)(?:/|[_.-]|$)", p, re.I)],
                orchestration_implementation_validated=False,
                record_boundary="Pinned default-branch build/platform sources, not a generated runtime or an authenticated multi-round history.")
        else:
            if any(Path(p).name.lower() in ("license", "license.txt", "license.md", "copying") and "/" not in p for p in tree):
                raise ValueError("License inventory changed; review redistribution policy")
            result.update(state="pinned_public_artifacts_imported_no_runtime_admission", source_artifacts=records)
            pairs = []
            if subject["id"] == "autoos":
                for name in ("polyos", "fedora", "ubuntu22_04"):
                    before = "optimized_result/" + name + "_config_origin.txt"
                    after = "optimized_result/" + name + "_config _optimized.txt"
                    old, old_duplicates = config_text(files[before])
                    new, new_duplicates = config_text(files[after])
                    changed = [k for k in sorted(old.keys() | new.keys()) if old.get(k) != new.get(k)]
                    pairs.append({"id": name, "before": before, "after": after,
                        "changed_textual_assignments": len(changed),
                        "duplicate_assignments": {"before": old_duplicates, "after": new_duplicates},
                        "configuration_dependencies_validated": False, "compiled": False, "booted": False,
                        "runtime_metrics": None, "costs": None})
                result["record_boundary"] = "Author-published initial/final configuration pairs, not a complete measured evolution history. Text changes are artifact metadata, not benchmark scores."
            else:
                for path in sorted(files):
                    if path.endswith("/base.c"):
                        generated = path.rsplit("/", 1)[0] + "/generated_code.c"
                        if generated not in files:
                            raise ValueError("Incomplete application source pair")
                        pairs.append({"id": path.split("/")[-2], "reference": path, "generated": generated,
                            "compiled": False, "booted": False, "runtime_metrics": None, "costs": None})
                tasks = list(csv.DictReader(io.StringIO(files["datasets/app.csv"])))
                answers = csv.DictReader(io.StringIO(files["datasets/output.csv"]))
                if set(answers.fieldnames or ()) != {"id", "code"}:
                    raise ValueError("Upstream output table schema changed")
                result.update(task_description_rows=len(tasks),
                    documented_benchmark_directory_present=any(p.startswith("benchmark/") for p in tree),
                    unstructured_nohup_log_present="core/nohup.out" in tree,
                    unstructured_nohup_log_git_blob=tree.get("core/nohup.out", {}).get("sha"),
                    unstructured_nohup_log_url="https://github.com/"+subject["repository"]+"/blob/"+subject["commit"]+"/core/nohup.out",
                    unstructured_log_imported_as_trace=False,
                    output_csv_boundary="id/code API-answer table, not measured runtime scores or per-attempt costs")
                result["record_boundary"] = "Application source pairs are an adjacent generation workload, not generated OS implementations. A successful build alone would not establish runtime correctness."
            result["artifact_pairs"] = pairs
        subjects.append(result)
    return {"schema": "iotos-generative-subject-import-v1", "date": registry["date"],
        "registry": {"path": REGISTRY, "sha256": sha((ROOT / REGISTRY).read_bytes())},
        "subjects": subjects,
        "summary": {"projects": len(subjects), "configuration_pairs_imported": len(subjects[0]["artifact_pairs"]),
            "application_pairs_imported": len(subjects[1]["artifact_pairs"]),
            "new_runtime_measurements": 0, "complete_evolution_histories_imported": 0},
        "source_code_redistributed_in_reproduction_package": False,
        "boundary": "Source/metadata inspection only. No third-party program, model API, installer, kernel replacement or firmware flashing was executed."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "import", "check"))
    parser.add_argument("--subject", choices=("autoos", "iotpilot", "tenonos"))
    args = parser.parse_args()
    if args.command == "fetch":
        fetch(args.subject)
    result = inspect()
    if args.command in ("import", "fetch"):
        (ROOT / REPORT).write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    elif result != json.loads((ROOT / REPORT).read_text()):
        raise ValueError("Subject import is stale")
    print(json.dumps({"audit": "pass", **result["summary"]}, indent=2))


if __name__ == "__main__":
    main()
