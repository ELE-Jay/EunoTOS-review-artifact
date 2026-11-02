#!/usr/bin/env python3
"""Replay frozen task outcomes against model, build and raw guest records."""
import argparse
import json
from pathlib import Path
import re
import statistics

from import_iotos_subjects import config_text
from iotos_task_benchmark import summarize_accounting
from tenonos_kvm_reproduce import sha
from tenonos_orchestrator import options_from_response


def require(condition, message):
    if not condition:
        raise ValueError(message)


def configuration(path):
    values, duplicates = config_text(path.read_text())
    require(not duplicates, "Duplicate configuration options")
    return {k.removeprefix("CONFIG_"): v for k, v in values.items()}


def audit(bank_path, folder, graph_path):
    bank = json.loads(bank_path.read_text())
    graph = json.loads(graph_path.read_text())
    registration = json.loads((folder / "registration.json").read_text())
    report = json.loads((folder / "results.json").read_text())
    require(bank["frozen_utc"] and registration["registered_utc"] >= bank["frozen_utc"] and
            registration["bank_sha256"] == sha(bank_path) and
            bank["graph_sha256"] == sha(graph_path), "Protocol or graph changed")
    planned = [(t["id"], i + 1, seed) for t in bank["tasks"] for i, seed in enumerate(bank["seeds"])]
    require(report["finished"] and len(report["records"]) == len(planned) == len(registration["trials"]),
            "Incomplete registered campaign")
    records, receipts = [], []
    for task_id, index, seed in planned:
        task = next(t for t in bank["tasks"] if t["id"] == task_id)
        trial_id = task_id + "-" + str(index)
        run = folder / trial_id
        record = json.loads((run / "trial.json").read_text())
        require(record == next(r for r in report["records"] if r["id"] == trial_id), "Trial/result disagreement")
        generated = json.loads((run / "candidate/generation.json").read_text())
        payload = json.loads((run / "candidate/request.json").read_text())
        expected_task = {**task, "protocol_id": bank["id"], "bank_sha256": sha(bank_path)}
        require(json.loads((run / "candidate/task.json").read_text()) == expected_task and
                generated["task_sha256"] == sha(run / "task.json") and
                generated["graph_sha256"] == sha(graph_path) and
                generated["generator_code_sha256"] == bank["generator_sha256"], "Task or generator identity changed")
        require(payload["model"] == bank["model"] and payload["temperature"] == bank["temperature"] and
                payload["seed"] == seed and payload["max_tokens"] == bank["maximum_output_tokens"] and
                generated["generator_invoked"] and generated["model_response_received"], "Model protocol differs")
        raw = json.loads((run / "candidate/response.json").read_text())
        require(raw["choices"][0]["message"]["content"] == (run / "candidate/candidate-response.txt").read_text(),
                "Raw model output differs")
        require(record["gates"]["generated"] == generated["valid_candidate"], "Generation gate differs")
        if generated["valid_candidate"]:
            options = options_from_response(raw["choices"][0]["message"]["content"], graph)
            require(options == generated["options"] and not (set(options) - set(task["candidate_controls"])),
                    "Model options changed")
            require(configuration(run / "candidate/candidate.defconfig") ==
                    {**task.get("starting_options", {}), **task["fixed_options"], **options}, "Candidate edited")
            require(sha(run / "candidate/candidate.defconfig") == generated["candidate_sha256"], "Candidate bytes changed")
            if not record["gates"]["built"]:
                failed = run / "evaluation/build"
                step = json.loads((failed / "build.json").read_text())
                require(step["state"] == "finished" and step["returncode"] != 0 and
                        sha(failed / "build.stdout") == step["stdout_sha256"] and
                        sha(failed / "build.stderr") == step["stderr_sha256"], "Missing build failure evidence")
        if record["gates"]["built"]:
            built = run / "evaluation/build"
            proof = json.loads((built / "build-result.json").read_text())
            require(sha(built / "runtime-image") == proof["image_sha256"] and
                    sha(built / ".config") == proof["config_sha256"] and
                    sha(built / "input.defconfig") == generated["candidate_sha256"], "Compiled artifact changed")
            actual = configuration(built / ".config")
            checks = [actual.get(k, "n") == v for k, v in task["required_options"].items()]
            if "maximum_image_bytes" in task:
                checks.append((built / "runtime-image").stat().st_size <= task["maximum_image_bytes"])
            if task.get("preserve_reference"):
                baseline = run / "candidate/starting-reference.config"
                require(sha(baseline) == task["preserve_reference"]["sha256"], "Starting configuration changed")
                old = configuration(baseline)
                changes = {k for k in old.keys() | actual.keys() if old.get(k, "n") != actual.get(k, "n")}
                checks.append(not (changes - set(task["preserve_reference"]["allowed_changes"])))
            boots = run / "evaluation/boots"
            verdict = json.loads((boots / "boot-result.json").read_text())
            require(verdict["image_sha256"] == proof["image_sha256"] and verdict["guest_memory_bytes"] == 134217728,
                    "Guest identity changed")
            complete = []
            for i in range(1, len(verdict["runs"]) + 1):
                receipt = json.loads((boots / f"boot{i}.json").read_text())
                require(sha(boots / f"boot{i}.stdout") == receipt["stdout_sha256"] and
                        sha(boots / f"boot{i}.stderr") == receipt["stderr_sha256"], "Raw guest capture changed")
                text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", (boots / f"boot{i}.stdout").read_text())
                values = re.findall(r"R-Rhealstone: ([^\r\n]+?) - (-?[0-9]+) (cycle|count)", text)
                complete.append(receipt["returncode"] == 0 and len(values) == len({v[0] for v in values}) == 6 and
                                text.count("RST: ") == 6 and not re.search(r"assertion.*fail|panic|\[E/RST\]", text, re.I))
                receipts.append({"trial": trial_id, "boot": i, "printed_values": values,
                                 "stdout_sha256": receipt["stdout_sha256"]})
            functional = len(complete) == 3 and all(complete)
            require(record["gates"]["booted"] == ("powered by tenonos" in (boots / "boot1.stdout").read_text().lower()) and
                    record["gates"]["functional"] == functional and record["gates"]["constraints"] == all(checks),
                    "Published stage gate disagrees with direct source replay")
        records.append(record)
    families = []
    for task in bank["tasks"]:
        group = [r for r in records if r["task_id"] == task["id"]]
        families.append({"task": task["id"], "family": task["family"], "accounting": summarize_accounting(group),
            "all_run_duration_median_s": statistics.median(r["observed_wall_s"] for r in group),
            "all_run_duration_range_s": [min(r["observed_wall_s"] for r in group), max(r["observed_wall_s"] for r in group)],
            "unique_candidate_fragments": len({sha(folder/r["id"]/"candidate/candidate.defconfig") for r in group
                                               if (folder/r["id"]/"candidate/candidate.defconfig").exists()})})
    for task in bank["tasks"]:
        for evidence in task["reference_files"]:
            require(sha(Path(evidence["path"])) == evidence["sha256"], "Manual reference changed")
    accounting = summarize_accounting(records)
    require(accounting == report["accounting"], "Summary does not preserve registered denominators")
    return {"audit": "pass", "protocol_id": bank["id"], "bank_sha256": sha(bank_path),
            "registered_trials": len(records), "families": families, "accounting": accounting,
            "raw_guest_captures": len(receipts), "original_results": receipts,
            "subject": "Independent Tenon-Kconfig baseline, Qwen2.5-1.5B-Instruct Q4_K_M",
            "not_author_tenonos_generator": True, "not_rsi": True, "ranking_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bank", type=Path, default=Path("registry/tenonos_tasks_rpi4_v1.json"))
    parser.add_argument("--folder", type=Path, default=Path("artifacts/reports/tenonos-rpi4-v1/formal-v1"))
    parser.add_argument("--graph", type=Path, default=Path("artifacts/reports/tenonos-rpi4-v1/rtos-graph/graph.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.bank, args.folder, args.graph)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "original_results"}, indent=2))
