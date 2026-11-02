#!/usr/bin/env python3
"""Compare an audited retained endpoint with every attempt and its actual costs."""
import argparse
import json
from pathlib import Path
import re

import run_esp32_policy_holdout as holdout
import run_esp32_policy_sequence as sequence
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/reports"


def independent_originals(folder, expected):
    from replay_esp32_followup import raw_rows
    titles={"message_processing":"Message Processing", "synchronization_processing":"Synchronization Processing",
            "interrupt_processing":"Interrupt Processing"}
    captures=[]
    for result_path in sorted(folder.rglob("result[123].json")):
        saved=json.loads(result_path.read_text())
        index=result_path.stem[-1]
        path=result_path.with_name("reset"+index+".jsonl")
        rows=raw_rows(path)
        title=titles[saved["case"]]
        headings=[(i,int(m[1]),r["elapsed_s"]) for i,r in enumerate(rows) if
            (m:=re.search(r"Thread-Metric "+title+r" Test .* Relative Time: (\d+)$",r["line"]))]
        totals=[(i,int(m[1])) for i,r in enumerate(rows) if
            (m:=re.fullmatch(r"Time Period Total:\s*(\d+)",r["line"].strip()))]
        if [h[1] for h in headings]!=[30,60,90] or len(totals)!=3 or not 25<headings[0][2]<40 or \
                any(not 29.5<b[2]-a[2]<30.5 for a,b in zip(headings,headings[1:])) or any(
                    not h[0]<t[0]<(headings[i+1][0] if i<2 else len(rows)) or t[1]<=0
                    for i,(h,t) in enumerate(zip(headings,totals))) or \
                [t[1] for t in totals]!=saved["original_window_totals"]:
            raise ValueError("Independent original-window replay differs: "+str(path))
        captures.append({"path":path.relative_to(folder).as_posix(),"case":saved["case"],
                         "original_counts_30s":[t[1] for t in totals]})
    if len(captures)!=expected:
        raise ValueError("Independent physical-capture coverage differs")
    return {"complete_captures":len(captures),"original_windows":3*len(captures),"captures":captures,
            "scope":"Separate raw-byte/chronology and original-heading/total replay; not an independent proof of adapter semantics"}


def contrast(result, initial, external=None):
    rows = []
    for history in result["histories"]:
        rounds = history["rounds"]
        if not rounds or history["final_options"] != rounds[-1]["retained_options"]:
            raise ValueError("Endpoint is not the retained final policy")
        endpoint = {"options": history["final_options"],
                    "unchanged_from_initial": history["final_options"] == initial,
                    "last_accepted_round": next((r["task"] for r in reversed(rounds) if r["accepted"]), None)}
        if external is not None:
            matches = [p for p in external["policies"] if any(
                a["alias"] == history["id"] + "/retained" for a in p["aliases"])]
            if len(matches) != 1 or matches[0]["options"] != endpoint["options"]:
                raise ValueError("Retained endpoint has no unique resolved held-out policy")
            policy = matches[0]
            endpoint["held_out"] = {k: policy[k] for k in
                ("id", "build_pass", "functional_pass", "original_counts_30s", "failure")}
            endpoint["held_out"]["case"] = external["case"]
        rows.append({"history": history["id"], "static_endpoint_projection": endpoint,
            "full_trajectory": {
                "model_calls": len(rounds),
                "stage_pass_counts": {k: sum(bool(r["gates"][k]) for r in rounds)
                    for k in ("generated", "built", "booted", "functional", "constraints")},
                "accepted_rounds": sum(r["accepted"] for r in rounds),
                "rejected_and_recovered_rounds": sum(not r["accepted"] for r in rounds),
                "functional_but_requirements_failed": [r["task"] for r in rounds
                    if r["gates"]["functional"] and not r["gates"]["constraints"]],
                "initialization_s": history["initialization_s"],
                "total_round_wall_s": history["total_round_wall_s"],
                "stage_costs_s": {k: sum(r["costs"][k] for r in rounds)
                    for k in ("generation_s", "build_s", "deploy_s", "evaluation_s")},
                "within_history_budget": history["within_history_budget"],
                "rounds": rounds}})
    return {"histories": rows, "held_out_evaluated": external is not None,
        "new_model_calls": 0, "new_board_resets": 0, "new_metric_created": False,
        "scope": "Projections of the same audited histories; endpoint configuration is not an end-to-end task-success claim. Rejected attempts and recovery remain in trajectory costs.",
        "statistics": "Descriptive counts and original timings for registered histories; no population success probability, P95, significance, ranking or assumed improvement."}


def audit(held_out_folder=None):
    if held_out_folder is not None:
        held_out_folder=Path(held_out_folder).resolve()
    folder = REPORTS / "esp32-policy-sequence-v1"
    result = sequence.audit(folder)
    if result != json.loads((folder / "audit.json").read_text()):
        raise ValueError("Previously audited real histories changed")
    initial = json.loads((folder / "protocol.json").read_text())["initial_config"]
    experiments = [{"source": folder.relative_to(ROOT).as_posix(),
        "source_audit_sha256": sha(folder / "audit.json"),
        "independent_raw_replay":independent_originals(folder,result["generated_physical_resets"]+
            result["initial_state_captures"]+result["recovery_state_captures"]),
        **contrast(result, initial)}]
    if held_out_folder is not None:
        external = holdout.audit(held_out_folder)
        if external != json.loads((held_out_folder / "audit.json").read_text()):
            raise ValueError("Prospective held-out evidence changed")
        initial = json.loads((held_out_folder / "sequence/protocol.json").read_text())["initial_config"]
        experiments.append({"source": held_out_folder.relative_to(ROOT).as_posix(),
            "source_audit_sha256": sha(held_out_folder / "audit.json"),
            "independent_raw_replay":independent_originals(held_out_folder,external["physical_resets"]+
                external["sequence"]["generated_physical_resets"]+external["sequence"]["initial_state_captures"]+
                external["sequence"]["recovery_state_captures"]),
            **contrast(external["sequence"], initial, external)})
    return {"audit": "pass", "experiments": experiments, "energy_measured": False,
        "whole_live_ram_measured": False, "rsi": False, "author_tenon_engine": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--held-out", type=Path, help="Completed prospectively registered acquisition, never an active partial collection")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.held_out.resolve() if args.held_out else None)
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
