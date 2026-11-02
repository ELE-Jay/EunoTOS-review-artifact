#!/usr/bin/env python3
"""Qualify task references and implement frozen task-level statistics."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
BANK = "registry/iotos_tasks_v1.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_qualification(records, root=ROOT, manual=()):
    bank = json.loads((root / BANK).read_text())
    if len({t["id"] for t in bank["tasks"]}) != len(bank["tasks"]):
        raise ValueError("Duplicate frozen task")
    results = []
    for task in bank["tasks"]:
        proofs, missing = [], []
        sizes, values, configs = {}, {}, {}
        for case in task["workloads"]:
            candidates = manual if task["reference_policy"] == "new_manual_reference_required" else records
            reference = next((r for r in candidates if r["os"] == "Zephyr" and r["case"] == case and
                              r["metric"] == "original_count_30s" and
                              all(r.get("resolved_config", {}).get(k) == v for k,v in task.get("required_config", {}).items())), None)
            if reference is None:
                missing.append(case + ": matching feasible reference not yet audited")
                continue
            image = root / reference["artifact"]["path"]
            if sha(image) != reference["artifact"]["sha256"] or len(reference["values"]) != 3 or \
                    any(type(v) not in (int,float) or not math.isfinite(v) or v <= 0 for v in reference["values"]):
                raise ValueError("Changed or incomplete reference")
            bound = task["constraints"].get("application_image_bytes")
            if bound is not None and image.stat().st_size > bound:
                missing.append(case + ": reference exceeds the declared image slot")
                continue
            config = reference.get("resolved_config")
            if config is None:
                from import_iotos_subjects import config_text
                source_proof = root/reference["source_proof"]["path"]
                if sha(source_proof) != reference["source_proof"]["sha256"]:
                    raise ValueError("Changed reference source proof")
                config_file = root/"artifacts/reports"/json.loads(source_proof.read_text())["source"]/"config"
                if sha(config_file) != reference["config_sha256"]:
                    raise ValueError("Changed reference resolved configuration")
                config, _ = config_text(config_file.read_text())
            sizes[case], values[case], configs[case] = image.stat().st_size, reference["values"], config
            # These are previously audited runtime references, never generation trials.
            proofs.append({"case":case, "reference_id":reference["id"], "artifact":reference["artifact"],
                "audit":reference["audit"], "source_proof":reference["source_proof"],
                "config_sha256":reference["config_sha256"],
                "image_bytes":image.stat().st_size, "reference_median":statistics.median(reference["values"]),
                "minimum_count_30s":(statistics.median(reference["values"])*task["constraints"]["minimum_reference_throughput_ratio"]
                    if "minimum_reference_throughput_ratio" in task["constraints"] else None),
                "board_mac":reference["board_mac"], "original_acquisition_utc":reference.get("acquired_utc"),
                "generation_evidence":False})
        if len({(p["board_mac"],p["config_sha256"]) for p in proofs}) > 1:
            missing.append("workloads do not share the required board and OS configuration")
        checks = None
        if not missing:
            checks = constraint_oracle(task, sizes, values, values, resolved_configs=configs)
            if not checks["pass"]:
                missing.append("feasible reference does not satisfy the frozen task constraints")
        results.append({**task, "admitted":not missing,
            "reference_admission":"admitted" if not missing else "pending",
            "reference_evidence":proofs, "reference_constraint_checks":checks, "missing":missing})
    return {"schema":bank["schema"], "bank_sha256":sha(root / BANK), "frozen_utc":bank["frozen_utc"],
        "subject_policy":bank["subject_policy"], "statistics":bank["statistics"], "budget":bank["budget"],
        "tasks":results, "admitted_tasks":sum(t["admitted"] for t in results),
        "planned_tasks":len(results), "public_generated_task_runs":0, "task_success_rate":None,
        "scope":"Initial kernel-configuration subset; no claim of a complete generative OS benchmark or calibrated universal difficulty."}


def constraint_oracle(task, image_sizes, candidate_counts, reference_counts, *, resolved_configs=None):
    """Use original units; inputs must be supplied by image/raw-capture auditors."""
    if set(image_sizes) != set(task["workloads"]) or set(candidate_counts) != set(task["workloads"]):
        raise ValueError("Missing task workload evidence")
    checks = []
    required = task.get("required_config", {})
    if required or len(task["workloads"]) > 1 or resolved_configs is not None:
        if resolved_configs is None or set(resolved_configs) != set(task["workloads"]) or any(
                not isinstance(c,dict) or not c or any(type(k) is not str or type(v) is not str for k,v in c.items())
                for c in resolved_configs.values()):
            raise ValueError("Resolved OS configurations are required for the complete task")
        fingerprints = {json.dumps(c,sort_keys=True) for c in resolved_configs.values()}
        checks.append({"gate":"shared_resolved_OS_configuration", "pass":len(fingerprints) == 1})
        for case, config in resolved_configs.items():
            for option, expected in required.items():
                checks.append({"case":case,"gate":"required_configuration", "option":option,
                    "expected":expected,"actual":config.get(option),"pass":config.get(option) == expected})
    for case in task["workloads"]:
        if type(image_sizes[case]) is not int or image_sizes[case] <= 0:
            raise ValueError("Invalid measured image size")
        values = candidate_counts[case]
        if len(values) != 3 or any(type(v) not in (int,float) or not math.isfinite(v) or v <= 0 for v in values):
            raise ValueError("Three independent valid reset-level counts required")
        if "application_image_bytes" in task["constraints"]:
            limit = task["constraints"]["application_image_bytes"]
            checks.append({"case":case, "metric":"application_image_bytes", "actual":image_sizes[case],
                           "limit":limit, "pass":image_sizes[case] <= limit})
        if "minimum_reference_throughput_ratio" in task["constraints"]:
            baseline = reference_counts[case]
            if len(baseline) != 3 or any(type(v) not in (int,float) or not math.isfinite(v) or v <= 0 for v in baseline):
                raise ValueError("Invalid fixed-reference counts")
            threshold = statistics.median(baseline)*task["constraints"]["minimum_reference_throughput_ratio"]
            checks.append({"case":case, "metric":"original_count_30s", "actual":statistics.median(values),
                           "limit":threshold, "pass":statistics.median(values) >= threshold})
    return {"pass":all(c["pass"] for c in checks), "checks":checks,
            "boundary":"Resolved-configuration and constraint checks on audited inputs; not image, generation-origin, functional or hardware admission."}


def summarize_accounting(runs):
    """Numerical reducer for benchmark-audited run receipts, not a receipt validator."""
    stages = ("generated", "built", "booted", "functional", "constraints")
    for run in runs:
        if any(type(run[k]) is not bool for k in ("applicable", "infrastructure_invalid", "timed_out")):
            raise ValueError("Run classification requires boolean flags")
    eligible = [r for r in runs if r["applicable"] and not r["infrastructure_invalid"]]
    success, elapsed, successes = 0, [], []
    passed = {k:0 for k in stages}
    for run in eligible:
        time = run["observed_wall_s"]
        if type(time) not in (int,float) or not math.isfinite(time) or time < 0:
            raise ValueError("Invalid observed wall time")
        budget = run["budget_wall_s"]
        if type(budget) not in (int,float) or not math.isfinite(budget) or budget <= 0:
            raise ValueError("Invalid wall-time budget")
        flags = [run["gates"][k] for k in stages]
        if any(type(v) is not bool and v is not None for v in flags) or any(v is True and any(p is not True for p in flags[:i]) for i,v in enumerate(flags)):
            raise ValueError("Impossible stage chronology")
        for k in stages:
            passed[k] += run["gates"][k] is True
        ok = all(v is True for v in flags) and not run["timed_out"] and time <= budget
        success += ok
        elapsed.append(time)
        if ok:
            successes.append(time)
    n = len(eligible)
    interval = None
    if n:
        z, p = 1.959963984540054, success/n
        center = (p+z*z/(2*n))/(1+z*z/n)
        half = z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/(1+z*z/n)
        interval = [max(0,center-half),min(1,center+half)]
    return {"registered_runs":len(runs), "applicable_runs":n, "successful_runs":success, "success_rate":success/n if n else None,
        "wilson_95_interval":interval, "unconditional_stage_success_rates":{k:passed[k]/n if n else None for k in stages},
        "successful_completion_median_s":statistics.median(successes) if successes else None,
        "successful_completion_range_s":[min(successes),max(successes)] if successes else None,
        "all_applicable_observed_duration_s":elapsed, "p95_s":None,
        "infrastructure_invalid_runs":sum(r["applicable"] and r["infrastructure_invalid"] for r in runs),
        "not_applicable_runs":sum(not r["applicable"] for r in runs),
        "boundary":"Accounting of already-audited receipts; does not authenticate or admit caller-supplied outcomes."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    from iotos_evolution import audited_inventory
    inventory=audited_inventory()
    result = reference_qualification(inventory["baseline_records"],manual=(inventory["fixed_reference_validation"] or {}).get("reference_records",()))
    path = ROOT / "artifacts/reports/iotos-task-bank-v1.json"
    if args.check:
        if result != json.loads(path.read_text()):
            raise ValueError("Task reference report is stale")
    else:
        path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"audit":"pass", "admitted_tasks":result["admitted_tasks"],
                      "planned_tasks":result["planned_tasks"], "new_generated_runs":0},indent=2))
