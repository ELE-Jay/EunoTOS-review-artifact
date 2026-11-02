#!/usr/bin/env python3
"""Reuse audited baselines and inspect submitted histories; never run an optimizer."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import shutil
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "registry/iotos_evolution_v1.json"
REPORT = "artifacts/reports/esp32-generative-reuse-v1.json"
SNAPSHOT = "artifacts/reports/esp32-benchmark-v1.json"
V1_BASELINE_CASES = frozenset(("message_processing", "cooperative_scheduling", "preemptive_scheduling",
    "synchronization_processing", "interrupt_processing", "interrupt_preemption_processing"))


def admitted_kernel_groups(groups):
    return [g for g in groups if g["case"] in V1_BASELINE_CASES and g["cells"] and
            all(c.get("comparison_eligible") is True for c in g["cells"])]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_ref(path, root=ROOT):
    path = path.resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Evidence is missing or outside its artifact root")
    return {"path": path.relative_to(root.resolve()).as_posix(), "sha256": digest(path)}


def check_ref(ref, root):
    actual = file_ref(root / ref["path"], root)
    if actual != ref:
        raise ValueError("Evidence path or SHA-256 differs: " + ref["path"])
    return root / ref["path"]


def expanded_tenon_summary(root=ROOT):
    reports = root / "artifacts/reports"
    native = reports / "tenonos-expanded-numeric-native-audit-v1.json"
    if not native.exists():
        return None
    from audit_tenonos_expanded_tasks import inventory, bind
    pipeline = reports / "tenonos-expanded-numeric-pipeline-v1"
    campaign = reports / "tenonos-expanded-numeric-campaign-v1"
    index = reports / "tenonos-expanded-numeric-behavior-inventory-v1.json"
    binding = reports / "tenonos-expanded-numeric-behavior-binding-v1.json"
    if inventory(root, pipeline, campaign, native) != load(index) or bind(root, index) != load(binding):
        raise ValueError("Expanded task evidence or behavioral qualification differs")
    checked, qualified = load(native), load(binding)
    rows = []
    for group in checked["runtime_audit"]["groups"]:
        account = group["accounting"]
        n = account["applicable_runs"]
        prefix = group["task"] + "-"
        successes = sum(r["qualified_task_pass"] for r in qualified["rows"]
                        if r["trial"].startswith(prefix) and r["trial"].endswith("-" + group["method"]))
        rows.append({"task": group["task"], "method": group["method"], "n": n,
                     "valid": round(account["unconditional_stage_success_rates"]["generated"] * n),
                     "runtime": round(account["unconditional_stage_success_rates"]["functional"] * n),
                     "qualified": successes, "all_attempt_median_s": group["observed_wall_median_s"]})
    energy = None
    energy_folder = reports / "tenonos-expanded-generated-energy-v1"
    if (energy_folder / "audit.json").exists():
        from audit_tenonos_energy import audit as energy_audit
        result = energy_audit(energy_folder, root)
        if result != load(energy_folder / "audit.json"):
            raise ValueError("Expanded generated-image energy differs")
        energy = {k: result[k] for k in ("summary", "activation_trials", "fresh_guest_boots", "boundary", "interpretation")}
        energy["evidence"] = file_ref(energy_folder / "audit.json", root)
    ram = None
    ram_folder = reports / "tenonos-expanded-allocated-rpi4-v1"
    if (ram_folder / "allocated-occupancy.json").exists():
        from measure_tenonos_expanded_ram import audit as allocated_audit
        measured = allocated_audit(ram_folder)
        if measured != load(ram_folder / "allocated-occupancy.json"):
            raise ValueError("Expanded allocated-occupancy evidence differs")
        ram = {"scope":measured["scope"], "profiles":[{
            "profile":p["profile"], "peak_allocated_occupancy_bytes":p["peak_allocated_occupancy_bytes"],
            "resident_reserved_bytes":p["peak"]["resident_reserved_bytes"],
            "allocator_metadata_reserved_bytes":p["peak"]["allocator_metadata_reserved_bytes"],
            "allocated_block_bytes":p["peak"]["allocated_block_bytes"],
            "lifecycle_events":p["lifecycle_events"],
            "generated_image_sha256":p["generated_image_sha256"], "observer_image_sha256":p["image_sha256"],
            "actual_stack_use_measured":p["actual_stack_use_measured"]} for p in measured["profiles"]],
            "observer_guests":measured["new_guests_in_observer_campaign"],
            "diagnostic_guests":measured["new_guests_in_supporting_captures"],
            "evidence":file_ref(ram_folder / "allocated-occupancy.json", root)}
    return {"registered_trials": checked["registered_trials"], "model_calls": checked["model_attempts"],
            "output_tokens": checked["completion_tokens"], "fresh_guest_captures": checked["raw_guest_captures"],
            "reused_behavior_guests": qualified["reused_behavior_guests"], "rows": rows,
            "distinct_runtime_configurations": load(index)["distinct_runtime_configurations"],
            "energy": energy, "evidence": file_ref(native, root), "behavior_evidence": file_ref(binding, root),
            "ram":ram,
            "ram_status": ("Matched observer allocated occupancy measured; actual stack use separate and unmeasured."
                           if ram else "New candidate complete allocated RAM not measured; historical reference peaks not reassigned."),
            "scope": "Additional tasks of the independent Tenon reconstruction, not author-engine, new OS or broad 18-task coverage."}


def joint_tenon_summary(root=ROOT):
    reports = root / 'artifacts/reports'
    path = reports / 'tenonos-joint-qualified-v1.json'
    if not path.exists():
        return None
    from audit_tenonos_joint_tasks import bind
    from tenonos_size_memory import audit as memory_audit
    from replay_tenonos_joint_energy import audit as energy_audit
    ram_folder = reports / 'tenonos-joint-candidates-allocated-rpi4-v2'
    result = bind(reports / 'tenonos-joint-candidate-behavior-rpi4-v1', ram_folder)
    if result != load(path):
        raise ValueError('Joint task admission differs from retained evidence')
    native = load(reports / 'tenonos-joint-resource-native-audit-v3.json')
    rows = []
    for group in native['runtime_audit']['groups']:
        account = group['accounting']; n = account['applicable_runs']
        qualified = next(r for r in result['groups'] if r['method'] == group['method'])
        if n != qualified['n']:
            raise ValueError('Joint task denominator differs')
        rows.append({'method':group['method'], 'n':n,
            **{key:round(account['unconditional_stage_success_rates'][stage]*n)
               for key,stage in (('valid','generated'),('built','built'),('runtime','functional'))},
            'qualified':qualified['joint_passes']})
    memory = memory_audit(ram_folder)
    if memory != load(ram_folder / 'allocated-occupancy.json'):
        raise ValueError('Joint task allocated RAM differs')
    profiles = [{'profile':p['profile'], 'peak_allocated_occupancy_bytes':p['peak_allocated_occupancy_bytes'],
        **{key:p['peak'][key] for key in ('resident_reserved_bytes','allocator_metadata_reserved_bytes','allocated_block_bytes')},
        'lifecycle_events':p['lifecycle_events'], 'actual_stack_use_measured':p['actual_stack_use_measured']}
        for p in memory['profiles']]
    energy_path = reports / 'tenonos-joint-generated-energy-independent-v1.json'
    energy = energy_audit()
    if energy != load(energy_path):
        raise ValueError('Joint generated-image energy differs')
    return {'registered_trials':result['registered_trials'], 'model_calls':result['model_calls'],
        'output_tokens':result['completion_tokens'], 'original_guests':result['new_original_guest_captures'],
        'rows':rows, 'distinct_qualified_configurations':result['distinct_qualified_configurations'],
        'ram':{'profiles':profiles, 'evidence':file_ref(ram_folder / 'allocated-occupancy.json',root)},
        'energy':{**{key:energy[key] for key in ('summary','activation_trials','fresh_guest_boots','boundary','calibration')},
                  'evidence':file_ref(energy_path,root)},
        'evidence':file_ref(path,root),
        'scope':'One joint resource task, five fresh requests per branch. Allocated RAM includes matched observer storage; '
            'actual stack use is separate. Post-generation resource qualification is outside native online latency. '
            'Energy is whole-Pi activation, not cloud inference or an OS ranking.'}


def complete_resource_tenon_summary(root=ROOT):
    reports=root/'artifacts/reports'
    path=reports/'tenonos-complete-resource-audit-v1.json'
    if not path.exists():
        return None
    from audit_tenonos_complete_resource import audit as completion_audit
    from tenonos_complete_resource import BASE
    previous=sys.path[:]
    try:
        sys.path.insert(0,str(root/BASE))
        value=completion_audit(reports/'tenonos-complete-resource-plan-v1',
                               reports/'tenonos-complete-resource-campaign-v1')
    finally:
        sys.path[:]=previous
    if value!=load(path):
        raise ValueError('Resource-verified completion evidence differs')
    return {key:value[key] for key in ('registered_trials','model_calls','output_tokens','original_guests',
        'new_resource_guests','distinct_new_profiles','premeasured_profiles','setup_catalog_s','groups','scope')} | {
            'evidence':file_ref(path,root)}


def resource_history_tenon_summary(root=ROOT):
    reports=root/'artifacts/reports'
    path=reports/'tenonos-resource-history-audit-v1.json'
    if not path.exists():
        return None
    from replay_tenonos_resource_histories import evaluate, PLAN
    pipeline=root/PLAN/'pipeline'
    names=[p.stem for p in pipeline.glob('*.py')]
    modules={name:sys.modules.pop(name,None) for name in names}
    previous=sys.path[:]
    try:
        sys.path.insert(0,str(pipeline))
        value=evaluate()
    finally:
        sys.path[:]=previous
        for name,module in modules.items():
            sys.modules.pop(name,None)
            if module is not None:sys.modules[name]=module
    if value!=load(path):
        raise ValueError('Prospective resource-history evidence differs')
    spec=load(root/'registry/tenonos_resource_histories_v1.json')
    limits=[r['maximum_ram_bytes'] for r in spec['rounds']]
    groups=[dict(g,final_constraint_passes=sum(h['retained_allocation_bytes'][-1]<=limits[-1]
        for h in value['histories'] if h['method']==g['method']),
        histories=sum(h['method']==g['method'] for h in value['histories'])) for g in value['groups']]
    return {key:value[key] for key in ('registered_histories','registered_rounds','histories','model_calls',
        'output_tokens','original_guests','parent_check_guests','new_resource_guests','distinct_new_profiles','scope')} | {
            'groups':groups,'round_ram_limits_bytes':limits,'evidence':file_ref(path,root)}


def baseline_inventory(data, view, root=ROOT):
    """Input view must come from publication_view's source/raw-data reaudits."""
    protocol = load(root / PROTOCOL)
    records = []
    groups = [{"evidence": "artifacts/reports/esp32-message-cohort-b1-v1", **view["b1_message"]}]
    groups += admitted_kernel_groups(view["b1_kernel"]["groups"])
    groups += [view["b1_energy"], *view["b1_kernel_energy"]]
    proofs = {}
    for group in groups:
        if not group:
            continue
        energy = group.get("energy_measured", False)
        folder = root / group["evidence"]
        campaign = load(folder / "campaign.json")
        for cell in group["cells"]:
            build = folder / cell["os"] / "build"
            if not energy:
                proofs[cell["os"], cell["case"]] = file_ref(folder / cell["os"] / "source-proof.json", root)
            proof = proofs[cell["os"], cell["case"]]
            artifact = file_ref(build / "application.bin", root)
            images = [file_ref(p, root) for p in sorted(build.iterdir()) if p.is_file()]
            if energy:
                metric = "energy_per_original_count_uj"
                values = [r["paired"][metric] for r in cell["runs"]]
            else:
                metric, values = "original_count_30s", cell["values"]
            contract = protocol["runtime_metrics"][metric]
            if len(values) != protocol["minimum_independent_resets"] or any(
                    not isinstance(v, (float, int)) or isinstance(v, bool) or not math.isfinite(v) or v <= 0 for v in values):
                raise ValueError("Incomplete reset-level baseline")
            records.append({"id": folder.name + "/" + cell["os"], "origin": "fixed_configuration",
                "os": cell["os"], "case": cell["case"], "metric": metric,
                "unit": contract["unit"], "direction": contract["direction"],
                "board": group["board"], "board_mac": group["board_mac"],
                "comparison_group": "B1/240MHz/one-core/100Hz/GCC13/" + cell["case"] + "/" + metric,
                "values": values, "median": statistics.median(values), "range": [min(values), max(values)],
                "independent_resets": len(values), "artifact": artifact, "installed_images": images,
                "source_proof": proof, "config_sha256": load(root / proof["path"])["config_sha256"],
                "audit": file_ref(folder / "audit.json", root),
                "manifest": file_ref(folder / "campaign.json", root),
                "acquired_utc": [campaign["started_utc"], campaign["completed_utc"]],
                "reuse_as": "traditional baseline; not a generated candidate or an evolution round",
                "boundary": ("Observed same-board energy/count comparison; instrument calibration and conversion latency unverified."
                    if energy else "Original workload count, not an isolated API or interrupt-entry latency.")})
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("Duplicate baseline identity")
    states = Counter(r["kind"] for r in view["rows"])
    subjects_path = root / "artifacts/reports/iotos-generative-subjects-v1.json"
    subjects = load(subjects_path)
    check_ref(subjects["registry"], root)
    tenonos_path = root / "artifacts/reports/tenonos-candidate-audit-v1.json"
    tenonos = load(tenonos_path)
    if tenonos["registry_sha256"] != digest(root / "registry/tenonos_candidate_v1.json") or tenonos["runtime_measurements"] != 0 or tenonos["ranking_eligible"]:
        raise ValueError("TenonOS source-only task qualification differs")
    control = root / "artifacts/reports/esp32-evolution-build-control-v1"
    from build_esp32_evolution_candidate import audit_control
    build_control = audit_control(control)
    if load(control / "task/job.json")["protocol_sha256"] != digest(root / PROTOCOL):
        raise ValueError("MCU task bundle uses an outdated protocol")
    reference_folder=root/"artifacts/reports/esp32-task-reference-b1-v1"
    reference_validation=None
    if (reference_folder/"campaign.json").is_file():
        from run_esp32_task_references import audit as audit_references
        reference_validation=audit_references(reference_folder,root)
    from iotos_task_benchmark import reference_qualification
    tasks=reference_qualification(records,root,reference_validation["reference_records"] if reference_validation else ())
    independent = {"tenon": None, "esp32": None, "esp32_tasks": [], "esp32_sequences": None, "esp32_holdout": None}
    tenon_runs = root / "artifacts/reports/tenonos-rpi4-v1/formal-v1"
    if (tenon_runs / "audit.json").is_file():
        from audit_tenonos_tasks import audit as audit_tenon_tasks
        independent["tenon"] = json.loads(json.dumps(audit_tenon_tasks(
            root / "registry/tenonos_tasks_rpi4_v1.json", tenon_runs,
            root / "artifacts/reports/tenonos-rpi4-v1/rtos-graph/graph.json")))
        if independent["tenon"] != load(tenon_runs / "audit.json"):
            raise ValueError("Independent Tenon configuration records differ from their raw replay")
    for task in tasks["tasks"]:
        version = "v2" if task["id"] in {"A2", "C2"} else "v1"
        esp32_runs = root / ("artifacts/reports/esp32-generated-" + task["id"].lower() + "-" + version)
        if (esp32_runs / "audit.json").is_file():
            from run_esp32_generated_task import audit as audit_generated_esp32
            measured = audit_generated_esp32(esp32_runs)
            if measured != load(esp32_runs / "audit.json"):
                raise ValueError("Independent ESP32 configuration records differ from their raw replay")
            registration = load(esp32_runs / "registration.json")
            independent["esp32_tasks"].append({"report": measured, "evidence": file_ref(esp32_runs / "audit.json", root),
                "timing": {"online_requirement_check": bool(registration.get("online_oracle")),
                    "completion_boundary": registration["completion_time"],
                    "registration": file_ref(esp32_runs / "registration.json", root)}})
            if task["id"] == "B1":
                independent["esp32"] = measured
    measured_trials = [t for group in independent["esp32_tasks"] for t in group["report"]["trials"]
                       if t["gates"]["functional"]]
    different_outputs = {tuple(sorted(t["options"].items())) for t in measured_trials}
    sequence_folder = root / "artifacts/reports/esp32-policy-sequence-v1"
    if (sequence_folder / "audit.json").is_file():
        from run_esp32_policy_sequence import audit as audit_sequence
        sequence = audit_sequence(sequence_folder)
        if sequence != load(sequence_folder / "audit.json"):
            raise ValueError("State-linked configuration history differs from its raw replay")
        independent["esp32_sequences"] = {"report": sequence,
            "evidence": file_ref(sequence_folder / "audit.json", root),
            "registration": file_ref(sequence_folder / "registration.json", root)}
    else:
        sequence = None
    held_out_folder=root/"artifacts/reports/esp32-policy-holdout-v1"
    held_out=None
    if (held_out_folder/"audit.json").is_file():
        from run_esp32_policy_holdout import audit as audit_held_out
        from audit_esp32_policy_trajectory import audit as audit_trajectory
        held_out=audit_held_out(held_out_folder)
        contrast=audit_trajectory(held_out_folder)
        if held_out!=load(held_out_folder/"audit.json") or contrast!=load(root/"artifacts/reports/esp32-policy-trajectory-contrast-v1.json"):
            raise ValueError("Prospective held-out/trajectory evidence differs from raw replay")
        independent["esp32_holdout"]={"report":held_out,"contrast":contrast["experiments"][-1],
            "evidence":file_ref(held_out_folder/"audit.json",root),
            "registration":file_ref(held_out_folder/"registration.json",root)}
    sequences=([sequence] if sequence else [])+([held_out["sequence"]] if held_out else [])
    paired = None
    paired_root = root / "artifacts/reports/tenonos-author-engine-20261027-v1"
    paired_audit = paired_root / "paired-v4-task-audit-v2.json"
    if paired_audit.exists():
        checked = load(paired_audit)
        campaign = paired_root / "paired-v4-campaign-v2"
        if not checked["generation_interface_admissible"] or not checked["runtime_audit"]["registered_task_outcomes_audited"]:
            raise ValueError("Paired Tenon task evidence has not passed replay")
        for name, expected in checked["campaign_evidence_manifest"].items():
            path = (campaign / name).resolve()
            path.relative_to(campaign.resolve())
            if digest(path) != expected:
                raise ValueError("Paired Tenon evidence changed: " + name)
        paired = {"model": checked["actual_model"], "trials": checked["registered_trials"],
                  "model_calls": checked["model_attempts"], "completion_tokens": checked["completion_tokens"],
                  "guest_captures": checked["runtime_audit"]["raw_guest_captures"],
                  "rows": [{"task": g["task"], "method": g["method"],
                            "n": g["accounting"]["applicable_runs"],
                            "stages": {k: round(v * g["accounting"]["applicable_runs"])
                                       for k, v in g["accounting"]["unconditional_stage_success_rates"].items()},
                            "successes": g["accounting"]["successful_runs"]}
                           for g in checked["runtime_audit"]["groups"]],
                  "evidence": file_ref(paired_audit, root), "author_engine": False,
                  "whole_ram_peak_measured": False, "new_energy_measured": False}
    budget_sensitivity = None
    budget_audit = paired_root / "budget-v4-sensitivity-audit-v1.json"
    if budget_audit.exists():
        from audit_tenonos_budget_sensitivity import audit as audit_budget
        checked = audit_budget(root, paired_root / "budget-sensitivity-pipeline-v2",
                               paired_root / "budget-v4-campaign-v1", paired_root / "budget-v4-task-audit-v1.json")
        if checked != load(budget_audit):
            raise ValueError("Tenon budget sensitivity differs from its independent replay")
        budget_sensitivity = {k: checked[k] for k in ("model", "registered_trials", "aggregate_output_cap",
            "graph_stage_caps", "model_calls", "completion_tokens", "raw_guest_captures", "finish_reasons")}
        budget_sensitivity["rows"] = [{"task": g["task"], "method": g["method"],
            "n": g["accounting"]["applicable_runs"], "successes": g["accounting"]["successful_runs"],
            "runtime_passes": round(g["accounting"]["unconditional_stage_success_rates"]["functional"] *
                                    g["accounting"]["applicable_runs"]),
            "observed_wall_median_s": g["observed_wall_median_s"],
            "successful_completion_median_s": g["accounting"]["successful_completion_median_s"]}
            for g in checked["groups"]]
        budget_sensitivity["evidence"] = file_ref(budget_audit, root)
    paired_histories = None
    sequence_audit = paired_root / "policy-sequence-audit-v1.json"
    if sequence_audit.exists():
        checked = load(sequence_audit)
        sequence_root = paired_root / "policy-sequence-v1"
        if checked["audit"] != "pass" or checked["registered_histories"] != 6 or checked["registered_rounds"] != 12:
            raise ValueError("Tenon history audit is incomplete")
        for name, expected in checked["evidence_manifest"].items():
            p = (sequence_root / name).resolve()
            p.relative_to(sequence_root.resolve())
            if digest(p) != expected:
                raise ValueError("Tenon history bytes changed: " + name)
        paired_histories = {"model": checked["model"], "histories": checked["histories"],
            "registered_histories": checked["registered_histories"], "registered_rounds": checked["registered_rounds"],
            "model_calls": checked["model_calls"], "completion_tokens": checked["completion_tokens"],
            "candidate_guest_captures": checked["candidate_guest_captures"],
            "parent_check_guest_captures": checked["parent_check_guest_captures"],
            "evidence": file_ref(sequence_audit, root), "author_engine": False, "rsi": False}
    native_threads = None
    thread_report=root/'artifacts/reports/tenonos-native-threads-rpi4-v2/audit.json'
    if thread_report.exists():
        from audit_tenonos_memory_lifecycle import audit as thread_audit
        from audit_tenonos_native_threads import summary as thread_summary
        checked=thread_audit(root,thread_report.parent,native_threads=True)
        if checked!=load(thread_report):raise ValueError('Native thread lifecycle changed')
        native_threads={**thread_summary(checked),'evidence':file_ref(thread_report,root)}
    memory_impact = None
    impact_report=root/'artifacts/reports/tenonos-memory-impact-rpi4-v1/audit.json'
    if impact_report.exists():
        from audit_tenonos_memory_impact import audit as impact_audit,bind_histories
        checked=impact_audit(root,impact_report.parent)
        if checked!=load(impact_report):raise ValueError('Native memory-observer impact changed')
        memory_impact={**checked,'evidence':file_ref(impact_report,root)}
        binding=root/'artifacts/reports/tenonos-repaired-profile-binding-v1.json'
        linked=bind_histories(root)
        if linked!=load(binding):raise ValueError('Repaired-state reuse changed')
        memory_impact['binding']={k:v for k,v in linked.items() if k!='aliases'}
        memory_impact['binding']['evidence']=file_ref(binding,root)
    allocated_ram = None
    allocated_report = root/'artifacts/reports/tenonos-allocated-occupancy-rpi4-v1.json'
    if allocated_report.exists():
        from audit_tenonos_allocated_ram import audit as allocated_audit, summary as allocated_summary
        checked = allocated_audit(root)
        if checked != load(allocated_report):
            raise ValueError('Allocated guest RAM differs from native replay')
        allocated_ram = {**allocated_summary(checked), 'evidence':file_ref(allocated_report,root)}
    ram_histories = None
    ram_history_report = root/'artifacts/reports/tenonos-allocated-history-profiles-v1.json'
    if ram_history_report.exists():
        from audit_tenonos_allocated_ram import trajectory_audit, trajectory_summary
        checked = trajectory_audit(root)
        if checked != load(ram_history_report):
            raise ValueError('Accepted-history reference RAM profiles changed')
        ram_histories = {**trajectory_summary(checked),'evidence':file_ref(ram_history_report,root)}
    repaired_histories = None
    repair_report = paired_root / 'policy-choice-audit-v1.json'
    if repair_report.exists():
        from tenonos_choice_adapter import audit as audit_choice_adapter
        checked = audit_choice_adapter(root, paired_root/'policy-choice-pipeline-v1',
            paired_root/'policy-choice-campaign-v1', paired_root/'policy-choice-native-audit-v1.json', None)
        if checked != load(repair_report):
            raise ValueError('Repaired fragment histories differ from native/raw replay')
        repaired_histories = {**checked, 'evidence':file_ref(repair_report,root)}
    budget_histories = None
    policy_budget_audit = paired_root / "policy-budget-audit-v1.json"
    if policy_budget_audit.exists():
        from audit_tenonos_policy_budget import audit as audit_policy_budget
        checked = audit_policy_budget(root, paired_root / "policy-budget-pipeline-v1",
                                      paired_root / "policy-budget-campaign-v1", paired_root / "policy-budget-native-audit-v1.json")
        if checked != load(policy_budget_audit):
            raise ValueError("Larger-budget Tenon histories differ from independent replay")
        budget_histories = {k: checked[k] for k in ("model", "histories", "groups", "registered_histories", "registered_rounds",
            "model_calls", "completion_tokens", "finish_reasons", "candidate_guest_captures", "parent_check_guest_captures",
            "aggregate_output_cap", "graph_stage_caps", "inherited_tlsf_choice_conflict_rounds")}
        budget_histories["evidence"] = file_ref(policy_budget_audit, root)
        binding = paired_root / "policy-budget-scale-binding-v1.json"
        if binding.exists():
            from bind_tenonos_policy_scale import bind as bind_scale
            linked = bind_scale(root, paired_root / "policy-budget-pipeline-v1", paired_root / "policy-budget-campaign-v1",
                                paired_root / "policy-budget-native-audit-v1.json", root / "artifacts/reports/tenonos-rpi4-scale-validation-v2")
            if linked != load(binding) or not linked["pass"]:
                raise ValueError("Retained-history scale reuse is incomplete or changed")
            budget_histories["scale_reuse"] = {k: linked[k] for k in ("retained_state_aliases", "distinct_configurations",
                "reused_guest_boots", "new_guest_boots", "external_workload_spec_frozen_before_this_generation")}
            budget_histories["scale_reuse"]["evidence"] = file_ref(binding, root)
    tenon_energy = None
    energy_folder = root / "artifacts/reports/tenonos-rpi4-activation-energy-v1"
    if (energy_folder / "audit.json").is_file():
        from audit_tenonos_energy import audit as audit_tenon_energy
        checked = audit_tenon_energy(energy_folder, root)
        if checked != load(energy_folder / "audit.json"):
            raise ValueError("Pi activation energy differs from signed-packet and guest replay")
        tenon_energy = {**checked, "evidence": file_ref(energy_folder / "audit.json", root)}
    tenon_build_energy = None
    build_energy_folder = root / "artifacts/reports/tenonos-rpi4-build-energy-v1"
    if (build_energy_folder / "audit.json").is_file():
        from audit_tenonos_build_energy import audit as audit_build_energy
        checked = audit_build_energy(root, build_energy_folder)
        if checked != load(build_energy_folder / "audit.json"):
            raise ValueError("Pi native-build energy differs from signed packets and build/guest replay")
        tenon_build_energy = {**checked, "evidence": file_ref(build_energy_folder / "audit.json", root)}
    tenon_scale = None
    scale_folder = root / "artifacts/reports/tenonos-rpi4-scale-validation-v2"
    if (scale_folder / "audit.json").is_file():
        from audit_tenonos_scale_validation import audit as audit_tenon_scale
        checked = audit_tenon_scale(scale_folder, root)
        if checked != load(scale_folder / "audit.json"):
            raise ValueError("Tenon scale validation differs from source, configuration and guest replay")
        tenon_scale = {**checked, "evidence": file_ref(scale_folder / "audit.json", root)}
    tenon_memory = None
    memory_folder = root / "artifacts/reports/tenonos-rpi4-native-memory-v3"
    if (memory_folder / "audit.json").is_file():
        from audit_tenonos_memory import audit as audit_tenon_memory
        checked = audit_tenon_memory(root, memory_folder)
        if checked != load(memory_folder / "audit.json"):
            raise ValueError("Tenon native memory differs from source/image/guest replay")
        tenon_memory = {k: checked[k] for k in ("pass", "fresh_guests", "model_calls", "scope",
                                               "whole_live_ram_peak_bytes", "ranking_eligible")}
        tenon_memory["profiles"] = [{k: p[k] for k in ("profile", "fresh_guests", "native_allocator_peaks_bytes",
            "median_native_allocator_peak_bytes", "writable_static_load", "statistic", "image_sha256", "ranking_eligible")}
                                    for p in checked["profiles"]]
        tenon_memory["evidence"] = file_ref(memory_folder / "audit.json", root)
        lifecycle = root / "artifacts/reports/tenonos-sem-lifecycle-scope-v1.json"
        if lifecycle.exists():
            from audit_tenonos_sem_lifecycle import audit as audit_lifecycle
            checked_lifecycle = audit_lifecycle(root, memory_folder)
            if checked_lifecycle != load(lifecycle):
                raise ValueError("Tenon semaphore lifecycle scope differs from compiled/source evidence")
            tenon_memory["semaphore_lifecycle"] = {"delete_releases_storage": False,
                "normal_test_path_requests_delete": False, "evidence": file_ref(lifecycle, root)}
    return {"schema": "iotos-generative-reuse-v1", "protocol": file_ref(root / PROTOCOL, root),
        "execution": protocol["execution"],
        "mcu_build_control": {**build_control, "evidence": file_ref(control / "control-build-metadata-aligned/build-result.json", root)},
        "subject_catalog": {"evidence": file_ref(subjects_path, root), **subjects},
        "tenonos_candidate_audit": {"evidence":file_ref(tenonos_path, root), **tenonos},
        "historical_snapshot": {**file_ref(root / SNAPSHOT, root), "rows": len(data["rows"]),
            "classification": dict(sorted(states.items())),
            "reuse": "Existing B0 contracts only; keep native configurations, diagnostics and pending rows separate."},
        "baseline_records": records,
        "fixed_reference_validation":reference_validation,
        "task_bank":tasks,
        "independent_configuration_baselines": independent,
        "paired_tenon_reconstruction": paired,
        "tenon_budget_sensitivity": budget_sensitivity,
        "paired_tenon_histories": paired_histories,
        "tenon_budget_histories": budget_histories,
        "tenon_repaired_histories": repaired_histories,
        "tenon_memory_impact": memory_impact,
        "tenon_allocated_ram": allocated_ram,
        "tenon_ram_histories": ram_histories,
        "tenon_native_threads": native_threads,
        "tenon_activation_energy": tenon_energy,
        "tenon_build_energy": tenon_build_energy,
        "tenon_scale_validation": tenon_scale,
        "tenon_native_memory": tenon_memory,
        "tenon_expanded_tasks": expanded_tenon_summary(root),
        "tenon_joint_task": joint_tenon_summary(root),
        "tenon_complete_resource": complete_resource_tenon_summary(root),
        "tenon_resource_histories": resource_history_tenon_summary(root),
        "summary": {"b1_performance_cells": sum(r["metric"] == "original_count_30s" for r in records),
            "b1_energy_cells": sum(r["metric"] == "energy_per_original_count_uj" for r in records),
            "reused_b1_resets": sum(r["independent_resets"] for r in records),
            "new_board_resets": reference_validation["independent_resets"] if reference_validation else 0,
            "fixed_reference_resets":reference_validation["independent_resets"] if reference_validation else 0,
            "generated_candidates_measured": 0,
            "generated_candidates_measured_scope": "Complete author-published IoT-OS generation engines; independent configuration baselines are counted separately.",
            "evolution_histories_measured": sum(q["registered_histories"] for q in sequences),
            "sequence_model_calls": sum(q["registered_model_calls"] for q in sequences),
            "sequence_generated_physical_resets": sum(q["generated_physical_resets"] for q in sequences),
            "independent_generated_configurations_measured": len(different_outputs),
            "independent_generated_physical_resets": sum(3 * len(t.get("workloads", (None,))) for t in measured_trials)},
        "experiments": [
            {"id": "E1", "state": "partial", "available": "Audited traditional OS baselines, workload-specific contracts and same-board independent generated-configuration tasks with source-bound runtime and requirement checks.",
             "missing": "Broader callable public OS-generation systems. Imported Linux configurations and IoT application artifacts do not supply comparable ESP32 OS-policy measurements."},
            {"id": "E2", "state": "measured" if held_out else "partial" if sequence else "pending",
             "available": ("Two separate real-history campaigns, with prospective external IRQ evaluation and endpoint/trajectory cost contrast; unchanged policies are shared, not counted as independent improvements."
                           if held_out else "Prospective physical two-round policy-update histories with actual retained parents, all model calls, native requirements, image verification and cumulative costs."
                           if sequence else "Offline history validator and cost/endpoint reporting."),
             "missing": ("No distinct resolved policy or generalization gain in this registered batch; broader generation-system coverage is future work, not an assumed RSI result."
                         if held_out else "Autonomous adaptation, held-out workloads and changes to an improver are not exercised by this externally requested configuration-update sequence."
                         if sequence else "A real chronological history including all attempts, failures, baseline and deployed artifacts; no historical search log or held-out evaluation is invented.")},
            {"id": "E3", "state": "partial", "available": "ESP32 raw captures, image verification, reset repeats, clean rebuilds and offline record replay on two hosts.",
             "missing": "External physical replication; QEMU-to-ESP32 matched experiment if that claim is retained. Prior MPS2 QEMU checks establish automation, not ESP32 timing or energy."}],
        "ram": {"status": "正在测", "included_in_score": False}, "composite_score": None,
        "new_metric_created": False, "optimizer_implemented": False,
        "historical_data_modified": False, "generated_results_inferred_from_repairs": False}


def number(value, name, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("Invalid nonnegative accounting value: " + name)
    if integer and not isinstance(value, int):
        raise ValueError("Integer accounting value required: " + name)
    return value


def timestamp(value):
    time = datetime.fromisoformat(value)
    if time.tzinfo is None:
        raise ValueError("Timezone required")
    return time


def review_trace(trace, inventory, root=ROOT):
    """Check a complete submitted chain against benchmark-owned measurements.

    This is an evidence inspector, not a source-semantic audit or model-log
    authentication service. New firmware needs a benchmark-owned audit adapter.
    """
    protocol = load(check_ref(inventory["protocol"], root))
    if set(trace) != {"schema", "protocol_sha256", "track", "split", "reference_id", "budget", "contract", "attempts"}:
        raise ValueError("Missing or unknown trace field")
    if trace["schema"] != "iotos-evolution-trace-v1" or trace["protocol_sha256"] != inventory["protocol"]["sha256"]:
        raise ValueError("Unknown or changed frozen protocol")
    if trace["track"] not in protocol["tracks"] or trace["split"] != "development":
        raise ValueError("Unknown track; held-out certification needs a separate sealed evaluator")
    contract = load(check_ref(trace["contract"], root))
    if contract["schema"] != "iotos-task-contract-v1" or any(
            contract[k] != trace[k] for k in ("protocol_sha256", "track", "split", "reference_id", "budget")):
        raise ValueError("Submission changed its frozen task or budget")
    receipts = {r["id"]: r for r in inventory["baseline_records"]}
    reference = receipts[trace["reference_id"]]
    # A submission references existing qualifications; it cannot supply new ones.
    for ref in (reference["audit"], reference["manifest"], reference["artifact"], reference["source_proof"]):
        check_ref(ref, root)
    budget = trace["budget"]
    number(budget["max_attempts"], "max_attempts", True)
    number(budget["max_wall_s"], "max_wall_s")
    if budget["max_tokens"] is not None:
        number(budget["max_tokens"], "max_tokens", True)
    attempts = trace["attempts"]
    if not attempts or len(attempts) - 1 > budget["max_attempts"]:
        raise ValueError("Empty or over-budget attempt history")
    if trace["track"] != "fixed_configuration" and len(attempts) < 2:
        raise ValueError("A generative track needs an actual attempted generation")
    costs = {key: 0 for key in protocol["accounting"]}
    deployed, rounds, previous_end, search_start = None, [], None, None
    for i, attempt in enumerate(attempts):
        if attempt["step"] != i or attempt["parent_deployed_step"] != deployed:
            raise ValueError("Missing/reordered attempt or wrong deployed parent")
        start, end = timestamp(attempt["started_utc"]), timestamp(attempt["ended_utc"])
        if end < start or (previous_end is not None and start < previous_end):
            raise ValueError("Overlapping or reversed attempt chronology")
        if timestamp(contract["frozen_utc"]) > start:
            raise ValueError("Task was not frozen before its declared attempts")
        if i == 1:
            search_start = start
        previous_end = end
        current = attempt["costs"]
        if set(current) != set(costs):
            raise ValueError("Missing or unknown cost field")
        for key, value in current.items():
            if value is None and key.endswith("tokens"):
                costs[key] = None
            else:
                number(value, key, key.endswith("tokens"))
                if costs[key] is not None:
                    costs[key] += value
        if sum(current[k] for k in current if k.endswith("_s")) > (end - start).total_seconds() + 1e-6:
            raise ValueError("Serial stage times exceed the attempt wall time")
        artifact = check_ref(attempt["artifact"], root)
        check_ref(attempt["log"], root)
        if i == 0:
            if attempt["status"] != "deployed" or attempt["measurement_id"] != reference["id"]:
                raise ValueError("Initial state must be the audited reference")
            if any(current[k] not in (0, None) for k in current):
                raise ValueError("Historical reference cost is unknown, not a new search cost")
        elif trace["track"] == "fixed_configuration":
            raise ValueError("Fixed configuration is not a generative history")
        else:
            generated = load(check_ref(attempt["generation_record"], root))
            candidate = check_ref(attempt["candidate"], root)
            for key in ("provider", "model", "revision"):
                if not isinstance(generated[key], str) or not generated[key].strip():
                    raise ValueError("Missing generation identity")
            check_ref(generated["request"], root)
            check_ref(generated["response"], root)
            if generated["output_sha256"] != digest(candidate):
                raise ValueError("Generation output differs from the submitted source/configuration")
            if generated["costs"] != current:
                raise ValueError("Generation log and submitted costs differ")
        status = attempt["status"]
        if status not in ("deployed", "build_failed", "boot_failed", "correctness_failed", "constraint_rejected"):
            raise ValueError("Unknown candidate outcome")
        value = None
        if status == "deployed":
            receipt = receipts.get(attempt["measurement_id"])
            if receipt is None:
                raise ValueError("Unregistered candidate: source/semantic/raw-data audit adapter required")
            if receipt["comparison_group"] != reference["comparison_group"]:
                raise ValueError("Board, workload, metric or experimental conditions differ")
            for ref in (receipt["audit"], receipt["manifest"], receipt["artifact"], receipt["source_proof"]):
                check_ref(ref, root)
            if digest(artifact) != receipt["artifact"]["sha256"]:
                raise ValueError("Measured firmware differs from the candidate")
            if i and receipt["origin"] == "fixed_configuration":
                if not attempt["identical_artifact_reuse"] or receipt["artifact"]["sha256"] != reference["artifact"]["sha256"]:
                    raise ValueError("Only an identical reference artifact may reuse a historical measurement in a generation history")
            value = receipt["median"]
            deployed = i
        elif attempt["measurement_id"] is not None:
            raise ValueError("Rejected candidate cannot claim a successful runtime score")
        rounds.append({"step": i, "status": status, "deployed_median": value,
            "cumulative_costs": dict(costs), "artifact_sha256": digest(artifact)})
    if trace["track"] == "one_shot_generation" and len(attempts) != 2:
        raise ValueError("One-shot means exactly one attempted generation")
    wall = (previous_end - search_start).total_seconds() if search_start is not None else 0
    tokens = None if any(costs[k] is None for k in ("input_tokens", "output_tokens")) else costs["input_tokens"] + costs["output_tokens"]
    if wall > budget["max_wall_s"] or (budget["max_tokens"] is not None and (tokens is None or tokens > budget["max_tokens"])):
        raise ValueError("Budget exceeded or token-limited accounting is unknown")
    initial, final = reference["median"], rounds[deployed]["deployed_median"]
    successful = [r["deployed_median"] for r in rounds if r["deployed_median"] is not None]
    lower = reference["direction"] == "lower"
    regressions = sum((b > a if lower else b < a) for a, b in zip(successful, successful[1:]))
    return {"schema": "iotos-evolution-review-v1", "audit": "format_and_registered_evidence_pass",
        "track": trace["track"], "metric": reference["metric"], "unit": reference["unit"],
        "initial": initial, "final_deployed": final, "final_relative_change_percent": 100 * (final / initial - 1),
        "rounds": rounds, "total_costs": costs, "wall_s": wall,
        "rejected_attempts": sum(r["status"] != "deployed" for r in rounds),
        "observed_deployed_metric_regressions": regressions,
        "generation_authenticity_verified": False, "history_completeness_independently_verified": False,
        "generated_source_to_firmware_binding_verified": False, "historical_search_costs_available": False,
        "held_out_certified": False, "rsi_claim_supported": False,
        "generative_comparison_eligible": False, "composite_score": None,
        "boundary": "Offline evidence inspection; supplied model logs do not prove origin or completeness. New candidate firmware and edited improvers require separate benchmark-owned audit and held-out evidence."}


def audited_inventory():
    from render_esp32_benchmark import followup_data, publication_view
    from standardize_esp32_benchmark import standardize
    data = load(ROOT / SNAPSHOT)
    view = publication_view(data, standardize(data), followup_data())
    return baseline_inventory(data, view)


def prepare_mcu(inventory, output, case):
    """Export a locked original ESP32 task; never fabricate a generator output."""
    execution = load(ROOT / PROTOCOL)["execution"]
    if case not in execution["esp32_feedback_cases"] + execution["esp32_validation_cases"]:
        raise ValueError("Not a frozen MCU original task")
    reference = next(r for r in inventory["baseline_records"] if r["os"] == "Zephyr"
                     and r["case"] == case and r["metric"] == "original_count_30s")
    proof = load(check_ref(reference["source_proof"], ROOT))
    source = ROOT / "artifacts/reports" / proof["source"]
    for item in (reference["audit"], reference["manifest"], reference["artifact"]):
        check_ref(item, ROOT)
    if digest(source / "config") != proof["config_sha256"]:
        raise ValueError("Reference configuration changed")
    output.mkdir(parents=True, exist_ok=False)
    paths = {"reference.config": source / "config"}
    paths.update({"app/src/" + n: source / n for n in ("main.c", "port.c", "test.c", "tm_override.h")})
    app = ROOT / "firmware/bsp/esp32/zephyr_thread_metric"
    paths.update({"app/" + n: app / n for n in ("CMakeLists.txt", "prj.conf")})
    paths.update({"original/" + n: ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / n
                  for n in ("tm_" + case + "_test.c", "tm_api.h", "tm_porting_layer.h", "LICENSE.txt", "LICENSED-HARDWARE.txt")})
    for name, path in paths.items():
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    job = {"schema": "iotos-esp32-candidate-build-v1", "case": case,
        "protocol_sha256": inventory["protocol"]["sha256"], "reference": reference,
        "execution": execution, "files": {name: digest(output / name) for name in paths},
        "generation_supplied": False, "runtime_admitted": False}
    (output / "job.json").write_text(json.dumps(job, indent=2) + "\n")
    return {"prepared": True, "case": case, "target": execution["primary_target"],
            "generated": False, "new_measurements": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "check", "review", "prepare-mcu"))
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", default="message_processing")
    args = parser.parse_args()
    inventory = audited_inventory()
    if args.command == "inventory":
        (ROOT / REPORT).write_text(json.dumps(inventory, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        result = inventory["summary"]
    elif args.command == "check":
        if inventory != load(ROOT / REPORT):
            raise ValueError("Reuse inventory is stale")
        result = {"audit": "pass", **inventory["summary"]}
    elif args.command == "prepare-mcu":
        if args.output is None:
            parser.error("prepare-mcu requires --output")
        result = prepare_mcu(inventory, args.output, args.case)
    else:
        if args.trace is None:
            parser.error("review requires --trace")
        result = review_trace(load(args.trace), inventory, ROOT)
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
