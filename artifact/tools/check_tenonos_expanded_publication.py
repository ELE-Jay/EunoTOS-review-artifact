#!/usr/bin/env python3
"""Check new manuscript tables and displayed aggregates against retained evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

from audit_sensys_runtime_tables import audit, require_rows
from audit_tenonos_paper_tasks import published_rows, require_published_table
from iotos_evolution import (expanded_tenon_summary, joint_tenon_summary,
    complete_resource_tenon_summary, resource_history_tenon_summary)
from tenonos_kvm_reproduce import save, sha

ROOT = Path(__file__).resolve().parents[1]
LABELS = {"TE-PERIODIC": "Periodic 2k", "TE-TICKLESS": "Tickless", "TE-PRIORITIES": "512 priorities"}


def check(root):
    return check_expanded(root, audit(root / "paper/sensys2027/iotosbench.tex"))


def check_expanded(root, existing):
    """Check additional tables using the runtime audit just executed by the caller."""
    source = root / "paper/sensys2027/iotosbench.tex"
    if existing.get("manuscript_sha256") != sha(source):
        raise ValueError("Expanded checks require the same current manuscript")
    text = source.read_text()
    reports = root / "artifacts/reports"
    paired = json.loads((reports / "tenonos-author-engine-20261027-v1/paired-v4-task-audit-v2.json").read_text())
    campaign = reports / "tenonos-author-engine-20261027-v1/paired-v4-campaign-v2"
    for name, digest in paired["campaign_evidence_manifest"].items():
        path = (campaign / name).resolve()
        path.relative_to(campaign.resolve())
        if sha(path) != digest:
            raise ValueError("Historical paired evidence differs")
    require_published_table(text, published_rows(paired))
    diagnostic_path = reports / "tenonos-expanded-composition-native-audit-v1.json"
    diagnostic = json.loads(diagnostic_path.read_text())
    diagnostic_campaign = reports / "tenonos-expanded-composition-campaign-v1"
    if (diagnostic["registered_trials"], diagnostic["model_attempts"], diagnostic["raw_guest_captures"]) != (30,60,36):
        raise ValueError("Historical numeric-interface diagnostic accounting differs")
    for name, digest in diagnostic["campaign_evidence_manifest"].items():
        path = (diagnostic_campaign / name).resolve()
        path.relative_to(diagnostic_campaign.resolve())
        if sha(path) != digest:
            raise ValueError("Historical diagnostic raw evidence differs")
    summary = expanded_tenon_summary(root)
    native = json.loads((reports / "tenonos-expanded-numeric-native-audit-v1.json").read_text())
    rows = []
    for row in summary["rows"]:
        name = LABELS[row["task"]] + " / " + row["method"]
        group = next(g for g in native["runtime_audit"]["groups"]
                     if g["task"] == row["task"] and g["method"] == row["method"])
        n = group["accounting"]["applicable_runs"]
        if n != row["n"]:
            raise ValueError("Task repetition count differs")
        values = [round(group["accounting"]["unconditional_stage_success_rates"][k] * n)
                  for k in ("generated", "built", "functional")] + [row["qualified"]]
        rows.append(name + " & " + " & ".join(str(v) + "/" + str(row["n"]) for v in values))
    require_rows(text, "tab:tenonexpanded", rows)
    energy_labels = {"te-periodic": "Periodic 2k", "te-tickless": "Tickless", "te-priorities": "512 priorities"}
    energy_rows = [energy_labels[r["variant"]] + " & %.2f & %.2f & %.3f" %
                   (r["energy_j"]["median"], r["duration_s"]["median"], r["average_power_w"]["median"])
                   for r in summary["energy"]["summary"]]
    require_rows(text, "tab:tenonexpandedenergy", energy_rows)
    ram_rows = []
    if summary.get("ram"):
        ram_rows = [energy_labels[r["profile"]] + " & " + " & ".join(format(r[k],",") for k in
            ("peak_allocated_occupancy_bytes", "resident_reserved_bytes", "allocator_metadata_reserved_bytes",
             "allocated_block_bytes")) for r in summary["ram"]["profiles"]]
        require_rows(text, "tab:tenonexpandedram", ram_rows)
        ram = summary["ram"]
        counts = {r["lifecycle_events"] for r in ram["profiles"]}
        if (ram["observer_guests"],ram["diagnostic_guests"],counts) != (9,12,{1031}) or \
                text.count('The three exit captures each retain 1,031 allocation/thread events through termination') != 1:
            raise ValueError("New RAM lifecycle accounting differs")
    accounting = ("The repaired batch makes %s model calls, uses %s output tokens and captures %s fresh guests." %
                  (summary["model_calls"], format(summary["output_tokens"], ","), summary["fresh_guest_captures"]))
    if text.count(accounting) != 1:
        raise ValueError("New manuscript accounting differs")
    html = root / "benchmark_esp32.html"
    view = json.loads(re.search(r'<script type="application/json" id="publication-view">(.*?)</script>', html.read_text(), re.S)[1])
    if 'category_scores' in existing['reset_level_values'] and \
            view.get('category_scores') != existing['reset_level_values']['category_scores']:
        raise ValueError('HTML category scores differ from current source replay')
    if view["generative_benchmark"]["tenon_expanded_tasks"] != summary:
        raise ValueError("Displayed new task/energy aggregates differ")
    joint = joint_tenon_summary(root)
    joint_tables = {}
    if joint:
        joint_tables['tab:tenonjoint'] = [r['method'].capitalize() + ' & ' + ' & '.join(
            str(r[k])+'/'+str(r['n']) for k in ('valid','built','runtime','qualified')) for r in joint['rows']]
        joint_tables['tab:tenonjointram'] = ['Generated / -Os & ' + ' & '.join(format(r[k],',') for k in
            ('peak_allocated_occupancy_bytes','resident_reserved_bytes','allocator_metadata_reserved_bytes','allocated_block_bytes'))
            for r in joint['ram']['profiles']]
        joint_tables['tab:tenonjointenergy'] = ['Generated / -Os & %.2f [%.2f, %.2f] & %.2f & %.3f' %
            (r['energy_j']['median'],r['energy_j']['min'],r['energy_j']['max'],
             r['duration_s']['median'],r['average_power_w']['median']) for r in joint['energy']['summary']]
        for label, expected in joint_tables.items():
            require_rows(text,label,expected)
        required = ('The ten registered attempts make 20 model calls and use 2,853 output tokens.',
                    'Three board-input activations run nine fresh guests without new model calls or builds.')
        if any(text.count(s)!=1 for s in required) or view['generative_benchmark'].get('tenon_joint_task') != joint:
            raise ValueError('Joint task manuscript accounting or displayed evidence differs')
    completion=complete_resource_tenon_summary(root)
    completion_tables={}
    if completion:
        def seconds(value):
            return '--' if value is None else '%.2f'%value
        completion_tables['tab:tenoncompletion']=[r['method'].capitalize()+' & '+str(r['full_passes'])+'/'+str(r['n'])+
            ' & '+seconds(r['successful_completion_median_s'])+' & '+
            ('--' if r['successful_completion_range_s'] is None else '[%.2f, %.2f]'%tuple(r['successful_completion_range_s']))+
            ' & '+seconds(r['all_attempt_median_s'] if r['full_passes']==0 else None) for r in completion['groups']]
        require_rows(text,'tab:tenoncompletion',completion_tables['tab:tenoncompletion'])
        if view['generative_benchmark'].get('tenon_complete_resource')!=completion or text.count(
                'The new ten requests make 20 model calls, use 3,188 output tokens and run fifteen fresh original-suite guests.')!=1:
            raise ValueError('Completion manuscript accounting or display differs')
        from tenonos_complete_resource import BASE, replay_fresh_profile
        validation=reports/'tenonos-complete-resource-fresh-path-v1'
        result=json.loads((validation/'result.json').read_text())
        registration=json.loads((validation/'registration.json').read_text())
        if not result['pass'] or result['new_model_calls'] or result['new_registered_task_trials'] or \
                result['fresh_validation_guests']!=10 or registration['planned_guests']!=10 or \
                sha(validation/'controller.py')!=registration['controller_sha256'] or \
                result['profile']['peak_bytes']!=joint['ram']['profiles'][0]['peak_allocated_occupancy_bytes']:
            raise ValueError('First-time resource profiling validation differs')
        previous=sys.path[:]
        try:
            sys.path.insert(0,str(root/BASE))
            replay_fresh_profile(result['profile'])
        finally:
            sys.path[:]=previous
    resource=resource_history_tenon_summary(root)
    resource_tables={}
    if resource:
        resource_tables['tab:tenonresourcehistory']=[r['method'].capitalize()+' & '+
            ' & '.join(str(r[k])+'/'+str(r['rounds']) for k in
                ('native_constraint_passes','accepted_rounds','ram_rejections'))+' & '+
            str(r['final_constraint_passes'])+'/'+str(r['histories'])+' & %.2f'%r['history_cost_median_s']
            for r in resource['groups']]
        require_rows(text,'tab:tenonresourcehistory',resource_tables['tab:tenonresourcehistory'])
        accounting=('The twelve modification requests make %s model calls, use %s output tokens and run '
            'eighteen fresh candidate guests plus 42 initial or recovery guests.'%
            (resource['model_calls'],format(resource['output_tokens'],',')))
        if text.count(accounting)!=1 or view['generative_benchmark'].get('tenon_resource_histories')!=resource or \
                resource['registered_rounds']!=12 or resource['registered_histories']!=6 or \
                resource['original_guests']!=18 or resource['parent_check_guests']!=42 or \
                resource['new_resource_guests'] or resource['distinct_new_profiles'] or \
                resource['round_ram_limits_bytes']!=[12*1024**2,6*1024**2]:
            raise ValueError('Prospective resource-history accounting or publication differs')
    rom_callback=None
    rom_path=reports/'esp32-rom-callbacks-v2.json'
    if rom_path.exists():
        from audit_esp32_rom_callbacks import audit as callback_audit
        rom_callback=json.loads(json.dumps(callback_audit(root)))
        if rom_callback!=json.loads(rom_path.read_text()) or rom_callback['rom_owner_exhaustiveness_verified'] or \
                rom_callback['ranking_eligible'] or rom_callback['whole_lifecycle_peak_allocated_occupancy_bytes'] is not None:
            raise ValueError('ROM callback evidence changed or incomplete RAM was promoted')
    if '\\label{app:allocatedcapacity}' in text:
        from esp32_allocated_capacity_publication import summary as capacity_summary
        capacity=capacity_summary(root)
        if view.get('allocated_capacity')!=capacity:
            raise ValueError('Normal-boot observer RAM display differs from retained source/bytes')
    return {"audit": "pass", "legacy_encoded_tables": list(existing["tables"]),
            "additionally_checked_tables": ["tab:tenonpaired", "tab:tenonexpanded", "tab:tenonexpandedenergy"] +
                (["tab:tenonexpandedram"] if ram_rows else []) + list(joint_tables) + list(completion_tables) + list(resource_tables),
            "joint_tables":joint_tables,
            "completion_tables":completion_tables,
            "resource_history_tables":resource_tables,
            "rom_callback_audit_sha256":sha(rom_path) if rom_callback else None,
            "new_task_rows": rows, "new_energy_rows": energy_rows, "new_ram_rows":ram_rows,
            "historical_numeric_diagnostic_sha256":sha(diagnostic_path),
            "manuscript_sha256": sha(source), "html_sha256": sha(html),
            "new_physical_measurements": 0, "new_model_calls": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform == "darwin" or args.output.exists():
        parser.error("Use leon and a new persistent report")
    os.chdir(ROOT)
    result = check(ROOT)
    save(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k not in ("new_task_rows", "new_energy_rows")}, indent=2))
