#!/usr/bin/env python3
"""Deduplicate generated configurations and bind separately observed behavior."""
import argparse
import hashlib
import json
from pathlib import Path

from audit_tenonos_tasks import configuration, require
from audit_tenonos_budget_sensitivity import audit as generation_audit
from audit_tenonos_runtime_oracle import audit as observer_audit
from tenonos_kvm_reproduce import sha

PARENT = 'artifacts/reports/tenonos-author-engine-20261027-v1'
OLD = 'artifacts/reports/tenonos-runtime-oracle-rpi4-v6'
INVENTORY = 'artifacts/reports/tenonos-runtime-candidate-inventory-v1.json'
PLAN = 'registry/tenonos_runtime_candidates_v1.json'
CAPTURE = 'artifacts/reports/tenonos-runtime-candidate-profile-v1'


def identity(config, source, compiler):
    """Compiler identity here is the retained --version output hash, not a binary hash."""
    return hashlib.sha256(json.dumps({'config':config,'source':source,'compiler':compiler}, sort_keys=True,
                                    separators=(',',':')).encode()).hexdigest()


def build_identity(build):
    value = json.loads((build/'build-result.json').read_text())
    require(sha(build/'.config') == value['config_sha256'] and sha(build/'runtime-image') == value['image_sha256'] and
            sha(build/'compiler.stdout') == value['compiler_version_stdout_sha256'], 'Generated build identity differs')
    return identity(configuration(build/'.config'), value['source_commits'], sha(build/'compiler.stdout')), value


def inventory(root):
    parent = root/PARENT
    cap = parent/'budget-v4-campaign-v1'
    generation = generation_audit(root,parent/'budget-sensitivity-pipeline-v2',cap,parent/'budget-v4-task-audit-v1.json')
    require(generation == json.loads((parent/'budget-v4-sensitivity-audit-v1.json').read_text()), 'Generation audit differs')
    old = observer_audit(root,root/OLD)
    require(old == json.loads((root/OLD/'audit.json').read_text()), 'Behavioral audit differs')
    known = {}
    for p in old['profiles']:
        folder = root/OLD/p['profile']
        proof = json.loads((folder/'source-proof.json').read_text())
        key = identity(configuration(folder/'input.config'),proof['identity'],sha(folder/'build/compiler.stdout'))
        require(key not in known, 'Ambiguous behavioral profile')
        known[key] = p['profile']
    rows, groups, missing = [], {}, []
    registration = json.loads((cap/'registration.json').read_text())
    for trial in registration['trials']:
        build = cap/trial['id']/'evaluation/build'
        key, proof = build_identity(build)
        if key not in groups:
            profile = known.get(key)
            if profile is None:
                profile = 'candidate-profile-%d' % (len(missing)+1)
                missing.append({'id':profile,'build':build.relative_to(root).as_posix(),
                    'config_sha256':proof['config_sha256'],'image_sha256':proof['image_sha256']})
            groups[key] = {'identity':key,'profile':profile,'reused':key in known,'trials':[]}
        groups[key]['trials'].append(trial['id'])
        rows.append({**trial,'build':build.relative_to(root).as_posix(),'identity':key,
            'config_sha256':proof['config_sha256'],'image_sha256':proof['image_sha256'],
            'profile':groups[key]['profile'],'reused':key in known})
    require(len(rows) == 18 and len({r['id'] for r in rows}) == 18, 'Registered candidate coverage differs')
    return {'scope':'Post-generation configuration-level behavioral qualification; no old image/timing qualification upgrade',
        'registered_trials':len(rows),'distinct_configurations':len(groups),'rows':rows,'groups':list(groups.values()),
        'variants':missing,'generation_audit_sha256':sha(parent/'budget-v4-sensitivity-audit-v1.json'),
        'prior_behavior_audit_sha256':sha(root/OLD/'audit.json'),'new_model_calls':0,
        'full_live_ram_peak_bytes':None,'ranking_eligible':False}


def bind(root):
    current = inventory(root)
    recorded = json.loads((root/INVENTORY).read_text())
    require(current == recorded, 'Candidate inventory changed')
    plan = json.loads((root/PLAN).read_text())
    require(sha(root/INVENTORY) == plan['reference_registry_sha256'], 'Frozen inventory changed')
    extra = observer_audit(root,root/CAPTURE,root/PLAN)
    require(extra == json.loads((root/CAPTURE/'audit.json').read_text()), 'Additional behavior audit differs')
    old = json.loads((root/OLD/'audit.json').read_text())
    profiles = {}
    for capture, report in ((OLD,old),(CAPTURE,extra)):
        for p in report['profiles']:
            folder = root/capture/p['profile']
            source = json.loads((folder/'source-proof.json').read_text())
            key = identity(configuration(folder/'input.config'),source['identity'],sha(folder/'build/compiler.stdout'))
            require(key not in profiles, 'Duplicate profile identity')
            profiles[key] = {'profile':p['profile'],'capture':capture,'admitted':p['admitted'],
                'guests':len(p['guests']),'source_identity':source['identity']}
    aliases = []
    for row in current['rows']:
        p = profiles.get(row['identity'])
        require(p is not None and p['profile'] == row['profile'], 'Generated configuration lacks a matching behavioral profile')
        aliases.append({**row,'behavior_admitted':p['admitted'],'behavior_campaign':p['capture']})
    used = {a['identity'] for a in aliases}
    require(len(used) == current['distinct_configurations'], 'Configuration coverage differs')
    reused = sum(profiles[k]['guests'] for k in used if profiles[k]['capture'] == OLD)
    fresh = sum(profiles[k]['guests'] for k in used if profiles[k]['capture'] == CAPTURE)
    return {'audit':'pass','registered_generated_candidates':len(aliases),'aliases':aliases,
        'distinct_configurations':len(used),'behavior_admitted_aliases':sum(a['behavior_admitted'] for a in aliases),
        'reused_guest_boots':reused,'new_guest_boots':fresh,'new_model_calls':0,
        'historical_success_rates_and_wall_times_unchanged':True,
        'inventory_sha256':sha(root/INVENTORY),'prior_behavior_audit_sha256':sha(root/OLD/'audit.json'),
        'additional_behavior_audit_sha256':sha(root/CAPTURE/'audit.json'),
        'compiler_identity_boundary':'Exact recorded gcc --version output bytes; historical compiler executable hashes were not captured. The registered phrase actual compiler bytes must not be read as a compiler-binary checksum claim.',
        'scope':'Post-generation observer-image validation of full configuration/source/adapter identities and compiler-version records. Aliases are not independent runtime samples; old firmware timing, energy, completion budgets and task-success denominators remain unchanged.',
        'full_live_ram_peak_bytes':None,'ranking_eligible':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inventory','bind'))
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Use leon and a new output path')
    result = inventory(root) if args.mode == 'inventory' else bind(root)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','groups','aliases','variants')},indent=2))
