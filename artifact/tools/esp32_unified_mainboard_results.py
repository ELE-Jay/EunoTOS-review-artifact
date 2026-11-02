#!/usr/bin/env python3
"""Admit all four measured categories, then compute the frozen five-system table."""
import argparse
import json
import math
from pathlib import Path
from statistics import median

from audit_esp32_unified_mainboard import audit as work_audit,overall_scores,weight_sensitivity
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
INPUTS='registry/esp32_unified_mainboard_inputs_v1.json'
PROTOCOL='registry/esp32_unified_mainboard_v1.json'


def score_configuration(indices,weights=None):
    """Score one externally admitted runtime configuration, including generated ones.

    The runtime judge supplies comparable fixed-reference indices. This numerical
    function does not establish hardware, workload or evidence comparability.
    """
    categories=json.loads((ROOT/PROTOCOL).read_text())['categories']
    keys=[c['id'] for c in categories]
    weights={c['id']:c['weight'] for c in categories} if weights is None else weights
    if set(indices)!=set(keys) or set(weights)!=set(keys) or any(
            not isinstance(v,(int,float)) or not math.isfinite(v) or v<=0 for v in indices.values()) or any(
            not isinstance(w,(int,float)) or not math.isfinite(w) or w<0 for w in weights.values()) or \
            not math.isclose(sum(weights.values()),1,abs_tol=1e-12):
        raise ValueError('All four admitted category indices and normalized weights are required')
    return 100*math.exp(sum(weights[k]*math.log(indices[k]/100) for k in keys))


def combine(work,network,ram,systems):
    indices={r['os']:r for r in work['scores']}
    expected=set(systems)
    if len(systems)!=5 or len(expected)!=5 or len(work['scores'])!=5 or any(
            set(values)!=expected for values in (indices,network,ram)):
        raise ValueError('Five unique complete systems are mandatory')
    for os in systems:
        if len(network[os])!=5 or len(ram[os])!=5 or any(not isinstance(v,(int,float)) or
                not math.isfinite(v) or v<=0 for v in [*network[os],*ram[os]]):
            raise ValueError('Need five positive independently qualified network and RAM observations per OS')
    reference_net=median(network['FreeRTOS']);reference_ram=median(ram['FreeRTOS'])
    rows=[{'os':os,'kernel_index':indices[os]['kernel_index'],'energy_index':indices[os]['energy_index'],
        'network_index':100*median(network[os])/reference_net,'ram_index':100*reference_ram/median(ram[os]),
        'network_mbit_s':median(network[os]),'network_reset_values_mbit_s':network[os],
        'peak_allocated_ram_bytes':median(ram[os]),'ram_reset_values_bytes':ram[os],
        'ram_observer_included':True} for os in systems]
    totals=overall_scores(rows)
    for row in rows:
        row['overall_score']=score_configuration({k:row[k+'_index'] for k in ('kernel','network','energy','ram')})
        if not math.isclose(row['overall_score'],totals[row['os']],rel_tol=1e-12):
            raise ValueError('Single-configuration and frozen cohort scorers disagree')
        row['rank']=1+sum(v>row['overall_score'] and not math.isclose(v,row['overall_score'],rel_tol=1e-10)
            for v in totals.values())
    return rows


def admitted_ram():
    from esp32_allocated_capacity_publication import summary
    from replay_esp32_riot_capacity import evaluate as riot_check,RESULT as RIOT_SECONDARY,PRIMARY as RIOT_PRIMARY
    from replay_esp32_rhino_capacity import evaluate as rhino_check,RESULT as RHINO_SECONDARY,PRIMARY as RHINO_PRIMARY
    controlled=summary(ROOT)
    if controlled is None:raise ValueError('Missing controlled observer capacity evidence')
    rows={r['os']:r['reset_values'] for r in controlled['rows']};bindings=dict(controlled['evidence'])
    observer_images={r['os']:{k:r[k] for k in ('source','capture','elf_sha256')} for r in controlled['rows']}
    for os,primary,secondary,checker,folder in (
            ('RIOT',RIOT_PRIMARY,RIOT_SECONDARY,riot_check,'esp32-riot-capacity-isolated-v1'),
            ('AliOS-Rhino',RHINO_PRIMARY,RHINO_SECONDARY,rhino_check,'esp32-rhino-capacity-isolated-v1')):
        checked=checker();recorded=json.loads((ROOT/secondary).read_text())
        value=json.loads((ROOT/primary).read_text())
        if checked!=recorded or not checked['complete_declared_lifecycle'] or \
                value['os']!=os or value['board_mac']!='34:98:7a:a2:85:28' or \
                value['definition_sha256']!=sha(ROOT/'registry/ram_allocated_occupancy_v1.json') or not value['observer_included']:
            raise ValueError('Native observer capacity/crosscheck differs')
        path=ROOT/'artifacts/reports'/folder/'receipt.json';receipt=json.loads(path.read_text())
        index=path.with_name('input-index.json')
        if not receipt['actual_isolated_copy_replay'] or not \
                receipt['original_evidence_network_devices_unapproved_subprocess_prohibited'] or \
                receipt['retained_independent_resets']!=5 or receipt['input_index_sha256']!=sha(index):
            raise ValueError('Missing actual isolated native capacity replay')
        rows[os]=value['whole_lifecycle_peak_allocated_occupancy_bytes']
        observer_images[os]={k:value[k] for k in ('source','capture','elf_sha256','bin_sha256')}
        bindings.update({n:sha(ROOT/n) for n in (primary,secondary,path.relative_to(ROOT).as_posix(),index.relative_to(ROOT).as_posix())})
    return rows,bindings,observer_images


def audit():
    from run_esp32_unified_native_udp import audit as network_audit
    protocol=json.loads((ROOT/PROTOCOL).read_text());inputs=json.loads((ROOT/INPUTS).read_text())
    systems=protocol['systems'];reports={};network={};network_details={};bindings={}
    identity=json.loads((ROOT/inputs['native_peer_identity']).read_text())
    if inputs['protocol']!=protocol['id'] or set(inputs['network'])!=set(systems) or set(inputs['ram'])!=set(systems):
        raise ValueError('Input contract differs from the complete frozen system set')
    work=work_audit()
    if work!=json.loads((ROOT/inputs['kernel_energy']).read_text()):
        raise ValueError('Retained same-window kernel/energy replay differs')
    bindings[inputs['kernel_energy']]=sha(ROOT/inputs['kernel_energy'])
    for os in systems:
        name=inputs['network'][os];folder=ROOT/name
        if name not in reports:
            result=network_audit(folder)
            if result!=json.loads((folder/'audit.json').read_text()):
                raise ValueError('Complete network replay differs: '+name)
            plan=json.loads((folder/'plan.json').read_text())
            if plan.get('host_preconditioning',{}).get('id')!=inputs['network_protocol']:
                raise ValueError('Network observations use different preconditioning profiles')
            if any(p['system']=='Zephyr' for p in plan['schedule']) and plan.get('native_peer_identity')!=identity:
                raise ValueError('Zephyr IPv4 peer binding lacks its frozen native-interface correction')
            reports[name]=result
            bindings.update({name+'/'+n:sha(folder/n) for n in ('audit.json','plan.json','campaign.json')})
        cells=[c for c in reports[name]['cells'] if c['os']==os]
        if len(cells)!=1 or cells[0]['independent_resets']!=5 or len(cells[0]['runs'])!=5:
            raise ValueError('Five complete common-network resets missing: '+os)
        network[os]=[r['receiver_bits_s']/1e6 for r in cells[0]['runs']]
        network_details[os]={'capture':name,'acquisition_attempts':reports[name]['acquisition_attempts'],
            'rejected_or_incomplete_attempts':reports[name]['rejected_or_incomplete_attempts']}
    bindings[inputs['native_peer_identity']]=sha(ROOT/inputs['native_peer_identity'])
    ram,ram_bindings,images=admitted_ram();bindings.update(ram_bindings)
    for os in systems:
        if inputs['ram'][os] not in bindings:
            raise ValueError('RAM input is not part of the qualified observer proof: '+os)
    rows=combine(work,network,ram,systems)
    return {'audit':'pass','schema':'esp32-unified-mainboard-v1','board_mac':protocol['hardware']['board_mac'],
        'protocol_sha256':sha(ROOT/PROTOCOL),'input_contract_sha256':sha(ROOT/INPUTS),
        'categories':protocol['categories'],'rows':rows,'ranking':sorted(rows,key=lambda r:(r['rank'],systems.index(r['os']))),
        'weight_sensitivity':weight_sensitivity(rows),'category_relationships':work['category_relationships'],
        'kernel_energy_raw_cells':work['rows'],'network_details':network_details,'ram_observer_images':images,
        'evidence':bindings,'qualified_systems':systems,'all_mandatory_categories_qualified':True,
        'historical_eligibility_flags_modified':False,'reused_kernel_energy_resets':75,
        'common_network_resets':25,'message_observer_ram_resets':25,
        'new_board_resets_during_replay':0,'new_model_calls':0,
        'scope':'Five measured B1 configurations, 240 MHz and one active core, common original workload/operation and observation boundaries. Native kernels, scheduler/tick policies, SDKs and compatible libraries are recorded parts of the configurations. The RAM category is fixed-observer allocated capacity, including observer and startup reservations, not inferred uninstrumented memory. Composite weights are the frozen benchmark policy; raw values and category dependence remain visible. No diagnostic/native-echo endpoint, missing-category renormalization, cross-board mixture or old-network profile substitution.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists() or not \
            args.output.resolve().is_relative_to((ROOT/'artifacts/reports').resolve()):
        parser.error('Evaluate on leon and preserve existing evidence')
    result=audit()
    with args.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'audit':result['audit'],'all_categories_qualified':True,
        'ranking':[{k:r[k] for k in ('os','rank','overall_score')} for r in result['ranking']],
        'sensitivity':result['weight_sensitivity']}))
