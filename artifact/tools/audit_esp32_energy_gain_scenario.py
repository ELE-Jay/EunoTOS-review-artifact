#!/usr/bin/env python3
"""Replay retained board energy under an explicit multiplicative-gain scenario."""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
from statistics import median
import sys

ROOT = Path(__file__).resolve().parents[1]
MANUAL = 'artifacts/source_snapshots/power-z-km003c-manual-20261028/manual.txt'
MANUAL_SHA = '73482f8306ea81904efed01644ef62b392d5c6cbf9651955a8361644837a33f6'
GAIN = 0.0025


def envelope(values, gain):
    if not values or any(not math.isfinite(v) or v <= 0 for v in values) or \
            not math.isfinite(gain) or not 0 <= gain < 1:
        raise ValueError('Finite positive observations and a gain below one are required')
    low, high = (1-gain)**2, (1+gain)**2
    return {'median':median(values),'observed_range':[min(values),max(values)],
        'gain_only_median_scenario':[median(values)*low,median(values)*high],
        'gain_expanded_observed_range':[min(values)*low,max(values)*high]}


def overlaps(a,b):
    return max(a[0],b[0]) <= min(a[1],b[1])


def audit(root):
    from audit_esp32_b1_controlled_energy import audit as controlled
    from audit_esp32_b1_native_energy import audit as native
    from audit_esp32_energy_window_sensitivity import CASES
    from run_esp32_followup import sha
    raw=(root/MANUAL).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=MANUAL_SHA:
        raise ValueError('The publisher-linked manual export changed')
    source=json.loads((root/MANUAL).with_name('source-via-proxy.json').read_text())
    if len([r for r in source if r.get('file')=='manual.txt' and r.get('sha256')==MANUAL_SHA and
            r.get('url')=='https://docs.google.com/document/d/1T55UeixUNN9La3tzAF0jO45Snw_rrd9RVGt3XQeRIM8/export?format=txt'])!=1:
        raise ValueError('Manual acquisition identity differs')
    text=raw.decode('utf-8-sig')
    for label in ('Voltage Measurement Gain Error','Current Measurement Gain Error'):
        if not re.search(re.escape(label)+r'\s+0\.05\s+0\.25\s+%',text):
            raise ValueError('The declared manual gain entries are absent')
    rows=[];captures=0
    for is_native in (False,True):
        for case in CASES:
            name='esp32-native-'+case+'-energy-b1-v1' if is_native else 'esp32-'+(
                'message' if case=='message_processing' else case)+'-energy-b1-v1'
            folder=root/'artifacts/reports'/name
            checked=(native if is_native else controlled)(folder)
            for cell in checked['cells']:
                runs=[r['paired'] for r in cell['runs']]
                if len(runs)!=3:raise ValueError('Different reset-level energy cohort')
                captures+=len(runs)
                rows.append({'campaign':name,'campaign_sha256':sha(folder/'campaign.json'),
                    'os':cell['os'],'case':case,'profile':'native' if is_native else 'controlled',
                    'independent_resets':len(runs),
                    'average_power_w':envelope([r['steady_average_power_w'] for r in runs],GAIN),
                    'energy_per_original_count_uj':envelope([r['energy_per_original_count_uj'] for r in runs],GAIN)})
    message=[r for r in rows if r['profile']=='controlled' and r['case']=='message_processing']
    if captures!=75 or len(rows)!=25 or {r['os'] for r in message}!={'FreeRTOS','Zephyr','NuttX'}:
        raise ValueError('Retained energy coverage differs')
    pairs=[]
    for a,b in itertools.combinations(message,2):
        pairs.append({'systems':[a['os'],b['os']],**{key:overlaps(
            a[key]['gain_expanded_observed_range'],b[key]['gain_expanded_observed_range'])
            for key in ('average_power_w','energy_per_original_count_uj')}})
    return {'audit':'pass','manual':MANUAL,'manual_sha256':MANUAL_SHA,
        'manual_url':'https://docs.google.com/document/d/1T55UeixUNN9La3tzAF0jO45Snw_rrd9RVGt3XQeRIM8',
        'publisher_support_url':'https://www.power-z.com/blogs/technical-support/power-z-km003c-km002c-technical-support',
        'independent_resets_reused':captures,'new_physical_measurements':0,'rows':rows,
        'gain_fraction_per_channel':GAIN,'energy_multipliers':[(1-GAIN)**2,(1+GAIN)**2],
        'maximum_positive_energy_change_fraction':(1+GAIN)**2-1,
        'controlled_message_pairwise_range_overlap':pairs,
        'same_fixed_gain_cancels_in_cross_run_ratios':True,
        'scope':'Sensitivity scenario, not calibrated error bars: independently allow +/-0.25% voltage and current gain per run; also report the common fixed-gain cancellation case. The manual lists 0.05 and 0.25% gain entries without a complete system uncertainty specification.',
        'excluded':['Offset, nonlinearity and temperature drift','Meter calibration and sensor conversion delay',
            'Aliased fast transients, supply/lead losses and unmetered supply validation'],
        'calibration_verified':False,'total_uncertainty_bound':None,'ranking_eligible':False}


def summary(value):
    return {k:v for k,v in value.items() if k!='rows'} | {'controlled_message':[
        r for r in value['rows'] if r['profile']=='controlled' and r['case']=='message_processing']}


def paper_text(value):
    pairs=value['controlled_message_pairwise_range_overlap']
    pair=next(r for r in pairs if set(r['systems'])=={'FreeRTOS','Zephyr'})
    if not pair['average_power_w'] or any(r['energy_per_original_count_uj'] for r in pairs) or \
            value['calibration_verified'] or value['total_uncertainty_bound'] is not None:
        raise ValueError('Report the actual sensitivity finding instead of the expected example')
    return ('A separate replay allows an independent $\\pm0.25\\%$ multiplicative gain change '
        'in each voltage/current channel per run, motivated by the publisher-linked manual entries~\\cite{powerzmanual}. '
        'This expands the observed FreeRTOS/Zephyr average-power ranges to overlap, while the '
        'three message-workload energy-per-count ranges remain disjoint. A common fixed gain '
        'instead cancels in ratios. This is a sensitivity scenario, not a calibrated error bound; '
        'offsets, temperature effects and sensor delay remain uncharacterized.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if sys.platform!='linux':parser.error('Real evidence stays on leon')
    value=audit(ROOT)
    with args.output.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
    print(json.dumps(summary(value),indent=2))
