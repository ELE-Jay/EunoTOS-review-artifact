#!/usr/bin/env python3
"""Offline arithmetic and coverage-index replay, not raw acquisition replay."""
import argparse,csv,json,math
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from eunotos_adoption_replay import integrity
from production_score_core import indices,totals,rank,sensitivity

def main(output):
 integrity()
 if output.exists():raise ValueError('Use a new output directory outside the artifact')
 if ROOT==output.resolve() or ROOT in output.resolve().parents:raise ValueError('Output must be outside the artifact')
 data=json.loads((ROOT/'current/score-replay-input.json').read_text())
 rows=data['rows'];ref=next(r for r in rows if r['os']=='FreeRTOS')
 if len(rows)!=8 or len(data['score_input_manifest'])!=48:raise ValueError('Incomplete eight-configuration inputs')
 actual=[]
 for row in rows:
  calculated=indices(row['phase_values'],data['reference_controls'][row['task_energy_block']],row['network_transactions_per_second'],ref['network_transactions_per_second'],row['peak_allocated_ram_bytes'],ref['peak_allocated_ram_bytes'])
  if any(not math.isclose(v,row[k],rel_tol=1e-12,abs_tol=1e-12) for k,v in calculated.items()):raise ValueError('Category ratio differs')
  if row['peak_allocated_ram_bytes']!=max(row['ram_reset_values']):raise ValueError('RAM maximum differs')
  from statistics import median
  if row['network_transactions_per_second']!=median(row['network_reset_values']):raise ValueError('UDP median differs')
  actual.append({**row,**calculated})
 scores=totals(actual)
 for row in actual:
  if not math.isclose(scores[row['os']],row['overall_score'],rel_tol=1e-12) or rank(scores[row['os']],scores)!=row['rank']:raise ValueError('Overall or rank differs')
 if sensitivity(actual)!=data['weight_sensitivity']:raise ValueError('235-profile sensitivity differs')
 coverage=json.loads((ROOT/'current/coverage-index.json').read_text());columns=coverage['columns']
 table=(ROOT/'current/benchmark-coverage.tex').read_text();symbols={'existing':'covexisting','added':'covnew','reproduced':'covreproduced','measured':'covmeasured','unmeasured':'covuntested'}
 count=0;pending=[];coverage_rows=[]
 for entry in coverage['entries']:
  expected=[]
  for system in columns:
   cell=entry['cells'][system];tested=cell['eunotos']['tested'];display=cell['display']
   if tested!=(display!='unmeasured'):raise ValueError('Coverage status disagrees')
   if tested and not cell['eunotos']['evidence']:raise ValueError('Coverage has no evidence binding')
   if not tested:pending.append([entry['id'],system])
   expected.append('\\'+('covhosted' if cell.get('hosted_thread_profile') else symbols[display]));coverage_rows.append([entry['id'],entry['name'],system,display,tested]);count+=1
  fragment=table.split('% coverage-row: '+entry['id']+'\n',1)[1].split('\\\\',1)[0]
  if not fragment.rstrip().endswith(' & '.join(expected)):raise ValueError('Table and index differ: '+entry['id'])
 if count!=70:raise ValueError('Coverage universe differs')
 output.mkdir(parents=True)
 with (output/'leaderboard.csv').open('w',newline='') as f:
  w=csv.writer(f);w.writerow(['configuration','task','communication','energy','allocated_ram','overall','rank'])
  for row in sorted(actual,key=lambda r:r['rank']):w.writerow([row['os'],row['task_index'],row['network_index'],row['energy_index'],row['ram_index'],scores[row['os']],row['rank']])
 with (output/'coverage.csv').open('w',newline='') as f:
  w=csv.writer(f);w.writerow(['subset','name','system','display','measured']);w.writerows(coverage_rows)
 receipt={'pass':True,'configurations':len(actual),'scalars':48,'reference':1,'preference_profiles':235,'coverage_cells':count,'unmeasured_cells':len(pending),'pending':pending,'scope':'Current score arithmetic and declared coverage bindings; new raw captures, ELF, RAM lifecycle and new coverage validators remain private. Legacy subset has its separate raw replay.','new_acquisitions':0,'new_model_calls':0}
 (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();main(a.output)
