"""Validate and merge six local-runtime transformer prediction files."""
import hashlib, json, statistics, math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; REPORT=ROOT/'evaluation/reports/2026-10-v3'; PRED=REPORT/'predictions'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def metrics(labels,scores,threshold_95=None,threshold_1=None):
 import numpy as np
 from sklearn.metrics import f1_score,average_precision_score
 y=np.asarray(labels,dtype=int);p=np.asarray(scores,dtype=float);pos=y==1;neg=~pos
 high=threshold_95
 if high is None: high=max(float(t) for t in np.unique(p[pos]) if float((p[pos]>=t).mean())>=.95)
 pred=p>=high; tp=int((pred&pos).sum());fp=int((pred&neg).sum());fn=int((~pred&pos).sum());tn=int((~pred&neg).sum())
 allowed=int(.01*neg.sum()); n=np.sort(p[neg]); threshold=threshold_1
 if threshold is None: threshold=float(np.nextafter(n[len(n)-allowed-1],np.inf)) if allowed<len(n) else 0.0
 edges=np.linspace(0,1,16);ece=0.0
 for i,(a,b) in enumerate(zip(edges[:-1],edges[1:])):
  m=(p>=a)&(p<(b if i<14 else b+1e-12))
  if m.any():ece+=float(m.mean()*abs(y[m].mean()-p[m].mean()))
 f1p=2*tp/max(2*tp+fp+fn,1);f1n=2*tn/max(2*tn+fp+fn,1)
 return {'n':len(y),'macro_f1_at_recall_95':float((f1p+f1n)/2),'threshold_at_recall_95':high,'legitimate_fpr_at_recall_95':float(fp/neg.sum()) if neg.any() else None,'recall_at_fpr_le_1pct':float((p[pos]>=threshold).mean()) if pos.any() else None,'threshold_at_fpr_le_1pct':threshold,'ece_15_bins':ece,'pr_auc':float(average_precision_score(y,p)) if pos.any() and neg.any() else None,'confusion_at_recall_95':{'tp':tp,'fp':fp,'fn':fn,'tn':tn}}
def main():
 split=json.loads((REPORT/'text_split.json').read_text(encoding='utf-8')); expected={r['row_id']:(r['content_sha256'],int(r['label']=='phishing'),r['split'],r['source'],r['language'],r['content_type']) for r in split['rows'] if r['split']=='val'}
 overlay_path=REPORT/'review-2026-10-13/language_overlay.json'
 if overlay_path.exists():
  overlay=json.loads(overlay_path.read_text(encoding='utf-8'))
  if overlay['data_sha256']!=split['data_sha256']:raise ValueError('Language overlay split identity differs')
  for row in overlay['rows']:
   if row['row_id'] in expected:
    values=list(expected[row['row_id']]);values[4]=row['corrected_language'];expected[row['row_id']]=tuple(values)
 by_model={}; inputs=[]
 for name in ['marbertv2','camelbert_da']:
  runs=[]
  for seed in [42,43,44]:
   path=PRED/f'{name}_seed{seed}.json'
   if not path.is_file():raise FileNotFoundError(f'Missing {path.name}')
   obj=json.loads(path.read_text(encoding='utf-8'));inputs.append({'file':path.name,'sha256':sha(path)})
   if obj.get('data_sha256')!=split['dataset_identity']['dataset_sha256'] or obj.get('text_split_sha256')!=split['text_split_sha256'] or obj.get('seed')!=seed:raise ValueError(f'Split or seed mismatch in {path.name}')
   if obj.get('runtime')!='local':raise ValueError(f'Local-runtime provenance is required in {path.name}')
   rows=obj['rows']; got={r['row_id'] for r in rows}
   if got!=set(expected) or len(rows)!=len(expected):raise ValueError(f'Validation row set differs or contains duplicates in {path.name}')
   if any(not math.isfinite(float(r['score'])) or not 0<=float(r['score'])<=1 for r in rows):raise ValueError(f'Invalid prediction scores in {path.name}')
   if not obj.get('cpu_latency',{}).get('cpu_only') or obj['cpu_latency'].get('batch_size')!=1:raise ValueError(f'CPU batch-size-one latency is required in {path.name}')
   for r in rows:
    h,y,*_=expected[r['row_id']]
    if r['content_sha256']!=h or r['label']!=y:raise ValueError(f'Content or label mismatch for row {r["row_id"]}')
   rows=sorted(rows,key=lambda r:r['row_id']); eligible=[r for r in rows if expected[r['row_id']][3]!='kaggle_dialectal_arabic_sms']; labels=[r['label'] for r in eligible]; scores=[r['score'] for r in eligible]; m=metrics(labels,scores)
   subgroup={}
   for dimension,index in [('source',3),('language',4),('content_type',5)]:
    subgroup[dimension]={}
    for group in sorted({expected[r['row_id']][index] for r in rows}):
     subset=[r for r in rows if expected[r['row_id']][index]==group]
     subgroup[dimension][group]=metrics([r['label'] for r in subset],[r['score'] for r in subset],m['threshold_at_recall_95'],m['threshold_at_fpr_le_1pct'])
     if dimension=='source':
      subgroup[dimension][group]['provenance']={'kaggle_arabic_phishing_fully_dataset':'translated fraud letters and UCI ham; not Egyptian SMS','salloum_gaber_bilingual_corpus':'translated/parallel emails; not Egyptian SMS','kaggle_dialectal_arabic_sms':'mixed-regional/non-Egyptian markers; apparently templated; origin unverified; training only'}.get(group,'not established')
      subgroup[dimension][group]['selection_eligible']=group!='kaggle_dialectal_arabic_sms'
   dialect='kaggle_dialectal_arabic_sms'
   subgroup['kaggle_dialectal_source']={'source':dialect,'geographic_interpretation':'Mixed-regional and apparently templated; not an authenticated Egyptian source; training only','metrics':subgroup['source'].get(dialect)}
   m['subgroups']=subgroup
   m.update({'seed':seed,'model_sha256':obj['model_sha256'],'model_size_bytes':obj['model_size_bytes'],'cpu_latency':obj['cpu_latency'],'libraries':obj['libraries']});runs.append(m)
  def mean(field):return statistics.mean(r[field] for r in runs)
  by_model[name]={'seeds':runs,'mean_macro_f1_at_recall_95':mean('macro_f1_at_recall_95'),'mean_legitimate_fpr_at_recall_95':mean('legitimate_fpr_at_recall_95'),'mean_recall_at_fpr_le_1pct':mean('recall_at_fpr_le_1pct'),'mean_ece_15_bins':mean('ece_15_bins'),'mean_cpu_p50_ms':statistics.mean(r['cpu_latency']['p50_ms'] for r in runs),'mean_cpu_p95_ms':statistics.mean(r['cpu_latency']['p95_ms'] for r in runs),'model_sha256_by_seed':[r['model_sha256'] for r in runs]}
 out={'stage':'development_validation','final_test_run':False,'data_sha256':split['dataset_identity']['dataset_sha256'],'text_split_sha256':split['text_split_sha256'],'model_sha256':None,'libraries':{'numpy':__import__('numpy').__version__,'pandas':__import__('pandas').__version__,'scikit-learn':__import__('sklearn').__version__},'input_prediction_files':inputs,'models':by_model,'aggregation':'unweighted mean across three seeds; seed-specific validation metrics retained','model_selection_rule':'Apply model_selection_rule.json after comparing local results; transformer results are external to this run and require local-runtime provenance.'}
 local=json.loads((REPORT/'text_local_metrics.json').read_text(encoding='utf-8'))
 combined={'stage':'development_validation_model_comparison','final_test_run':False,'data_sha256':split['dataset_identity']['dataset_sha256'],'text_split_sha256':split['text_split_sha256'],'model_sha256':None,'libraries':out['libraries'],'local_models':local['models'],'transformer_models':by_model,'selection_rule':json.loads((REPORT/'model_selection_rule.json').read_text(encoding='utf-8')),'final_choice_waits_for_transformers':False,'input_prediction_files':inputs}
 revised=REPORT/'review-2026-10-13/model_selection_rule.json'
 if revised.exists():combined['selection_rule']=json.loads(revised.read_text())
 combined['final_choice']=False
 combined['final_choice_waits_for_transformers']=True
 combined['selection_status']='INCOMPLETE: validation predictions alone cannot select a winner. Supply transformer leave-one-source-out and everyday-probe evidence under the revised rule.'
 out['model_selection_rule']=combined['selection_status']
 (REPORT/'combined_model_comparison.json').write_text(json.dumps(combined,indent=2),encoding='utf-8')
 (REPORT/'transformer_comparison.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps({k:{'mean_macro_f1':v['mean_macro_f1_at_recall_95'],'mean_legit_fpr':v['mean_legitimate_fpr_at_recall_95']} for k,v in by_model.items()},indent=2))
if __name__=='__main__':main()
