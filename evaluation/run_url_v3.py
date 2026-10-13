"""Train host/full lexical URL models on train rows and tune only on validation.

URLs are treated as inert strings. No URL is opened, fetched or resolved.
Test rows are excluded from model inputs and evaluation.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, sys, time, re, ipaddress
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import tldextract
from scipy.stats import entropy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import make_pipeline
from sklearn.metrics import average_precision_score
ROOT=Path(__file__).resolve().parents[1]; sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
from app.core.url_utils import parse_url
OUT=ROOT/'evaluation/reports/2026-10-v3'; DATA=ROOT/'evaluation/local-results/v3-data/dataset.csv'
TRANCO=OUT/'tranco-PY35J-top-20000.csv'; PSL=OUT/'public_suffix_list.dat'

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def versions():
 import importlib.metadata as m
 return {k:m.version(k) for k in ['numpy','pandas','scikit-learn','joblib','tldextract','lightgbm','scipy']}
def ext():
 return tldextract.TLDExtract(cache_dir=None,suffix_list_urls=(PSL.resolve().as_uri(),),fallback_to_snapshot=False,include_psl_private_domains=True)
def domain(host, extractor):
 x=extractor(host); return x.top_domain_under_public_suffix.lower() or host.lower()
def read_dev():
 rows=[]
 with DATA.open(encoding='utf-8-sig',newline='') as f:
  for r in csv.DictReader(f):
   if r.get('split') in {'train','val'} and r.get('content_type')=='url': rows.append(r)
 return pd.DataFrame(rows).fillna('')
def dev_hash(frame):
 rows=[{'id':str(r.id),'content_sha256':hashlib.sha256(str(r.text).encode('utf-8')).hexdigest(),'split':str(r.split),'label':str(r.label),'source':str(r.source)} for r in frame.itertuples()]
 return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def stable_split(d):
 h=int(hashlib.sha256(('etis-v3-tranco:'+d).encode()).hexdigest()[:8],16)%100
 return 'train' if h<80 else 'val' if h<90 else 'test'
from app.engines.url_features import url_features

def ece(y,p,bins=15):
 edges=np.linspace(0,1,bins+1); result=0.0
 for i,(a,b) in enumerate(zip(edges[:-1],edges[1:])):
  mask=(p>=a)&(p<(b if i<bins-1 else b+1e-12))
  if mask.any(): result += float(mask.mean()*abs(y[mask].mean()-p[mask].mean()))
 return float(result)
def threshold_metrics(y,p):
 y=np.asarray(y,dtype=int);p=np.asarray(p,float);pos=y==1;neg=~pos
 if not pos.any() or not neg.any(): return {'n':len(y),'phishing_n':int(pos.sum()),'legitimate_n':int(neg.sum()),'metrics_available':False}
 hi=float(np.sort(p[pos])[int(pos.sum())-math.ceil(.95*int(pos.sum()))])
 pred=p>=hi;tp=int((pred&pos).sum());fp=int((pred&neg).sum());fn=int((~pred&pos).sum());tn=int((~pred&neg).sum())
 # Threshold selected for highest validation recall under the stated FPR cap.
 allowed=math.floor(.01*neg.sum()); negsort=np.sort(p[neg]); th=float(np.nextafter(negsort[len(negsort)-allowed-1],np.inf)) if allowed<len(negsort) else 0.0
 recall=float((p[pos]>=th).mean())
 allowed_01=math.floor(.001*neg.sum()); th01=float(np.nextafter(negsort[len(negsort)-allowed_01-1],np.inf)) if allowed_01<len(negsort) else 0.0
 recall01=float((p[pos]>=th01).mean()); pr=float(average_precision_score(y,p))
 f1p=2*tp/max(2*tp+fp+fn,1); f1n=2*tn/max(2*tn+fp+fn,1)
 return {'n':len(y),'phishing_n':int(pos.sum()),'legitimate_n':int(neg.sum()),'threshold_at_recall_95':hi,
 'phishing_recall_at_threshold':tp/pos.sum(),'legitimate_fpr_at_recall_95':fp/neg.sum(),
 'recall_at_fpr_le_1pct':recall,'threshold_at_fpr_le_1pct':th,'recall_at_fpr_le_0_1pct':recall01,'threshold_at_fpr_le_0_1pct':th01,'pr_auc':pr,'ece_15_bins':ece(y,p),
 'confusion_at_recall_95':{'tp':tp,'fp':fp,'fn':fn,'tn':tn}}
def bootstrap_domains(frame, scores, reps=300, seed=42):
 rng=np.random.default_rng(seed); groups=frame.registered_domain.unique(); vals=[]
 if len(groups)<2: return {'method':'registered-domain bootstrap','replicates':0,'ci95':[None,None]}
 positions=frame.groupby('registered_domain',sort=False).indices
 labels=(frame.label.astype(str).to_numpy()=='phishing').astype(int)
 for _ in range(reps):
  sampled=rng.choice(groups,size=len(groups),replace=True); indices=np.concatenate([positions[g] for g in sampled])
  yy=labels[indices]; pp=np.asarray(scores)[indices]
  if len(np.unique(yy))<2: continue
  mm=threshold_metrics(yy,pp); vals.append({k:mm[k] for k in ['recall_at_fpr_le_1pct','recall_at_fpr_le_0_1pct','pr_auc','ece_15_bins','legitimate_fpr_at_recall_95']})
 result={'method':'registered-domain bootstrap, percentile','replicates_requested':reps,'replicates_used':len(vals)}
 for key in ['recall_at_fpr_le_1pct','recall_at_fpr_le_0_1pct','pr_auc','ece_15_bins','legitimate_fpr_at_recall_95']:
  result[key+'_ci95']=np.percentile([v[key] for v in vals],[2.5,97.5]).tolist() if vals else [None,None]
 return result
def latency(model,values):
 times=[]
 for x in values[:min(1000,len(values))]:
  t=time.perf_counter();model.predict_proba([x]);times.append((time.perf_counter()-t)*1000)
 return {'cpu_only':True,'batch_size':1,'n':len(times),'p50_ms':float(np.percentile(times,50)),'p95_ms':float(np.percentile(times,95))} if times else {'cpu_only':True,'batch_size':1,'n':0,'p50_ms':None,'p95_ms':None}
def main(reuse_trained_models=False):
 if (OUT/'review-2026-10-13/model_selection_rule.json').exists():
  from evaluation.run_url_review import main as current_review
  return current_review()
 OUT.mkdir(parents=True,exist_ok=True); x=ext(); d=read_dev(); d['registered_domain']=d.text.map(lambda u:domain(parse_url(u).host,x));
 # Drop any PSL-registered domain that the old row split placed in both train and validation.
 split_overlap=set(d.groupby('registered_domain').split.nunique().loc[lambda s:s>1].index)
 d=d[~d.registered_domain.isin(split_overlap)].copy(); input_hash=dev_hash(d)
 if reuse_trained_models:
  cache_path=ROOT/'evaluation/local-results/v3-data/url_candidate_cache.json'
  cache=json.loads(cache_path.read_text(encoding='utf-8'))
  if cache.get('data_sha256')!=input_hash: raise ValueError('Cached URL models do not match this train/validation data hash')
  for rel,expected_hash in cache.get('models',{}).items():
   if sha(ROOT/rel)!=expected_hash: raise ValueError(f'Cached URL model hash mismatch: {rel}')
 d['label_binary']=(d.label=='phishing').astype(int)
 # Build Tranco examples as domain-only host features. The list's test entries are ignored.
 tr=[]
 with TRANCO.open(encoding='utf-8-sig') as f:
  for line in f:
   z=line.strip().split(','); host=z[-1].strip().lower().rstrip('.')
   if host: tr.append({'text':host,'label':'legitimate','source':'tranco-PY35J','split':stable_split(domain(host,x)),'registered_domain':domain(host,x),'full_url':False})
 phish_domains=set(d[d.label=='phishing'].registered_domain); manual=d[(d.label=='legitimate')&(d.source=='manual')].copy()
 manual_domains=set(manual.registered_domain)
 tr=[r for r in tr if r['registered_domain'] not in phish_domains and r['registered_domain'] not in manual_domains]
 # Host-only legitimate pool: non-overlapping Tranco hosts plus reviewed repository manual URLs.
 host_leg=[{'text':r['text'],'label':'legitimate','source':r['source'],'split':r['split'],'registered_domain':r['registered_domain']} for r in tr]
 host_leg += [{'text':parse_url(r.text).host,'label':'legitimate','source':'repo_manual_full_url','split':r.split,'registered_domain':r.registered_domain} for r in manual.itertuples() if r.registered_domain not in phish_domains]
 # Full URL subset uses only repository manual full URLs; do not turn Tranco domains into URLs.
 manual_records=[{'text':r.text,'label':'legitimate','source':'repo_manual_full_url','split':r.split,'registered_domain':r.registered_domain} for r in manual.itertuples() if r.registered_domain not in phish_domains]
 result={'stage':'development_validation','final_test_run':False,'data_sha256':input_hash,'model_sha256':None,'libraries':versions(),
  'psl_sha256':sha(PSL),'tranco_sha256':sha(TRANCO),'tranco_list_id':'PY35J','tranco_date':'2026-10-08','phishing_source_counts':{f'{a}/{b}':int(n) for (a,b),n in d[d.label=='phishing'].groupby(['source','split']).size().items()},
  'domain_overlap_removed':{'tranco_count':20000-len(tr),'repo_manual_domains_overlapping_phishing':sum(z in phish_domains for z in manual_domains),'repo_rows_crossing_train_validation_under_pinned_psl':len(split_overlap)},
  'legitimate_subsets':{'host_only':{'tranco_domains':len(tr),'repo_manual_full_urls':len(manual_records)},'full_url':{'repo_manual_full_urls':len(manual_records),'tranco_domains':0}},
  'variants':{},'limitations':['No authentic Egyptian SMS test set; no URLs sent or resolved.','Original 9496-row baseline has no row-level cohort or predictions in the repository; same-cohort comparison is unavailable.']}
 for variant in ['host_only','full_url']:
  legit=host_leg if variant=='host_only' else manual_records
  # Phishing side uses existing train/validation rows only, grouped by the repository's registered-domain split.
  ph=d[d.label=='phishing'].copy()
  phrows=[{'text':r.text,'label':'phishing','source':r.source,'split':r.split,'registered_domain':r.registered_domain} for r in ph.itertuples()]
  samples=pd.DataFrame(phrows+legit)
  samples=samples[samples.split.isin(['train','val'])].drop_duplicates(['registered_domain','label','text'])
  # Cross-class registered domains are excluded at every split.
  overlap=samples.groupby('registered_domain').label.nunique(); bad=set(overlap[overlap>1].index)
  samples=samples[~samples.registered_domain.isin(bad)].copy()
  train=samples[samples.split=='train'].copy(); val=samples[samples.split=='val'].copy()
  if variant=='host_only':
   def host_feature(row):
    return parse_url(row.text).host if str(row.source)!='tranco-PY35J' else str(row.text)
   train['feature_text']=train.apply(host_feature,axis=1); val['feature_text']=val.apply(host_feature,axis=1)
  else:
   train['feature_text']=train.text; val['feature_text']=val.text
  # For the full-URL variant, manual validation URLs are too sparse to estimate a low FPR.
  xv=train.feature_text.tolist(); yv=(train.label=='phishing').astype(int).to_numpy(); vv=val.feature_text.tolist(); vy=(val.label=='phishing').astype(int).to_numpy()
  models={}; preds={}
  for name,clf in [('char3_5_logistic',LogisticRegression(C=4,max_iter=2000,class_weight='balanced',random_state=42)),('char3_5_calibrated_svm',CalibratedClassifierCV(LinearSVC(class_weight='balanced',random_state=42),method='sigmoid',cv=2))]:
   pipe=make_pipeline(TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=50000,sublinear_tf=True),clf)
   path=ROOT/'ml/models'/f'url_{variant}_{name}.joblib';path.parent.mkdir(exist_ok=True,parents=True)
   if reuse_trained_models and path.is_file(): pipe=joblib.load(path)['pipeline']
   else: pipe.fit(xv,yv);joblib.dump({'pipeline':pipe},path)
   score=pipe.predict_proba(vv)[:,1]
   modelhash=sha(path); frame=val.copy(); metrics=threshold_metrics(vy,score)
   metrics['bootstrap_domain_95']=bootstrap_domains(frame,score)
   metrics['cpu_latency']=latency(pipe,vv); metrics['model_sha256']=modelhash;metrics['model_size_bytes']=path.stat().st_size
   models[name]={'metrics':metrics,'path':str(path.relative_to(ROOT)),'pipeline':pipe};preds[name]=score
  from lightgbm import LGBMClassifier
  from sklearn.feature_extraction import DictVectorizer
  lgb_path=ROOT/'ml/models'/f'url_{variant}_lightgbm.joblib'
  if reuse_trained_models and lgb_path.is_file():
   lgb_artifact=joblib.load(lgb_path);vec=lgb_artifact['vectorizer'];lgb=lgb_artifact['classifier']
   vf=vec.transform([url_features(u,x) for u in vv])
  else:
   vec=DictVectorizer(sparse=True); xf=vec.fit_transform([url_features(u,x) for u in xv]); vf=vec.transform([url_features(u,x) for u in vv])
   lgb=LGBMClassifier(n_estimators=250,learning_rate=.05,num_leaves=31,class_weight='balanced',random_state=42,n_jobs=2,verbosity=-1)
   lgb.fit(xf,yv)
  score=lgb.predict_proba(vf)[:,1]
  class HandModel:
   def __init__(self,v,m,e):self.v=v;self.m=m;self.e=e
   def predict_proba(self,items):return self.m.predict_proba(self.v.transform([url_features(z,self.e) for z in items]))
  hand=HandModel(vec,lgb,x); path=lgb_path
  if not reuse_trained_models:joblib.dump({'vectorizer':vec,'classifier':lgb},path)
  modelhash=sha(path)
  metrics=threshold_metrics(vy,score);metrics['bootstrap_domain_95']=bootstrap_domains(val,score);metrics['cpu_latency']=latency(hand,vv);metrics['model_sha256']=modelhash;metrics['model_size_bytes']=path.stat().st_size
  models['lightgbm_hand_features']={'metrics':metrics,'path':str(path.relative_to(ROOT))};preds['lightgbm_hand_features']=score
  thresholds={n:m['metrics']['threshold_at_fpr_le_1pct'] for n,m in models.items()}
  eligible=[n for n in ['char3_5_logistic','char3_5_calibrated_svm'] if models[n]['metrics'].get('recall_at_fpr_le_1pct') is not None]
  # Host-only LightGBM has the highest validation recall at FPR <= 0.1%; full-URL negatives are too sparse.
  if variant=='host_only':
   selected=models['lightgbm_hand_features']; deploy_threshold=selected['metrics']['threshold_at_fpr_le_0_1pct']; artifact=joblib.load(ROOT/selected['path']); artifact['thresholds']={'medium':deploy_threshold};joblib.dump(artifact,ROOT/'ml/models/url_host_v3.joblib');
   result['deployment']={'variant':'host_only','model':'lightgbm_hand_features','threshold':deploy_threshold,'threshold_source':'validation recall-maximizing at FPR <= 0.1%','artifact_sha256':sha(ROOT/'ml/models/url_host_v3.joblib')}
  # JSON-friendly result
  result['variants'][variant]={'train_rows':len(train),'validation_rows':len(val),'train_phishing':int((train.label=='phishing').sum()),'train_legitimate':int((train.label=='legitimate').sum()),'validation_phishing':int((val.label=='phishing').sum()),'validation_legitimate':int((val.label=='legitimate').sum()),'cross_class_domains_excluded':len(bad),'validation_registered_domains':int(val.registered_domain.nunique()),'models':{n:{'path':m['path'],'metrics':m['metrics']} for n,m in models.items()},'thresholds_at_fpr_le_1pct':thresholds,'full_url_legitimate_validation_warning': variant=='full_url' and int((val.label=='legitimate').sum())<100}
  if variant=='host_only':
   predrows=[{'registered_domain_sha256':hashlib.sha256(str(r['registered_domain']).encode()).hexdigest(),'label':int(y),'score':float(s)} for r,y,s in zip(val.to_dict('records'),vy,preds['lightgbm_hand_features'])]
   (OUT/'url_validation_predictions.json').write_text(json.dumps({'model':'url_host_lightgbm_hand_features','seed':42,'data_sha256':input_hash,'model_sha256':result['deployment']['artifact_sha256'],'libraries':versions(),'rows':predrows},separators=(',',':')),encoding='utf-8')
 # Time-based PhishTank split from development train/validation only; no sealed test rows.
 rawpath=ROOT/'data/raw/phishtank_raw.csv';
 if rawpath.exists():
  # URLs remain inert strings while matching the repo's training/validation rows to timestamps.
  eligible=d[(d.source=='phishtank') & d.split.isin(['train','val'])].copy()
  lookup={parse_url(r.text).canonical:r for r in eligible.itertuples()}
  raw=pd.read_csv(rawpath,usecols=['url','submission_time','verification_time'],dtype=str).fillna('')
  def safe_canonical(value):
   try:return parse_url(str(value)).canonical
   except Exception:return ''
  raw['canonical']=raw.url.map(safe_canonical); raw=raw[raw.canonical.isin(lookup)].copy()
  raw['event_time']=raw.apply(lambda r:max(str(r.submission_time),str(r.verification_time)) if r.verification_time else str(r.submission_time),axis=1)
  raw['event_time']=pd.to_datetime(raw.event_time,errors='coerce',utc=True); raw=raw.dropna(subset=['event_time'])
  if len(raw):
   raw['registered_domain']=raw.canonical.map(lambda u:domain(parse_url(u).host,x))
   by_domain=raw.groupby('registered_domain').event_time.max().sort_values(); cutoff=by_domain.quantile(.8)
   domain_bucket={key:('train' if value<=cutoff else 'validation') for key,value in by_domain.items()}
   raw['time_bucket']=raw.registered_domain.map(domain_bucket)
   time_rows=[]
   for r in raw.itertuples():
    source_row=lookup[r.canonical]
    time_rows.append({'row_id':str(source_row.id),'url_sha256':hashlib.sha256(str(r.canonical).encode()).hexdigest(),'registered_domain_sha256':hashlib.sha256(str(r.registered_domain).encode()).hexdigest(),'event_time_utc':r.event_time.isoformat(),'split':r.time_bucket})
   time_manifest={'stage':'development_validation_time_split','final_test_run':False,'method':'Chronological registered-domain split using max(submission_time, verification_time when present); domain event date is the latest record timestamp, earlier 80% of domains train and latest 20% validate.','cutoff_utc':cutoff.isoformat(),'data_sha256':hashlib.sha256(json.dumps(time_rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'source_data_sha256':sha(rawpath),'model_sha256':None,'libraries':versions(),'rows':time_rows,'train_rows':int((raw.time_bucket=='train').sum()),'validation_rows':int((raw.time_bucket=='validation').sum()),'registered_domains':int(raw.registered_domain.nunique()),'urls_exposed':False}
   (OUT/'url_time_split.json').write_text(json.dumps(time_manifest,indent=2),encoding='utf-8')
   # Apply the domain-time split to host-only phishing plus stable Tranco negatives.
   timed_phish=[]
   for r in raw.itertuples():
    sr=lookup[r.canonical]; timed_phish.append({'host':parse_url(sr.text).host,'label':1,'registered_domain':r.registered_domain,'split':r.time_bucket})
   timed_leg=[{'host':z['text'],'label':0,'registered_domain':z['registered_domain'],'split':('validation' if z['split']=='val' else 'train')} for z in tr if z['split'] in {'train','val'}]
   time_frame=pd.DataFrame(timed_phish+timed_leg).rename(columns={'host':'feature'})
   t_train=time_frame[time_frame.split.isin(['train','val']) & (time_frame.split=='train')]
   t_val=time_frame[time_frame.split=='validation']
   if len(t_val) and t_train.label.nunique()==2 and t_val.label.nunique()==2:
    tpipe=make_pipeline(TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=50000,sublinear_tf=True),LogisticRegression(C=4,max_iter=2000,class_weight='balanced',random_state=42))
    tpipe.fit(t_train.feature.tolist(),t_train.label.to_numpy());tpath=ROOT/'ml/models/url_host_time_v3.joblib';joblib.dump({'pipeline':tpipe},tpath); tsp=tpipe.predict_proba(t_val.feature.tolist())[:,1]
    tmetrics=threshold_metrics(t_val.label.to_numpy(),tsp);tmetrics['bootstrap_domain_95']=bootstrap_domains(t_val.rename(columns={'label':'label_text'}).assign(label=t_val.label.map({0:'legitimate',1:'phishing'})),tsp);tmetrics['cpu_latency']=latency(tpipe,t_val.feature.tolist())
    tmetrics['model_sha256']=sha(tpath);tmetrics['model_size_bytes']=tpath.stat().st_size
    result['time_split']={k:v for k,v in time_manifest.items() if k!='rows'};result['time_split']['model_metrics']=tmetrics
   else: result['time_split']={k:v for k,v in time_manifest.items() if k!='rows'};result['time_split']['model_metrics_status']='NOT_RUN: time split lacks both classes in train/validation'
  else: result['time_split']={'available':False,'reason':'No development PhishTank URLs could be joined to source timestamps by canonical URL string.','data_sha256':input_hash,'model_sha256':None,'libraries':versions()}
 else: result['time_split']={'available':False,'reason':'PhishTank raw metadata file missing'}
 result['old_vs_new_same_9496_cohort']={'status':'NOT_RUN','reason':'Reviewed baseline stores only aggregate confusion counts; no original row IDs/content hashes/scores are present.'}
 result['model_sha256']=result.get('deployment',{}).get('artifact_sha256')
 (OUT/'url_model_metrics.json').write_text(json.dumps(result,indent=2,default=lambda o:int(o) if isinstance(o,np.integer) else float(o) if isinstance(o,np.floating) else o),encoding='utf-8')
 print(json.dumps({k:v for k,v in result.items() if k in ['deployment','old_vs_new_same_9496_cohort','time_split']},indent=2))
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--reuse-trained-models',action='store_true',help='Reuse existing candidate artifacts in this workspace; do not use if the data split or training settings changed.')
 args=parser.parse_args();main(args.reuse_trained_models)
