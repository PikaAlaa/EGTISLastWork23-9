"""Paired URL shortcut ablation on development rows, using the repository Tranco only.

No destination fetches. Full-URL models are diagnostic, never deployment candidates.
The original frozen splits are not rewritten. Private-PSL train/val overlaps are excluded.
"""
import hashlib,json,math,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
import joblib,numpy as np,pandas as pd
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from lightgbm import LGBMClassifier
from app.core.url_utils import parse_url
from app.engines.url_features import url_features
from evaluation.run_url_v3 import ext,domain,read_dev,dev_hash,threshold_metrics,bootstrap_domains,latency,PSL
from evaluation.review_common import OUT,PREVIOUS,write,sha

def confusion(y,p,t):
    pos=np.asarray(y)==1; pred=np.asarray(p)>=t
    tp=int((pos&pred).sum());fp=int((~pos&pred).sum());fn=int((pos&~pred).sum());tn=int((~pos&~pred).sum())
    return {'tp':tp,'fp':fp,'fn':fn,'tn':tn,'recall':tp/max(tp+fn,1),'false_positive_rate':fp/max(fp+tn,1),'threshold':t}

def shortcut(value):
    p=parse_url(value)
    return {'total_length':len(value),'path_length':len(p.path),'query_length':len(p.query),
            'has_nonroot_path':int(p.path not in ('','/')),'has_query':int(bool(p.query)),
            'https':int(str(value).lower().startswith('https://'))}

def describe(d):
    result={}
    for label,g in d.groupby('label'):
        f=[shortcut(u) for u in g.text]
        result[label]={'n':len(g),'median_length':float(np.median([x['total_length'] for x in f])),
          'path_fraction':float(np.mean([x['has_nonroot_path'] for x in f])),
          'query_fraction':float(np.mean([x['has_query'] for x in f])),
          'https_fraction':float(np.mean([x['https'] for x in f])),
          'sources':g.source.value_counts().to_dict()}
    return result

class HandModel:
    def __init__(self,vec,clf,extractor,short=False):self.vec=vec;self.clf=clf;self.extractor=extractor;self.short=short
    def predict_proba(self,items):
        features=[shortcut(u) if self.short else url_features(u,self.extractor) for u in items]
        return self.clf.predict_proba(self.vec.transform(features))

def main():
    # Save URL-specific selection policy before fitting anything in this script.
    rule={'host_only_primary':True,'candidate_order':['lightgbm','char_logistic','char_calibrated_svm'],
      'selection':'Highest development recall at FPR <= 0.1%, CPU p95 <= 300 ms; exact tie follows candidate_order.',
      'ablation':'Identical development rows for host-only, full URLs, and shortcut-only model. Per-model validation thresholds; paired full-URL path removal keeps its threshold fixed.',
      'path_removal':'Replace path with / and remove query/fragment, preserve scheme and authority. Diagnostic perturbation, not new genuine data.',
      'tranco_source':'data/raw/tranco_final_approved.csv','tranco_list_id':None,'tranco_list_date':None,
      'limitations':['Tranco list ID and original download date not recorded.','No licensed genuine legitimate path URLs available; import pending GramBeddings attachment.','Thresholds and model selection share exposed validation; results are development estimates.']}
    rule_path=OUT/'url_selection_rule.json'
    if not rule_path.exists():write('url_selection_rule.json',rule)
    x=ext();d=read_dev();d['registered_domain']=d.text.map(lambda u:domain(parse_url(u).host,x))
    # This reuses exactly the existing frozen Tranco examples and verifies their hosts
    # against the approved raw list; no freshly downloaded list or synthetic paths.
    tranco=ROOT/r'data/raw/tranco_final_approved.csv';hosts=set(pd.read_csv(tranco).domain.str.lower())
    legit=d[d.label=='legitimate'];unknown=[u for u in legit[legit.source!='manual'].text if parse_url(u).host not in hosts]
    assert not unknown, 'Legitimate development hosts not present in existing approved Tranco'
    overlap=set(d.groupby('registered_domain').split.nunique().loc[lambda v:v>1].index)
    cross=set(d.groupby('registered_domain').label.nunique().loc[lambda v:v>1].index)
    samples=d[~d.registered_domain.isin(overlap|cross)].copy()
    tr=samples[samples.split=='train'].reset_index(drop=True);v=samples[samples.split=='val'].reset_index(drop=True)
    assert set(tr.registered_domain).isdisjoint(v.registered_domain)
    y=(tr.label=='phishing').astype(int).to_numpy();vy=(v.label=='phishing').astype(int).to_numpy()
    datahash=dev_hash(samples);md=OUT/'models/url';md.mkdir(parents=True,exist_ok=True)
    from urllib.parse import urlsplit,urlunsplit
    stripped=[urlunsplit((p.scheme,p.netloc,'/','','')) for p in map(urlsplit,v.text)]
    results={'data_sha256':datahash,'rule_sha256':sha(rule_path),'psl_sha256':sha(PSL),
      'tranco_raw_sha256':sha(ROOT/'data/raw/tranco_raw.csv'),'tranco_approved_sha256':sha(tranco),
      'tranco_list_id':None,'tranco_list_date':None,'source_counts':samples.groupby(['split','source','label']).size().to_dict(),
      'development_before_exclusions':describe(d),'development_after_exclusions':describe(samples),
      'train_rows':len(tr),'validation_rows':len(v),'cross_split_domains_excluded':len(overlap),'cross_class_domains_excluded':len(cross),
      'legitimate_path_data_status':'BLOCKED: PhiUSIIL legitimate URLs contain no non-root path/query; GramBeddings requires personal-information form. Await attachment.',
      'variants':{},'limitations':rule['limitations'],'final_test_run':False}
    results['source_counts']={'/'.join(k):int(n) for k,n in results['source_counts'].items()}
    scores={};artifacts={}
    for variant in ['host_only','full_url','shortcut_only']:
        tx=tr.text.map(lambda u:parse_url(u).host).tolist() if variant=='host_only' else tr.text.tolist()
        vx=v.text.map(lambda u:parse_url(u).host).tolist() if variant=='host_only' else v.text.tolist()
        names=['char_logistic','char_calibrated_svm','lightgbm'] if variant!='shortcut_only' else ['lightgbm']
        results['variants'][variant]={}
        for name in names:
            if name=='lightgbm':
                features=lambda items:[shortcut(u) if variant=='shortcut_only' else url_features(u,x) for u in items]
                vec=DictVectorizer();xf=vec.fit_transform(features(tx))
                clf=LGBMClassifier(n_estimators=250,learning_rate=.05,num_leaves=31,class_weight='balanced',random_state=42,n_jobs=2,verbosity=-1)
                clf.fit(xf,y);model=HandModel(vec,clf,x,variant=='shortcut_only');artifact={'vectorizer':vec,'classifier':clf}
            else:
                clf=LogisticRegression(C=4,max_iter=2000,class_weight='balanced',random_state=42) if name=='char_logistic' else CalibratedClassifierCV(LinearSVC(class_weight='balanced',random_state=42),method='sigmoid',cv=2)
                model=make_pipeline(TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=50000,sublinear_tf=True),clf)
                model.fit(tx,y);artifact={'pipeline':model}
            p=model.predict_proba(vx)[:,1];path=md/f'{variant}_{name}.joblib';joblib.dump(artifact,path)
            m=threshold_metrics(vy,p);m['model_sha256']=sha(path);m['model_size_bytes']=path.stat().st_size
            m['cpu_latency']=latency(model,vx[:300]);m['bootstrap_domain_95']=bootstrap_domains(v,p)
            m['at_1pct']=confusion(vy,p,m['threshold_at_fpr_le_1pct']);m['at_0_1pct']=confusion(vy,p,m['threshold_at_fpr_le_0_1pct'])
            if variant=='full_url':
                sp=model.predict_proba(stripped)[:,1]
                m['same_model_paths_removed']={'fixed_1pct_threshold':confusion(vy,sp,m['threshold_at_fpr_le_1pct']),
                  'fixed_0_1pct_threshold':confusion(vy,sp,m['threshold_at_fpr_le_0_1pct']),
                  'mean_probability_delta_full_minus_stripped_phishing':float(np.mean((p-sp)[vy==1])),
                  'mean_probability_delta_full_minus_stripped_legitimate':float(np.mean((p-sp)[vy==0])),
                  'interpretation':'Paired feature sensitivity, not a causal fraction of phishing detection.'}
            scores[(variant,name)]=p;artifacts[(variant,name)]=path;results['variants'][variant][name]=m
            print(variant,name,m['at_1pct'],flush=True)
            write('url_review_metrics.json',results)
    eligible=[n for n in rule['candidate_order'] if results['variants']['host_only'][n]['cpu_latency']['p95_ms']<=300]
    winner=max(eligible,key=lambda n:results['variants']['host_only'][n]['recall_at_fpr_le_0_1pct'])
    winner_metrics=results['variants']['host_only'][winner];artifact=joblib.load(artifacts[('host_only',winner)])
    artifact['thresholds']={'medium':winner_metrics['threshold_at_fpr_le_0_1pct']}
    artifact['training_metadata']={'data_sha256':datahash,'features':'host_only','tranco_list_id':None,'tranco_list_date':None,'report':'evaluation/reports/2026-10-v3/review-2026-10-13/url_review_metrics.json'}
    deploy=ROOT/'ml/models/url_host_v3.joblib';joblib.dump(artifact,deploy)
    results['deployment']={'model':winner,'features':'host_only','threshold':artifact['thresholds']['medium'],'artifact_sha256':sha(deploy)}
    results['model_sha256']=sha(deploy)
    records=[{'row_id':r.id,'content_sha256':hashlib.sha256(r.text.encode()).hexdigest(),'registered_domain_sha256':hashlib.sha256(r.registered_domain.encode()).hexdigest(),'split':r.split,'label':r.label,'source':r.source} for r in samples.itertuples()]
    write('url_split_manifest.json',{'data_sha256':datahash,'rows':records,'psl_sha256':sha(PSL),'model_sha256':sha(deploy)})
    write('url_review_metrics.json',results)
    print('DEPLOYMENT',results['deployment'],flush=True)

if __name__=='__main__':main()
