"""End-to-end current policy and temporal stress check using existing local data only."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend'),str(ROOT/'evaluation')]
import numpy as np,pandas as pd,joblib
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from app.core.url_utils import parse_url
from evaluation.run_url_v3 import read_dev,threshold_metrics,ext,domain,bootstrap_domains,latency
from evaluation.run_url_benchmark import benchmark
from evaluation.review_common import OUT,PREVIOUS,sha,write

def main():
    manifest=json.loads((OUT/'url_split_manifest.json').read_text());ids={r['row_id'] for r in manifest['rows']}
    allrows=read_dev();d=allrows[allrows.id.isin(ids)].copy();x=ext()
    d['registered_domain']=d.text.map(lambda u:domain(parse_url(u).host,x))
    # The private PSL refines existing groups. Verify there is no group collapse that
    # could cross an unseen sealed boundary, without opening sealed URL records.
    compatible=d.apply(lambda r:r.registered_domain==r.group_id or r.registered_domain.endswith('.'+r.group_id),axis=1)
    assert compatible.all()
    current=benchmark(d[(d.split=='train')&(d.label=='phishing')].text.tolist(),d[d.split=='val'])
    write('url_policy_replay.json',{'data_sha256':manifest['data_sha256'],'model_sha256':sha(ROOT/'ml/models/url_host_v3.joblib'),
      'scope':'Current integrated MEDIUM-or-HIGH policy on the cleaned development validation cohort, using training-only frozen blacklist.',
      'result':current,'psl_refines_frozen_groups_verified':True,'sealed_rows_selected_or_scored':False})
    # Reuse the previously saved source timestamp membership; no new feed fetch.
    old=json.loads((PREVIOUS/'url_time_split.json').read_text())
    assignment={r['row_id']:r['split'] for r in old['rows']}
    ph=d[(d.source=='phishtank')&d.id.isin(assignment)].copy();ph['time_split']=ph.id.map(assignment).replace({'validation':'val'})
    leg=d[d.label=='legitimate'].copy();leg['time_split']=leg.split
    timed=pd.concat([ph,leg]);train=timed[timed.time_split=='train'];val=timed[timed.time_split=='val']
    assert set(train.registered_domain).isdisjoint(val.registered_domain)
    tx=train.text.map(lambda u:parse_url(u).host).tolist();vx=val.text.map(lambda u:parse_url(u).host).tolist()
    pipe=make_pipeline(TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=50000,sublinear_tf=True),LogisticRegression(C=4,max_iter=2000,class_weight='balanced',random_state=42))
    pipe.fit(tx,(train.label=='phishing').astype(int));scores=pipe.predict_proba(vx)[:,1]
    path=OUT/'models/url/host_only_time_char_logistic.joblib';joblib.dump({'pipeline':pipe},path)
    metrics=threshold_metrics((val.label=='phishing').astype(int),scores)
    metrics['bootstrap_domain_95']=bootstrap_domains(val,scores);metrics['cpu_latency']=latency(pipe,vx[:300])
    write('url_time_review.json',{'data_sha256':manifest['data_sha256'],'model_sha256':sha(path),
      'prior_time_manifest_sha256':sha(PREVIOUS/'url_time_split.json'),'cutoff_utc':old['cutoff_utc'],
      'train_rows':len(train),'validation_rows':len(val),'metrics':metrics,
      'source_counts':{'/'.join(k):int(n) for k,n in timed.groupby(['time_split','source','label']).size().items()},
      'limitations':['Domain-recency stress test, not strictly forward-time: latest date assigns the whole domain including earlier URLs.',
        'Tranco original list ID/date unknown; negatives use the repository list, not a historical snapshot matched to the cutoff.',
        'Tests character-logistic host representation, not a temporal estimate for deployed LightGBM.']})
    print('Current policy',current['medium_or_high']['confusion']);print('Time stress',metrics['recall_at_fpr_le_1pct'])

if __name__=='__main__':main()
