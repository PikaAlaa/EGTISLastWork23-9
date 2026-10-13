"""Measure Decision-v2's validation recall cost and replay everyday probes."""
import hashlib,importlib.util,json,sys
from collections import Counter,defaultdict
from pathlib import Path
from datetime import date
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT)]
from app.core.database import Base
from app.engines import risk_scoring
from app.engines.text_model import score_text
from app.engines.rule_based.arabic_keyword_detector import calculate_arabic_keyword_phishing_score
from app.engines.rule_based.english_keyword_detector import calculate_english_keyword_phishing_score
from app.core.detection_signals import has_secret_request,has_phone_or_short_link_with_urgent_action
from app.services.registry import populate_registry
from evaluation.run_text_v3 import versions,sha
from evaluation.review_common import read_frozen,language,DIALECT,PROVENANCE,OUT as REPORT
def main():
 rows,split=read_frozen(); rows.loc[rows.source==DIALECT,'language']=rows.loc[rows.source==DIALECT,'text'].map(language); val=rows[rows.split=='val'].reset_index(drop=True); ph=val[val.label=='phishing']
 engine=create_engine('sqlite://');Base.metadata.create_all(engine); original=risk_scoring.blacklist_health
 risk_scoring.blacklist_health=lambda _db:{'available':True,'reason':None,'mode':'empty-evaluation-db'}
 moved=[]
 try:
  with Session(engine) as db:
   populate_registry(db)
   for row in ph.itertuples():
    finding=score_text(row.text); before_high=float(finding['probability'])>=float(finding.get('high_threshold',.8))
    after=risk_scoring.calculate_final_risk_score(text=row.text,db=db)['verdict']
    if before_high and after=='MEDIUM': moved.append({'language':str(row.language),'source':str(row.source)})
   spec=importlib.util.spec_from_file_location('review_cases',ROOT/'evaluation/review-evidence/cases.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
   daily=[]
   for i,text in enumerate(mod.EVERYDAY_SMS,1):
    finding=score_text(text);prob=float(finding['probability']);high=float(finding.get('high_threshold',.8));low=float(finding.get('low_threshold',.2))
    keywords=max(calculate_arabic_keyword_phishing_score(text)['score'],calculate_english_keyword_phishing_score(text)['score'])
    before='HIGH' if prob>=high else ('MEDIUM' if prob>low or keywords>=60 else 'LOW')
    after=risk_scoring.calculate_final_risk_score(text=text,db=db)['verdict']
    daily.append({'probe_id':f'everyday_{i:02d}','before_verdict':before,'after_verdict':after})
 finally:
  risk_scoring.blacklist_health=original;engine.dispose()
 by=defaultdict(Counter)
 for r in moved:
  by['language'][r['language']]+=1;by['source'][r['source']]+=1
 out={'stage':'development_validation','final_test_run':False,'data_sha256':split['dataset_identity']['dataset_sha256'],'validation_rows':len(val),'validation_phishing_rows':len(ph),'model_sha256':sha(ROOT/'ml/models/deployed_char.joblib'),'url_model_sha256':sha(ROOT/'ml/models/url_host_v3.joblib'),'baseline_model':'unchanged September deployed character model','libraries':versions(),'decision_policy':'decision-v2','high_to_medium_phishing_validation_count':len(moved),'high_to_medium_by_language':dict(by['language']),'high_to_medium_by_source':dict(by['source']),'everyday_probe_verdicts':daily,'everyday_before_counts':dict(Counter(x['before_verdict'] for x in daily)),'everyday_after_counts':dict(Counter(x['after_verdict'] for x in daily)),'nbe_probe':'accepted non-HIGH; strict xfail removed','limitations':['Everyday probes are invented regression fixtures, not population evidence.','Validation content is not authentic Egyptian SMS.']}
 out['source_provenance']=PROVENANCE;out['frozen_split_changed']=False;out['dialectal_metrics_usage']='Historical diagnostics only; excluded from selection.'
 (REPORT/'decision_metrics.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({k:out[k] for k in ['high_to_medium_phishing_validation_count','high_to_medium_by_language','high_to_medium_by_source','everyday_before_counts','everyday_after_counts']},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
