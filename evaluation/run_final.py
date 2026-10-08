"""One-shot final text/SMS evaluation, gated on frozen targets and real independent data.
It reads local files only and never sends submitted messages to public services.
"""
import argparse,hashlib,json,sys
from pathlib import Path
import pandas as pd,joblib
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
from metrics import binary_metrics,proportion
from app.engines.text_model import score_text
from app.core.settings import settings
from app.core.text_utils import normalize_arabic_text,text_windows
from app.core.dataset_identity import dataset_identity
from model_predictions import predict as predict_model
def run(dataset,sealed_sms,targets,output):
    target=json.loads(Path(targets).read_text())
    if not target.get('approved_by') or not target.get('approved_at') or target.get('new_domain_minimum_recall') is None:
        raise ValueError('Freeze supervisor-approved targets, including the development-derived new-domain minimum, before final evaluation.')
    d=pd.read_csv(dataset,low_memory=False).fillna('');sms=pd.read_csv(sealed_sms).fillna('')
    if len(sms)<target['real_sms_minimum'] or not sms.source.eq('consented_sms').all() or not sms.label.eq('legitimate').all():
        raise ValueError('A sealed set of at least 200 consented, anonymized, genuine everyday SMS is required.')
    if 'group_id' not in sms or sms.group_id.nunique()<target['real_sms_minimum']:
        raise ValueError('At least 200 independent sealed SMS template groups are required.')
    test=d[(d.split=='test')&d.content_type.isin(['text','email'])].copy()
    if set(test.group_id)&set(d[d.split.isin(['train','val'])].group_id):raise ValueError('Group leakage')
    if set(sms.group_id)&set(d.group_id):raise ValueError('Sealed SMS group leakage')
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    reservation=output/'FINAL_RUN_LOCK.json'
    metadata={**dataset_identity(dataset),
        'sealed_sms_identity':dataset_identity(sealed_sms),
        'targets_sha256':hashlib.sha256(Path(targets).read_bytes()).hexdigest(),'model':settings.model_backend,'policy':'decision-v2'}
    selection=json.loads((ROOT/'evaluation/local-results/model-selection.json').read_text())
    if any(metadata[key]!=selection.get(key) for key in ['dataset_sha256','dataset_fingerprint_method']):raise ValueError('Dataset differs from model selection')
    from ml.select_model import checked_reports
    _,current=checked_reports(dataset)  # Reject stale candidates before reserving a final run.
    for name,candidate in current.items():
        for key in ['artifact_sha256','tokenizer_sha256','low_threshold','high_threshold']:
            if candidate.get(key)!=selection['candidates'][name].get(key):raise ValueError('Candidate differs from frozen model selection')
    if selection['selected']!=settings.model_backend:raise ValueError('Runtime differs from selected model')
    # Exclusive creation makes a second scoring run explicit instead of silently retuning on sealed results.
    with reservation.open('x',encoding='utf-8') as f:json.dump(metadata,f,indent=2)
    reports={}
    for name in ['bilstm','char','lightgbm']:
        probabilities,threshold,model_hash=predict_model(test.text.tolist(),name)
        test['prediction']=[p>=threshold for p in probabilities]
        report={'all':binary_metrics(test.label.eq('phishing').tolist(),test.prediction.tolist()),'by_source':{},'by_language':{},'by_content_type':{},'artifact_sha256':model_hash}
        for column in ['source','language','content_type']:
            for value,group in test.groupby(column):report['by_'+column][value]=binary_metrics(group.label.eq('phishing').tolist(),group.prediction.tolist())
        reports[name]=report
    # Evaluate the complete scanner on sealed SMS, including keyword rules and embedded links.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from datetime import date
    from app.core.database import Base
    from app.core.url_utils import parse_url,url_hash
    from app.models import BlacklistEntry
    from app.engines import risk_scoring
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    original_health=risk_scoring.blacklist_health
    risk_scoring.blacklist_health=lambda db:{'available':True,'reason':None,'mode':'frozen_evaluation'}
    try:
        with Session(engine) as db:
            urls=d[(d.split=='train')&(d.content_type=='url')&(d.label=='phishing')].text
            seen=set();entries=[]
            for value in urls:
                p=parse_url(value);digest=url_hash(value)
                if digest in seen:continue
                seen.add(digest);entries.append(dict(url=p.canonical,url_hash=digest,domain=p.host,source='manual',first_seen=date(2026,7,1),last_seen=date(2026,7,1),is_active=True,reputation_score=90))
            db.bulk_insert_mappings(BlacklistEntry,entries);db.commit()
            verdicts=[risk_scoring.calculate_final_risk_score(text=text,db=db)['verdict'] for text in sms.text]
    finally:risk_scoring.blacklist_health=original_health;engine.dispose()
    high=[v=='HIGH' for v in verdicts];low=[v=='LOW' for v in verdicts]
    report={'versions':metadata,'text_models':reports,'sealed_sms':{'high':proportion(sum(high),len(high)),'low':proportion(sum(low),len(low))},
        'remaining':['URL protocols and genuine shared-link false positives must be run separately','Public-tool comparisons require timestamped observations; never interpret an absent observation as a clean verdict']}
    (output/'text-final.json').write_text(json.dumps(report,indent=2),encoding='utf-8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default=str(ROOT/'data/processed/v2/dataset.csv'))
    p.add_argument('--sealed-sms',default=str(ROOT/'data/processed/v2/sealed_sms.csv'));p.add_argument('--targets',default=str(ROOT/'evaluation/targets.json'))
    p.add_argument('--output',default=str(ROOT/'evaluation/local-results/final'));a=p.parse_args()
    try:print(json.dumps(run(a.dataset,a.sealed_sms,a.targets,a.output),indent=2))
    except (ValueError,FileNotFoundError,FileExistsError) as e:raise SystemExit(str(e))
