"""Replay the reviewer inputs locally against the real model and an isolated DB.

No HTTP requests, live-feed changes, training, final-test access or external services.
The author's Linux HTTP scripts and captured results remain unchanged as provenance.
"""
import argparse
import importlib.util
import importlib.metadata
import json
import sys
import hashlib
from collections import Counter
from datetime import date
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import Base
from app.core.exceptions import InvalidScanInputError
from app.core.settings import settings
from app.core.url_utils import url_hash
from app.engines import risk_scoring
from app.models import BlacklistEntry
from app.services.registry import populate_registry

def run(output=None):
    source=ROOT/'evaluation/review-evidence'
    spec=importlib.util.spec_from_file_location('followup_review_cases',source/'cases.py')
    cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
    probes=json.loads((ROOT/'evaluation/followup-probes.json').read_text(encoding='utf-8'))
    reviewers=json.loads((source/'followup-2026-10-08/unseen_probes_results.json').read_text(encoding='utf-8'))
    expected_review={row['probe']:row['got'] for row in reviewers}
    blacklisted='https://rllling.shop/spid/'
    fill=lambda value:value.replace('{BLACKLISTED_URL_UPPER}',blacklisted.replace('rllling.shop','RLLLING.SHOP')).replace('{BLACKLISTED_URL}',blacklisted)
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    health=risk_scoring.blacklist_health
    risk_scoring.blacklist_health=lambda db:{'available':True,'reason':None,'mode':'isolated_frozen_followup_fixture'}
    try:
        with Session(engine) as db:
            populate_registry(db)
            db.add(BlacklistEntry(url=blacklisted,url_hash=url_hash(blacklisted),domain='rllling.shop',
                source='manual',first_seen=date(2026,7,1),last_seen=date(2026,7,1),is_active=True,reputation_score=90))
            db.commit()
            def scan(body):
                try:
                    result=risk_scoring.calculate_final_risk_score(**body,db=db)
                    return result['verdict'],result['decisive_reason']
                except InvalidScanInputError:
                    return 400,'invalid_input'
            api=[]
            for cid,description,body,accepted in cases.API_CASES:
                verdict,reason=scan({key:fill(value) for key,value in body.items()})
                api.append({'id':cid,'got':verdict,'reason':reason,'pass':verdict in accepted})
            robust=[]
            for cid,description,text,accepted in cases.ROBUSTNESS:
                verdict,reason=scan({'text':fill(text)})
                robust.append({'id':cid,'got':verdict,'reason':reason,'pass':verdict in accepted})
            everyday=[scan({'text':text})[0] for text in cases.EVERYDAY_SMS]
            extra=[]
            for row in probes:
                verdict,reason=scan(row['body'])
                passed=verdict in {'LOW','MEDIUM','HIGH','INCOMPLETE'} if row['expected']=='not 400' else verdict in row['expected'].split('/')
                extra.append({'probe':row['name'],'expected':row['expected'],'got':verdict,'reason':reason,
                    'pass':passed,'known_limitation':row.get('known_limitation',False),
                    'matches_supplied_result':verdict==expected_review[row['name']]})
    finally:
        risk_scoring.blacklist_health=health;engine.dispose()
    deployment=json.loads((ROOT/'ml/models/deployment_model.json').read_text())
    report={'kind':'exposed development inputs; in-process engine replay, not HTTP or final accuracy',
        'blacklist':'single frozen fixture in isolated in-memory SQLite; no live DB/feed changes',
        'model':settings.model_backend,'policy':'decision-v2','artifact_sha256':deployment['artifact_sha256'],
        'probes_sha256':hashlib.sha256((ROOT/'evaluation/followup-probes.json').read_bytes()).hexdigest(),
        'detection_cases':api,'robustness':robust,'everyday_invented':dict(Counter(everyday)),
        'followup_probes':extra,'final_test_run':False,
        'summary':{'detection_passed':sum(row['pass'] for row in api),'detection_total':len(api),
            'robustness_passed':sum(row['pass'] for row in robust),'robustness_total':len(robust),
            'followup_passed':sum(row['pass'] for row in extra),'followup_total':len(extra),
            'supplied_probe_results_matched':sum(row['matches_supplied_result'] for row in extra),
            'known_limitations':[row['probe'] for row in extra if not row['pass'] and row['known_limitation']]}}
    report['data_sha256']=hashlib.sha256((source/'cases.py').read_bytes()+(ROOT/'evaluation/followup-probes.json').read_bytes()).hexdigest()
    report['model_sha256']=hashlib.sha256((ROOT/'ml/models/deployed_char.joblib').read_bytes()).hexdigest()
    report['url_model_sha256']=hashlib.sha256((ROOT/'ml/models/url_host_v3.joblib').read_bytes()).hexdigest()
    report['libraries']={name:importlib.metadata.version(name) for name in ['numpy','pandas','scikit-learn','joblib','tldextract','SQLAlchemy']}
    output=Path(output) if output is not None else ROOT/'evaluation/reports/2026-10-v3/review-2026-10-13/followup-replay.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,help='Save a new replay without rewriting historical reports')
    args=parser.parse_args()
    report=run(args.output);print(json.dumps(report['summary'],indent=2))
    unexpected=any(not row['pass'] and not row['known_limitation'] for row in report['followup_probes'])
    failures=any(not row['pass'] for row in report['detection_cases']+report['robustness'])
    raise SystemExit(1 if unexpected or failures else 0)
