"""Real selected-model regression and latency checks against an isolated fixture database.
These are development probes, never final accuracy measurements or the live blacklist.
"""
import json,sys,time,platform,hashlib
from datetime import date
from pathlib import Path
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'evaluation/review-evidence')]
from app.core.database import Base
from app.core.url_utils import url_hash
from app.core.settings import settings
from app.engines.risk_scoring import calculate_final_risk_score
from app.engines import risk_scoring
from app.core.exceptions import InvalidScanInputError
from app.models import BlacklistEntry
from cases import API_CASES,ROBUSTNESS,EVERYDAY_SMS,PHISH_TEXT
def run():
    risk_scoring.blacklist_health=lambda db:{'available':True,'reason':None,'mode':'isolated_development_fixture'}
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine);Session=sessionmaker(bind=engine)
    bad='https://known-phish.example/login'
    with Session() as db:
        db.add(BlacklistEntry(url=bad,url_hash=url_hash(bad),domain='known-phish.example',source='manual',first_seen=date.today(),last_seen=date.today()));db.commit()
        substitute=lambda value:value.replace('{BLACKLISTED_URL_UPPER}',bad.replace('known-phish.example','KNOWN-PHISH.EXAMPLE')).replace('{BLACKLISTED_URL}',bad)
        outcomes=[]
        for cid,description,body,accept in API_CASES:
            body={k:substitute(v) for k,v in body.items()}
            try:result=calculate_final_risk_score(**body,db=db);actual=result['verdict']
            except InvalidScanInputError:actual=400
            outcomes.append({'id':cid,'actual':actual,'expected':sorted(accept,key=str),'passed':actual in accept})
        robust=[]
        for cid,description,text,accept in ROBUSTNESS:
            r=calculate_final_risk_score(text=substitute(text),db=db)
            robust.append({'id':cid,'actual':r['verdict'],'passed':r['verdict'] in accept,'model_probability':(r['text_finding'] or {}).get('probability')})
        everyday=[calculate_final_risk_score(text=text,db=db)['verdict'] for text in EVERYDAY_SMS]
        latency={}
        for name,body in {'url':{'url':'https://ebanking.cibeg.com/'},'text':{'text':PHISH_TEXT},'mixed':{'text':PHISH_TEXT,'url':'https://cibeg.com/'}}.items():
            times=[]
            for _ in range(30):
                start=time.perf_counter();calculate_final_risk_score(**body,db=db);times.append((time.perf_counter()-start)*1000)
            latency[name]={'n':len(times),'p50_ms':float(np.percentile(times,50)),'p95_ms':float(np.percentile(times,95))}
    output={'kind':'development fixtures; invented messages; not population accuracy','platform':platform.platform(),
        'model':settings.model_backend,'policy':'decision-v2','api_cases':outcomes,'robustness':robust,
        'everyday_invented':{v:everyday.count(v) for v in set(everyday)},'warm_latency':latency,'final_test_run':False}
    path=ROOT/'evaluation/local-results/development.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(output,indent=2),encoding='utf-8');return output
if __name__=='__main__':print(json.dumps(run(),indent=2))
