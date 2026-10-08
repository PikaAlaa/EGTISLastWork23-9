"""Frozen offline URL benchmark. Development uses grouped validation domains only.
Final uses a separate frozen training blacklist, a retrospective verified-time split,
and genuine shared-link negatives. Live feeds and the runtime database are never read.
"""
import argparse,json,hashlib,sys,tempfile
from pathlib import Path
from datetime import date
from urllib.parse import urlsplit,urlunsplit
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import Base
from app.core.dataset_identity import dataset_identity
from app.core.url_utils import parse_url,url_hash,registered_domain
from app.models import BlacklistEntry
from app.engines import risk_scoring
from metrics import binary_metrics,proportion
def variants(url):
    p=urlsplit(url);host=p.hostname.upper();host='['+host+']' if ':' in host else host
    if p.port:host+=':'+str(p.port)
    result=[url,urlunsplit((p.scheme,host,p.path,p.query,'')),url+'#x',url+('&' if p.query else '?')+'utm_source=etis_fixture']
    if p.port is None:result.append(urlunsplit((p.scheme,p.netloc+(':443' if p.scheme=='https' else ':80'),p.path,p.query,'')))
    return result
def benchmark(known,examples,limit=None,functional=False):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine);Session=sessionmaker(bind=engine)
    # Staleness does not apply to an explicitly frozen experimental snapshot.
    original=risk_scoring.blacklist_health;risk_scoring.blacklist_health=lambda db:{'available':True,'reason':None,'mode':'frozen_evaluation'}
    try:
        with Session() as db:
            objects=[];seen=set()
            for value in known:
                try:p=parse_url(value)
                except Exception:continue
                digest=url_hash(p.canonical)
                if digest in seen:continue
                seen.add(digest);objects.append({'url':p.canonical,'url_hash':digest,'domain':p.host,'source':'manual','first_seen':date(2026,7,1),'last_seen':date(2026,7,1),'is_active':True,'reputation_score':90})
            db.bulk_insert_mappings(BlacklistEntry,objects);db.commit()
            if functional:
                total=passed=0
                for value in list(known)[:limit] if limit else known:
                    for variant in variants(value):
                        total+=1;passed+=risk_scoring.calculate_final_risk_score(url=variant,db=db)['verdict']=='HIGH'
                return {'functional_only':True,'all_high':passed==total,'matched':passed,'variants':total}
            labels=[];predictions=[];counts={}
            for row in examples.head(limit).itertuples() if limit else examples.itertuples():
                try:verdict=risk_scoring.calculate_final_risk_score(url=row.text,db=db)['verdict']
                except Exception:verdict='INCOMPLETE'
                counts[verdict]=counts.get(verdict,0)+1;labels.append(row.label=='phishing');predictions.append(verdict in ('MEDIUM','HIGH'))
            return {'medium_or_high':binary_metrics(labels,predictions),'verdicts':counts,'n':len(labels)}
    finally:risk_scoring.blacklist_health=original;engine.dispose()
def run(dataset,stage,output,protocol=None,shared=None,targets=None,limit=200):
    d=pd.read_csv(dataset,low_memory=False).fillna('');d=d[d.content_type=='url'];train=d[(d.split=='train')&(d.label=='phishing')]
    report={'stage':stage,**dataset_identity(dataset),'policy':'decision-v2','live_blacklist_used':False}
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    if stage=='final':
        t=json.loads(Path(targets or ROOT/'evaluation/targets.json').read_text())
        if not t.get('approved_by') or not t.get('approved_at') or t.get('new_domain_minimum_recall') is None:raise ValueError('Freeze approved targets before final evaluation')
        if not protocol or not shared:raise ValueError('Final evaluation requires the retrospective protocol folder and genuine shared-link negatives')
        shared_df=pd.read_csv(shared).fillna('')
        if len(shared_df)<t['real_shared_links_minimum'] or not {'consent','anonymized','text','label'}<=set(shared_df):raise ValueError('200 genuine reviewed shared links with consent and anonymization confirmation required')
        if not shared_df.label.eq('legitimate').all() or not shared_df.consent.eq('yes').all() or not shared_df.anonymized.eq('yes').all():raise ValueError('Shared-link provenance/labels incomplete')
        with (output/'URL_FINAL_RUN_LOCK.json').open('x') as f:json.dump(report,f,indent=2)
        limit=None;test=d[d.split=='test']
        if set(test.group_id)&set(train.group_id):raise ValueError('Registered-domain leakage')
        protocol=Path(protocol);frozen=pd.read_csv(protocol/'frozen_time_blacklist.csv')
        known_paths=pd.read_csv(protocol/'new_paths_known_domains.csv').rename(columns={'url':'text'}).assign(label='phishing')
        report['new_pages_known_domains']=benchmark(frozen.url.tolist(),known_paths)
        report['time_protocol']=json.loads((protocol/'protocol.json').read_text())
        report['real_shared_links']=benchmark(train.text.tolist(),shared_df)
        # Precision for phishing-only time cohorts is undefined: include real negatives separately.
        report['new_pages_known_domains']['precision_limitation']='Phishing-only cohort; interpret precision jointly with genuine shared-link false alarms.'
    else:
        test=d[d.split=='val'].sample(frac=1,random_state=42)
    known=train.text.tolist()
    report['known_url_functional']=benchmark(known,None,200 if stage=='development' else None,functional=True)
    report['new_registered_domains']=benchmark(known,test,limit)
    report['sample_limit']=limit
    (output/f'url-{stage}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default=str(ROOT/'data/processed/v2/dataset.csv'))
    p.add_argument('--stage',choices=['development','final'],default='development');p.add_argument('--limit',type=int,default=200)
    p.add_argument('--protocol');p.add_argument('--shared-links');p.add_argument('--targets');p.add_argument('--output',default=str(ROOT/'evaluation/local-results'))
    a=p.parse_args()
    try:print(json.dumps(run(a.dataset,a.stage,a.output,a.protocol,a.shared_links,a.targets,a.limit),indent=2))
    except (ValueError,FileExistsError,FileNotFoundError) as e:raise SystemExit(str(e))
