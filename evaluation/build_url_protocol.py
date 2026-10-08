"""Retrospective July snapshot benchmark. Verification must precede the training cutoff.
This creates files only; it never loads future URLs into the evaluation blacklist.
"""
import argparse,json,sys,hashlib
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.url_utils import parse_url,registered_domain

def build(raw,cutoff,output):
    d=pd.read_csv(raw);d['submitted']=pd.to_datetime(d.submission_time,utc=True);d['verified_at']=pd.to_datetime(d.verification_time,utc=True)
    cut=pd.Timestamp(cutoff,tz='UTC')
    records=[]
    for _,r in d.iterrows():
        try:p=parse_url(r.url)
        except Exception:continue
        records.append({'url':p.canonical,'domain':registered_domain(p.host),'submitted':r.submitted,'verified_at':r.verified_at})
    d=pd.DataFrame(records).sort_values('submitted').drop_duplicates('url')
    known=d[(d.submitted<cut)&(d.verified_at<cut)]
    future=d[d.submitted>=cut];seen=set(known.domain)
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    known.to_csv(output/'frozen_time_blacklist.csv',index=False)
    future[future.domain.isin(seen)].to_csv(output/'new_paths_known_domains.csv',index=False)
    future[~future.domain.isin(seen)].to_csv(output/'new_domains_time.csv',index=False)
    report={'cutoff':str(cut),'source_sha256':hashlib.sha256(Path(raw).read_bytes()).hexdigest(),
            'known_verified_before_cutoff':len(known),'future_known_domains':int(future.domain.isin(seen).sum()),
            'future_new_domains':int((~future.domain.isin(seen)).sum()),
            'submission_before_verification_after_excluded':int(((d.submitted<cut)&(d.verified_at>=cut)).sum()),
            'limitation':'retrospective online-valid July snapshot; not a full historical archive; OpenPhish excluded'}
    (output/'protocol.json').write_text(json.dumps(report,indent=2),encoding='utf-8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',default=str(ROOT/'data/raw/phishtank_raw.csv'))
    p.add_argument('--cutoff',default='2026-07-01');p.add_argument('--output',default=str(ROOT/'evaluation/local-results/url-protocol'))
    a=p.parse_args();print(json.dumps(build(a.raw,a.cutoff,a.output),indent=2))
