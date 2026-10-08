"""Explicit archival/runtime or training-only evaluation seed. Never mixes modes implicitly."""
import argparse,sys,json
from pathlib import Path
from datetime import datetime
import pandas as pd
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from app.models import EgyptianBrand,BrandDomain
from app.services.feeds import activate_snapshot

def seed(dataset,mode):
    d=pd.read_csv(dataset).fillna('')
    if mode=='evaluation':
        if 'split' not in d:raise ValueError('evaluation_seed_requires_split')
        d=d[d.split=='train']
    d=d[(d.content_type=='url')&(d.label=='phishing')]
    reports=[]
    with SessionLocal() as db:
        for name,domain in EGYPTIAN_BRAND_DOMAINS:
            brand=db.query(EgyptianBrand).filter_by(brand_name=name).first()
            if not brand:
                brand=EgyptianBrand(brand_name=name,category='Verified registry');db.add(brand);db.flush()
            if not db.query(BrandDomain).filter_by(domain=domain).first():
                db.add(BrandDomain(brand_id=brand.id,domain=domain,verified_date=datetime.now().date()))
        db.commit()
        for source in ['phishtank','openphish']:
            rows=d[d.source==source]
            if rows.empty:continue
            # Never pretend that an archival July seed is freshly observed today.
            captured=pd.to_datetime(rows.date_collected).max().to_pydatetime()
            reports.append(activate_snapshot(db,source,rows.text.tolist(),captured_at=captured,validate=False))
    return {'mode':mode,'snapshots':reports,'note':'Archival data may be stale; refresh feeds before relying on clean URL results.'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['archive','evaluation'],required=True)
    p.add_argument('--dataset',default=str(ROOT/'data/processed/dataset.csv'));a=p.parse_args()
    print(json.dumps(seed(a.dataset,a.mode),indent=2))
