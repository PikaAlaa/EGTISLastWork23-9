import argparse,sys,json,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.services.feeds import fetch_feed,activate_snapshot,rollback_snapshot,expire_sources
from app.services.indicators import sync_feed_indicators
from retention import delete_expired,delete_expired_malware
from app.core.settings import settings

def refresh():
    results=[]
    for source in ['phishtank','openphish']:
        with SessionLocal() as db:
            try:results.append(activate_snapshot(db,source,fetch_feed(source)))
            except Exception as exc:
                db.rollback();results.append({'source':source,'updated':False,'error_type':type(exc).__name__,'previous_snapshot_preserved':True})
    with SessionLocal() as db:
        try:
            expire_sources(db)
            results.append({"retention_deleted":delete_expired(db,settings.retention_days)})
            results.append({"malware_retention_deleted":delete_expired_malware(db)})
        except Exception as exc:db.rollback();results.append({"retention_error":type(exc).__name__})
    results.append(sync_indicators())
    return results
def sync_indicators():
    # Runs after feed changes have committed, in its own transaction; failure leaves feeds untouched.
    with SessionLocal() as db:
        try:return {"indicator_sync":sync_feed_indicators(db)}
        except Exception as exc:db.rollback();return {"indicator_sync_error":type(exc).__name__}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--watch',action='store_true');p.add_argument('--interval',type=int,default=3600);p.add_argument('--rollback')
    a=p.parse_args()
    if a.rollback:
        with SessionLocal() as db:print(json.dumps(rollback_snapshot(db,a.rollback)))
        print(json.dumps(sync_indicators()))
    else:
        while True:
            print(json.dumps(refresh()),flush=True)
            if not a.watch:break
            time.sleep(max(300,a.interval))
