"""Verify running local services without printing secrets or submitted content."""
import concurrent.futures,json,sys,time,hashlib
from pathlib import Path
import requests,numpy as np
from dotenv import dotenv_values
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
def run():
    base='http://127.0.0.1:5173';session=requests.Session();checks={}
    ready=session.get(base+'/api/health/ready',timeout=30);ready.raise_for_status()
    checks['component_health']=ready.json()
    bad=session.post(base+'/api/analyze',json={'url':'https://cibeg.com:443@evil.example/login'},timeout=30)
    bad.raise_for_status();assert bad.json()['verdict']=='HIGH';checks['userinfo_disguise']='passed'
    clean=session.post(base+'/api/analyze',json={'url':'https://ebanking.cibeg.com/'},timeout=30)
    clean.raise_for_status();assert clean.json()['verdict']=='LOW';checks['official_subdomain']='passed'
    marker='PRIVATE_SMOKE_932174_NOT_STORED'
    private=session.post(base+'/api/analyze',json={'text':marker},timeout=30)
    private.raise_for_status();assert marker not in private.text
    invalid=session.post(base+'/api/analyze',json={'text':{'private':marker}},timeout=30)
    assert invalid.status_code==400 and marker not in invalid.text
    from app.core.database import SessionLocal
    from app.models import ScanRequest,ScanResult
    with SessionLocal() as db:
        records=[(r.text_hash,r.url_hash) for r in db.query(ScanRequest)]
        breakdowns=[r.engine_breakdown for r in db.query(ScanResult)]
        assert marker not in str(records)+str(breakdowns)
    for log in (ROOT/'var').glob('*.log'):assert marker not in log.read_text(encoding='utf-8',errors='replace')
    checks['privacy_marker_database_logs_errors']='passed'
    assert requests.post('http://127.0.0.1:8000/analyze',json={'url':'https://example.com/'},timeout=10).status_code==401
    assert requests.get(base+'/api/stats',headers={'Host':'untrusted.example'},timeout=10).status_code==403
    assert requests.post(base+'/api/analyze',json={'url':'https://example.com/'},headers={'Origin':'https://untrusted.example'},timeout=10).status_code==403
    assert requests.post(base+'/api/analyze',data='x'*33000,timeout=10).status_code==413
    cookie=ready.headers.get('Set-Cookie','');assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    checks['authentication_proxy_origin_host_size_session']='passed'
    key=dotenv_values(ROOT/'.env').get('ETIS_API_KEY')
    assert key
    for asset in (ROOT/'etis-frontend/dist').rglob('*.js'):
        assert key not in asset.read_text(encoding='utf-8')
    checks['browser_bundle_has_no_server_key']='passed'
    for route in ['/scan','/stats','/threats']:
        r=session.get(base+route,timeout=10);assert r.status_code==200 and '<div id="root">' in r.text
    checks['browser_route_refresh']='passed'
    def request_one(_):
        start=time.perf_counter();r=requests.get(base+'/api/stats',timeout=30);r.raise_for_status();return (time.perf_counter()-start)*1000
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:times=list(pool.map(request_one,range(10)))
    checks['concurrent_proxy_requests']={'n':10,'passed':True,'p95_ms':float(np.percentile(times,95))}
    target=ROOT/'evaluation/local-results/local-smoke.json';target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(checks,indent=2),encoding='utf-8');return checks
if __name__=='__main__':print(json.dumps(run(),indent=2))
