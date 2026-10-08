import json, sys, time, re
sys.path.insert(0, '/home/claude/etis-evidence')
import requests
from urllib.parse import urlsplit, urlunsplit
from cases import API_CASES, EVERYDAY_SMS, ROBUSTNESS
U = sys.argv[1]; BASE = 'http://127.0.0.1:8010'
key = re.search(r'^ETIS_API_KEY=(.*)$', open(U + '/.env').read(), re.M).group(1).strip()
H = {'X-API-Key': key}
BL = 'https://rllling.shop/spid/'
p = urlsplit(BL); BLU = urlunsplit((p.scheme, p.netloc.upper(), p.path, p.query, p.fragment))
sub = {'{BLACKLISTED_URL}': BL, '{BLACKLISTED_URL_UPPER}': BLU}
def fill(v):
    for k, r in sub.items(): v = v.replace(k, r)
    return v
def call(body):
    r = requests.post(BASE + '/analyze', json=body, headers=H, timeout=60); time.sleep(3.2)
    try: j = r.json()
    except Exception: j = {'raw': r.text[:300]}
    return r.status_code, j
out = {'cases': [], 'sms': [], 'robust': []}
for cid, desc, body, acc in API_CASES:
    body = {k: fill(v) for k, v in body.items()}
    s, j = call(body); got = j.get('verdict') if s == 200 else s
    out['cases'].append({'id': cid, 'status': s, 'verdict': j.get('verdict'), 'reason': j.get('decisive_reason') or j.get('reason'), 'accept': sorted(map(str, acc)), 'pass': got in acc, 'resp': j})
    print(cid, s, j.get('verdict'), 'PASS' if got in acc else 'FAIL', flush=True)
for i, t in enumerate(EVERYDAY_SMS, 1):
    s, j = call({'text': t}); out['sms'].append({'i': i, 'verdict': j.get('verdict'), 'resp': j}); print('SMS', i, j.get('verdict'), flush=True)
for cid, desc, t, acc in ROBUSTNESS:
    s, j = call({'text': fill(t)}); got = j.get('verdict')
    out['robust'].append({'id': cid, 'verdict': got, 'pass': got in acc, 'resp': j}); print(cid, got, 'PASS' if got in acc else 'FAIL', flush=True)
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
