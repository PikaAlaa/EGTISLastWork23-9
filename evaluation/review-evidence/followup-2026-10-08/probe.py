import json, sys, time, re, requests
U = sys.argv[1]; key = re.search(r'^ETIS_API_KEY=(.*)$', open(U + '/.env').read(), re.M).group(1).strip()
H = {'X-API-Key': key}
P = [
 ('brand domain as subdomain', {'url': 'https://www.cibeg.com.account-check.example/login'}, 'HIGH'),
 ('cyrillic c in cibeg', {'url': 'https://сibeg.com/login'}, 'HIGH'),
 ('instapay lookalike', {'url': 'https://instapay-eg.com/verify'}, 'HIGH'),
 ('fawry lookalike, no action word', {'url': 'https://fawry-eg.net/'}, 'MEDIUM/HIGH'),
 ('banquemisr typo', {'url': 'https://banquemlsr.com/login'}, 'MEDIUM/HIGH'),
 ('vodafone cash lookalike', {'url': 'http://vodafone-cash-gift.com/claim'}, 'MEDIUM/HIGH'),
 ('official NBE deep link', {'url': 'https://www.nbe.com.eg/NBE/E/#/EN/Home'}, 'LOW'),
 ('official Banque Misr subdomain', {'url': 'https://bm-online.banquemisr.com/'}, 'LOW'),
 ('official vodafone subdomain', {'url': 'https://web.vodafone.com.eg/'}, 'LOW'),
 ('defanged link in SMS', {'text': 'حدث بياناتك هنا hxxps://cib-egypt-secure[.]com/verify'}, 'HIGH'),
 ('bare domain in SMS', {'text': 'ادخل على cib-eg-update.com وأكد بياناتك'}, 'HIGH'),
 ('legit NBE SMS with official link', {'text': 'البنك الأهلي المصري: لمعرفة تفاصيل حسابك زوروا www.nbe.com.eg'}, 'LOW/MEDIUM'),
 ('scheme bare domain', {'url': 'cibeg.com'}, 'LOW'),
 ('https on port 80', {'url': 'https://example.com:80/'}, 'not 400'),
 ('11 links', {'text': ' '.join(f'https://example{i}.com/' for i in range(11))}, 'INCOMPLETE'),
]
out = []
for name, body, exp in P:
    r = requests.post('http://127.0.0.1:8010/analyze', json=body, headers=H, timeout=60); time.sleep(3.2)
    j = r.json() if r.headers.get('content-type','').startswith('application/json') else {}
    v = j.get('verdict') if r.status_code == 200 else r.status_code
    reason = j.get('decisive_reason') or j.get('reason') or {}
    out.append({'probe': name, 'expected': exp, 'got': v, 'reason': reason})
    print(f'{name:36s} expected {exp:12s} got {v}  | {json.dumps(reason, ensure_ascii=False)[:110]}', flush=True)
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
