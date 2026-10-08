"""Run every API evidence case against a live ETIS backend and record exact requests/responses.

Usage: PYTHONPATH=<repo>/backend DATABASE_URL=... python run_api_cases.py http://127.0.0.1:8000
Requests are spaced 3.2 s apart to stay under the 20/min per-IP limit.
"""
import json, sys, time, hashlib, datetime, platform
from urllib.parse import urlsplit, urlunsplit
import requests, pandas as pd
from sqlalchemy import create_engine, text as sql
import os
from cases import API_CASES, EVERYDAY_SMS, ROBUSTNESS

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
REPO = os.environ.get("ETIS_REPO", "/home/claude/etis-group")
from app.engines.threat_intel.blacklist_lookup import SHARED_HOSTING_DOMAINS
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain

eng = create_engine(os.environ["DATABASE_URL"])
d = pd.read_csv(f"{REPO}/data/processed/dataset.csv")
cand = d[(d.content_type == "url") & (d.label == "phishing") & (d.split == "test")].text
with eng.connect() as c:
    for u in cand:
        if not u.startswith("http") or normalize_domain(u) in SHARED_HOSTING_DOMAINS or len(u) > 80:
            continue
        h = hashlib.sha256(u.encode()).hexdigest()
        if c.execute(sql("select 1 from blacklist_entries where url_hash=:h"), {"h": h}).first():
            BL = u
            break
p = urlsplit(BL)
BL_UPPER = urlunsplit((p.scheme, p.netloc.upper(), p.path, p.query, p.fragment))
subst = {"{BLACKLISTED_URL}": BL, "{BLACKLISTED_URL_UPPER}": BL_UPPER}


def fill(v):
    if isinstance(v, str):
        for k, r in subst.items():
            v = v.replace(k, r)
    return v


def call(body):
    t = time.perf_counter()
    r = requests.post(f"{BASE}/analyze", json=body, timeout=120)
    ms = round((time.perf_counter() - t) * 1000, 1)
    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text[:500]}
    time.sleep(3.2)
    return r.status_code, ms, j


def summarise(cid, desc, body, accept, status, ms, j):
    out = {"id": cid, "description": desc, "request": {k: (v if len(v) <= 300 else v[:120] + f"...[{len(v)} chars]") for k, v in body.items()},
           "http_status": status, "latency_ms": ms, "accept": sorted(map(str, accept))}
    if status == 200:
        det = j.get("engine_details", {})
        out.update(final_score=j.get("final_score"), verdict=j.get("verdict"), allowlisted=j.get("allowlisted"),
                   engine_scores={k: (v or {}).get("score") for k, v in det.items() if v},
                   rule_parts={k: (v or {}).get("score") for k, v in ((det.get("rule_based") or {}).get("engine_results") or {}).items() if v},
                   blacklist_match=(det.get("blacklist") or {}).get("match_type") if det.get("blacklist") else None,
                   confidence=j.get("confidence"))
        got = j.get("verdict")
    else:
        out["error"] = j
        got = status
    out["pass"] = got in accept
    return out


results = {"meta": {"base": BASE, "run_at": datetime.datetime.now().isoformat(timespec="seconds"),
                    "python": platform.python_version(), "blacklisted_url_used": BL, "blacklisted_url_upper": BL_UPPER},
           "cases": [], "everyday_sms": [], "robustness": []}
for cid, desc, body, accept in API_CASES:
    body = {k: fill(v) for k, v in body.items()}
    s, ms, j = call(body)
    results["cases"].append(summarise(cid, desc, body, accept, s, ms, j))
    print(cid, s, results["cases"][-1].get("verdict"), results["cases"][-1].get("final_score"), "PASS" if results["cases"][-1]["pass"] else "FAIL", flush=True)
for i, t in enumerate(EVERYDAY_SMS, 1):
    s, ms, j = call({"text": t})
    results["everyday_sms"].append(summarise(f"E14-{i:02d}", "Everyday Egyptian SMS", {"text": t}, {"LOW"}, s, ms, j))
    print("E14", i, j.get("verdict"), j.get("final_score"), flush=True)
for cid, desc, t, accept in ROBUSTNESS:
    t = fill(t)
    s, ms, j = call({"text": t})
    results["robustness"].append(summarise(cid, desc, {"text": t}, accept, s, ms, j))
    print(cid, j.get("verdict"), j.get("final_score"), flush=True)

json.dump(results, open("results/api_cases.json", "w"), ensure_ascii=False, indent=1, default=str)
print("saved results/api_cases.json")
