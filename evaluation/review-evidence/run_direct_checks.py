"""Direct function calls and controlled scoring (no HTTP). Needs the seeded database for blacklist lookups.

Controlled scoring replaces one engine's output with a fixed value so the fusion rule can be
examined on its own; every engine score used is recorded in the output.
"""
import json, os, logging, warnings
from urllib.parse import urlsplit
from unittest import mock
logging.disable(logging.CRITICAL); warnings.filterwarnings("ignore")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import app.engines.risk_scoring as rs
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain, calculate_domain_typosquatting_score
from app.engines.deep_learning.lstm_inference import calculate_lstm_phishing_score as L
from cases import PHISH_TEXT, NEUTRAL_TEXT, CONTROLLED_PAIRS

db = sessionmaker(bind=create_engine(os.environ["DATABASE_URL"]))()
api = json.load(open("results/api_cases.json"))
BL = api["meta"]["blacklisted_url_used"]
out = {"blacklisted_url_used": BL}

# D1: host parsing
u = "https://cibeg.com:443@evil.example/login"
out["D1_parsing"] = {"input": u, "etis_normalize_domain": normalize_domain(u), "urllib_hostname": urlsplit(u).hostname}


def fused(text=None, url=None, fix=None):
    """Run calculate_final_risk_score with selected engines fixed. fix = {'lstm': 95, ...}"""
    patches = []
    if fix and "lstm" in fix:
        patches.append(mock.patch.object(rs, "calculate_lstm_phishing_score", lambda t: {"score": float(fix["lstm"])}))
    if fix and "rule_based" in fix:
        patches.append(mock.patch.object(rs, "calculate_rule_based_score", lambda text=None, url=None: {"score": float(fix["rule_based"])}))
    if fix and "blacklist" in fix:
        patches.append(mock.patch.object(rs, "calculate_blacklist_reputation_score", lambda u, d: {"score": float(fix["blacklist"])}))
    for p in patches: p.start()
    try:
        r = rs.calculate_final_risk_score(text=text, url=url, db=db)
    finally:
        for p in patches: p.stop()
    return {"input": {"text": text, "url": url}, "fixed": fix or {},
            "engine_scores": {k: (v or {}).get("score") for k, v in r["engine_details"].items() if v},
            "final_score": r["final_score"], "verdict": r["verdict"], "allowlisted": r["allowlisted"],
            "confidence": r["confidence"]}

# D3: dilution. Model fixed at 95 (phishing text), then 5 (neutral text). Rule and blacklist scores are real.
out["D3_controlled"] = [
    fused(text=PHISH_TEXT, fix={"lstm": 95}),
    fused(text=PHISH_TEXT, url="https://www.example.com/", fix={"lstm": 95}),
    fused(url=BL),
    fused(url=BL, text=NEUTRAL_TEXT, fix={"lstm": 5}),
]

# D6-D8: brand checker called directly
out["D6_D8_brand_checker"] = {x: calculate_domain_typosquatting_score(x).get("score") for x in [
    "http://nbe-online-login.com/", "http://cib-eg.net/login", "http://qnb-verify-account.com/",
    "https://ebanking.cibeg.com/", "https://bm-online.banquemisr.com/", "https://web.vodafone.com.eg/", "https://afternoon.com/", "https://elite.eg/", "https://cibeg.com/"]}

# D11 / E8: verdict boundaries
out["boundaries"] = {str(s): rs._classify(s) for s in [0.0, 0.01, 49.99, 50.0, 50.01]}

# E10: confidence formula, worked example
out["E10_confidence_example"] = {"engine_scores": {"rule_based": 0.0, "blacklist": 0.0, "lstm": 95.0},
                                 "result": rs._calculate_confidence({"rule_based": 0.0, "blacklist": 0.0, "lstm": 95.0})}

# Model sensitivity pairs (real model)
out["model_pairs"] = [{"pair": n, "with_money_wording": {"text": a, "lstm": L(a)["score"]},
                       "without": {"text": b, "lstm": L(b)["score"]}} for n, a, b in CONTROLLED_PAIRS]

# E9: committed acceptance report -- status vs verdict
rep = json.load(open(os.environ.get("ETIS_REPO", "/home/claude/etis-group") + "/acceptance_test_report.json", encoding="utf-8-sig"))
out["E9_acceptance_report"] = [{"id": r["Id"], "expected": r["Expected"], "actual": r["Actual"], "score": r["Score"], "status": r["Status"],
                                "verdict_matches": r["Actual"] in r["Expected"].split("/")} for r in rep]

json.dump(out, open("results/direct_checks.json", "w"), ensure_ascii=False, indent=1, default=str)
print(json.dumps(out, ensure_ascii=False, indent=1, default=str)[:6000])
