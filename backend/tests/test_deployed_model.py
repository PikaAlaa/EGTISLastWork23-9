"""Real artifact regressions complement the deterministic policy/endpoint tests."""
import importlib.util,json,hashlib
from pathlib import Path
import pytest
from app.engines.risk_scoring import calculate_final_risk_score
from app.engines.rule_based.domain_typosquatting_detector import calculate_domain_typosquatting_score

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('review_cases',ROOT/'evaluation/review-evidence/cases.py')
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)

@pytest.mark.parametrize('cid,description,text,expected',cases.ROBUSTNESS,ids=[r[0] for r in cases.ROBUSTNESS])
def test_real_deployed_model_robustness(db,cid,description,text,expected):
    result=calculate_final_risk_score(text=text.replace('{BLACKLISTED_URL}','https://known-phish.example/login'),db=db)
    assert result['verdict'] in expected

def test_deployed_artifact_hash_matches_manifest():
    manifest=json.loads((ROOT/'ml/models/deployment_model.json').read_text())
    assert manifest['selected']=='char'
    assert hashlib.sha256((ROOT/'ml/models/deployed_char.joblib').read_bytes()).hexdigest()==manifest['artifact_sha256']

def test_userinfo_other_brand_on_official_host():
    assert calculate_domain_typosquatting_score('https://cibeg.com@nbe.com.eg/login')['decisive']
    assert not calculate_domain_typosquatting_score('https://cibeg.com@cibeg.com/')['decisive']

def test_extended_confusable_and_unrelated_idn():
    assert calculate_domain_typosquatting_score('https://cibeɡ.com/')['technique']=='homoglyph_confusable'
    assert not calculate_domain_typosquatting_score('https://bücher.de/')['decisive']
