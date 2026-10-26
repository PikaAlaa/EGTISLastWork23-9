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
    comparison=json.loads((ROOT/'evaluation/reports/2026-10-v5/comparison.json').read_text())
    assert manifest['selected']==comparison['selected_model']=='tfidf_lightgbm'
    assert manifest['comparison_sha256']==hashlib.sha256((ROOT/manifest['comparison_path']).read_bytes()).hexdigest()
    assert manifest['source_artifact_sha256']==comparison['models']['tfidf_lightgbm']['runs'][0]['model_sha256']
    assert hashlib.sha256((ROOT/'ml/models/deployed_char.joblib').read_bytes()).hexdigest()==manifest['artifact_sha256']


@pytest.mark.parametrize('index,text',list(enumerate(cases.EVERYDAY_SMS)),ids=[str(i+1) for i in range(12)])
def test_selected_pipeline_reproduces_everyday_scores_and_verdicts(db,index,text):
    from app.engines.text_model import score_text
    deployment=json.loads((ROOT/'evaluation/reports/2026-10-v5/deployment.json').read_text())
    expected=deployment['after_probes']['rows'][index]
    scored=score_text(text)
    assert scored['model']=='tfidf_lightgbm'
    assert scored['version']==deployment['artifact_sha256'][:16]
    assert scored['high_threshold']==deployment['high_threshold']
    assert scored['low_threshold']==.2
    assert scored['probability']==pytest.approx(expected['probability'],abs=1e-12)
    assert calculate_final_risk_score(text=text,db=db)['verdict']==expected['verdict']

def test_userinfo_other_brand_on_official_host():
    assert calculate_domain_typosquatting_score('https://cibeg.com@nbe.com.eg/login')['decisive']
    assert not calculate_domain_typosquatting_score('https://cibeg.com@cibeg.com/')['decisive']

def test_extended_confusable_and_unrelated_idn():
    assert calculate_domain_typosquatting_score('https://cibeɡ.com/')['technique']=='homoglyph_confusable'
    assert not calculate_domain_typosquatting_score('https://bücher.de/')['decisive']
