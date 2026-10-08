import importlib.util
from pathlib import Path
from dataclasses import replace
import pytest
from app.engines import risk_scoring
from app.models import ScanRequest,ScanResult

spec=importlib.util.spec_from_file_location('review_cases',Path(__file__).resolve().parents[2]/'evaluation/review-evidence/cases.py')
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)

@pytest.mark.parametrize('case',cases.API_CASES,ids=[c[0] for c in cases.API_CASES])
def test_review_detection_cases(client,monkeypatch,case):
    # Deterministic engine fixture tests orchestration. Real-model probes run separately.
    monkeypatch.setattr(risk_scoring,'score_text',lambda _:dict(probability=.99,score=99,model='fixture',version='test',windows=1))
    _,_,body,accept=case
    body={k:v.replace('{BLACKLISTED_URL_UPPER}','https://KNOWN-PHISH.EXAMPLE/login').replace('{BLACKLISTED_URL}','https://known-phish.example/login') for k,v in body.items()}
    response=client.post('/analyze',json=body)
    got=response.json().get('verdict') if response.status_code==200 else response.status_code
    assert got in accept,response.json()

def test_privacy_success_and_error(client,db,caplog,monkeypatch):
    marker='PRIVATE_MARKER_9347_NEVER_PERSIST'
    monkeypatch.setattr(risk_scoring,'score_text',lambda _:dict(probability=.01,score=1,model='fixture',version='test',windows=1))
    response=client.post('/analyze',json={'text':marker})
    assert response.status_code==200;assert response.json()['saved']
    assert marker not in str([(r.text_hash,r.url_hash) for r in db.query(ScanRequest)])
    assert marker not in str([r.engine_breakdown for r in db.query(ScanResult)])
    def fail():raise RuntimeError(marker)
    monkeypatch.setattr(db,'flush',fail)
    response=client.post('/analyze',json={'text':marker})
    assert response.status_code==200 and not response.json()['saved']
    assert marker not in response.text and marker not in caplog.text
    response=client.post('/analyze',json={'text':{'secret':marker}})
    assert response.status_code==400 and marker not in response.text

def test_missing_key_is_401(client,monkeypatch):
    from app.core import security
    monkeypatch.setattr(security,'settings',replace(security.settings,api_key='server-only-test-key'))
    assert client.post('/analyze',json={'url':'https://example.com/'}).status_code==401

def test_unexpected_failure_never_logs_or_echoes_input(client,caplog,monkeypatch):
    from app.routers import analyze
    marker='PRIVATE_EXCEPTION_MARKER_459721'
    def broken(**kwargs):raise RuntimeError(marker)
    monkeypatch.setattr(analyze,'calculate_final_risk_score',broken)
    response=client.post('/analyze',json={'text':marker})
    assert response.status_code==503
    assert marker not in response.text and marker not in caplog.text

def test_health_degraded_components(client,monkeypatch,db):
    from app.main import app
    from app.engines import text_model
    from app.engines.threat_intel import blacklist_lookup
    def missing(_):raise FileNotFoundError()
    monkeypatch.setattr(text_model,'score_text',missing)
    monkeypatch.setattr(blacklist_lookup,'blacklist_health',lambda _:dict(available=True))
    assert client.get('/health/ready').status_code==200
    monkeypatch.setattr(blacklist_lookup,'blacklist_health',lambda _:dict(available=False,reason='database_unavailable'))
    assert client.get('/health/ready').status_code==503
    assert client.get('/health/live').status_code==200
