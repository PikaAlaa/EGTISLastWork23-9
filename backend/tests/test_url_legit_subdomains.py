"""Reviewer-supplied legitimate host regressions; all URLs are inert strings."""
import sys
import hashlib
import json
from pathlib import Path
import pytest
from app.engines import risk_scoring
from app.engines.url_model import score_url

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from evaluation.probe_legit_hosts import HOSTS


def test_packaged_model_and_frozen_rule_match_deployment_metadata():
    root=Path(__file__).resolve().parents[2]
    metadata=json.loads((root/'ml/models/url_host_deployment.json').read_text())
    assert hashlib.sha256((root/'ml/models/url_host_v3.joblib').read_bytes()).hexdigest()==metadata['artifact_sha256']
    assert hashlib.sha256((root/'evaluation/reports/2026-10-v4/url_selection_rule.md').read_bytes()).hexdigest()==metadata['selection_rule_sha256']


@pytest.mark.parametrize('host', HOSTS)
def test_legitimate_probe_not_alerted_by_url_model_alone(db, monkeypatch, host):
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    result = risk_scoring.calculate_final_risk_score(url='https://' + host + '/', db=db)
    model = score_url('https://' + host + '/')
    assert model['probability'] < model['threshold']
    assert 'url_model' not in result['supporting_signals']
    assert result['verdict'] != 'HIGH'
    if result['verdict'] == 'MEDIUM':
        # The pre-existing Vodafone family resemblance is a separate rule; no
        # assertion presents its remaining false alarm as fixed by retraining.
        assert result['supporting_signals'] == ['brand_resemblance']


def test_promoted_model_keeps_official_and_shared_host_suppression(db, monkeypatch):
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: {'probability': 1., 'threshold': .5})
    for host in ['ebanking.cibeg.com', 'docs.google.com']:
        result = risk_scoring.calculate_final_risk_score(url='https://' + host + '/', db=db)
        assert 'url_model' not in result['supporting_signals']
        assert result['checked_links'][0]['url_model_raw_above_threshold']


def test_subdomain_subset_excludes_www_only_and_uses_private_psl():
    pytest.importorskip('pyarrow')
    from evaluation.run_url_subdomains_v4 import benign_subdomain
    from evaluation.run_url_v3 import ext
    extractor = ext()
    assert not benign_subdomain('www.example.com', extractor)
    assert not benign_subdomain('tenant.github.io', extractor)
    assert benign_subdomain('login.example.com', extractor)
    assert benign_subdomain('www.login.example.com', extractor)
    assert not benign_subdomain(None, extractor)
