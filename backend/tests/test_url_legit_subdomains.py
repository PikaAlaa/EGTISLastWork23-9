"""Reviewer-supplied legitimate host regressions; all URLs are inert strings."""
import sys
import hashlib
import json
import re
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
    rule_path=root.joinpath(*re.split(r'[\\/]', metadata.get('selection_rule_path', 'evaluation/reports/2026-10-v4/url_selection_rule.md')))
    assert hashlib.sha256(rule_path.read_bytes()).hexdigest()==metadata['selection_rule_sha256']
    if metadata.get('policy') in {'ordinary', 'corroboration_only'}:
        assert risk_scoring.URL_MODEL_POLICY == metadata['policy']
        frozen_path=root.joinpath(*re.split(r'[\\/]', metadata['frozen_thresholds_path']))
        assert hashlib.sha256(frozen_path.read_bytes()).hexdigest()==metadata['frozen_thresholds_sha256']
        frozen=json.loads(frozen_path.read_text())
        record=next(row for row in frozen['models'] if row['sha256']==metadata['source_artifact_sha256']
                    and row.get('input_mode', 'original')==metadata.get('input_mode', 'original'))
        assert record['path']==metadata['selected']
        assert record['representation']==metadata['representation']
        assert any(point['threshold']==metadata['threshold'] for point in record['thresholds'])
        if metadata.get('pattern_policy'):
            from app.engines.rule_based import url_pattern_analyzer
            assert url_pattern_analyzer.PATTERN_ALERT_POLICY == metadata['pattern_policy']
            assert hashlib.sha256((root/'evaluation/reports/2026-10-v4/url_pattern_acceptance_rule_v3.md').read_bytes()).hexdigest()==metadata['pattern_acceptance_rule_sha256']
            assert hashlib.sha256((root/'evaluation/reports/2026-10-v4/pattern_training_proposal_v3.json').read_bytes()).hexdigest()==metadata['pattern_training_proposal_sha256']


@pytest.mark.parametrize('host', HOSTS)
def test_legitimate_probe_not_alerted_by_url_model_alone(db, monkeypatch, host):
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    result = risk_scoring.calculate_final_risk_score(url='https://' + host + '/', db=db)
    model = score_url('https://' + host + '/')
    if risk_scoring.URL_MODEL_POLICY == 'ordinary':
        assert model['probability'] < model['threshold']
    assert 'url_model' not in result['supporting_signals']
    assert result['verdict'] == 'LOW'


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
