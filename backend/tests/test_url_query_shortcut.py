"""Query safety properties of the deployed artifact, not held-out accuracy.

The former combined full-URL artifact's high raw query scores are historical
evidence in query-shortcut/REPORT.md, never an expectation for its replacement.
"""
import sys
from pathlib import Path

import pytest
from app.engines import risk_scoring
from app.engines.url_model import _load, score_url
from app.services.registry import populate_registry

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from evaluation.probe_query_shortcut import HOSTS, VARIANTS


@pytest.fixture
def healthy_db(db, monkeypatch):
    populate_registry(db)
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    return db


@pytest.mark.parametrize('host', HOSTS)
@pytest.mark.parametrize('variant,suffix', VARIANTS.items())
def test_ordinary_url_shape_cannot_create_model_support(healthy_db, host, variant, suffix):
    result = risk_scoring.calculate_final_risk_score(url='https://' + host + suffix, db=healthy_db)
    link = result['checked_links'][0]
    assert result['verdict'] == 'LOW'
    assert not link['shared_hosting_domain']
    # Four reviewer hosts already have registry suppression in this checkout.
    # The other four must pass without it; no new registry entries are added.
    if host in {'youm7.com', 'masrawy.com', 'vezeeta.com', 'wuzzuf.net'}:
        assert not link['verified_official_host']
    assert not link['url_model_above_threshold']
    assert 'url_model' not in result['supporting_signals']
    assert not link['url_model_raw_above_threshold']
    # Check raw probabilities, so suppression cannot conceal query dependence.
    if _load().get('deployment_schema', {}).get('input_mode') == 'host_path':
        base = ('https://' + host + suffix).split('#', 1)[0].split('?', 1)[0]
        baseline = score_url(base)
        for tail in ['', '?utm_source=sms', '#status', '?next=/home#status']:
            scored = score_url(base + tail)
            assert scored['probability'] == baseline['probability']
            assert scored['threshold'] == baseline['threshold']
        assert link['url_model_probability'] == baseline['probability']


def test_ordinary_model_support_alone_can_warn_but_cannot_be_high(healthy_db, monkeypatch):
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: {'probability': 1., 'threshold': .99})
    result = risk_scoring.calculate_final_risk_score(url='https://unlisted-service.test/?x=1', db=healthy_db)
    link = result['checked_links'][0]
    assert not link['verified_official_host'] and not link['shared_hosting_domain']
    assert risk_scoring.URL_MODEL_POLICY == 'ordinary'
    assert result['verdict'] == 'MEDIUM'
    assert link['url_model_raw_above_threshold']
    assert link['url_model_above_threshold']
    assert result['supporting_signals'] == ['url_model']


def test_query_model_cannot_escalate_unrelated_high_text(healthy_db, monkeypatch):
    monkeypatch.setattr(risk_scoring, 'score_text', lambda _: {
        'probability': .99, 'score': 99, 'high_threshold': .9, 'low_threshold': .2})
    result = risk_scoring.calculate_final_risk_score(
        url='https://youm7.com/track?order=12345', text='An ordinary update.', db=healthy_db)
    assert result['verdict'] == 'MEDIUM'
    assert result['supporting_signals'] == ['text_model_high_uncorroborated']
    assert not result['checked_links'][0]['url_model_raw_above_threshold']


@pytest.mark.parametrize('url,expected,signal', [
    ('https://192.0.2.1/track?order=12345', 'MEDIUM', 'url_patterns'),
    ('https://youm7.com:8443/track?order=12345', 'MEDIUM', 'url_patterns'),
    ('https://person@youm7.com/track?order=12345', 'MEDIUM', 'url_patterns'),
    ('https://xn--bcher-kva.de/track?order=12345', 'MEDIUM', 'url_patterns'),
    ('https://cibeg.com@evil.example/track?order=12345', 'HIGH', 'userinfo_brand'),
    ('https://known-phish.example/login', 'HIGH', 'blacklist_exact'),
])
def test_independent_url_evidence_survives(healthy_db, url, expected, signal):
    result = risk_scoring.calculate_final_risk_score(url=url, db=healthy_db)
    assert result['verdict'] == expected
    assert signal in result['supporting_signals']


def test_query_keeps_exact_blacklist_identity(healthy_db):
    from app.core.url_utils import url_hash
    from app.models import BlacklistEntry
    url = 'https://youm7.com/track?order=12345'
    entry = healthy_db.query(BlacklistEntry).filter_by(domain='known-phish.example').one()
    entry.url, entry.url_hash, entry.domain = url, url_hash(url), 'youm7.com'
    healthy_db.commit()
    result = risk_scoring.calculate_final_risk_score(url=url, db=healthy_db)
    assert result['verdict'] == 'HIGH'
    assert result['decisive_reason'] == 'blacklist_exact'


def test_model_alert_with_explicit_secret_request_is_high(healthy_db, monkeypatch):
    # Exercise policy with a deterministic alert, without requiring a benign
    # query to trigger the real classifier's historical shortcut.
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: {'probability': 1., 'threshold': .99})
    monkeypatch.setattr(risk_scoring, 'score_text', lambda _: {'probability': .01, 'score': 1})
    result = risk_scoring.calculate_final_risk_score(url='https://youm7.com/track?order=12345',
        text='Send your one-time code to continue', db=healthy_db)
    assert result['verdict'] == 'HIGH'
    assert result['decisive_reason'] == 'url_model_corroborated'


def test_query_does_not_hide_unavailable_checks(healthy_db, monkeypatch):
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {
        'available': False, 'reason': 'database_unavailable'})
    result = risk_scoring.calculate_final_risk_score(url='https://youm7.com/track?order=12345', db=healthy_db)
    assert result['verdict'] == 'INCOMPLETE'
    assert not result['analysis_complete']
    assert 'url_model' not in result['supporting_signals']


def test_historical_promotion_cannot_restore_shortcut_policy():
    from evaluation.run_url_followup_v3 import promote
    with pytest.raises(RuntimeError, match='blocked by the query shortcut review'):
        promote()


def test_historical_renderer_cannot_publish_ordinary_policy_as_current():
    from evaluation.report_url_v3 import main
    with pytest.raises(RuntimeError, match='cannot overwrite the current mitigation report'):
        main()
