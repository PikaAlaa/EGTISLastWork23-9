"""Decision-rule regressions. All text fixtures below are invented test-only strings."""
from app.engines import risk_scoring
import pytest


def _high_text(_text):
    return {"probability": 0.99, "score": 99, "high_threshold": 0.9,
            "low_threshold": 0.2, "model": "test-fixture"}


def test_text_only_secret_request_can_still_be_high(monkeypatch):
    monkeypatch.setattr(risk_scoring, "score_text", _high_text)
    monkeypatch.setattr(risk_scoring, "score_url", lambda _url: None)
    result = risk_scoring.calculate_final_risk_score(
        text="Your account is blocked. Send your one-time code now to restore access.")
    assert result["verdict"] == "HIGH"
    assert result["decisive_reason"] == "text_high_corroborated"


def test_bank_alert_without_link_or_secret_request_cannot_be_high(monkeypatch):
    monkeypatch.setattr(risk_scoring, "score_text", _high_text)
    monkeypatch.setattr(risk_scoring, "score_url", lambda _url: None)
    result = risk_scoring.calculate_final_risk_score(
        text="A transaction was completed. Your account balance is available in the banking app.")
    assert result["verdict"] == "MEDIUM"
    assert result["decisive_reason"] == "text_model_high_uncorroborated"


def test_url_model_alert_alone_is_medium(monkeypatch, db):
    # Historical policy remains an evaluation comparator.
    monkeypatch.setattr(risk_scoring, 'URL_MODEL_POLICY', 'ordinary')
    monkeypatch.setattr(risk_scoring, "score_text", _high_text)
    monkeypatch.setattr(risk_scoring, "blacklist_health", lambda _db: {
        "available": True, "reason": None, "mode": "test-fixture"})
    monkeypatch.setattr(risk_scoring, "score_url", lambda _url: {
        "probability": 0.91, "threshold": 0.80, "version": "test"})
    result = risk_scoring.calculate_final_risk_score(url="https://example.test/path", db=db)
    assert result["verdict"] == "MEDIUM"
    assert "url_model" in result["supporting_signals"]


def _corroboration_fixture(monkeypatch):
    monkeypatch.setattr(risk_scoring, 'URL_MODEL_POLICY', 'corroboration_only')
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: {'probability': .99, 'threshold': .8})
    monkeypatch.setattr(risk_scoring, 'calculate_domain_typosquatting_score', lambda *args, **kwargs:
                        {'score': 0, 'decisive': False, 'technique': None})
    monkeypatch.setattr(risk_scoring, 'calculate_url_pattern_score', lambda _: {'score': 0, 'flags': []})


def test_corroboration_model_alone_stays_low_and_cannot_corroborate_text(monkeypatch, db):
    _corroboration_fixture(monkeypatch)
    result = risk_scoring.calculate_final_risk_score(url='https://example.test/path', db=db)
    assert result['verdict'] == 'LOW'
    assert result['checked_links'][0]['url_model_raw_above_threshold']
    assert not result['checked_links'][0]['url_model_above_threshold']
    monkeypatch.setattr(risk_scoring, 'score_text', _high_text)
    result = risk_scoring.calculate_final_risk_score(url='https://example.test/path', text='An ordinary update.', db=db)
    assert result['verdict'] == 'MEDIUM'
    assert result['supporting_signals'] == ['text_model_high_uncorroborated']


@pytest.mark.parametrize('signal', ['brand', 'pattern', 'domain', 'secret'])
def test_corroboration_accepts_exactly_the_authorized_signal_families(monkeypatch, db, signal):
    _corroboration_fixture(monkeypatch)
    if signal == 'brand':
        monkeypatch.setattr(risk_scoring, 'calculate_domain_typosquatting_score', lambda *args, **kwargs:
                            {'score': 40, 'decisive': False, 'technique': 'edit_distance'})
    elif signal == 'pattern':
        monkeypatch.setattr(risk_scoring, 'calculate_url_pattern_score', lambda _:
                            {'score': 25, 'flags': ['test_pattern']})
    elif signal == 'domain':
        monkeypatch.setattr(risk_scoring, 'calculate_blacklist_reputation_score', lambda *args:
                            {'score': 60, 'match_type': 'domain', 'matched_entry': None})
    monkeypatch.setattr(risk_scoring, 'score_text', lambda _: {'probability': .01, 'score': 1})
    text = 'Send your one-time code to continue' if signal == 'secret' else None
    result = risk_scoring.calculate_final_risk_score(url='https://example.test/path', text=text, db=db)
    assert 'url_model' in result['supporting_signals']
    assert result['verdict'] == ('HIGH' if signal == 'secret' else 'MEDIUM')


def test_corroboration_does_not_borrow_patterns_from_another_link(monkeypatch, db):
    _corroboration_fixture(monkeypatch)
    monkeypatch.setattr(risk_scoring, 'calculate_url_pattern_score', lambda url:
                        {'score': 25, 'flags': ['test_pattern']} if 'other.test' in url else {'score': 0, 'flags': []})
    monkeypatch.setattr(risk_scoring, 'score_text', lambda _: {'probability': .01, 'score': 1})
    result = risk_scoring.calculate_final_risk_score(url='https://example.test/path', text='https://other.test/', db=db)
    assert not result['checked_links'][0]['url_model_above_threshold']
    assert result['checked_links'][1]['url_model_above_threshold']


def test_url_model_plus_secret_request_is_high(monkeypatch, db):
    monkeypatch.setattr(risk_scoring, "blacklist_health", lambda _db: {
        "available": True, "reason": None, "mode": "test-fixture"})
    monkeypatch.setattr(risk_scoring, "score_text", lambda _text: {
        "probability": 0.1, "score": 10, "high_threshold": 0.9,
        "low_threshold": 0.2, "model": "test-fixture"})
    monkeypatch.setattr(risk_scoring, "score_url", lambda _url: {
        "probability": 0.91, "threshold": 0.80, "version": "test"})
    result = risk_scoring.calculate_final_risk_score(
        url="https://example.test/path", text="Send your one-time code to continue", db=db)
    assert result["verdict"] == "HIGH"
    assert result["decisive_reason"] == "url_model_corroborated"
