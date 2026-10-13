"""Decision-rule regressions. All text fixtures below are invented test-only strings."""
from app.engines import risk_scoring


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
    monkeypatch.setattr(risk_scoring, "score_text", _high_text)
    monkeypatch.setattr(risk_scoring, "blacklist_health", lambda _db: {
        "available": True, "reason": None, "mode": "test-fixture"})
    monkeypatch.setattr(risk_scoring, "score_url", lambda _url: {
        "probability": 0.91, "threshold": 0.80, "version": "test"})
    result = risk_scoring.calculate_final_risk_score(url="https://example.test/path", db=db)
    assert result["verdict"] == "MEDIUM"
    assert "url_model" in result["supporting_signals"]


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
