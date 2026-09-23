from datetime import date
import hashlib

from app.models import BlacklistEntry
from app.engines.rule_based.url_utils import canonicalize_url
from app.core.config import settings
from app.schemas import AnalyzeRequest
from app.services.analyzer import analyze


BAD_URL = "https://evil.example/account/verify"


def seed_bad_url(db):
    db.add(BlacklistEntry(
        url=BAD_URL,
        url_hash=hashlib.sha256(canonicalize_url(BAD_URL).encode()).hexdigest(),
        domain="evil.example",
        source="test_feed",
        brand_target="Example",
        first_seen=date.today(),
        last_seen=date.today(),
    ))
    db.commit()


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_analyze_exact_blacklist_match(client, db):
    seed_bad_url(db)
    response = client.post("/analyze", json={"url": BAD_URL})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "HIGH"
    assert body["engine_details"]["blacklist"]["match_type"] == "exact"
    assert body["saved"] is True


def test_verified_clean_domain_is_low(client):
    body = client.post("/analyze", json={"url": "https://www.cibeg.com"}).json()
    assert body["final_score"] == 0
    assert body["verdict"] == "LOW"


def test_verified_domain_does_not_hide_phishing_text(client):
    body = client.post("/analyze", json={
        "url": "https://www.cibeg.com",
        "text": "عاجل أدخل كلمة المرور ورمز التحقق فورا",
    }).json()
    assert body["verdict"] == "HIGH"
    assert body["engine_details"]["rule_based"]["sub_engines"]["domain_typosquatting"]["allowlisted"] is True


def test_canonical_exact_blacklist_match(client, db):
    seed_bad_url(db)
    body = client.post("/analyze", json={"url": "https://evil.example/account/verify/"}).json()
    assert body["engine_details"]["blacklist"]["match_type"] == "exact"


def test_shared_hosting_does_not_apply_domain_wide_match(client, db):
    bad = "https://attacker.netlify.app/login"
    db.add(BlacklistEntry(
        url=bad,
        url_hash=hashlib.sha256(canonicalize_url(bad).encode()).hexdigest(),
        domain="attacker.netlify.app",
        source="test_feed",
        brand_target=None,
        first_seen=date.today(),
        last_seen=date.today(),
    ))
    db.commit()
    body = client.post("/analyze", json={"url": "https://attacker.netlify.app/other"}).json()
    assert body["engine_details"]["blacklist"]["match_type"] is None


def test_text_only_scan_runs_rule_engine(client):
    body = client.post("/analyze", json={"text": "عاجل أدخل كلمة المرور ورمز التحقق"}).json()
    assert body["engine_details"]["rule_based"]["applicable"] is True
    assert body["engine_details"]["blacklist"]["applicable"] is False


def test_threats_and_stats(client, db):
    seed_bad_url(db)
    threats = client.get("/threats").json()
    stats = client.get("/stats").json()
    assert threats["total"] == 1
    assert threats["items"][0]["source"] == "test_feed"
    assert stats["blacklist_total"] == 1


def test_empty_request_is_rejected(client):
    assert client.post("/analyze", json={}).status_code == 422


def test_api_key_is_enforced_when_configured(client):
    original = settings.api_key
    settings.api_key = "test-secret"
    try:
        assert client.get("/stats").status_code == 401
        assert client.get("/stats", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/stats", headers={"X-API-Key": "test-secret"}).status_code == 200
    finally:
        settings.api_key = original


def test_threat_filters_pagination_and_bounds(client, db):
    for index, source in enumerate(("feed_a", "feed_a", "feed_b"), start=1):
        url = f"https://bad{index}.example/login"
        db.add(BlacklistEntry(
            url=url,
            url_hash=hashlib.sha256(canonicalize_url(url).encode()).hexdigest(),
            domain=f"bad{index}.example",
            source=source,
            brand_target=None,
            first_seen=date.today(),
            last_seen=date.today(),
        ))
    db.commit()
    first_page = client.get("/threats", params={"page": 1, "page_size": 1, "source": "feed_a"})
    assert first_page.status_code == 200
    assert first_page.json()["total"] == 2
    assert len(first_page.json()["items"]) == 1
    assert client.get("/threats", params={"domain": "bad3"}).json()["total"] == 1
    assert client.get("/threats", params={"page": 0}).status_code == 422
    assert client.get("/threats", params={"page_size": 101}).status_code == 422


def test_analysis_survives_persistence_failure(db, monkeypatch):
    def fail_commit():
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(db, "commit", fail_commit)
    result = analyze(AnalyzeRequest(text="عاجل أدخل كلمة المرور ورمز التحقق"), db)
    assert result["final_score"] > 0
    assert result["saved"] is False
    assert result["save_error"] is not None
