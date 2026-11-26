"""INVENTED-only endpoint fixtures using inert example.eg URLs. No real SMS."""
from dataclasses import replace

from app.engines.provider_claims import ProviderClaimEngine
from app.engines.registry import registry
from app.models import FindingAttack, FindingRecord
from app.routers import analyze
from provider_fixtures import INVENTED_URL, write_invented_registry


def test_populated_provider_engine_is_additive_to_real_model_verdict(client, db, tmp_path, monkeypatch):
    instance = ProviderClaimEngine(write_invented_registry(tmp_path))
    monkeypatch.setitem(registry._engines, instance.name, instance)
    body = {'text': f'This is Invented Example Bank; click {INVENTED_URL}'}
    monkeypatch.setattr(analyze, 'settings', replace(analyze.settings, findings_enabled=False))
    off = client.post('/analyze', json=body)
    monkeypatch.setattr(analyze, 'settings', replace(analyze.settings, findings_enabled=True))
    on = client.post('/analyze', json=body)
    assert off.status_code == on.status_code == 200
    before, after = off.json(), on.json()
    before.pop('timing_ms'); after.pop('timing_ms')
    assert before == after and after['saved']
    finding = db.query(FindingRecord).filter_by(engine_name=instance.name).one()
    assert (finding.severity, finding.confidence) == ('medium', 'single_signal')
    assert finding.scan_request_id is not None
    # /analyze has no explicit SMS-channel input: text presence alone cannot map Mobile.
    mapped = {(a.technique_id, a.matrix) for a in db.query(FindingAttack).filter_by(finding_id=finding.id)}
    assert mapped == {('T1684.001', 'enterprise')}


def test_empty_registry_ready_health_reports_its_own_missing_coverage(client):
    response = client.get('/health/ready')
    assert response.json()['engines']['phishing.provider_claim']['reason'] == 'provider_registry_empty'
