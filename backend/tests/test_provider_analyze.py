"""INVENTED-only endpoint fixtures using inert example.eg URLs. No real SMS."""
from dataclasses import replace
from functools import partial

import pytest

from app.engines.provider_claims import ProviderClaimEngine
from app.engines.registry import registry
from app.models import BlacklistEntry, FindingAttack, FindingRecord, ScanRequest
from app.core.url_utils import parse_url, url_hash
from app.routers import analyze
from app.services import provider_findings
from provider_fixtures import INVENTED_URL, NOW, write_invented_registry


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


@pytest.mark.parametrize('provider_outcome', ['engine_raises', 'raises_after_write', 'success'])
def test_provider_transaction_preserves_primary_scan(client, db, tmp_path, monkeypatch, caplog, provider_outcome):
    # The invented local blacklist entry guarantees a primary phishing Finding.
    db.add(BlacklistEntry(url=INVENTED_URL, url_hash=url_hash(INVENTED_URL), domain=parse_url(INVENTED_URL).host,
                          source='manual', first_seen=NOW.date(), last_seen=NOW.date(), reputation_score=90))
    db.commit()
    body = {'text': f'This is Invented Example Bank; click {INVENTED_URL}', 'url': INVENTED_URL}
    monkeypatch.setattr(analyze, 'record_provider_scan', partial(analyze.record_provider_scan, now=NOW))
    baseline = client.post('/analyze', json=body)
    assert baseline.status_code == 200
    expected = baseline.json()
    expected.pop('timing_ms')
    assert expected['verdict'] == 'HIGH' and expected['saved'] and expected['save_error'] is None
    original = db.query(ScanRequest).one()
    primary = db.query(FindingRecord).filter_by(scan_request_id=original.id, engine_name='phishing.analyze').one()

    engine = ProviderClaimEngine(write_invented_registry(tmp_path))
    monkeypatch.setitem(registry._engines, engine.name, engine)
    if provider_outcome == 'engine_raises':
        def fail_engine(observation):
            raise RuntimeError(observation.data['text'])
        monkeypatch.setattr(engine, 'analyze', fail_engine)
    elif provider_outcome == 'raises_after_write':
        write = provider_findings.record_findings

        def fail_after_flush(*args, **kwargs):
            write(*args, **kwargs)
            raise RuntimeError(body['url'])
        monkeypatch.setattr(provider_findings, 'record_findings', fail_after_flush)

    caplog.clear()
    response = client.post('/analyze', json=body)
    assert response.status_code == 200
    actual = response.json()
    actual.pop('timing_ms')
    assert actual == expected

    db.expire_all()
    saved = db.query(ScanRequest).filter(ScanRequest.id != original.id).one()
    assert (saved.text_hash, saved.url_hash) == (original.text_hash, original.url_hash)
    assert saved.result.verdict == expected['verdict']
    assert saved.result.engine_breakdown == original.result.engine_breakdown
    findings = db.query(FindingRecord).filter_by(scan_request_id=saved.id)
    phishing = findings.filter_by(engine_name='phishing.analyze').one()
    assert (phishing.kind, phishing.severity, phishing.confidence, phishing.evidence) == (
        primary.kind, primary.severity, primary.confidence, primary.evidence)
    provider_rows = findings.filter_by(engine_name=engine.name).all()
    logs = [r for r in caplog.records if r.name == analyze.logger.name]
    if provider_outcome == 'success':
        assert [row.kind for row in provider_rows] == ['provider_proof_mismatch']
        assert not logs
    else:
        assert not provider_rows
        assert [r.getMessage() for r in logs] == ['provider_findings_failed']
        assert not logs[0].exc_info and not logs[0].args
        assert INVENTED_URL not in caplog.text
