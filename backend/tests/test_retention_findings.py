"""Retention of scan-derived findings (design core-v1 §7.2, §9.10). Invented values only."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.findings import Finding
from app.core.indicators import normalize
from app.models import (FindingAttack, FindingIndicator, FindingRecord, Incident, IncidentEvent, IncidentIndicator,
                        Indicator, IndicatorSighting, ScanRequest, ScanResult)
from app.services.findings import record_findings, seed_correlation_stoplist
from app.services.indicators import sync_feed_indicators

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('retention', ROOT / 'data/scripts/retention.py')
retention = importlib.util.module_from_spec(spec); spec.loader.exec_module(retention)


def ref(kind, value, role):
    n = normalize(kind, value)
    return {'type': kind, 'value_hash': n.value_hash, 'value': None, 'role': role,
            'registered_domain_hash': n.registered_domain_hash}


def scan_with_finding(db, *refs, age_days):
    submitted = datetime.now() - timedelta(days=age_days)
    scan = ScanRequest(input_type='url', url_hash='a' * 64, submitted_at=submitted)
    db.add(scan); db.flush()
    db.add(ScanResult(scan_request_id=scan.id, verdict='HIGH', engine_breakdown={}, final_score=90))
    at = submitted.replace(tzinfo=timezone.utc)
    finding = Finding.model_validate(dict(
        engine={'name': 'phishing.analyze', 'version': 'test'}, domain='phishing', kind='url_phishing',
        severity='high', confidence='corroborated', indicators=list(refs),
        attack=[{'technique_id': 'T1566', 'matrix': 'enterprise', 'attack_version': '20.0', 'basis': 'phishing_message'}],
        observed_at=at, created_at=at, source={'kind': 'scan', 'ref': f'scan_requests:{scan.id}'}))
    record, = record_findings(db, [finding], scan_request_id=scan.id)
    db.commit()
    return scan, record


@pytest.fixture
def seeded(db):
    seed_correlation_stoplist(db)
    return db


def test_old_findings_and_orphan_indicators_are_deleted_incident_kept(seeded):
    shared = ref('url', 'https://shared-lure.example/pay', 'delivery_link')
    old_only = ref('phone', '01000000003', 'contact_phone')
    _, old = scan_with_finding(seeded, shared, old_only, age_days=35)
    _, new = scan_with_finding(seeded, shared, age_days=25)
    assert old.incident_id == new.incident_id  # 10 days apart: inside the 14-day window
    incident_id = old.incident_id
    result = retention.delete_expired(seeded, 30, details=True)
    assert result == {'scans': 1, 'findings': 1, 'indicators': 1}
    assert seeded.query(FindingRecord).count() == 1 and seeded.get(FindingRecord, new.id)
    assert seeded.query(FindingAttack).filter_by(finding_id=old.id).count() == 0
    assert seeded.query(FindingIndicator).filter_by(finding_id=old.id).count() == 0
    assert seeded.query(Indicator).filter_by(value_hash=old_only['value_hash']).count() == 0
    assert seeded.query(Indicator).filter_by(value_hash=shared['value_hash']).count() == 1
    assert seeded.query(IndicatorSighting).count() == 1
    assert {row.indicator_id for row in seeded.query(IncidentIndicator)} == \
        {seeded.query(Indicator).filter_by(value_hash=shared['value_hash']).one().id}
    assert seeded.get(Incident, incident_id) is not None
    event = seeded.query(IncidentEvent).filter_by(incident_id=incident_id, action='findings_expired').one()
    assert event.note == '1' and event.actor == 'etis'
    assert seeded.query(ScanRequest).count() == 1 and seeded.query(ScanResult).count() == 1


def test_feed_indicator_survives_retention(seeded):
    sync_feed_indicators(seeded)
    known = ref('url', 'https://known-phish.example/login', 'delivery_link')
    _, old = scan_with_finding(seeded, known, age_days=60)
    assert retention.delete_expired(seeded, 30, details=True) == {'scans': 1, 'findings': 1, 'indicators': 0}
    indicator = seeded.query(Indicator).filter_by(type='url', value_hash=known['value_hash']).one()
    assert indicator.value == 'https://known-phish.example/login'
    assert seeded.query(IndicatorSighting).filter_by(indicator_id=indicator.id, source_kind='feed').count() == 1


def test_retention_without_findings_keeps_old_return_shape(seeded):
    seeded.add(ScanRequest(input_type='text', text_hash='b' * 64, submitted_at=datetime.now() - timedelta(days=90)))
    seeded.commit()
    assert retention.delete_expired(seeded, 30) == 1


def test_end_to_end_scan_findings_expire(client, db):
    seed_correlation_stoplist(db)
    response = client.post('/analyze', json={'url': 'https://known-phish.example/login'})
    assert response.status_code == 200 and response.json()['verdict'] == 'HIGH'
    assert db.query(FindingRecord).count() == 1
    incident_id = db.query(FindingRecord).one().incident_id
    db.query(ScanRequest).update({'submitted_at': datetime.now() - timedelta(days=45)})
    db.commit()
    assert retention.delete_expired(db, 30, details=True)['findings'] == 1
    assert db.query(FindingRecord).count() == 0 and db.query(Indicator).count() == 0
    assert db.query(FindingIndicator).count() == 0 and db.query(IndicatorSighting).count() == 0
    assert db.get(Incident, incident_id) is not None
