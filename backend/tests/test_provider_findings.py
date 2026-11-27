"""INVENTED-only scan fixtures, example.com names, blocked sockets, isolated DBs."""
from datetime import timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import socket

import pytest

from app.core.indicators import normalize_phone
from app.engines.provider_claims import ProviderClaimEngine
from app.models import (AttackTechnique, FindingAttack, FindingRecord, Indicator, ScanRequest, Incident)
from app.services.attack import parse_techniques
from app.services.provider_findings import record_provider_scan
from app.engines.registry import registry
from provider_fixtures import INVENTED_PHONE, INVENTED_URL, NOW, write_invented_registry

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('provider persistence test attempted network access')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def invented_scan(db, text, url=None):
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest() if value else None
    scan = ScanRequest(text_hash=digest(text), url_hash=digest(url), input_type='text')
    db.add(scan)
    db.flush()
    return scan


def invented_engine(tmp_path):
    return ProviderClaimEngine(write_invented_registry(tmp_path))


def test_engine_registered_and_empty_health_is_explicit():
    engine = registry.get('phishing.provider_claim')
    assert engine.health({}) == {'available': False, 'reason': 'provider_registry_empty'}
    assert registry.get('phishing.analyze').name == 'phishing.analyze'
    assert len(engine.version) <= 200


def test_unchanged_core_writer_owns_persistence_and_dedup(tmp_path, db, monkeypatch):
    import app.services.provider_findings as service
    calls, original = [], service.record_findings
    def capture(*args, **kwargs):
        calls.append(kwargs['scan_request_id'])
        return original(*args, **kwargs)
    monkeypatch.setattr(service, 'record_findings', capture)
    text = f'This is Invented Example Bank; click {INVENTED_URL}; call {INVENTED_PHONE}'
    scan = invented_scan(db, text)
    records = record_provider_scan(db, scan.id, text=text, channel='sms', now=NOW, engine=invented_engine(tmp_path))
    assert len(records) == 2 and calls == [scan.id]
    assert all(r.scan_request_id == scan.id and r.source_ref == f'scan_requests:{scan.id}' for r in records)
    again = record_provider_scan(db, scan.id, text=text, channel='sms', now=NOW, engine=invented_engine(tmp_path))
    assert {r.id for r in again} == {r.id for r in records}
    assert len(calls) == 1


def test_privacy_all_persisted_columns_and_logs(tmp_path, db, caplog):
    text = (f'This is Invented Example Bank; click {INVENTED_URL}/InventedPrivateMarker; '
            f'call {INVENTED_PHONE}')
    scan = invented_scan(db, text)
    records = record_provider_scan(db, scan.id, text=text, channel='sms', now=NOW,
                                   sender_id='INVENTEDOTHER', engine=invented_engine(tmp_path))
    assert records and all(r.severity == 'high' and r.confidence == 'corroborated' for r in records)
    stored = []
    for table in db.bind.dialect.get_table_names(db.connection()):
        from sqlalchemy import text as sql_text
        stored.extend(tuple(row) for row in db.execute(sql_text('SELECT * FROM "' + table + '"')))
    serialized = json.dumps(stored, default=str) + caplog.text
    for private in (text, INVENTED_PHONE, INVENTED_URL, 'InventedPrivateMarker', 'INVENTEDOTHER'):
        assert private not in serialized
    phones = db.query(Indicator).filter_by(type='phone').all()
    assert any(p.value_hash == normalize_phone(INVENTED_PHONE).value_hash and p.value is None for p in phones)
    # Official registrable-parent pivots are withheld without mutating the core stoplist.
    assert not db.query(Indicator).filter_by(type='domain').count()


def test_active_attack_mappings_validate_against_local_catalogue_fixture(tmp_path, db):
    fixture = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-subset.json').read_text(encoding='utf-8'))
    lock = json.loads((ROOT / 'data/attack-lock.json').read_text(encoding='utf-8'))
    assert {k: v['sha256'] for k, v in fixture['sources'].items()} == {f['collection']: f['sha256'] for f in lock['files']}
    for matrix in ('enterprise', 'mobile'):
        db.add_all(AttackTechnique(**r) for r in parse_techniques(fixture['objects'][matrix], matrix, '20.0'))
    text = f'This is Invented Example Bank; click {INVENTED_URL}'
    scan = invented_scan(db, text)
    records = record_provider_scan(db, scan.id, text=text, channel='sms', now=NOW, engine=invented_engine(tmp_path))
    emitted = {(a.technique_id, a.matrix, a.basis) for a in db.query(FindingAttack)}
    assert emitted == {('T1684.001', 'enterprise', 'provider_claim_proof_conflict'),
                       ('T1660', 'mobile', 'sms_deceptive_action')}
    assert 'T1656' not in {a[0] for a in emitted}


def test_scan_retention_removes_provider_findings_and_orphan_phone(tmp_path, db):
    text = f'This is Invented Example Bank; call {INVENTED_PHONE}'
    scan = invented_scan(db, text)
    scan.submitted_at = NOW.replace(tzinfo=None) - timedelta(days=90)
    record_provider_scan(db, scan.id, text=text, now=NOW, engine=invented_engine(tmp_path))
    db.commit()
    assert db.query(FindingRecord).count() == 1
    spec = importlib.util.spec_from_file_location('provider_retention_check', ROOT / 'data/scripts/retention.py')
    retention = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(retention)
    retention.delete_expired(db, days=30)
    assert db.query(FindingRecord).count() == 0
    assert db.query(Indicator).count() == 0


def test_scan_owner_mismatch_refuses_cross_message_links(tmp_path, db):
    scan = invented_scan(db, 'invented original message')
    for scan_id in ('import:invented', -1, True, scan.id + 1):
        with pytest.raises(ValueError, match='provider_scan_owner'):
            record_provider_scan(db, scan_id, text='invented other', engine=invented_engine(tmp_path))
    with pytest.raises(ValueError, match='provider_scan_owner_mismatch'):
        record_provider_scan(db, scan.id, text='invented different message', engine=invented_engine(tmp_path))
    assert db.query(FindingRecord).count() == 0


def test_empty_registry_emits_nothing_and_failed_registry_degrades_only_itself(db, monkeypatch):
    from app.engines import provider_claims
    from app.core.provider_registry import RegistryUnavailable
    text = 'invented input without provider coverage'
    scan = invented_scan(db, text)
    assert record_provider_scan(db, scan.id, text=text, now=NOW) == []
    def unavailable():
        raise RegistryUnavailable('provider_registry_unavailable')
    monkeypatch.setattr(provider_claims, 'load_bundled_registry', unavailable)
    record, = record_provider_scan(db, scan.id, text=text, now=NOW)
    assert (record.kind, record.severity, record.confidence) == ('provider_check_incomplete', 'info', 'undetermined')
    assert registry.health({})['phishing.provider_claim']['reason'] == 'provider_registry_unavailable'


def test_core_correlation_joins_suspicious_contact_but_never_official_parent(tmp_path, db):
    instance = invented_engine(tmp_path)
    text = f'This is Invented Example Bank; call {INVENTED_PHONE}'
    for _ in range(2):
        scan = invented_scan(db, text)
        record_provider_scan(db, scan.id, text=text, channel='sms', now=NOW, engine=instance)
    assert db.query(Incident).count() == 1
    assert len({r.incident_id for r in db.query(FindingRecord)}) == 1
    # Distinct scans sharing only the official registrable parent do not pivot.
    for suffix in ('invented-one', 'invented-two'):
        text = f'This is Invented Example Bank; click {INVENTED_URL}/{suffix}'
        scan = invented_scan(db, text)
        records = record_provider_scan(db, scan.id, text=text, now=NOW, engine=instance)
        assert all(r.incident_id is None for r in records)
    assert db.query(Incident).count() == 1
