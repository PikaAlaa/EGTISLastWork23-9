"""network.windows step 12: retention of import records and their Findings (design §7, §8.11).

Imports run through data/scripts/import_network_windows.py on invented files (helpers shared with
the step 11 tests). Sockets are blocked.
"""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.indicators import sha256_hex
from app.models import (FindingRecord, IncidentEvent, Indicator, IndicatorSighting, MalwareScan,
                        NetworkWindowsImport)
from malware_fixtures import block_network
from test_network_windows_import_command import C2, build_engine, command, inputs, run

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('etis_retention_network', ROOT / 'data/scripts/retention.py')
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    block_network(monkeypatch)


def two_imports(db, tmp_path):
    engine = build_engine(tmp_path / 'root')
    for name in ('a', 'b'):
        folder = tmp_path / name
        folder.mkdir()
        assert run(folder, db, inputs(folder), engine=engine)[0] == command.EXIT_OK
    return [row.id for row in db.query(NetworkWindowsImport).order_by(NetworkWindowsImport.id)]


def age(db, import_id, days):
    row = db.get(NetworkWindowsImport, import_id)
    row.started_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    db.commit()


def refs(db, import_id):
    return db.query(FindingRecord).filter_by(source_ref=f'network_windows_imports:{import_id}')


def test_old_imports_expire_with_their_findings_and_orphan_indicators(db, tmp_path):
    old, recent = two_imports(db, tmp_path)
    assert refs(db, old).count() == 1 and refs(db, recent).count() == 1   # N1 to the listed C2 address
    incidents = {r.incident_id for r in refs(db, old)}
    age(db, old, 40)
    assert retention.delete_expired_network_windows(db, 30) == {
        'network_windows_imports': 1, 'findings': 1, 'indicators': 0}
    assert [r.id for r in db.query(NetworkWindowsImport)] == [recent] and refs(db, old).count() == 0
    for incident_id in incidents:
        assert db.query(IncidentEvent).filter_by(incident_id=incident_id, action='findings_expired').count() == 1
    age(db, recent, 40)
    assert retention.delete_expired_network_windows(db, 30) == {
        'network_windows_imports': 1, 'findings': 1, 'indicators': 1}
    assert db.query(Indicator).filter_by(value_hash=sha256_hex(C2)).count() == 0
    assert db.query(IndicatorSighting).filter_by(source_name='network.windows').count() == 0


def test_feed_rows_with_a_plaintext_value_are_kept(db, tmp_path):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    feed = Indicator(type='ip', value_hash=sha256_hex(C2), value=C2, first_seen=now, last_seen=now)
    db.add(feed)
    db.flush()
    db.add(IndicatorSighting(indicator_id=feed.id, source_kind='feed', source_name='invented_feed', first_seen=now,
                             last_seen=now, active=True))
    db.commit()
    old, recent = two_imports(db, tmp_path)
    age(db, old, 40)
    age(db, recent, 40)
    assert retention.delete_expired_network_windows(db, 30)['indicators'] == 0
    assert db.query(Indicator).filter_by(value_hash=sha256_hex(C2)).one().value == C2


def test_retention_uses_the_network_setting(db, tmp_path, monkeypatch):
    old, _ = two_imports(db, tmp_path)
    age(db, old, 10)
    assert retention.delete_expired_network_windows(db)['network_windows_imports'] == 0
    monkeypatch.setattr(retention, 'settings', SimpleNamespace(network_retention_days=5, retention_days=30,
                                                               malware_retention_days=30))
    assert retention.delete_expired_network_windows(db)['network_windows_imports'] == 1


def test_other_retention_paths_leave_network_findings(db, tmp_path):
    old, recent = two_imports(db, tmp_path)
    age(db, old, 400)
    assert retention.delete_expired(db, 0, details=True)['findings'] == 0
    assert retention.delete_expired_malware(db, 0) == {'malware_scans': 0, 'findings': 0, 'indicators': 0}
    assert db.query(FindingRecord).filter_by(engine_name='network.windows').count() == 2
    assert db.query(MalwareScan).count() == 0


def test_the_setting_is_documented():
    assert 'ETIS_NETWORK_RETENTION_DAYS=30' in (ROOT / '.env.example').read_text(encoding='utf-8')
    from app.core.settings import settings
    assert settings.network_retention_days >= 1
