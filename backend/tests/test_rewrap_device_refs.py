"""One-off rewrap of refs stored before core v2 (design core-v2 §3.2, owner decision Q20, step 7b).

Rows are seeded directly, as earlier imports stored them (endpoint `hmac:` refs, no
finding_devices). Every ref, name and key is invented.
"""
import importlib.util
import io
import json
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from app.core import device_names as dn
from app.engines.host.pseudonyms import Pseudonymizer
from app.models import FindingDevice, FindingRecord

ROOT = Path(__file__).resolve().parents[2]
HOST_KEY = bytes(range(70, 102))
PC = Pseudonymizer(HOST_KEY).host_ref('invented-pc')
OTHER = Pseudonymizer(HOST_KEY).host_ref('other-pc')
ACCOUNT = Pseudonymizer(HOST_KEY).account_ref(name='invented-user', domain='invented')
T0 = datetime(2026, 11, 1, 9, 0)


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


command = _load('etis_rewrap_device_refs', 'data/scripts/rewrap_device_refs.py')
retention = _load('etis_retention_rewrap', 'data/scripts/retention.py')


def seed(db, details, source_ref='network_windows_imports:1', engine='network.windows'):
    row = FindingRecord(id=str(uuid.uuid4()), schema_version='finding-v1', engine_name=engine, engine_version='old',
                        domain='network', kind='beaconing', severity='high', confidence='corroborated',
                        evidence={'reasons': ['periodic_beaconing'], 'details': details}, observed_at=T0,
                        created_at=T0, source_kind='import', source_ref=source_ref)
    db.add(row)
    db.commit()
    return row.id


def snapshot(db):
    db.expire_all()
    return (sorted((r.id, json.dumps(r.evidence, sort_keys=True)) for r in db.query(FindingRecord)),
            sorted((r.finding_id, r.device_ref, r.attributed_by) for r in db.query(FindingDevice)))


def run(db, env_file=None):
    out = io.StringIO()
    code = command.main([], session_factory=sessionmaker(bind=db.get_bind(), expire_on_commit=False),
                        env_file=env_file, out=out)
    return code, out.getvalue()


@pytest.fixture
def world(db):
    return {
        'network': seed(db, {'detection': 'N6', 'device_ref': PC}),
        'sysmon': seed(db, {'device_ref': PC, 'account_ref': ACCOUNT}),
        'system': seed(db, {'device_ref': PC, 'account_ref': 'sid:S-1-5-18'}),
        'host': seed(db, {'host_ref': PC, 'account_ref': ACCOUNT}, engine='host.windows'),
        'agent': seed(db, {'device_ref': PC}, source_ref='agent_devices:2:batch-9', engine='malware.files'),
        'conflict': seed(db, {'device_ref': PC, 'host_ref': OTHER}),
        'malformed': seed(db, {'device_ref': 'hmac:not-hex'}),
        'phishing': seed(db, {'verdict': 'HIGH'}, source_ref='scan_requests:1', engine='phishing.analyze'),
    }


def test_rewrap_hmac_refs_to_srv_and_fill_finding_devices(db, world):
    code, printed = run(db)
    assert code == 0
    key = dn.load_server_key()
    device, account = dn.wrap_ref(PC, 'device', key), dn.wrap_ref(ACCOUNT, 'account', key)
    db.expire_all()
    details = {name: db.get(FindingRecord, fid).evidence['details'] for name, fid in world.items()}
    assert details['network'] == {'detection': 'N6', 'device_ref': device}
    assert details['sysmon'] == {'device_ref': device, 'account_ref': account}
    assert details['system'] == {'device_ref': device, 'account_ref': 'sid:S-1-5-18'}
    assert details['host'] == {'host_ref': device, 'account_ref': account}
    rows = {r.finding_id: (r.device_ref, r.attributed_by) for r in db.query(FindingDevice)}
    assert rows[world['agent']] == (device, 'agent') and rows[world['network']] == (device, 'engine_details')
    assert set(rows) == {world[k] for k in ('network', 'sysmon', 'system', 'host', 'agent')}
    assert json.loads(printed)['rewrap_device_refs'] == {
        'finding_devices_added': 5, 'findings_with_refs': 7, 'rewritten': 5,
        'skipped_device_ref_conflict': 1, 'skipped_ref_format_invalid': 1}


def test_rewrap_skipped_rows_are_left_untouched(db, world):
    before = {k: json.dumps(db.get(FindingRecord, world[k]).evidence) for k in ('conflict', 'malformed', 'phishing')}
    run(db)
    db.expire_all()
    assert {k: json.dumps(db.get(FindingRecord, world[k]).evidence) for k in before} == before
    assert db.get(FindingDevice, world['conflict']) is None


def test_rewrap_second_run_changes_nothing(db, world):
    run(db)
    first = snapshot(db)
    code, printed = run(db)
    assert code == 0 and snapshot(db) == first
    counts = json.loads(printed)['rewrap_device_refs']
    assert counts.get('rewritten', 0) == 0 and counts.get('finding_devices_added', 0) == 0
    assert counts['already_stored_form'] == 5


def test_rewrap_fills_missing_device_row_for_already_stored_form(db):
    stored = dn.wrap_ref(PC, 'device', dn.load_server_key())
    fid = seed(db, {'device_ref': stored})
    run(db)
    assert db.get(FindingDevice, fid).device_ref == stored


def test_rewrap_refuses_without_the_server_key(db, world, tmp_path, monkeypatch):
    monkeypatch.delenv(dn.SERVER_KEY_ENV)
    before = snapshot(db)
    code, printed = run(db, env_file=tmp_path / 'absent.env')
    assert code == 2 and printed == '' and snapshot(db) == before


def test_rewrap_prints_counts_only(db, world, capsys):
    _, printed = run(db)
    stored = dn.wrap_ref(PC, 'device', dn.load_server_key())
    for value in (PC, OTHER, ACCOUNT, stored, 'hmac:', 'srv:'):
        assert value not in printed and value not in capsys.readouterr().err
    assert set(json.loads(printed)) == {'rewrap_device_refs'}


def test_rewrap_then_retention_deletes_device_rows_with_their_findings(db, world):
    run(db)
    expired, _ = retention._expire_findings(db, finding_filter=FindingRecord.id.in_([world['network'], world['agent']]))
    db.commit()
    assert expired == 2
    assert db.get(FindingDevice, world['network']) is None and db.get(FindingDevice, world['agent']) is None
    assert db.get(FindingDevice, world['sysmon']) is not None
