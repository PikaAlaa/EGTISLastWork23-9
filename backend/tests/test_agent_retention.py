"""Retention of agent batches, sensor Findings and revoked devices (design windows-agent-lan-v1 §7.3, §10 step 4).

Owner decision Q2: the existing per-engine settings (ETIS_HOST_RETENTION_DAYS, ETIS_MALWARE_RETENTION_DAYS,
ETIS_NETWORK_RETENTION_DAYS), no agent setting. Isolated in-memory database, invented payloads only.
"""
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.settings import settings
from app.models import (AgentBatch, Device, DevicePairingToken, FindingDevice, FindingRecord, IncidentEvent, Indicator,
                        IndicatorSighting)
from app.services import agent_devices
from agent_fixtures import INVENTED_DEVICE, batch, body, host_finding, malware_finding, network_finding

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('etis_retention_agent', ROOT / 'data/scripts/retention.py')
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)
NOW = datetime(2026, 12, 20, 12, 0, 0)       # invented clock
OLD = '2026-12-05T10:00:00+00:00'            # 15 days before NOW
RECENT = '2026-12-19T10:00:00+00:00'         # 1 day before NOW


@pytest.fixture(autouse=True)
def fresh_limiter():
    agent_devices.pair_limiter.reset()


def pair(client, device=INVENTED_DEVICE):
    code = client.post('/devices/pairing-invites').json()['pairing_code']
    response = client.post('/agent/v1/pair', content=body({
        'schema_version': 'agent-pair-v1', 'pairing_code': code, 'device_ref': device,
        'agent_instance_id': '7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d', 'agent_version': 'agent-v1.0.0',
        'notice_version_ack': 'pdpl-notice-v1'}))
    assert response.status_code == 200, response.text
    return response.json()


def send(client, token, findings):
    payload = batch(findings)
    response = client.post('/agent/v1/batches', content=body(payload), headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200, response.text
    return payload['batch_id']


def hash_ind(value_hash, role):
    return [{'type': 'hash', 'value_hash': value_hash, 'value': None, 'role': role, 'hash_algo': 'sha256'}]


def age_batches(db, received_at):
    db.query(AgentBatch).update({'received_at': received_at})
    db.commit()


def engines_left(db):
    return sorted(r.engine_name for r in db.query(FindingRecord))


def test_each_engine_expires_under_its_own_setting(client, db):
    token = pair(client)['agent_token']
    send(client, token, [host_finding(observed_at=OLD, indicators=hash_ind('1' * 64, 'executed_file')),
                         malware_finding(observed_at=OLD, indicators=hash_ind('2' * 64, 'scanned_file')),
                         network_finding(observed_at=OLD)])
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=30, network_days=60, now=NOW)
    assert (result['host.windows'], result['malware.files'], result['network.windows']) == (1, 0, 0)
    assert engines_left(db) == ['malware.files', 'network.windows']
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=14, network_days=60, now=NOW)
    assert result['malware.files'] == 1 and engines_left(db) == ['network.windows']
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=14, network_days=14, now=NOW)
    assert result['network.windows'] == 1 and engines_left(db) == []
    assert db.query(FindingDevice).count() == 0


def test_defaults_come_from_the_existing_per_engine_settings(client, db, monkeypatch):
    assert settings.host_retention_days == 30 and settings.malware_retention_days == 30
    assert settings.network_retention_days == 30
    assert not any(name.startswith('agent_retention') for name in vars(type(settings)).get('__annotations__', {}))
    token = pair(client)['agent_token']
    send(client, token, [host_finding(observed_at=OLD), network_finding(observed_at=OLD)])
    monkeypatch.setattr(retention, 'settings', SimpleNamespace(host_retention_days=5, malware_retention_days=30,
                                                               network_retention_days=30))
    result = retention.delete_expired_agent_findings(db, now=NOW)
    assert (result['host.windows'], result['network.windows']) == (1, 0)


def test_orphan_hash_only_indicators_go_while_shared_and_feed_indicators_stay(client, db):
    token = pair(client)['agent_token']
    send(client, token, [host_finding(observed_at=OLD, indicators=hash_ind('3' * 64, 'executed_file')),
                         host_finding(observed_at=OLD, indicators=hash_ind('4' * 64, 'executed_file')),
                         malware_finding(observed_at=RECENT, indicators=hash_ind('4' * 64, 'scanned_file')),
                         network_finding(observed_at=OLD, indicators=[{'type': 'ip', 'value_hash': '5' * 64,
                                                                       'value': None, 'role': 'remote_endpoint'}])])
    feed = db.query(Indicator).filter_by(value_hash='5' * 64).one()
    feed.value = '203.0.113.5'                      # invented feed plaintext (TEST-NET-3)
    db.add(IndicatorSighting(indicator_id=feed.id, source_kind='feed', source_name='invented_feed',
                             first_seen=NOW, last_seen=NOW, active=True, ref=None))
    db.commit()
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=10, network_days=10, now=NOW)
    assert result['findings'] == 3 and result['indicators'] == 1
    assert db.query(Indicator).filter_by(value_hash='3' * 64).count() == 0      # only expired agent Findings
    assert db.query(Indicator).filter_by(value_hash='4' * 64).count() == 1      # still used by a recent Finding
    assert db.query(Indicator).filter_by(value_hash='5' * 64).count() == 1      # feed value kept


def test_findings_expired_events_are_written_on_incidents(client, db):
    token = pair(client)['agent_token']
    send(client, token, [network_finding(observed_at=OLD)])
    incident_id = db.query(FindingRecord).one().incident_id
    assert incident_id is not None
    retention.delete_expired_agent_findings(db, host_days=30, malware_days=30, network_days=10, now=NOW)
    event = db.query(IncidentEvent).filter_by(incident_id=incident_id, action='findings_expired').one()
    assert event.note == '1'


def test_batches_go_only_when_no_finding_remains_and_after_the_longest_window(client, db):
    token = pair(client)['agent_token']
    send(client, token, [network_finding(observed_at=OLD)])
    send(client, token, [host_finding(observed_at=OLD)])
    age_batches(db, NOW - timedelta(days=40))
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=60, network_days=30, now=NOW)
    assert result['host.windows'] == 1 and result['agent_batches'] == 0          # 40 days < longest window (60)
    result = retention.delete_expired_agent_findings(db, host_days=10, malware_days=30, network_days=30, now=NOW)
    assert result['agent_batches'] == 1                                         # the host batch is now empty
    remaining = db.query(AgentBatch).one()
    assert db.query(FindingRecord).one().source_ref.endswith(remaining.batch_id)


def test_revoked_devices_go_only_with_nothing_left_and_active_devices_stay(client, db):
    active, revoked = pair(client), pair(client, device='hmac:' + '6f' * 16)
    send(client, revoked['agent_token'], [network_finding(device='hmac:' + '6f' * 16, observed_at=OLD)])
    client.post(f"/devices/{revoked['device_id']}/revoke")
    db.query(Device).filter_by(id=revoked['device_id']).update({'revoked_at': NOW - timedelta(days=45)})
    age_batches(db, NOW - timedelta(days=45))
    db.commit()
    keep_findings = retention.delete_expired_agent_findings(db, host_days=30, malware_days=30, network_days=60, now=NOW)
    assert keep_findings['devices'] == 0 and db.get(Device, revoked['device_id']) is not None
    result = retention.delete_expired_agent_findings(db, host_days=30, malware_days=30, network_days=14, now=NOW)
    assert result['network.windows'] == 1 and result['agent_batches'] == 1 and result['devices'] == 1
    assert db.get(Device, revoked['device_id']) is None and db.get(Device, active['device_id']) is not None
    assert db.query(DevicePairingToken).filter_by(device_id=revoked['device_id']).count() == 0


def test_expired_invitations_are_removed_and_import_findings_untouched(client, db):
    client.post('/devices/pairing-invites')
    db.add(FindingRecord(id='9b2f6a51-6c1e-4a6f-8a7f-2b8e7d0c4e11', schema_version='finding-v1',
                         engine_name='network.windows', engine_version='invented', domain='network', kind='beaconing',
                         severity='low', confidence='single_signal', evidence={'reasons': [], 'details': {}},
                         observed_at=datetime(2026, 1, 1), created_at=datetime(2026, 1, 1), source_kind='import',
                         source_ref='network_windows_imports:7'))
    db.commit()
    result = retention.delete_expired_agent_findings(db, host_days=1, malware_days=1, network_days=1, now=NOW)
    assert result['pairing_invites'] == 1 and db.query(DevicePairingToken).count() == 0
    assert db.query(FindingRecord).count() == 1        # standalone import Findings follow their own retention


def test_sensor_sightings_count_as_derived():
    assert {('sensor', 'host.windows'), ('sensor', 'malware.files'), ('sensor', 'network.windows')} <= set(
        retention.SCAN_DERIVED_SIGHTINGS)
    assert ('feed', None) not in retention.SCAN_DERIVED_SIGHTINGS
