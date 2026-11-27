"""LAN agent server API (design windows-agent-lan-v1 §4.1, §5.1-5.3, §6, §10 step 3; owner decisions Q1, Q3).

Isolated in-memory database (conftest `db`/`client`), invented payloads only (agent_fixtures.py), invented
server key from conftest. No real hostname, username, path or address is used.
"""
import json
from dataclasses import replace
from datetime import datetime

import pytest
from sqlalchemy import inspect, text

from app.core import device_names as dn
from app.core import security
from app.models import (AgentBatch, Device, DevicePairingToken, FindingDevice, FindingRecord, Incident,
                        IncidentEvent, Indicator)
from app.services import agent_devices
from agent_fixtures import (INVENTED_ACCOUNT, INVENTED_DEVICE, INVENTED_HASH, INVENTED_OTHER_DEVICE, batch, body,
                            host_finding, malware_finding, network_finding)

KEY = dn.load_server_key()
INSTANCE = '7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d'


@pytest.fixture(autouse=True)
def fresh_limiter():
    agent_devices.pair_limiter.reset()
    yield
    agent_devices.pair_limiter.reset()


def invite(client, label='Dept-01'):
    response = client.post('/devices/pairing-invites', json={'display_label': label} if label else None)
    assert response.status_code == 200, response.text
    return response.json()


def pair_body(code, device=INVENTED_DEVICE, **extra):
    return {'schema_version': 'agent-pair-v1', 'pairing_code': code, 'device_ref': device,
            'agent_instance_id': INSTANCE, 'agent_version': 'agent-v1.0.0', 'notice_version_ack': 'pdpl-notice-v1',
            **extra}


def pair(client, device=INVENTED_DEVICE):
    response = client.post('/agent/v1/pair', content=body(pair_body(invite(client)['pairing_code'], device)))
    assert response.status_code == 200, response.text
    return response.json()


def send(client, token, payload, path='/agent/v1/batches', **headers):
    return client.post(path, content=body(payload), headers={'Authorization': f'Bearer {token}', **headers})


def all_rows_text(db) -> str:
    """Every value of every table, as one string (for leak checks)."""
    out = []
    for table in inspect(db.get_bind()).get_table_names():
        out.extend(json.dumps(list(map(str, row))) for row in db.execute(text(f'SELECT * FROM {table}')))
    return '\n'.join(out)


# ---------------------------------------------------------------- pairing

def test_one_use_pairing_stores_srv_and_never_echoes_device_ref(client, db):
    invited = invite(client)
    assert set(invited) == {'invite_id', 'pairing_code', 'expires_at', 'primary_cert_sha256', 'next_cert_sha256'}
    response = client.post('/agent/v1/pair', content=body(pair_body(invited['pairing_code'])))
    assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
    paired = response.json()
    assert set(paired) == {'schema_version', 'device_id', 'agent_token', 'server_instance_id'}
    assert 'hmac:' not in response.text and 'srv:' not in response.text
    device = db.get(Device, paired['device_id'])
    assert device.device_ref == dn.wrap_ref(INVENTED_DEVICE, 'device', KEY) and device.status == 'active'
    assert device.token_hash == agent_devices.digest(paired['agent_token']) and device.display_label == 'Dept-01'
    token_row = db.query(DevicePairingToken).one()
    assert token_row.used_at is not None and token_row.device_id == device.id
    rows = all_rows_text(db)
    assert INVENTED_DEVICE not in rows and invited['pairing_code'] not in rows and paired['agent_token'] not in rows
    again = client.post('/agent/v1/pair', content=body(pair_body(invited['pairing_code'])))
    assert (again.status_code, again.json()['error']) == (401, 'pairing_code_invalid')


def test_pairing_errors(client, db, monkeypatch, tmp_path):
    code = invite(client)['pairing_code']
    srv = client.post('/agent/v1/pair', content=body(pair_body(code, device='srv:' + '9' * 32)))
    assert (srv.status_code, srv.json()['detail']) == (400, 'invalid_input')
    notice = client.post('/agent/v1/pair', content=body(pair_body(code, notice_version_ack='none')))
    assert (notice.status_code, notice.json()['error']) == (400, 'notice_ack_required')
    unknown = client.post('/agent/v1/pair', content=body(pair_body('Z' * 43)))
    assert (unknown.status_code, unknown.json()['error']) == (401, 'pairing_code_invalid')
    db.query(DevicePairingToken).update({'expires_at': datetime(2026, 1, 1)})
    db.commit()
    expired = client.post('/agent/v1/pair', content=body(pair_body(code)))
    assert (expired.status_code, expired.json()['error']) == (401, 'pairing_code_expired')
    code = invite(client)['pairing_code']
    monkeypatch.delenv(dn.SERVER_KEY_ENV)
    monkeypatch.setattr(dn, 'PROJECT_ROOT', tmp_path)     # never read a developer .env
    missing = client.post('/agent/v1/pair', content=body(pair_body(code)))
    assert (missing.status_code, missing.json()['error']) == (503, 'server_ref_key_missing')
    assert db.query(Device).count() == 0 and db.query(DevicePairingToken).filter_by(used_at=None).count() == 2


def test_pairing_is_rate_limited_per_source(client):
    for _ in range(agent_devices.PAIR_ATTEMPTS_PER_MINUTE):
        client.post('/agent/v1/pair', content=body(pair_body('Z' * 43)))
    limited = client.post('/agent/v1/pair', content=body(pair_body('Z' * 43)))
    assert (limited.status_code, limited.json()['error']) == (429, 'rate_limited')


def test_re_pairing_rotates_the_token_and_reactivates(client, db):
    first = pair(client)
    client.post(f"/devices/{first['device_id']}/revoke", json={'reason': 'operator_test'})
    second = pair(client)
    assert second['device_id'] == first['device_id'] and second['agent_token'] != first['agent_token']
    assert db.get(Device, first['device_id']).status == 'active'
    old = send(client, first['agent_token'], batch([]))
    assert (old.status_code, old.json()['error']) == (401, 'token_invalid')
    assert send(client, second['agent_token'], batch([])).status_code == 200


def test_invite_label_must_be_opaque(client):
    for label in ('invented.user@invented.example', r'INVENTED\user', 'C:/Users/x', 'a' * 65, ''):
        response = client.post('/devices/pairing-invites', json={'display_label': label})
        assert response.status_code == 400
    assert client.post('/devices/pairing-invites').status_code == 200


# ---------------------------------------------------------------- batches

def test_batch_stores_sensor_findings_with_srv_refs_only(client, db):
    paired = pair(client)
    payload = batch([network_finding(), malware_finding(), host_finding()])
    response = send(client, paired['agent_token'], payload)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['duplicate_batch'] is False and result['accepted_findings'] == 3 and result['duplicate_findings'] == 0
    stored = dn.wrap_ref(INVENTED_DEVICE, 'device', KEY)
    records = db.query(FindingRecord).all()
    assert {r.source_kind for r in records} == {'sensor'}
    assert {r.source_ref for r in records} == {f"agent_devices:{paired['device_id']}:{payload['batch_id']}"}
    assert {(d.device_ref, d.attributed_by) for d in db.query(FindingDevice)} == {(stored, 'agent')}
    host = next(r for r in records if r.engine_name == 'host.windows')
    assert host.evidence['details']['account_ref'] == dn.wrap_ref(INVENTED_ACCOUNT, 'account', KEY)
    assert host.evidence['details']['host_ref'] == stored
    rows = all_rows_text(db)
    for ref in (INVENTED_DEVICE, INVENTED_ACCOUNT):          # endpoint device/account refs never stored
        assert ref not in rows
    malware = next(r for r in records if r.engine_name == 'malware.files')
    assert malware.evidence['details']['path_ref'].startswith('hmac:')   # local file pseudonym, not re-wrapped
    assert db.query(AgentBatch).one().accepted_findings == 3
    device = db.get(Device, paired['device_id'])
    assert device.last_coverage['engines']['host.windows']['detections']['H1'] == 'not_visible'


def test_no_hmac_device_or_account_ref_is_stored_anywhere(client, db):
    paired = pair(client)
    send(client, paired['agent_token'], batch([network_finding(), host_finding()]))
    for record in db.query(FindingRecord):
        details = record.evidence['details']
        for field in ('device_ref', 'host_ref', 'account_ref'):
            assert not str(details.get(field, '')).startswith('hmac:')
    assert all(d.device_ref.startswith('srv:') for d in db.query(Device))
    assert all(d.device_ref.startswith('srv:') for d in db.query(FindingDevice))


def test_retried_batch_is_idempotent_and_known_finding_ids_are_skipped(client, db):
    paired = pair(client)
    first_finding = network_finding()
    payload = batch([first_finding])
    assert send(client, paired['agent_token'], payload).json()['accepted_findings'] == 1
    retry = send(client, paired['agent_token'], payload).json()
    assert retry['duplicate_batch'] is True and retry['accepted_findings'] == 0 and retry['duplicate_findings'] == 1
    mixed = send(client, paired['agent_token'], batch([first_finding, malware_finding()])).json()
    assert (mixed['duplicate_batch'], mixed['accepted_findings'], mixed['duplicate_findings']) == (False, 1, 1)
    assert db.query(FindingRecord).count() == 2 and db.query(AgentBatch).count() == 2


@pytest.mark.parametrize('finding, code', [
    (network_finding(device=INVENTED_OTHER_DEVICE), 'device_ref_mismatch'),
    (network_finding(device='srv:' + '9' * 32), 'ref_prefix_invalid'),
    (host_finding(details={'device_ref': INVENTED_OTHER_DEVICE}), 'device_ref_conflict'),
    (network_finding(details={'query_name': 'invented-c2.example'}), 'disallowed_evidence_field'),
    (malware_finding(indicators=[{'type': 'hash', 'value_hash': INVENTED_HASH, 'value': INVENTED_HASH,
                                  'role': 'scanned_file', 'hash_algo': 'sha256'}]), 'plaintext_indicator_forbidden'),
])
def test_privacy_rejections_store_nothing(client, db, finding, code):
    paired = pair(client)
    response = send(client, paired['agent_token'], batch([network_finding(), finding]))
    assert (response.status_code, response.json()['error']) == (422, code)
    assert db.query(FindingRecord).count() == 0 and db.query(AgentBatch).count() == 0
    assert db.query(Indicator).count() == 0 and db.query(FindingDevice).count() == 0
    assert 'invented-c2' not in response.text and INVENTED_OTHER_DEVICE not in response.text


def test_limits_and_schema_errors(client):
    token = pair(client)['agent_token']
    too_many = send(client, token, batch([network_finding() for _ in range(101)]))
    assert (too_many.status_code, too_many.json()['error']) == (413, 'limit_exceeded')
    big = client.post('/agent/v1/batches', content=b'{' + b' ' * (600 * 1024) + b'}',
                      headers={'Authorization': f'Bearer {token}'})
    assert (big.status_code, big.json()['error']) == (413, 'limit_exceeded')
    bad = send(client, token, {**batch([]), 'unexpected': 1})
    assert (bad.status_code, bad.json()['error']) == (400, 'invalid_input')
    query = client.post('/agent/v1/batches?x=1', content=body(batch([])), headers={'Authorization': f'Bearer {token}'})
    assert query.status_code == 400


# ---------------------------------------------------------------- tokens, X-API-Key isolation

def test_agent_routes_need_a_device_token_and_ignore_the_api_key(client, monkeypatch):
    monkeypatch.setattr(security, 'settings', replace(security.settings, api_key='invented-operator-key'))
    for path in ('/agent/v1/batches', '/agent/v1/heartbeat', '/agent/v1/unpair'):
        response = client.post(path, content=body(batch([])), headers={'X-API-Key': 'invented-operator-key'})
        assert (response.status_code, response.json()['error']) == (401, 'token_invalid')
        assert response.headers['cache-control'] == 'no-store'
    assert client.post('/agent/v1/batches', content=body(batch([])),
                       headers={'Authorization': 'Basic abc'}).status_code == 401


def test_device_routes_need_the_api_key_and_refuse_an_agent_token(client, monkeypatch):
    monkeypatch.setattr(security, 'settings', replace(security.settings, api_key='invented-operator-key'))
    key_headers = {'X-API-Key': 'invented-operator-key'}
    code = client.post('/devices/pairing-invites', headers=key_headers).json()['pairing_code']
    token = client.post('/agent/v1/pair', content=body(pair_body(code))).json()['agent_token']
    for method, path in (('get', '/devices'), ('get', '/devices/1'), ('post', '/devices/pairing-invites'),
                         ('post', '/devices/1/revoke'), ('patch', '/devices/1')):
        response = getattr(client, method)(path, headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401, path
    assert client.get('/devices', headers=key_headers).status_code == 200


# ---------------------------------------------------------------- operator view, revoke, purge

def test_device_list_and_detail_show_srv_refs_only(client, db):
    paired = pair(client)
    send(client, paired['agent_token'], batch([network_finding(), host_finding()]))
    listing = client.get('/devices')
    assert listing.status_code == 200 and listing.headers['cache-control'] == 'no-store'
    item = listing.json()['items'][0]
    assert item['device_ref'].startswith('srv:') and item['findings_by_severity'] == {'high': 2}
    assert item['open_incidents'] >= 1
    detail = client.get(f"/devices/{paired['device_id']}").json()
    assert detail['findings']['total'] == 2 and len(detail['batches']) == 1
    accounts = {f['account_ref'] for f in detail['findings']['items']}
    assert accounts == {None, dn.wrap_ref(INVENTED_ACCOUNT, 'account', KEY)}
    for response in (listing, client.get(f"/devices/{paired['device_id']}")):
        assert 'hmac:' not in response.text
    assert client.get('/devices/999').status_code == 404
    assert client.get('/devices?status=unknown').status_code == 400


def test_label_edit_is_opaque(client):
    paired = pair(client)
    assert client.patch(f"/devices/{paired['device_id']}", json={'display_label': 'Dept-02'}).json()[
        'display_label'] == 'Dept-02'
    assert client.patch(f"/devices/{paired['device_id']}", json={'display_label': 'invented user'}).status_code == 400


def test_revoked_device_is_refused_and_its_findings_stay_marked(client, db):
    paired = pair(client)
    send(client, paired['agent_token'], batch([network_finding()]))
    revoked = client.post(f"/devices/{paired['device_id']}/revoke", json={'reason': 'operator_test'})
    assert revoked.status_code == 200 and revoked.json()['status'] == 'revoked'
    for path in ('/agent/v1/batches', '/agent/v1/heartbeat'):
        response = send(client, paired['agent_token'], batch([network_finding()]) if 'batches' in path
                        else {k: v for k, v in batch([]).items() if k not in ('batch_id', 'findings')}
                        | {'schema_version': 'agent-heartbeat-v1'}, path=path)
        assert (response.status_code, response.json()['error']) == (401, 'device_revoked')
    assert db.query(FindingRecord).count() == 1
    detail = client.get(f"/devices/{paired['device_id']}").json()
    assert [f['from_revoked_device'] for f in detail['findings']['items']] == [True]
    device = db.get(Device, paired['device_id'])
    assert device.revoked_reason == 'operator_test' and device.revoked_at is not None


def test_purge_is_manual_revoked_only_and_removes_only_findings_since(client, db):
    paired = pair(client)
    old = network_finding(observed_at='2026-11-01T10:00:00+00:00',
                          indicators=[{'type': 'ip', 'value_hash': 'c' * 64, 'value': None, 'role': 'remote_endpoint'}])
    new = network_finding(observed_at='2026-11-27T10:00:00+00:00')
    send(client, paired['agent_token'], batch([old]))
    send(client, paired['agent_token'], batch([new]))
    since = {'since': '2026-11-20T00:00:00+00:00', 'reason': 'compromise_suspected'}
    active = client.post(f"/devices/{paired['device_id']}/purge-findings", json=since)
    assert (active.status_code, active.json()['error']) == (409, 'device_not_revoked')
    assert db.query(FindingRecord).count() == 2
    client.post(f"/devices/{paired['device_id']}/revoke")
    db.query(AgentBatch).update({'received_at': datetime(2026, 11, 2)})   # both batches arrived long ago
    db.commit()
    incident_id = db.query(FindingRecord).filter(FindingRecord.observed_at >= datetime(2026, 11, 20)).one().incident_id
    purged = client.post(f"/devices/{paired['device_id']}/purge-findings", json=since)
    assert purged.status_code == 200, purged.text
    assert purged.json()['findings_purged'] == 1 and purged.json()['batches_purged'] == 0
    remaining = db.query(FindingRecord).all()
    assert [r.observed_at for r in remaining] == [datetime(2026, 11, 1, 10)]
    assert db.query(Indicator).filter_by(value_hash='f' * 64).count() == 0      # orphan hash-only indicator removed
    assert db.query(Indicator).filter_by(value_hash='c' * 64).count() == 1
    assert incident_id is not None
    assert db.query(IncidentEvent).filter_by(incident_id=incident_id, action='findings_expired').count() == 1
    missing_reason = client.post(f"/devices/{paired['device_id']}/purge-findings", json={'since': since['since']})
    assert missing_reason.status_code == 400


def test_purge_also_removes_batches_received_since(client, db):
    paired = pair(client)
    send(client, paired['agent_token'], batch([network_finding(observed_at='2026-10-01T10:00:00+00:00')]))
    client.post(f"/devices/{paired['device_id']}/revoke")
    purged = client.post(f"/devices/{paired['device_id']}/purge-findings",
                         json={'since': '2026-11-01T00:00:00+00:00', 'reason': 'compromise_suspected'}).json()
    assert purged['findings_purged'] == 1 and purged['batches_purged'] == 1
    assert db.query(FindingRecord).count() == 0 and db.query(AgentBatch).count() == 0


# ---------------------------------------------------------------- heartbeat, unpair, correlation

def test_heartbeat_and_unpair(client, db):
    paired = pair(client)
    beat = {k: v for k, v in batch([]).items() if k not in ('batch_id', 'findings')} | {
        'schema_version': 'agent-heartbeat-v1'}
    response = send(client, paired['agent_token'], beat, path='/agent/v1/heartbeat')
    assert response.status_code == 200 and response.json()['schema_version'] == 'agent-heartbeat-v1'
    unpaired = send(client, paired['agent_token'], {'schema_version': 'agent-unpair-v1'}, path='/agent/v1/unpair')
    assert unpaired.json() == {'status': 'revoked'}
    device = db.get(Device, paired['device_id'])
    assert device.status == 'revoked' and device.revoked_reason == 'user_uninstalled'
    again = send(client, paired['agent_token'], {'schema_version': 'agent-unpair-v1'}, path='/agent/v1/unpair')
    assert (again.status_code, again.json()['error']) == (401, 'device_revoked')


def test_cross_engine_and_cross_device_correlation(client, db):
    one, two = pair(client), pair(client, device=INVENTED_OTHER_DEVICE)
    send(client, one['agent_token'], batch([malware_finding(), host_finding()]))     # same file hash, one PC
    send(client, one['agent_token'], batch([network_finding()]))
    send(client, two['agent_token'], batch([network_finding(device=INVENTED_OTHER_DEVICE)]))   # same remote IP hash
    records = db.query(FindingRecord).all()
    by_engine = {}
    for r in records:
        by_engine.setdefault(r.engine_name, []).append(r.incident_id)
    assert len(set(by_engine['malware.files'] + by_engine['host.windows'])) == 1          # hash pivot
    assert len(set(by_engine['network.windows'])) == 1 and None not in by_engine['network.windows']   # ip pivot
    assert by_engine['network.windows'][0] != by_engine['malware.files'][0]                # device never pivots
    refs = {d.device_ref for d in db.query(FindingDevice)}
    assert refs == {dn.wrap_ref(INVENTED_DEVICE, 'device', KEY), dn.wrap_ref(INVENTED_OTHER_DEVICE, 'device', KEY)}
    assert db.query(Incident).count() == 2
