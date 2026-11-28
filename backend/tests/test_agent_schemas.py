"""Agent wire schemas and the server privacy gate (design windows-agent-lan-v1 §5.1, §5.2, §10 step 2).

All payloads are invented (agent_fixtures.py). The server key is the invented test key from conftest.py.
"""
import copy
import json

import pytest

from app.core import device_names as dn
from app.core.findings import Finding
from app.services import agent_privacy as privacy
from app.services.agent_schemas import (AgentBatchRequest, AgentHeartbeatRequest, AgentPairRequest, AgentRequestError,
                                        AgentUnpairRequest, MAX_BODY_BYTES, parse_request)
from agent_fixtures import (INVENTED_ACCOUNT, INVENTED_DEVICE, INVENTED_OTHER_DEVICE, batch, body, host_finding,
                            malware_finding, network_finding)

KEY = dn.load_server_key()
STORED = dn.wrap_ref(INVENTED_DEVICE, 'device', KEY)


def parsed(payload):
    return parse_request(AgentBatchRequest, body(payload))


def gate(*findings):
    request = parsed(batch(findings))
    privacy.check_batch(request.findings, STORED, KEY)
    return request


def rejected(*findings) -> tuple[int, str]:
    with pytest.raises(AgentRequestError) as caught:
        gate(*findings)
    return caught.value.status, caught.value.code


# ---------------------------------------------------------------- schemas

@pytest.mark.parametrize('make', [network_finding, malware_finding, host_finding])
def test_valid_batches_for_each_engine_pass(make):
    request = gate(make())
    assert len(request.findings) == 1 and isinstance(request.findings[0], Finding)


def test_a_batch_mixing_all_three_engines_passes_and_an_empty_batch_is_valid():
    assert len(gate(network_finding(), malware_finding(), host_finding()).findings) == 3
    assert gate().findings == []


def test_pair_heartbeat_and_unpair_schemas():
    pair = {'schema_version': 'agent-pair-v1', 'pairing_code': 'A' * 43, 'device_ref': INVENTED_DEVICE,
            'agent_instance_id': '7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d', 'agent_version': 'agent-v1.0.0',
            'notice_version_ack': 'pdpl-notice-v1'}
    assert parse_request(AgentPairRequest, body(pair)).device_ref == INVENTED_DEVICE
    with pytest.raises(AgentRequestError) as caught:
        parse_request(AgentPairRequest, body({**pair, 'notice_version_ack': None}))
    assert (caught.value.status, caught.value.code) == (400, 'notice_ack_required')
    with pytest.raises(AgentRequestError) as caught:
        parse_request(AgentPairRequest, body({**pair, 'agent_instance_id': '7c1d6c1e-3f0a-1c55-9a39-1a1d3e1b2c3d'}))
    assert caught.value.code == 'invalid_input'   # UUID1-shaped, not UUID4
    with pytest.raises(AgentRequestError):
        parse_request(AgentPairRequest, body({**pair, 'computer_name': 'INVENTED-PC'}))
    beat = {k: v for k, v in batch([]).items() if k not in ('batch_id', 'findings')}
    beat['schema_version'] = 'agent-heartbeat-v1'
    assert parse_request(AgentHeartbeatRequest, body(beat)).agent_version == 'agent-v1.0.0'
    assert parse_request(AgentUnpairRequest, body({'schema_version': 'agent-unpair-v1'}))
    with pytest.raises(AgentRequestError):
        parse_request(AgentUnpairRequest, body({'schema_version': 'agent-unpair-v1', 'reason': 'x'}))


@pytest.mark.parametrize('mutate, code, status', [
    (lambda p: p.update(extra_field=1), 'invalid_input', 400),
    (lambda p: p.update(schema_version='agent-batch-v2'), 'invalid_input', 400),
    (lambda p: p.update(batch_id='not-a-uuid'), 'invalid_input', 400),
    (lambda p: p.update(sent_at='2026-11-27T10:00:00'), 'invalid_input', 400),             # naive time
    (lambda p: p['coverage']['queue_status'].update(queued_batches=-1), 'invalid_input', 400),
    (lambda p: p['coverage'].update(engines={'network.flows': {}}), 'invalid_input', 400),
    (lambda p: p['findings'][0].update(schema_version='finding-v2'), 'invalid_input', 400),
    (lambda p: p['findings'][0]['engine'].update(name='phishing.analyze'), 'invalid_input', 400),
    (lambda p: p.update(findings=[network_finding() for _ in range(101)]), 'limit_exceeded', 413),
])
def test_schema_errors_and_limits(mutate, code, status):
    payload = batch([network_finding()])
    mutate(payload)
    with pytest.raises(AgentRequestError) as caught:
        parsed(payload)
    assert (caught.value.status, caught.value.code) == (status, code)


def test_body_limit_duplicate_keys_and_non_objects():
    with pytest.raises(AgentRequestError) as caught:
        parse_request(AgentBatchRequest, b' ' * (MAX_BODY_BYTES + 1))
    assert (caught.value.status, caught.value.code) == (413, 'limit_exceeded')
    for raw in (b'', b'[]', b'{"schema_version":"agent-batch-v1","schema_version":"agent-batch-v1"}', b'\xff'):
        with pytest.raises(AgentRequestError) as caught:
            parse_request(AgentBatchRequest, raw)
        assert caught.value.code == 'invalid_input'


def test_errors_never_echo_submitted_values():
    marker = 'INVENTED-MARKER-PC-7731'
    payload = batch([network_finding(details={'computer_name': marker})])
    with pytest.raises(AgentRequestError) as caught:
        gate_payload = parsed(payload)
        privacy.check_batch(gate_payload.findings, STORED, KEY)
    assert marker not in str(caught.value) and marker not in repr(caught.value)


# ---------------------------------------------------------------- device binding

def test_wrapped_hmac_matching_the_stored_srv_ref_passes():
    gate(network_finding(), host_finding(), malware_finding())


@pytest.mark.parametrize('make', [network_finding, malware_finding, host_finding])
def test_a_different_hmac_ref_is_a_device_ref_mismatch(make):
    assert rejected(make(device=INVENTED_OTHER_DEVICE)) == (422, 'device_ref_mismatch')


def test_one_mismatched_finding_rejects_the_whole_batch():
    assert rejected(network_finding(), network_finding(device=INVENTED_OTHER_DEVICE)) == (422, 'device_ref_mismatch')


def test_a_finding_without_any_device_ref_is_refused():
    finding = network_finding()
    del finding['evidence']['details']['device_ref']
    assert rejected(finding) == (422, 'device_ref_mismatch')


def test_binding_uses_compare_digest_on_the_wrapped_ref(monkeypatch):
    calls = []
    real = privacy.hmac.compare_digest
    monkeypatch.setattr(privacy.hmac, 'compare_digest', lambda a, b: calls.append((a, b)) or real(a, b))
    gate(network_finding())
    assert calls == [(STORED.encode('ascii'), STORED.encode('ascii'))]


@pytest.mark.parametrize('field', ['device_ref', 'host_ref', 'account_ref', 'path_ref'])
def test_srv_refs_on_the_wire_are_refused(field):
    srv = 'srv:' + '9' * 32
    make = host_finding if field in ('host_ref', 'account_ref') else malware_finding if field == 'path_ref' \
        else network_finding
    finding = make()
    finding['evidence']['details'][field] = srv
    assert rejected(finding) == (422, 'ref_prefix_invalid')


def test_srv_anywhere_in_details_is_refused():
    finding = network_finding(details={'values': {'note': 'srv:' + '9' * 32}})
    assert rejected(finding) == (422, 'ref_prefix_invalid')


def test_differing_device_ref_and_host_ref_is_a_conflict():
    finding = host_finding(details={'device_ref': INVENTED_OTHER_DEVICE})
    assert rejected(finding) == (422, 'device_ref_conflict')


def test_the_stored_device_ref_is_the_core_v2_wrap():
    assert STORED == dn.wrap_ref(INVENTED_DEVICE, 'device', KEY) and STORED.startswith('srv:') and len(STORED) == 36


# ---------------------------------------------------------------- indicators and allowlist

@pytest.mark.parametrize('make, value', [(network_finding, '203.0.113.9'), (malware_finding, 'e' * 64),
                                         (host_finding, 'e' * 64)])
def test_plaintext_indicator_values_are_forbidden(make, value):
    finding = make()
    finding['indicators'][0]['value'] = value
    assert rejected(finding) == (422, 'plaintext_indicator_forbidden')


@pytest.mark.parametrize('make, key, value', [
    (network_finding, 'query_name', 'invented-c2.example'),          # unknown key
    (network_finding, 'computer_name', 'INVENTED-PC'),               # unknown key
    (host_finding, 'username', 'invented.user'),                     # unknown key
    (host_finding, 'command_line', 'powershell -enc invented'),      # unknown key
    (malware_finding, 'path', r'C:\Users\invented\Downloads\x.exe'),  # unknown key
    (malware_finding, 'file_name', 'invented.exe'),                  # unknown key
])
def test_unknown_evidence_keys_are_refused(make, key, value):
    assert rejected(make(details={key: value})) == (422, 'disallowed_evidence_field')


@pytest.mark.parametrize('make, key, value', [
    # raw paths, user names and host names placed in allowed fields fail their format checks
    (malware_finding, 'path_ref', r'C:\Users\invented\Downloads\x.exe'),
    (malware_finding, 'extension', r'\invented.exe'),
    (malware_finding, 'location_class', r'C:\Users\invented'),
    (host_finding, 'account_ref', r'INVENTED-DOMAIN\invented.user'),
    (host_finding, 'account_ref', 'invented.user@invented.example'),
    (host_finding, 'account_ref', 'sid:S-1-5-21-1111111111-2222222222-3333333333-1001'),   # a real-user SID
    (host_finding, 'host_ref', 'INVENTED-PC'),
    (host_finding, 'parent', r'C:\Program Files\Invented\winword.exe'),
    (host_finding, 'child', 'INVENTED-PC'),
    (network_finding, 'device_ref', 'invented-pc.corp.example'),
    (network_finding, 'detection', 'invented-pc'),
    (network_finding, 'window', {'first': 'INVENTED-PC', 'last': '2026-11-27T10:00:00Z'}),
    (network_finding, 'values', {'query': 'invented user name'}),
    (network_finding, 'lists', [{'list': 'invented_list', 'title': 'x', 'version': 'v', 'licence': 'x',
                                 'link': 'https://feodotracker.abuse.ch/'}]),
    (network_finding, 'lists', [{'list': 'feodo_tracker', 'title': 'x', 'version': 'v', 'licence': 'x',
                                 'link': 'https://invented.example/'}]),
    (network_finding, 'input_files_sha256', [r'C:\exports\dns.evtx']),
    (malware_finding, 'layers', {'yara': {'status': 'ok', 'rules': [{'rule': 'R', 'rule_file': r'..\..\x.yar'}]}}),
])
def test_values_that_fail_their_format_are_refused(make, key, value):
    assert rejected(make(details={key: value})) == (422, 'disallowed_evidence_field')


def test_well_known_service_accounts_are_allowed_in_clear():
    for sid in ('sid:S-1-5-18', 'sid:S-1-5-19', 'sid:S-1-5-20'):
        gate(host_finding(details={'account_ref': sid}))
    gate(host_finding(details={'account_ref': INVENTED_ACCOUNT}))


def test_engine_and_domain_must_agree():
    finding = network_finding()
    finding['domain'] = 'host'
    assert rejected(finding) == (400, 'invalid_input')


def test_an_agent_cannot_set_an_incident():
    finding = network_finding(incident_id=5)
    assert rejected(finding) == (400, 'invalid_input')


def test_gate_stores_nothing_and_returns_nothing():
    request = parsed(batch([network_finding()]))
    before = copy.deepcopy([f.model_dump(mode='json') for f in request.findings])
    assert privacy.check_batch(request.findings, STORED, KEY) is None
    assert [f.model_dump(mode='json') for f in request.findings] == before


def test_fixture_payloads_hold_no_plaintext_markers():
    text = json.dumps(batch([network_finding(), malware_finding(), host_finding()]))
    for marker in ('INVENTED-PC', 'invented.user', 'C:\\\\Users', '203.0.113.'):
        assert marker not in text
