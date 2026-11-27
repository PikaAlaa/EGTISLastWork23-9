"""The network.windows engine (design network-windows-v1 §4.7, §5, §6, §7, §8.7-8.9).

The shipped-item manifest, its frozen rule and FREEZE.json are invented in tmp_path for these
tests only; the repository ships none, so the real engine is unavailable. Records are invented
(RFC 5737 addresses, `.example` names). Sockets are blocked.
"""
import hashlib
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.findings import Finding
from app.core.indicators import sha256_hex
from app.engines.network_windows import detections
from app.engines.network_windows import engine as nw
from app.engines.network_windows.blocklists import Blocklists, ListSpec
from app.engines.network_windows.engine import (NetworkWindowsEngine, NetworkWindowsEngineError, UrlScorer,
                                                verify_manifest)
from app.engines.network_windows.readers import ConnRecord, DnsRecord, InputFile, ReadResult
from app.engines.registry import EngineRegistry, Observation
from app.models import FindingRecord, Incident
from app.services.findings import record_findings
from network_windows_fixtures import write_shipped

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc)
DEV = 'hmac:' + '1' * 32
C2 = '203.0.113.66'
LOCK_SHA = 'f' * 64
GUID = '{invented-guid-1}'
PROC_SHA = 'ab' * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def ts(seconds):
    return (T0 + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def q(name, at=0.0, status=None, qtype=1, event_id=3006, answers=()):
    return DnsRecord(time=ts(at), source='dns_client', event_id=event_id, query_name=name, query_type=qtype,
                     status=status, answers=tuple(answers), device_ref=DEV)


def c(ip, port=443, at=0.0, action='allowed', source='firewall', guid=None):
    return ConnRecord(time=ts(at), source=source, direction='outbound', action=action, protocol='tcp', remote_ip=ip,
                      remote_local=False, remote_port=port, local_port=50000, process_guid=guid, device_ref=DEV)


def read(dns=(), conns=(), hashes=None):
    result = ReadResult()
    result.dns, result.connections = list(dns), list(conns)
    result.process_hashes = dict(hashes or {})
    result.files = [InputFile('firewall', 'e' * 64, 10, len(result.connections))]
    return result


def blocklists(*ips):
    spec = ListSpec(name='feodo_tracker', url='https://feodotracker.abuse.ch/invented.txt',
                    fetched_at='2026-01-04T00:00:00Z', path=Path('invented.txt'), size=1, sha256='c' * 64, rows=len(ips),
                    format='ip_lines')
    return Blocklists(lists={'feodo_tracker': spec}, ips={ip: ('feodo_tracker',) for ip in ips}, lock_sha256=LOCK_SHA)


def engine(tmp_path, rules=None, validation='samples', lists=(C2,), scorer=None, popular=None):
    manifest = write_shipped(tmp_path, rules=rules, validation=validation, lists=[('feodo_tracker', LOCK_SHA)])
    return NetworkWindowsEngine(verify_manifest(manifest, tmp_path), lists=blocklists(*lists), url_scorer=scorer,
                                popular_rank=popular if popular is not None else (lambda domain: None))


def run(eng, result, **data):
    observation = Observation(kind=nw.OBSERVATION_KIND, source_ref='network_windows_imports:1', observed_at=T0,
                              data={'read': result, **data})
    return eng.process(observation)


def by_kind(outcome):
    out = {}
    for finding in outcome.findings:
        out.setdefault(finding.evidence.details['detection'], []).append(finding)
    return out


# ----------------------------------------------------------------- availability

def test_repository_ships_no_manifest_so_the_engine_is_unavailable():
    assert not nw.SHIPPED.exists()
    eng = nw.load_engine(url_scorer=None)
    health = eng.health()
    assert health['available'] is False and health['status'] == 'rules_missing'
    assert health['rules_detail'] == 'shipped_manifest_missing' and health['reasons'][0] == 'rules_missing'
    assert eng.registrable is False and eng.version.startswith('netwin-v1+rules:none+lists:none+url:none')
    target = EngineRegistry()
    assert nw.register(target, eng) is None and target.names() == []
    with pytest.raises(NetworkWindowsEngineError, match='^engine_unavailable$'):
        eng.analyze(Observation(kind=nw.OBSERVATION_KIND, source_ref='network_windows_imports:1', observed_at=T0,
                                data={'read': read(conns=[c(C2)])}))
    assert 'network.windows' not in __import__('app.engines.registry', fromlist=['registry']).registry.names()


@pytest.mark.parametrize('change, code', [
    ({'schema': 'other'}, 'shipped_manifest_invalid'),
    ({'raw_rules': [{'id': 'N2', 'constants': {}, 'validation': 'samples'}]}, 'shipped_manifest_invalid'),
    ({'raw_rules': [{'id': 'N7', 'constants': {'usual_ports': [443]}, 'validation': 'samples'}]},
     'shipped_rule_constants_mismatch'),
    ({'raw_rules': [{'id': 'N9', 'constants': detections.RULE_CONSTANTS['N9'], 'validation': 'maybe'}]},
     'shipped_manifest_invalid'),
    ({'raw_rules': []}, 'shipped_manifest_invalid'),
    ({'selection_rule': {'path': 'evaluation/reports/2026-01-01-network-windows-v1/selection_rule.md',
                         'sha256': '0' * 64}}, 'selection_rule_mismatch'),
    ({'selection_rule': {'path': '../outside.md', 'sha256': '0' * 64}}, 'shipped_manifest_invalid'),
    ({'freeze': {'path': 'evaluation/reports/absent/FREEZE.json'}}, 'freeze_missing'),
    ({'freeze_sha': '1' * 64}, 'freeze_mismatch'),
    ({'lists': [{'name': 'urlhaus', 'lock_sha256': LOCK_SHA}]}, 'shipped_manifest_invalid'),
])
def test_manifests_that_do_not_verify_leave_the_engine_unavailable(tmp_path, change, code):
    path = write_shipped(tmp_path, **change)
    with pytest.raises(NetworkWindowsEngineError) as caught:
        verify_manifest(path, tmp_path)
    assert str(caught.value) == code
    eng = nw.load_engine(path, tmp_path, lock=tmp_path / 'absent.json', url_scorer=None)
    assert eng.health()['rules_detail'] == code and not eng.registrable


def test_a_verified_manifest_registers_and_names_its_versions(tmp_path):
    eng = engine(tmp_path, scorer=UrlScorer('ee0ba9f0077c1fd140aa', detections.N4_THRESHOLD, lambda u: 0.0))
    target = EngineRegistry()
    assert nw.register(target, eng) is eng and target.names() == ['network.windows']
    manifest_sha = hashlib.sha256((tmp_path / 'data' / 'network-windows-shipped.json').read_bytes()).hexdigest()
    assert eng.version == f'netwin-v1+rules:{manifest_sha[:12]}+lists:{LOCK_SHA[:12]}+url:ee0ba9f0077c1fd140aa'
    assert eng.health({'now': datetime(2026, 1, 5, tzinfo=timezone.utc)})['status'] == 'available'
    assert target.health()['network.windows']['available'] is True


def test_health_reasons_in_order(tmp_path):
    manifest = write_shipped(tmp_path, lists=[('feodo_tracker', '9' * 64)])
    eng = NetworkWindowsEngine(verify_manifest(manifest, tmp_path), lists=blocklists(C2))
    health = eng.health({'indicator_store_count': 0})
    assert health['available'] is True
    assert health['reasons'] == ['blocklists_missing', 'indicator_store_empty', 'url_model_unavailable']
    stale = engine(tmp_path / 'b').health({'now': datetime(2026, 1, 20, tzinfo=timezone.utc)})
    assert stale['reasons'] == ['blocklists_stale', 'url_model_unavailable']


def test_the_frozen_url_artifact_and_threshold_are_unchanged():
    deployment = json.loads((ROOT / 'ml' / 'models' / 'url_host_deployment.json').read_text(encoding='utf-8'))
    assert deployment['candidate_id'] == detections.N4_URL_CANDIDATE == 'ee0ba9f0077c1fd140aa'
    assert deployment['threshold'] == detections.N4_THRESHOLD == 0.9870690448552604
    scorer = nw.load_url_scorer()
    if scorer is None:
        pytest.skip('URL artifact not loadable here')
    assert scorer.threshold == 0.9870690448552604 and 0.0 <= scorer.score('https://pay.invented.example/') <= 1.0


# ----------------------------------------------------------------- severity, confidence, ATT&CK

def test_n1_severity_by_action_and_answer_only_confidence(tmp_path):
    eng = engine(tmp_path, lists=(C2, '198.51.100.66', '203.0.113.67'))
    allowed = by_kind(run(eng, read(conns=[c(C2)])))['N1'][0]
    assert (allowed.kind, allowed.severity, allowed.confidence, allowed.attack) == (
        'known_bad_destination', 'high', 'single_signal', [])
    dropped = by_kind(run(eng, read(conns=[c(C2, action='dropped')])))['N1'][0]
    assert dropped.severity == 'medium'
    answer = q('c2.invented.example', event_id=3008, status=0, answers=['198.51.100.66'])
    only_dns = by_kind(run(eng, read(dns=[answer])))['N1'][0]
    assert (only_dns.severity, only_dns.confidence) == ('medium', 'undetermined')
    with_conn = by_kind(run(eng, read(dns=[answer], conns=[c('203.0.113.99')])))['N1'][0]
    assert with_conn.confidence == 'single_signal'
    details = allowed.evidence.details
    assert details['lists'] == [{'list': 'feodo_tracker', 'title': 'abuse.ch Feodo Tracker IP blocklist',
                                 'version': '2026-01-04T00:00:00Z+sha256:cccccccccccc',
                                 'licence': 'CC0 (abuse.ch terms of use §3.4)',
                                 'link': 'https://feodotracker.abuse.ch/blocklist/'}]


def beacon(ip, port, count=10, gap=300, **kw):
    return [c(ip, port=port, at=i * gap, **kw) for i in range(count)]


def test_beaconing_with_a_list_hit_is_high_and_corroborated_without_attack(tmp_path):
    out = by_kind(run(engine(tmp_path), read(conns=beacon(C2, 443))))
    (n6,), (n1,) = out['N6'], out['N1']
    assert (n6.kind, n6.severity, n6.confidence, n6.attack) == ('beaconing', 'high', 'corroborated', [])
    assert (n1.severity, n1.confidence, n1.attack) == ('high', 'corroborated', [])
    assert n6.evidence.details['combined_with'] == ['N1']


def test_beaconing_alone_is_low_and_unusual_port_with_beaconing_maps_t1571(tmp_path):
    out = by_kind(run(engine(tmp_path, lists=()), read(conns=beacon('203.0.113.20', 4444))))
    (n6,), (n7,) = out['N6'], out['N7']
    assert (n6.severity, n6.confidence, n6.attack) == ('low', 'single_signal', [])
    assert (n7.kind, n7.severity) == ('unusual_port', 'medium')
    assert [(a.technique_id, a.basis) for a in n7.attack] == [('T1571', 'n7_with_n6')]
    alone = by_kind(run(engine(tmp_path / 'b', lists=()), read(conns=[c('203.0.113.21', port=4444)])))['N7'][0]
    assert (alone.severity, alone.attack) == ('low', [])


def test_unusual_port_to_a_listed_destination_maps_t1571(tmp_path):
    out = by_kind(run(engine(tmp_path), read(conns=[c(C2, port=4444)])))
    assert [a.technique_id for a in out['N7'][0].attack] == ['T1571'] and out['N1'][0].attack == []


DGA = ['bcdfghjklmn' + ch for ch in 'pqrstvwxz'] + ['qwrtzpsdfghk']


def test_dga_single_name_low_and_nxdomain_burst_medium_with_t1568_002(tmp_path):
    eng = engine(tmp_path, lists=())
    single = by_kind(run(eng, read(dns=[q('bcdfghjklmnp.example')])))['N5'][0]
    assert (single.kind, single.severity, single.attack) == ('suspicious_domain', 'low', [])
    burst = by_kind(run(eng, read(dns=[q(f'{label}.example', at=i, status=9003, event_id=3008)
                                       for i, label in enumerate(DGA)])))['N5']
    assert len(burst) == 10
    assert all(f.severity == 'medium' and [a.technique_id for a in f.attack] == ['T1568.002'] for f in burst)


def test_dns_beaconing_with_a_dga_name_is_medium(tmp_path):
    dns = [q('bcdfghjklmnp.example', at=i * 300) for i in range(10)]
    out = by_kind(run(engine(tmp_path, lists=()), read(dns=dns)))
    (n6,) = out['N6']
    assert (n6.severity, n6.confidence) == ('medium', 'corroborated')
    assert out['N5'][0].confidence == 'corroborated' and out['N5'][0].severity == 'low'


def tunnel(count=50, length=30, txt=0):
    records = [q(f'{i:04d}{"ab" * 20}'[:length] + '.tunnel-invented.example', at=i) for i in range(count)]
    return records + [q('t.tunnel-invented.example', at=100 + i, qtype=16) for i in range(txt)]


def test_tunnelling_one_sign_low_two_signs_medium_with_t1071_004(tmp_path):
    eng = engine(tmp_path, lists=())
    one = by_kind(run(eng, read(dns=tunnel())))['N8'][0]
    assert (one.kind, one.severity, one.attack) == ('dns_tunnelling_signs', 'low', [])
    two = by_kind(run(eng, read(dns=tunnel(txt=20))))['N8'][0]
    assert two.severity == 'medium' and [a.technique_id for a in two.attack] == ['T1071.004']
    assert [i.type for i in two.indicators] == ['domain']


def test_n4_alone_low_undetermined_and_with_n3_medium_corroborated(tmp_path):
    scorer = UrlScorer('ee0ba9f0077c1fd140aa', detections.N4_THRESHOLD, lambda url: 0.999)
    eng = engine(tmp_path, lists=(), scorer=scorer)
    alone = by_kind(run(eng, read(dns=[q('pay.bad-invented.example')])))['N4'][0]
    assert (alone.kind, alone.severity, alone.confidence) == ('phishing_domain_lookup', 'low', 'undetermined')
    both = by_kind(run(eng, read(dns=[q('pay.bad-invented.example')]),
                       indicator_domain_hashes=frozenset({sha256_hex('bad-invented.example')})))
    assert (both['N4'][0].severity, both['N4'][0].confidence) == ('medium', 'corroborated')
    assert (both['N3'][0].severity, both['N3'][0].confidence, both['N3'][0].attack) == ('medium', 'corroborated', [])


def test_rare_destination_is_info(tmp_path):
    dns = [q('old-invented.example'), q('new-invented.example', at=30 * 3600), q('end-invented.example', at=48 * 3600)]
    n9 = by_kind(run(engine(tmp_path, lists=()), read(dns=dns)))['N9']
    assert {f.severity for f in n9} == {'info'} and all(f.kind == 'rare_destination' and not f.attack for f in n9)


def test_unvalidated_rules_are_capped_at_single_signal(tmp_path):
    eng = engine(tmp_path, validation={r: ('unvalidated_on_samples' if r == 'N6' else 'samples')
                                       for r in detections.SHIPPABLE})
    out = by_kind(run(eng, read(conns=beacon(C2, 443))))
    assert out['N6'][0].confidence == 'single_signal' and out['N1'][0].confidence == 'corroborated'
    assert out['N6'][0].evidence.details['rule_validation'] == 'unvalidated_on_samples'


def test_only_shipped_rules_emit_and_the_rest_are_listed(tmp_path):
    outcome = run(engine(tmp_path, rules=['N1']), read(conns=beacon(C2, 4444)))
    assert {f.evidence.details['detection'] for f in outcome.findings} == {'N1'}
    assert outcome.not_run['N6'] == 'not_shipped' and outcome.not_run['N2'] == 'inactive_in_v1'


# ----------------------------------------------------------------- indicators and privacy

def test_indicators_are_hash_only_with_roles(tmp_path):
    out = by_kind(run(engine(tmp_path), read(conns=[c(C2, guid=GUID)], hashes={GUID: PROC_SHA})))
    (n1,) = out['N1']
    refs = {(i.type, i.role): i for i in n1.indicators}
    assert set(refs) == {('ip', 'remote_endpoint'), ('hash', 'connecting_process')}
    assert all(i.value is None for i in n1.indicators)
    assert refs[('ip', 'remote_endpoint')].value_hash == sha256_hex(C2)
    assert refs[('hash', 'connecting_process')].value_hash == sha256_hex(PROC_SHA)
    assert n1.evidence.details['process_category'] == 'known_process_hash'
    domain = by_kind(run(engine(tmp_path / 'b', lists=()), read(dns=[q('bcdfghjklmnp.example')])))['N5'][0]
    (ref,) = domain.indicators
    assert (ref.type, ref.role, ref.value, ref.registered_domain_hash) == (
        'domain', 'resolved_name', None, sha256_hex('bcdfghjklmnp.example'))


def test_findings_hold_no_names_addresses_or_process_ids(tmp_path):
    eng = engine(tmp_path, lists=(C2,))
    result = read(dns=[q('marker-query.bcdfghjklmnp.example', answers=['203.0.113.66'], event_id=3008, status=0)],
                  conns=beacon(C2, 4444, guid='{marker-guid}'), hashes={'{marker-guid}': PROC_SHA})
    outcome = run(eng, result)
    text = json.dumps([f.model_dump(mode='json') for f in outcome.findings]) + json.dumps(outcome.coverage)
    for marker in (C2, 'marker-query', 'bcdfghjklmnp', 'marker-guid', PROC_SHA):
        assert marker not in text, marker
    assert outcome.findings and all(isinstance(f, Finding) for f in outcome.findings)


def test_records_must_be_pseudonymised(tmp_path):
    record = ConnRecord(time=ts(0), source='sysmon3', direction='outbound', action='observed', protocol='tcp',
                        remote_ip=C2, remote_local=False, computer='INVENTED-PC')
    with pytest.raises(NetworkWindowsEngineError, match='^records_not_pseudonymised$'):
        run(engine(tmp_path), read(conns=[record]))


# ----------------------------------------------------------------- core path and correlation

def _seed(db, kind, indicator, severity='high', domain='phishing', engine_name='phishing.analyze'):
    finding = Finding.model_validate(dict(
        engine={'name': engine_name, 'version': 'invented-1'}, domain=domain, kind=kind, severity=severity,
        confidence='corroborated', indicators=[indicator], observed_at=T0, created_at=T0,
        source={'kind': 'scan', 'ref': 'scan_requests:1'}))
    (record,) = record_findings(db, [finding])
    db.commit()
    return record


def test_n3_joins_the_phishing_incident_by_domain(db, tmp_path):
    seeded = _seed(db, 'phishing_url', {'type': 'domain', 'value_hash': sha256_hex('phish-invented.example'),
                                        'value': 'phish-invented.example', 'role': 'link_host'})
    outcome = run(engine(tmp_path, lists=()), read(dns=[q('login.phish-invented.example')]),
                  indicator_domain_hashes=frozenset({sha256_hex('phish-invented.example')}))
    (n3,) = by_kind(outcome)['N3']
    (record,) = record_findings(db, [n3])
    db.commit()
    assert record.incident_id == seeded.incident_id is not None


def test_connecting_process_hash_joins_a_malware_incident(db, tmp_path):
    seeded = _seed(db, 'known_bad_hash', {'type': 'hash', 'value_hash': sha256_hex(PROC_SHA), 'value': None,
                                          'role': 'scanned_file', 'hash_algo': 'sha256'},
                   domain='malware', engine_name='malware.files')
    outcome = run(engine(tmp_path), read(conns=[c(C2, port=4444, guid=GUID)], hashes={GUID: PROC_SHA}))
    records = record_findings(db, outcome.findings)
    db.commit()
    assert {r.incident_id for r in records} == {seeded.incident_id}


def test_low_and_info_open_no_incident_and_devices_never_pivot(db, tmp_path):
    eng = engine(tmp_path, lists=())
    low = run(eng, read(conns=[c('203.0.113.30', port=4444)])).findings
    assert [f.severity for f in low] == ['low']
    assert [r.incident_id for r in record_findings(db, low)] == [None]
    first = run(eng, read(dns=[q(f'{label}.example', at=i, status=9003, event_id=3008)
                               for i, label in enumerate(DGA)])).findings
    records = record_findings(db, first)
    db.commit()
    incidents = {r.incident_id for r in records}
    assert None not in incidents and len(incidents) == len(first)   # same device, different destinations
    assert db.query(Incident).count() == len(first)
    assert db.query(FindingRecord).filter_by(engine_name='network.windows').count() == len(first) + 1
