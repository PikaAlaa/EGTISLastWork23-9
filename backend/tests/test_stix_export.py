"""STIX 2.1 pattern and object builders (design core-v2 §1, step 3).

Pure builders only; the export command and its licence filter are step 4. Every value is
invented and uses reserved documentation names and addresses.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest

from app.services import stix_export as sx

NS = uuid.UUID('5b0f7c1e-2f43-4a51-9d0e-0c1d2e3f4a5b')
OTHER_NS = uuid.UUID('0e9d8c7b-6a59-4483-b2a1-f0e1d2c3b4a5')
T0 = datetime(2026, 11, 20, 10, 0, 0, 123456)
T1 = datetime(2026, 11, 25, 8, 30, 0)
SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


# ---------------------------------------------------------------- patterns

@pytest.mark.parametrize('kind,value,algo,expected', [
    ('url', 'https://login.evil.example/verify', None, "[url:value = 'https://login.evil.example/verify']"),
    ('domain', 'evil.example', None, "[domain-name:value = 'evil.example']"),
    ('ip', '203.0.113.7', None, "[ipv4-addr:value = '203.0.113.7']"),
    ('ip', '2001:db8::1', None, "[ipv6-addr:value = '2001:db8::1']"),
    ('email', 'payroll@evil.example', None, "[email-addr:value = 'payroll@evil.example']"),
    ('hash', SHA256, 'sha256', f"[file:hashes.'SHA-256' = '{SHA256}']"),
    ('hash', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha1',
     "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"),
    ('hash', 'd41d8cd98f00b204e9800998ecf8427e', 'md5', "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"),
])
def test_pattern_per_type_uses_the_real_value(kind, value, algo, expected):
    assert sx.pattern_for(kind, value, algo) == expected


def test_pattern_escapes_quote_and_backslash():
    assert sx.escape_literal("it's") == "it\\'s"
    assert sx.escape_literal('a\\b') == 'a\\\\b'
    assert sx.escape_literal("\\'") == "\\\\\\'"
    assert sx.pattern_for('url', "https://evil.example/it's") == "[url:value = 'https://evil.example/it\\'s']"


def test_phone_gives_no_pattern_and_no_indicator_objects():
    assert sx.pattern_for('phone', '+201000000000') is None
    ident = sx.identity(NS, tlp='amber')
    assert sx.indicator(NS, indicator_id=9, kind='phone', value='+201000000000', first_seen=T0,
                        identity_ref=ident['id'], tlp='amber', sources=['analyst:manual']) is None


@pytest.mark.parametrize('kind,value', [
    ('url', 'hxxps://evil[.]example/login'),
    ('domain', 'evil[.]example'),
    ('email', 'payroll[@]evil[.]example'),
    ('ip', '203.0.113[.]7'),
    ('url', 'HTTPS://Evil.EXAMPLE:443/login'),
    ('domain', 'Evil.Example'),
    ('hash', SHA256.upper()),
])
def test_pattern_refuses_defanged_or_non_canonical_values(kind, value):
    with pytest.raises(sx.StixExportError) as info:
        sx.pattern_for(kind, value, 'sha256' if kind == 'hash' else None)
    assert str(info.value) == 'value_not_canonical'
    assert value not in str(info.value)


def test_pattern_refuses_unknown_types():
    with pytest.raises(sx.StixExportError):
        sx.pattern_for('sms', 'evil.example')


# ---------------------------------------------------------------- ids

def test_ids_stable_across_runs_and_different_across_namespaces():
    first = sx.object_id('incident', NS, 'incidents:7')
    assert first == sx.object_id('incident', NS, 'incidents:7')
    assert first != sx.object_id('incident', OTHER_NS, 'incidents:7')
    assert first != sx.object_id('incident', NS, 'incidents:8')
    assert sx.identity(NS, tlp='amber')['id'] == sx.identity(NS, tlp='amber')['id']
    assert sx.identity(NS, tlp='amber')['id'] != sx.identity(OTHER_NS, tlp='amber')['id']
    assert uuid.UUID(first.split('--', 1)[1]).version == 5


def test_ids_same_key_different_types_never_collide():
    assert sx.object_id('incident', NS, 'k').split('--')[1] != sx.object_id('indicator', NS, 'k').split('--')[1]


@pytest.mark.parametrize('bad', ['', 'not-a-uuid', '00abedb4-aa42-466c-9c01-fed23315a9b7',
                                 '00000000-0000-0000-0000-000000000000'])
def test_ids_refuse_invalid_or_sco_namespace(bad):
    with pytest.raises(sx.StixExportError):
        sx.namespace_from(bad)


def test_ids_bundle_is_random_uuid4():
    a, b = sx.bundle_id(), sx.bundle_id()
    assert a != b and uuid.UUID(a.split('--')[1]).version == 4


def test_ids_timestamps_are_utc_milliseconds():
    assert sx.timestamp(T0) == '2026-11-20T10:00:00.123Z'
    assert sx.timestamp(T1) == '2026-11-25T08:30:00.000Z'
    aware = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc).astimezone()
    assert sx.timestamp(aware) == '2026-11-20T12:00:00.000Z'


# ---------------------------------------------------------------- objects

def sample_objects(tlp='amber'):
    ident = sx.identity(NS, tlp=tlp)
    inc = sx.incident(NS, incident_id=3, title='sms_phishing: invented bank', opened_at=T0, last_activity_at=T1,
                      identity_ref=ident['id'], tlp=tlp,
                      custom={'x_etis_status': 'open', 'x_etis_severity': 'high', 'x_etis_domain': 'phishing',
                              'x_etis_resolution': None, 'x_etis_finding_counts': {'sms_phishing': 2}})
    ind = sx.indicator(NS, indicator_id=11, kind='domain', value='evil.example', first_seen=T0,
                       identity_ref=ident['id'], tlp=tlp, sources=['analyst:manual'])
    sight = sx.sighting(NS, finding_id='6f0e8c2a-6b1e-4d4e-9a55-0a4c1c7b9b21', indicator_ref=ind['id'],
                        observed_at=T1, identity_ref=ident['id'], tlp=tlp,
                        custom={'x_etis_engine': {'name': 'phishing.analyze', 'version': 'decision-v2'},
                                'x_etis_kind': 'sms_phishing', 'x_etis_severity': 'high',
                                'x_etis_confidence': 'corroborated', 'x_etis_reasons': ['brand_label_reuse']})
    ap = sx.attack_pattern(NS, technique_id='T1660', matrix='mobile', attack_version='20.0', name='Phishing',
                           url='https://attack.mitre.org/techniques/T1660', identity_ref=ident['id'], tlp=tlp,
                           mitre_stix_id='attack-pattern--00000000-0000-4000-8000-000000000001', created=T0)
    rels = [sx.relationship(NS, relationship_type='related-to', source_ref=inc['id'], target_ref=ind['id'],
                            identity_ref=ident['id'], tlp=tlp, created=T0),
            sx.relationship(NS, relationship_type='related-to', source_ref=inc['id'], target_ref=ap['id'],
                            identity_ref=ident['id'], tlp=tlp, created=T0,
                            custom={'x_etis_basis': ['sms_text_present']}),
            sx.relationship(NS, relationship_type='indicates', source_ref=ind['id'], target_ref=ap['id'],
                            identity_ref=ident['id'], tlp=tlp, created=T0)]
    nt = sx.note(NS, key='export', content=sx.ATTACK_NOTICE, object_refs=[inc['id']], identity_ref=ident['id'],
                 tlp=tlp, created=T1)
    return [sx.tlp_marking(tlp), ident, inc, ind, sight, ap, *rels, nt]


def test_objects_meet_the_required_properties_of_the_subset():
    for obj in sample_objects():
        assert sx.validate_object(obj) == [], obj['type']
    data = sx.bundle(sample_objects())
    assert sx.validate_bundle(data) == []
    assert 'spec_version' not in data and data['type'] == 'bundle'


@pytest.mark.parametrize('stix_type', ['identity', 'incident', 'indicator', 'sighting', 'attack-pattern',
                                       'relationship', 'note', 'marking-definition'])
def test_objects_missing_a_required_property_are_reported(stix_type):
    obj = next(o for o in sample_objects() if o['type'] == stix_type)
    rules = sx.SUBSET['types'][stix_type]
    for name in rules['required'] + ([] if rules.get('no_common_required') else sx.SUBSET['common_required']):
        broken = {k: v for k, v in obj.items() if k != name}
        expected = 'type_not_in_subset' if name == 'type' else f'missing:{name}'
        assert expected in sx.validate_object(broken)


def test_objects_never_carry_a_confidence_property():
    for obj in sample_objects():
        assert 'confidence' not in obj
    obj = dict(sample_objects()[3], confidence=80)
    assert 'confidence_forbidden' in sx.validate_object(obj)
    assert 'confidence' not in json.dumps(sx.bundle(sample_objects())).replace('x_etis_confidence', '')


@pytest.mark.parametrize('level', ['white', 'green', 'amber', 'red'])
def test_objects_all_carry_one_tlp_marking(level):
    objects = sample_objects(level)
    for obj in objects:
        if obj['type'] == 'marking-definition':
            assert obj['id'] == sx.TLP[level] and obj['created'] == '2017-01-20T00:00:00.000Z'
            assert obj['definition'] == {'tlp': level} and obj['name'] == f'TLP:{level.upper()}'
        else:
            assert obj['object_marking_refs'] == [sx.TLP[level]]
    assert sx.validate_bundle(sx.bundle(objects)) == []


def test_objects_tlp_unknown_level_refused():
    with pytest.raises(sx.StixExportError):
        sx.tlp_marking('clear')
    with pytest.raises(sx.StixExportError):
        sx.identity(NS, tlp='purple')


def test_objects_marking_missing_or_dangling_ref_is_reported():
    objects = sample_objects()
    unmarked = {k: v for k, v in objects[2].items() if k != 'object_marking_refs'}
    assert 'tlp_marking_missing' in sx.validate_object(unmarked)
    without_marking = [o for o in objects if o['type'] != 'marking-definition']
    assert any(p.endswith('dangling:object_marking_refs') for p in sx.validate_bundle(sx.bundle(without_marking)))


def test_objects_created_by_identity_and_identity_is_a_system():
    objects = sample_objects()
    ident = objects[1]
    assert ident['identity_class'] == 'system' and ident['name'] == 'ETIS local instance'
    assert 'created_by_ref' not in ident
    for obj in objects[2:]:
        assert obj['created_by_ref'] == ident['id']


def test_objects_indicator_shape():
    ind = sample_objects()[3]
    assert ind['pattern'] == "[domain-name:value = 'evil.example']"
    assert ind['pattern_type'] == 'stix' and ind['indicator_types'] == ['malicious-activity']
    assert ind['valid_from'] == '2026-11-20T10:00:00.123Z' and ind['created'] == ind['modified']
    assert ind['x_etis_type'] == 'domain' and ind['x_etis_sources'] == ['analyst:manual']
    with pytest.raises(sx.StixExportError):
        sx.indicator(NS, indicator_id=1, kind='domain', value='evil.example', first_seen=T0,
                     identity_ref=ind['created_by_ref'], tlp='amber', sources=[])


def test_objects_incident_modified_not_before_created_and_empty_custom_dropped():
    objects = sample_objects()
    inc = objects[2]
    assert inc['created'] == '2026-11-20T10:00:00.123Z' and inc['modified'] == '2026-11-25T08:30:00.000Z'
    assert 'x_etis_resolution' not in inc
    backwards = sx.incident(NS, incident_id=4, title='t', opened_at=T1, last_activity_at=T0,
                            identity_ref=objects[1]['id'], tlp='amber')
    assert backwards['modified'] == backwards['created']


def test_objects_sighting_points_at_indicator_and_identity():
    objects = sample_objects()
    sight = objects[4]
    assert sight['sighting_of_ref'] == objects[3]['id'] and sight['where_sighted_refs'] == [objects[1]['id']]
    assert sight['count'] == 1 and sight['first_seen'] == sight['last_seen']


def test_objects_attack_pattern_references_mitre_without_reusing_its_id():
    ap = sample_objects()[5]
    assert ap['external_references'] == [{'source_name': 'mitre-attack', 'external_id': 'T1660',
                                          'url': 'https://attack.mitre.org/techniques/T1660'}]
    assert ap['id'] != ap['x_etis_mitre_stix_id'] and ap['id'].startswith('attack-pattern--')


def test_objects_custom_property_names_and_relationship_types_checked():
    with pytest.raises(sx.StixExportError):
        sx.incident(NS, incident_id=5, title='t', opened_at=T0, last_activity_at=T1,
                    identity_ref=sample_objects()[1]['id'], tlp='amber', custom={'severity': 'high'})
    with pytest.raises(sx.StixExportError):
        sx.relationship(NS, relationship_type='uses', source_ref='a', target_ref='b', identity_ref='c',
                        tlp='amber', created=T0)
    assert 'reserved:severity' in sx.validate_object(dict(sample_objects()[2], severity='high'))


def test_objects_bundle_sorted_unique_and_not_empty():
    data = sx.bundle(sample_objects(), bundle_ref='bundle--1f2e3d4c-5b6a-4978-8f6e-5d4c3b2a1908')
    keys = [(o['type'], o['id']) for o in data['objects']]
    assert keys == sorted(keys)
    with pytest.raises(sx.StixExportError):
        sx.bundle([])
    with pytest.raises(sx.StixExportError):
        sx.bundle(sample_objects() + sample_objects()[:1])


def test_objects_empty_lists_are_reported():
    assert 'empty_list_or_dict' in sx.validate_object(dict(sample_objects()[3], indicator_types=[]))


def test_objects_builders_are_deterministic():
    assert json.dumps(sample_objects(), sort_keys=True) == json.dumps(sample_objects(), sort_keys=True)

# ================================================================ step 4: offline export command
# Selectors: command, privacy, scope, licence. Every incident, feed row, list and value is invented.
import hashlib
import importlib.util
import io
import json
import socket
import uuid
from datetime import date, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from app.core.indicators import normalize
from app.core.url_utils import url_hash
from app.engines.network_windows import blocklists
from app.models import (AttackTechnique, BlacklistEntry, CommunityReport, FeedObservation, FeedSnapshot,
                        FindingAttack, FindingIndicator, FindingRecord, Incident, IncidentEvent, Indicator,
                        IndicatorSighting)
from app.services import stix_export as sx

ROOT = Path(__file__).resolve().parents[2]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


command = _load('etis_export_stix', 'data/scripts/export_stix.py')
initialize = _load('etis_initialize_stix', 'scripts/initialize.py')

CMD_NS = '7d3c1b2a-4e5f-4a6b-8c7d-9e0f1a2b3c4d'
NOW = datetime(2026, 11, 28, 12, 0, 0)
CMD_T0 = datetime(2026, 11, 20, 9, 0, 0)
MARK_FEED = 'marker-openphish-5521'
MARK_NOTE = 'marker-analyst-note-5521'
MARK_DETAIL = 'marker-evidence-detail-5521'
MARK_PSEUDO = 'hmac:' + 'ab' * 16
C2 = '203.0.113.66'
UNLISTED_IP = '198.51.100.9'
SHARED = {
    'analyst_domain': ('domain', 'analyst-own.example', [('feed', 'manual')]),
    'analyst_url': ('url', 'https://own-investigation.example/kit', [('analyst', 'own_investigation')]),
    'declared_openphish': ('url', 'https://declared-op.example/x', [('analyst', 'openphish')]),
    'domain_overlap': ('domain', 'overlap-domain.example', [('feed', 'manual')]),
    'observation_overlap': ('url', 'https://observed-op.example/login', [('feed', 'manual')]),
    'snapshot_overlap': ('url', 'https://snapshot-pt.example/login', [('feed', 'manual')]),
    'mixed': ('url', 'https://mixed.example/a', [('feed', 'manual'), ('feed', 'openphish')]),
    'openphish_only': ('url', f'https://{MARK_FEED}.example/a', [('feed', 'openphish')]),
    'phishtank_only': ('domain', 'phishtank-only.example', [('feed', 'phishtank')]),
    'community': ('domain', 'community-report.example', [('community', 'community_reports')]),
    'analyst_phone': ('phone', '+201000000001', [('analyst', 'own_investigation')]),
}


def sessions(db):
    return sessionmaker(bind=db.get_bind(), expire_on_commit=False)


def env_file(tmp_path, namespace=CMD_NS):
    path = tmp_path / '.env'
    path.write_text(f'ETIS_STIX_NAMESPACE={namespace}\n', encoding='utf-8')
    return path


def add_indicator(db, kind, value, sightings, *, plaintext=True, hash_algo=None):
    n = normalize(kind, value, hash_algo)
    row = Indicator(type=n.type, value_hash=n.value_hash, value=n.value if plaintext else None, hash_algo=n.hash_algo,
                    first_seen=CMD_T0, last_seen=CMD_T0)
    db.add(row)
    db.flush()
    for source_kind, source_name in sightings:
        ref = None
        if source_kind == 'community':
            report = CommunityReport(reported_value=value, status='confirmed', reviewed_at=CMD_T0)
            db.add(report)
            db.flush()
            ref = f'community_reports:{report.id}'
        db.add(IndicatorSighting(indicator_id=row.id, source_kind=source_kind, source_name=source_name,
                                 first_seen=CMD_T0, last_seen=CMD_T0, active=True, ref=ref))
    return row


def add_finding(db, incident, indicators, *, engine='phishing.analyze', kind='url_phishing', reasons=('blacklist_exact',),
                details=None, attack=()):
    finding = FindingRecord(id=str(uuid.uuid4()), schema_version='finding-v1', engine_name=engine,
                            engine_version='test-v1', domain=incident.domain, kind=kind, severity='high',
                            confidence='corroborated', evidence={'reasons': list(reasons), 'details': details or {}},
                            observed_at=CMD_T0, created_at=CMD_T0, source_kind='import', source_ref='test:1',
                            incident_id=incident.id)
    db.add(finding)
    db.flush()
    for row in indicators:
        db.add(FindingIndicator(finding_id=finding.id, indicator_id=row.id, role='delivery_link'))
    for technique_id, matrix, basis in attack:
        db.add(FindingAttack(finding_id=finding.id, technique_id=technique_id, matrix=matrix, attack_version='20.0',
                             basis=basis))
    return finding


def add_incident(db, title='url phishing', status='open', resolution=None, domain='phishing', last=CMD_T0):
    incident = Incident(title=title, domain=domain, severity='high', status=status, resolution=resolution,
                        opened_at=CMD_T0, last_activity_at=last)
    db.add(incident)
    db.flush()
    return incident


@pytest.fixture
def world(db):
    """One open incident holding every source kind of §1.4, plus restricted feed records."""
    db.add(BlacklistEntry(url='https://overlap-domain.example/old', url_hash=url_hash('https://overlap-domain.example/old'),
                          domain='overlap-domain.example', source='openphish', is_active=False,
                          first_seen=date(2026, 1, 1), last_seen=date(2026, 1, 2)))
    db.add(FeedObservation(url_hash=url_hash('https://observed-op.example/login'), source='openphish',
                           last_seen=date(2026, 2, 1)))
    db.add(FeedSnapshot(source='phishtank', version='pt-rejected-1', captured_at=datetime(2026, 3, 1), row_count=1,
                        accepted=False, payload=['https://snapshot-pt.example/login']))
    db.add(AttackTechnique(technique_id='T1660', matrix='mobile', attack_version='20.0', name='Phishing',
                           tactics=['initial-access'], platforms=['Android'],
                           stix_id='attack-pattern--00000000-0000-4000-8000-000000000001',
                           url='https://attack.mitre.org/techniques/T1660'))
    incident = add_incident(db)
    rows = {key: add_indicator(db, kind, value, sightings) for key, (kind, value, sightings) in SHARED.items()}
    rows['scan_hash_only'] = add_indicator(db, 'domain', 'scan-only.example', [('scan', 'scan_requests')],
                                           plaintext=False)
    rows['malware'] = add_indicator(db, 'hash', 'aa' * 32, [('import', 'malware_scans')], plaintext=False,
                                    hash_algo='sha256')
    add_finding(db, incident, [rows[k] for k in rows], details={'note': MARK_DETAIL, 'device_ref': MARK_PSEUDO},
                attack=[('T1660', 'mobile', 'sms_text_present'), ('T9999', 'enterprise', 'uncatalogued_basis')])
    network = add_incident(db, title='known bad destination', domain='network')
    rows['c2'] = add_indicator(db, 'ip', C2, [('import', 'network_windows_imports')], plaintext=False)
    rows['unlisted'] = add_indicator(db, 'ip', UNLISTED_IP, [('import', 'network_windows_imports')], plaintext=False)
    add_finding(db, network, [rows['c2'], rows['unlisted']], engine='network.windows', kind='known_bad_destination',
                reasons=('blocklist_ip_connection',))
    db.add(IncidentEvent(incident_id=incident.id, actor='local-operator', action='note', note=MARK_NOTE, at=CMD_T0))
    db.commit()
    return {'incident': incident, 'network': network, 'rows': rows}


class FakeLists:
    def __init__(self, ips):
        self.ips = ips
        self.lists = {'feodo_tracker': object()} if ips else {}


def run(db, tmp_path, *args, lists=None, now=NOW, env=None, name='out.json'):
    out = io.StringIO()
    target = tmp_path / name
    code = command.main([*args, '--out', str(target)], session_factory=sessions(db),
                        env_file=env or env_file(tmp_path), out=out, lists_loader=lambda: lists, now=now)
    return code, target, out.getvalue()


def bundle_of(path):
    return json.loads(path.read_text(encoding='utf-8'))


def patterns(data):
    return sorted(o['pattern'] for o in data['objects'] if o['type'] == 'indicator')


# ---------------------------------------------------------------- licence filter

def test_licence_filter_exports_only_redistributable_values(db, tmp_path, world):
    code, path, printed = run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    assert code == 0
    data = bundle_of(path)
    assert sx.validate_bundle(data) == []
    assert patterns(data) == sorted([
        "[domain-name:value = 'analyst-own.example']",
        "[url:value = 'https://own-investigation.example/kit']",
        f"[ipv4-addr:value = '{C2}']",
    ])
    report = json.loads(printed)
    assert report['indicators_exported'] == 3
    assert report['not_exported_by_reason'] == {
        'community_licence_not_accepted': 1, 'hash_only': 3, 'phone_no_pattern': 1,
        'restricted_feed': 2, 'restricted_feed_overlap': 5}


def test_licence_q14_overlap_with_any_stored_restricted_record(db, tmp_path, world):
    """Declared source, inactive blacklist domain, feed observation, rejected snapshot, and a mixed sighting."""
    code, path, _ = run(db, tmp_path)
    text = path.read_text(encoding='utf-8')
    for host in ('declared-op.example', 'overlap-domain.example', 'observed-op.example', 'snapshot-pt.example',
                 'mixed.example'):
        assert host not in text


def test_licence_sources_name_only_allowed_sources(db, tmp_path, world):
    _, path, _ = run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    sources = {o['pattern']: o['x_etis_sources'] for o in bundle_of(path)['objects'] if o['type'] == 'indicator'}
    assert sources[f"[ipv4-addr:value = '{C2}']"] == ['list:feodo_tracker']
    assert sources["[domain-name:value = 'analyst-own.example']"] == ['analyst:manual']
    assert sources["[url:value = 'https://own-investigation.example/kit']"] == ['analyst:own_investigation']
    assert not any('openphish' in s or 'phishtank' in s for v in sources.values() for s in v)


def test_licence_list_not_installed_counts_n1_ips(db, tmp_path, world):
    code, path, printed = run(db, tmp_path, lists=None)
    assert code == 0 and C2 not in path.read_text(encoding='utf-8')
    assert json.loads(printed)['not_exported_by_reason']['list_not_installed'] == 2


def _write_list(tmp_path, ips, *, sha=None):
    dest = tmp_path / 'lists'
    dest.mkdir(exist_ok=True)
    body = ('# invented list\n' + '\n'.join(ips) + '\n').encode('utf-8')
    (dest / 'feodo.txt').write_bytes(body)
    lock = {'destination': 'lists', 'lists': [{
        'name': 'feodo_tracker', 'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'fetched_at': '2026-11-27T00:00:00Z', 'file': 'feodo.txt', 'size': len(body),
        'sha256': sha or hashlib.sha256(body).hexdigest(), 'rows': len(ips), 'format': 'ip_lines'}]}
    (tmp_path / 'lock.json').write_text(json.dumps(lock), encoding='utf-8')
    return lambda: blocklists.load(tmp_path / 'lock.json', tmp_path)


def test_licence_verified_local_list_recovers_only_listed_ips(db, tmp_path, world):
    out = io.StringIO()
    code = command.main(['--out', str(tmp_path / 'a.json')], session_factory=sessions(db), env_file=env_file(tmp_path),
                        out=out, lists_loader=_write_list(tmp_path, [C2]), now=NOW)
    text = (tmp_path / 'a.json').read_text(encoding='utf-8')
    assert code == 0 and f"'{C2}'" in text and UNLISTED_IP not in text


def test_licence_list_with_wrong_lock_hash_is_not_used(db, tmp_path, world):
    out = io.StringIO()
    code = command.main(['--out', str(tmp_path / 'b.json')], session_factory=sessions(db), env_file=env_file(tmp_path),
                        out=out, lists_loader=_write_list(tmp_path, [C2], sha='0' * 64), now=NOW)
    assert code == 0 and C2 not in (tmp_path / 'b.json').read_text(encoding='utf-8')
    assert json.loads(out.getvalue())['not_exported_by_reason']['list_not_installed'] == 2


def test_licence_community_requires_cc0_acceptance_and_q18_overlap(db, tmp_path, world, monkeypatch):
    monkeypatch.setattr(command, 'community_accepted', lambda db_, s: True)
    _, path, _ = run(db, tmp_path, name='accepted.json')
    assert "[domain-name:value = 'community-report.example']" in patterns(bundle_of(path))
    db.add(BlacklistEntry(url='https://community-report.example/p', url_hash=url_hash('https://community-report.example/p'),
                          domain='community-report.example', source='phishtank', is_active=True,
                          first_seen=date(2026, 1, 1), last_seen=date(2026, 1, 1)))
    db.commit()
    _, path2, printed = run(db, tmp_path, name='overlap.json')
    assert 'community-report.example' not in path2.read_text(encoding='utf-8')
    assert json.loads(printed)['not_exported_by_reason']['restricted_feed_overlap'] == 6


def test_licence_exportable_sources_constant_is_pinned():
    assert set(command.EXPORTABLE_SOURCES) == {'analyst', 'community', 'list:feodo_tracker'}
    assert command.RESTRICTED_FEEDS == ('openphish', 'phishtank')


def test_licence_feed_tables_unchanged_by_export(db, tmp_path, world):
    def snapshot():
        return (sorted((r.url_hash, r.source, r.is_active) for r in db.query(BlacklistEntry)),
                sorted((r.url_hash, r.source) for r in db.query(FeedObservation)),
                sorted((r.version, r.accepted) for r in db.query(FeedSnapshot)),
                sorted((r.indicator_id, r.source_kind, r.source_name, r.active) for r in db.query(IndicatorSighting)),
                sorted((r.id, r.value) for r in db.query(Indicator)))
    before = snapshot()
    run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    db.expire_all()
    assert snapshot() == before
    assert db.query(Indicator).filter_by(value=C2).count() == 0


# ---------------------------------------------------------------- privacy

def test_privacy_markers_never_written_or_printed(db, tmp_path, world):
    _, path, printed = run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    text = path.read_text(encoding='utf-8')
    for marker in (MARK_FEED, MARK_NOTE, MARK_DETAIL, MARK_PSEUDO, 'scan-only.example', 'aa' * 32):
        assert marker not in text and marker not in printed
    hash_only = [world['rows'][k].value_hash for k in ('scan_hash_only', 'malware', 'unlisted')]
    assert not any(h in text for h in hash_only)


def test_privacy_terminal_prints_counts_and_path_only(db, tmp_path, world):
    _, path, printed = run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    for value in ('analyst-own.example', 'own-investigation.example', C2):
        assert value not in printed
    assert set(json.loads(printed)) == {'written', 'tlp', 'incidents', 'objects', 'indicators_exported',
                                        'not_exported_by_reason', 'not_exported_by_type'}


def test_privacy_note_defangs_values_and_patterns_stay_real(db, tmp_path, world):
    _, path, _ = run(db, tmp_path, lists=FakeLists({C2: ('feodo_tracker',)}))
    data = bundle_of(path)
    note = next(o for o in data['objects'] if o['type'] == 'note')
    assert 'analyst-own[.]example' in note['content'] and 'hxxps://own-investigation[.]example/kit' in note['content']
    assert '203.0.113[.]66' in note['content'] and 'analyst-own.example' not in note['content']
    assert 'Values below are de-fanged' in note['content'] and sx.ATTACK_NOTICE in note['content']
    assert all('[.]' not in p for p in patterns(data))


def test_privacy_no_details_pseudonyms_notes_or_confidence(db, tmp_path, world):
    _, path, _ = run(db, tmp_path)
    data = bundle_of(path)
    for obj in data['objects']:
        assert 'confidence' not in obj and 'details' not in json.dumps(obj)
    sightings = [o for o in data['objects'] if o['type'] == 'sighting']
    assert sightings and all(o['x_etis_reasons'] == ['blacklist_exact'] for o in sightings)


def test_privacy_attack_patterns_and_uncatalogued_ids(db, tmp_path, world):
    _, path, _ = run(db, tmp_path)
    data = bundle_of(path)
    ap = [o for o in data['objects'] if o['type'] == 'attack-pattern']
    assert [a['external_references'][0]['external_id'] for a in ap] == ['T1660']
    inc = next(o for o in data['objects'] if o['type'] == 'incident' and o['name'] == 'url phishing')
    assert inc['x_etis_attack_ids'] == ['enterprise:T9999']
    rel_types = {(o['relationship_type'], o['target_ref'].split('--')[0]) for o in data['objects']
                 if o['type'] == 'relationship'}
    assert {('related-to', 'indicator'), ('related-to', 'attack-pattern'), ('indicates', 'attack-pattern')} <= rel_types


# ---------------------------------------------------------------- scope

def _incident_names(path):
    return sorted(o['name'] for o in bundle_of(path)['objects'] if o['type'] == 'incident')


def test_scope_default_is_open_and_investigating(db, tmp_path, world):
    add_incident(db, title='closed true positive', status='resolved', resolution='true_positive')
    add_incident(db, title='investigating one', status='investigating')
    db.commit()
    _, path, _ = run(db, tmp_path)
    assert _incident_names(path) == ['investigating one', 'known bad destination', 'url phishing']


def test_scope_resolved_benign_excluded_unless_flag(db, tmp_path, world):
    benign = add_incident(db, title='benign one', status='resolved', resolution='benign')
    fp = add_incident(db, title='false positive one', status='resolved', resolution='false_positive')
    db.commit()
    ids = ['--incident', str(benign.id), '--incident', str(fp.id), '--incident', str(world['incident'].id)]
    _, path, _ = run(db, tmp_path, *ids, name='a.json')
    assert _incident_names(path) == ['url phishing']
    _, path, _ = run(db, tmp_path, *ids, '--include-resolved-benign', name='b.json')
    assert _incident_names(path) == ['benign one', 'false positive one', 'url phishing']


def test_scope_since_uses_last_activity(db, tmp_path, world):
    add_incident(db, title='recent resolved', status='resolved', resolution='true_positive', last=datetime(2026, 11, 27))
    db.commit()
    _, path, _ = run(db, tmp_path, '--since', '2026-11-25')
    assert _incident_names(path) == ['recent resolved']


def test_scope_empty_is_refused(db, tmp_path):
    code, path, _ = run(db, tmp_path, '--since', '2030-01-01')
    assert code == 2 and not path.exists()


# ---------------------------------------------------------------- command

def test_command_refuses_to_overwrite(db, tmp_path, world):
    target = tmp_path / 'out.json'
    target.write_text('keep', encoding='utf-8')
    code, _, _ = run(db, tmp_path)
    assert code == 2 and target.read_text(encoding='utf-8') == 'keep'
    assert not list(tmp_path.glob('.out.json.*.tmp'))


def test_command_runs_with_sockets_blocked(db, tmp_path, world, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError('socket_blocked_in_test')
    monkeypatch.setattr(socket, 'socket', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)
    code, path, _ = run(db, tmp_path)
    assert code == 0 and path.exists()


def test_command_output_deterministic_apart_from_bundle_id(db, tmp_path, world):
    lists = FakeLists({C2: ('feodo_tracker',)})
    _, first, _ = run(db, tmp_path, lists=lists, name='1.json')
    _, second, _ = run(db, tmp_path, lists=lists, name='2.json')
    a, b = bundle_of(first), bundle_of(second)
    assert a['id'] != b['id']
    a.pop('id'), b.pop('id')
    assert a == b


def test_command_ids_stable_across_runs_and_namespaces(db, tmp_path, world):
    _, first, _ = run(db, tmp_path, name='1.json', now=datetime(2026, 11, 28))
    _, second, _ = run(db, tmp_path, name='2.json', now=datetime(2026, 11, 29))
    other = tmp_path / 'other'
    other.mkdir()
    other_env = env_file(other, namespace='1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d')
    _, third, _ = run(db, tmp_path, name='3.json', env=other_env)
    ids = [sorted(o['id'] for o in bundle_of(p)['objects'] if o['type'] != 'note') for p in (first, second, third)]
    assert ids[0] == ids[1] and set(ids[0]) - set(ids[2]) != set()


def test_command_tlp_choice_marks_every_object(db, tmp_path, world):
    _, path, printed = run(db, tmp_path, '--tlp', 'white')
    data = bundle_of(path)
    assert all(o['object_marking_refs'] == [sx.TLP['white']] for o in data['objects'] if o['type'] != 'marking-definition')
    assert json.loads(printed)['tlp'] == 'white'
    with pytest.raises(SystemExit):
        command.parse_args(['--tlp', 'clear'])
    assert 'TLP 2.0 calls it CLEAR' in command.TLP_HELP


def test_command_refuses_without_namespace(db, tmp_path, world, monkeypatch):
    monkeypatch.delenv('ETIS_STIX_NAMESPACE', raising=False)
    empty = tmp_path / 'empty.env'
    empty.write_text('', encoding='utf-8')
    code, path, _ = run(db, tmp_path, env=empty)
    assert code == 2 and not path.exists()
    code, path, _ = run(db, tmp_path, env=env_file(tmp_path, namespace='00abedb4-aa42-466c-9c01-fed23315a9b7'))
    assert code == 2 and not path.exists()


def test_command_default_path_under_var_exports(monkeypatch):
    args = command.parse_args([])
    path = command.output_path(args, datetime(2026, 11, 28, 12, 0, 5))
    assert path == ROOT / 'var' / 'exports' / 'etis-stix-20261128T120005Z.json'
    assert 'var/' in (ROOT / '.gitignore').read_text(encoding='utf-8')


def test_command_initialize_generates_namespace_once(tmp_path):
    env = tmp_path / '.env'
    env.write_text('ETIS_API_KEY=x\n', encoding='utf-8')
    initialize.ensure_env_secrets(env)
    first = env.read_text(encoding='utf-8')
    value = next(line.split('=', 1)[1] for line in first.splitlines() if line.startswith('ETIS_STIX_NAMESPACE='))
    assert uuid.UUID(value).version == 4
    initialize.ensure_env_secrets(env)
    assert env.read_text(encoding='utf-8') == first
