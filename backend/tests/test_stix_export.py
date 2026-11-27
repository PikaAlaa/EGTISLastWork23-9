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
