"""finding-v1 schema and indicator normalization (design core-v1 §9.2, §9.4).

All values are invented placeholders; `.example` and 2001:db8:: are reserved.
"""
import hashlib
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.core.findings import Finding, IndicatorRef, severity_rank
from app.core.indicators import normalize
from app.core.url_utils import url_hash

H = 'a' * 64
NOW = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)


def base(**overrides):
    data = dict(engine={'name': 'phishing.analyze', 'version': 'decision-v2'}, domain='phishing',
                kind='sms_phishing', severity='high', confidence='corroborated',
                indicators=[{'type': 'url', 'value_hash': H, 'role': 'delivery_link'}],
                attack=[{'technique_id': 'T1660', 'matrix': 'mobile', 'attack_version': '20.0', 'basis': 'sms_text_present'}],
                evidence={'reasons': ['text_high_corroborated'], 'details': {'verdict': 'HIGH'}},
                observed_at=NOW, created_at=NOW, source={'kind': 'scan', 'ref': 'scan_requests:1'})
    data.update(overrides)
    return data


def test_valid_finding_round_trips_through_json():
    finding = Finding.model_validate(base())
    again = Finding.model_validate_json(finding.model_dump_json())
    assert again == finding
    assert finding.schema_version == 'finding-v1' and finding.incident_id is None
    assert json.loads(finding.model_dump_json())['observed_at'].startswith('2026-11-18T10:00:00')


@pytest.mark.parametrize('field,value', [
    ('domain', 'fraud'), ('severity', 'severe'), ('confidence', '0.97'), ('confidence', 0.97),
    ('schema_version', 'finding-v2'), ('kind', 'Has Spaces'), ('id', 'not-a-uuid'),
    ('id', '00000000-0000-1000-8000-000000000000'), ('observed_at', datetime(2026, 11, 18)),
])
def test_enum_and_format_rejection(field, value):
    with pytest.raises(ValidationError):
        Finding.model_validate(base(**{field: value}))


def test_extra_fields_are_forbidden_at_every_level():
    with pytest.raises(ValidationError):
        Finding.model_validate(base(verdict='HIGH'))
    with pytest.raises(ValidationError):
        Finding.model_validate(base(evidence={'reasons': [], 'details': {}, 'raw_text': 'x'}))
    with pytest.raises(ValidationError):
        Finding.model_validate(base(indicators=[{'type': 'url', 'value_hash': H, 'role': 'x', 'note': 'y'}]))


@pytest.mark.parametrize('indicator', [
    {'type': 'hash', 'value_hash': H, 'role': 'sample'},
    {'type': 'url', 'value_hash': H, 'role': 'link', 'hash_algo': 'sha256'},
    {'type': 'hash', 'value_hash': H, 'role': 'sample', 'hash_algo': 'md5', 'value': 'ab'},
    {'type': 'url', 'value_hash': 'A' * 64, 'role': 'link'},
    {'type': 'phone', 'value_hash': H, 'role': 'contact', 'registered_domain_hash': H},
    {'type': 'sms_sender', 'value_hash': H, 'role': 'sender'},
])
def test_invalid_indicator_refs(indicator):
    with pytest.raises(ValidationError):
        IndicatorRef.model_validate(indicator)


@pytest.mark.parametrize('technique', ['T1566.4', 't1566', 'T15660', 'TA0001'])
def test_attack_id_format(technique):
    with pytest.raises(ValidationError):
        Finding.model_validate(base(attack=[{'technique_id': technique, 'matrix': 'enterprise',
                                             'attack_version': '20.0', 'basis': 'x'}]))


def test_severity_order():
    assert severity_rank('info') < severity_rank('low') < severity_rank('medium') < severity_rank('high') < severity_rank('critical')


def test_url_hash_matches_blacklist_formula():
    for raw in ['https://Known-Phish.EXAMPLE:443/login', 'known-phish.example/login', 'http://[2001:db8::1]:8080/a?b=1#frag']:
        indicator = normalize('url', raw)
        assert indicator.value_hash == url_hash(raw)
        assert indicator.value_hash == hashlib.sha256(indicator.value.encode()).hexdigest()


def test_url_and_domain_registered_parent():
    url = normalize('url', 'https://login.tenant.weebly.com/x')
    domain = normalize('domain', 'Login.Tenant.Weebly.com.')
    assert domain.value == 'login.tenant.weebly.com'
    assert url.registered_domain == domain.registered_domain == 'weebly.com'
    assert url.registered_domain_hash == hashlib.sha256(b'weebly.com').hexdigest()
    assert normalize('url', 'http://192.0.2.7/login').registered_domain is None


def test_idna_domain_normalization():
    assert normalize('domain', 'bücher.example').value == 'xn--bcher-kva.example'
    assert normalize('domain', 'XN--BCHER-KVA.example').value == 'xn--bcher-kva.example'
    for bad in ['', 'localhost', '192.0.2.1', 'a..example']:
        with pytest.raises(ValueError):
            normalize('domain', bad)


def test_ip_compression():
    assert normalize('ip', '2001:0db8:0000:0000:0000:0000:0000:0001').value == '2001:db8::1'
    assert normalize('ip', '[2001:db8::1]').value == '2001:db8::1'
    assert normalize('ip', '192.0.2.10').value == '192.0.2.10'
    with pytest.raises(ValueError):
        normalize('ip', '999.1.1.1')


@pytest.mark.parametrize('raw,expected,short', [
    ('010 0000 0000', '+201000000000', False),
    ('+20 100 000 0000', '+201000000000', False),
    ('00201000000000', '+201000000000', False),
    ('201000000000', '+201000000000', False),
    ('(02) 0000-0000', '+20200000000', False),
    ('19623', '19623', True),
    ('9999', '9999', True),
])
def test_phone_normalization(raw, expected, short):
    indicator = normalize('phone', raw)
    assert (indicator.value, indicator.short_code) == (expected, short)


@pytest.mark.parametrize('raw', ['12', 'abc', '+12', '1234567', '+1234567890123456', '01234567890123'])
def test_invalid_phone(raw):
    with pytest.raises(ValueError):
        normalize('phone', raw)


def test_email_and_hash_normalization():
    assert normalize('email', 'Someone@Bücher.Example').value == 'someone@xn--bcher-kva.example'
    for bad in ['no-at.example', 'a@b@c.example', 'a@localhost']:
        with pytest.raises(ValueError):
            normalize('email', bad)
    assert normalize('hash', 'D41D8CD98F00B204E9800998ECF8427E', 'md5').value == 'd41d8cd98f00b204e9800998ecf8427e'
    with pytest.raises(ValueError):
        normalize('hash', 'd41d8cd98f00b204e9800998ecf8427e', 'sha256')
    with pytest.raises(ValueError):
        normalize('url', 'https://x.example/', hash_algo='md5')
    with pytest.raises(ValueError):
        normalize('sms_sender', 'NBE')
