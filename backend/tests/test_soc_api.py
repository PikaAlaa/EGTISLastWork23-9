"""SOC console API: incidents, campaigns, indicators, community review, ATT&CK (design core-v1 §6, §9.11).

All inputs are invented; .example domains and placeholder numbers only.
"""
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from app.models import AttackTechnique, CommunityReport, IncidentEvent, IndicatorSighting, BlacklistEntry
from app.services.attack import parse_techniques
from app.services.findings import seed_correlation_stoplist
from app.services.indicators import sync_feed_indicators
from app.services.registry import populate_registry

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-subset.json').read_text(encoding='utf-8'))
MARKER = 'private-marker-soc-77'


@pytest.fixture
def soc(client, db):
    populate_registry(db)
    seed_correlation_stoplist(db)
    for matrix in ('enterprise', 'mobile'):
        db.add_all(AttackTechnique(**row) for row in parse_techniques(FIXTURE['objects'][matrix], matrix, '20.0'))
    db.commit()
    return client


def scan(client, **body):
    response = client.post('/analyze', json=body)
    assert response.status_code == 200 and response.json()['saved']
    return response.json()


def first_incident(client):
    listing = client.get('/incidents').json()
    assert listing['total_matching'] >= 1
    return listing['results'][0]


@pytest.mark.parametrize('method,path,body', [
    ('get', '/incidents', None), ('get', '/incidents/1', None), ('patch', '/incidents/1', {'note': 'x'}),
    ('post', '/incidents/1/merge', {'into': 2}), ('get', '/campaigns', None), ('post', '/campaigns', {'name': 'x'}),
    ('get', '/campaigns/suggestions', None), ('post', '/campaigns/1/incidents', {'incident_id': 1}),
    ('get', '/indicators?type=domain&q=lure.example', None), ('get', '/indicators/1', None),
    ('get', '/community-reports', None), ('patch', '/community-reports/1', {'status': 'rejected'}),
    ('get', '/attack/techniques', None), ('get', '/attack/coverage', None), ('get', '/attack/techniques/T1566', None),
])
def test_every_soc_endpoint_requires_the_api_key(client, monkeypatch, method, path, body):
    from app.core import security
    monkeypatch.setattr(security, 'settings', replace(security.settings, api_key='server-only-test-key'))
    response = getattr(client, method)(path, **({'json': body} if body is not None else {}))
    assert response.status_code == 401


def test_incident_list_detail_and_filters(soc):
    result = scan(soc, url='https://known-phish.example/login')
    assert result['verdict'] == 'HIGH'
    incident = first_incident(soc)
    assert incident['status'] == 'open' and incident['severity'] == 'high' and incident['finding_count'] == 1
    detail = soc.get(f"/incidents/{incident['id']}").json()
    assert detail['findings'][0]['verdict'] == 'HIGH'
    assert detail['findings'][0]['reasons'][0] == 'blacklist_exact'
    assert {t['technique_id'] for t in detail['techniques']} >= {'T1566', 'T1204.001'}
    assert next(t for t in detail['techniques'] if t['technique_id'] == 'T1566')['name'] == 'Phishing'
    assert all(i['value'] is None for i in detail['indicators'] if i['type'] == 'url')
    assert [e['action'] for e in detail['events']] == ['created'] and detail['expired_findings'] == 0
    assert soc.get('/incidents?status=resolved').json()['total_matching'] == 0
    assert soc.get('/incidents?severity=high&domain=phishing').json()['total_matching'] == 1
    assert soc.get('/incidents?since=2999-01-01').json()['total_matching'] == 0
    assert soc.get('/incidents?brand=no-such-brand').json()['total_matching'] == 0
    assert soc.get('/incidents/9999').status_code == 404


def test_brand_filter_uses_matched_brands(soc):
    scan(soc, url='https://cibeg.com:443@brand-lure.example/login')
    incident = first_incident(soc)
    assert incident['brands'], incident
    brand = incident['brands'][0]
    assert soc.get('/incidents', params={'brand': brand[:5]}).json()['total_matching'] == 1


def test_status_workflow_and_notes_via_api(soc):
    scan(soc, url='https://known-phish.example/login')
    incident_id = first_incident(soc)['id']
    assert soc.patch(f'/incidents/{incident_id}', json={'status': 'investigating', 'note': 'invented note'}).status_code == 200
    bad = soc.patch(f'/incidents/{incident_id}', json={'status': 'resolved'})
    assert bad.status_code == 409 and bad.json()['detail'] == 'resolution_required'
    done = soc.patch(f'/incidents/{incident_id}', json={'status': 'resolved', 'resolution': 'true_positive'}).json()
    assert done['status'] == 'resolved' and done['resolution'] == 'true_positive'
    assert soc.patch(f'/incidents/{incident_id}', json={'status': 'open'}).json()['detail'] == 'reopen_note_required'
    assert soc.patch(f'/incidents/{incident_id}', json={'note': 'second invented note'}).status_code == 200
    assert soc.patch(f'/incidents/{incident_id}', json={}).status_code == 400
    assert soc.patch(f'/incidents/{incident_id}', json={'status': 'closed'}).status_code == 400
    assert soc.patch('/incidents/9999', json={'note': 'x'}).status_code == 404
    actions = [e['action'] for e in soc.get(f'/incidents/{incident_id}').json()['events']]
    assert actions == ['created', 'status_change', 'status_change', 'note']


def test_merge_and_campaigns(soc):
    scan(soc, url='https://known-phish.example/login')
    scan(soc, url='https://second-phish.example/login')
    ids = sorted(i['id'] for i in soc.get('/incidents').json()['results'])
    assert len(ids) == 2
    assert soc.post(f'/incidents/{ids[1]}/merge', json={'into': ids[1]}).status_code == 409
    merged = soc.post(f'/incidents/{ids[1]}/merge', json={'into': ids[0], 'note': 'same lure'}).json()
    assert merged['id'] == ids[0] and merged['finding_count'] == 2
    source = soc.get(f'/incidents/{ids[1]}').json()
    assert source['status'] == 'resolved' and source['resolution'] == 'duplicate'
    assert {'incident_id': ids[1], 'related_incident_id': ids[0], 'relation': 'merged_into'} in source['links']
    created = soc.post('/campaigns', json={'name': 'Invented campaign'})
    assert created.status_code == 201
    campaign_id = created.json()['id']
    assigned = soc.post(f'/campaigns/{campaign_id}/incidents', json={'incident_id': ids[0]}).json()
    assert assigned['campaign'] == {'id': campaign_id, 'name': 'Invented campaign'}
    assert soc.get('/campaigns').json()['results'][0]['incident_count'] == 1
    assert soc.post('/campaigns/999/incidents', json={'incident_id': ids[0]}).status_code == 404
    assert soc.post('/campaigns', json={'name': ''}).status_code == 400


def test_campaign_suggestions_for_shared_contact_outside_window(soc, db):
    from datetime import timedelta, timezone
    from app.core.findings import Finding
    from app.core.indicators import normalize
    from app.services.findings import record_findings
    phone = normalize('phone', '01000000004')
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    for offset in (0, 40):  # 40 days apart: outside the 14-day window, so two incidents
        at = start + timedelta(days=offset)
        record_findings(db, [Finding.model_validate(dict(
            engine={'name': 'phishing.analyze', 'version': 'test'}, domain='phishing', kind='sms_phishing',
            severity='high', confidence='corroborated', observed_at=at, created_at=at,
            indicators=[{'type': 'phone', 'value_hash': phone.value_hash, 'role': 'contact_phone'}],
            source={'kind': 'scan', 'ref': 'scan_requests:0'}))])
    db.commit()
    incidents = sorted(i['id'] for i in soc.get('/incidents').json()['results'])
    assert len(incidents) == 2
    suggestions = soc.get('/campaigns/suggestions').json()['results']
    assert suggestions == [{'incident_ids': incidents, 'reason': 'shared_contact', 'brands': [],
                            'shared_indicator_types': ['phone']}]


def test_indicator_exact_lookup_shows_value_only_for_exact_match(soc, db):
    sync_feed_indicators(db)
    found = soc.get('/indicators', params={'type': 'url', 'q': 'HTTPS://Known-Phish.EXAMPLE:443/login'}).json()
    assert found['found'] and found['indicator']['value'] == 'https://known-phish.example/login'
    assert {s['source_kind'] for s in found['indicator']['sightings']} == {'feed'}
    by_id = soc.get(f"/indicators/{found['indicator']['id']}").json()
    assert by_id['value_hash'] == found['indicator']['value_hash']
    missing = soc.get('/indicators', params={'type': 'domain', 'q': 'never-seen.example'}).json()
    assert missing == {'type': 'domain', 'found': False, 'indicator': None}
    assert soc.get('/indicators/99999').status_code == 404


def test_incident_detail_carries_recommended_actions(soc, monkeypatch):
    """Design core-v2 §2.4: read-only action text per finding and for the incident header."""
    import copy
    from app.services import recommended_actions as ra
    scan(soc, url='https://known-phish.example/login')
    detail = soc.get(f"/incidents/{first_incident(soc)['id']}").json()
    # Shipped texts are all draft: hidden until the named reviewer has checked them.
    assert detail['recommended_actions'] == [] and detail['findings'][0]['recommended_actions'] == []
    raw = json.loads(ra.CATALOGUE_PATH.read_text(encoding='utf-8'))
    for text in [*raw['entries'].values(), *raw['kind_defaults'].values(), raw['fallback']]:
        text.update(status='reviewed', reviewed_by='Arabic-speaking team member', reviewed_on='2026-11-28')
    monkeypatch.setattr(ra, 'load_catalogue', lambda *a, **k: ra.parse_catalogue(copy.deepcopy(raw)))
    detail = soc.get(f"/incidents/{first_incident(soc)['id']}").json()
    primary = detail['findings'][0]['recommended_actions'][0]
    assert primary['reason_code'] == 'blacklist_exact' and primary['en'] and primary['ar']
    assert detail['recommended_actions'] == [primary]
    assert 'known-phish' not in json.dumps(detail['recommended_actions'])


@pytest.mark.parametrize('kind,plain,defanged', [
    ('url', 'https://known-phish.example/login', 'hxxps://known-phish[.]example/login'),
    ('url', 'https://known-phish.example/login', 'HXXPS://Known-Phish[.]EXAMPLE:443/login'),
    ('domain', 'known-phish.example', 'known-phish[.]example'),
])
def test_defanged_lookup_finds_the_same_indicator(soc, db, kind, plain, defanged):
    sync_feed_indicators(db)
    expected = soc.get('/indicators', params={'type': kind, 'q': plain}).json()
    found = soc.get('/indicators', params={'type': kind, 'q': defanged}).json()
    assert expected['found'] and found == expected


def test_defanged_lookup_for_email_and_ipv6_values(soc, db):
    from app.core.indicators import normalize
    from app.models import Indicator
    now = datetime(2026, 11, 27)
    for kind, value in (('email', 'payroll@evil.example'), ('ip', '2001:db8::1')):
        n = normalize(kind, value)
        db.add(Indicator(type=n.type, value_hash=n.value_hash, value=n.value, first_seen=now, last_seen=now))
    db.commit()
    for kind, plain, defanged in (('email', 'payroll@evil.example', 'payroll[@]evil[.]example'),
                                  ('ip', '2001:db8::1', '2001[:]db8[:][:]1'),
                                  ('ip', '2001:db8::1', '[2001[:]db8[:][:]1]')):
        expected = soc.get('/indicators', params={'type': kind, 'q': plain}).json()
        found = soc.get('/indicators', params={'type': kind, 'q': defanged}).json()
        assert expected['found'] and found == expected


@pytest.mark.parametrize('params', [{'type': 'url', 'q': f'hxxps://{MARKER}[.]'},
                                    {'type': 'domain', 'q': f'{MARKER}[.]'},
                                    {'type': 'email', 'q': f'{MARKER}[@]'}])
def test_invalid_defanged_lookup_never_echoes_input(soc, params, caplog):
    response = soc.get('/indicators', params=params)
    assert response.status_code == 400 and response.json()['detail'] == 'invalid_input'
    assert MARKER not in response.text and MARKER not in caplog.text


def test_scan_derived_indicator_has_no_plaintext(soc):
    result = scan(soc, url=f'https://cibeg.com:443@{MARKER}.example/login')
    assert result['verdict'] == 'HIGH'  # userinfo brand disguise is decisive
    found = soc.get('/indicators', params={'type': 'domain', 'q': f'{MARKER}.example'}).json()
    assert found['found'] and found['indicator']['value'] is None
    assert MARKER not in json.dumps(found['indicator'])
    detail = soc.get(f"/incidents/{found['indicator']['incidents'][0]['id']}").json()
    assert MARKER not in json.dumps(detail)


@pytest.mark.parametrize('params', [{'type': 'domain', 'q': MARKER}, {'type': 'phone', 'q': MARKER},
                                    {'type': 'hash', 'q': MARKER}, {'type': 'sms', 'q': MARKER},
                                    {'type': 'url', 'q': ''}])
def test_invalid_lookup_never_echoes_input(soc, params, caplog):
    response = soc.get('/indicators', params=params)
    assert response.status_code == 400 and MARKER not in response.text and MARKER not in caplog.text


def test_community_review_confirm_and_reject(soc, db):
    db.add_all([CommunityReport(reported_value='https://community-lure.example/x', status='pending'),
                CommunityReport(reported_value='not a phone', status='pending')])
    db.commit()
    listing = soc.get('/community-reports?status=pending').json()
    assert listing['total_matching'] == 2
    first, second = sorted(r['id'] for r in listing['results'])
    assert soc.patch(f'/community-reports/{first}', json={'status': 'confirmed'}).json()['detail'] == 'indicator_type_required'
    confirmed = soc.patch(f'/community-reports/{first}', json={'status': 'confirmed', 'indicator_type': 'url'}).json()
    assert confirmed['status'] == 'confirmed' and confirmed['indicator_id']
    sighting = db.query(IndicatorSighting).filter_by(indicator_id=confirmed['indicator_id']).one()
    assert sighting.source_kind == 'community'
    assert db.query(BlacklistEntry).filter(BlacklistEntry.url.contains('community-lure')).count() == 0
    assert soc.patch(f'/community-reports/{first}', json={'status': 'rejected'}).status_code == 409
    bad = soc.patch(f'/community-reports/{second}', json={'status': 'confirmed', 'indicator_type': 'phone'})
    assert bad.status_code == 400 and 'not a phone' not in bad.text
    assert soc.patch(f'/community-reports/{second}', json={'status': 'rejected'}).json()['status'] == 'rejected'


def test_attack_catalogue_and_coverage(soc):
    techniques = soc.get('/attack/techniques?matrix=mobile').json()
    assert techniques['installed'] and techniques['attack_version'] == '20.0'
    assert techniques['copyright'].startswith('Copyright 2015-2026, The MITRE Corporation.')
    assert {t['technique_id'] for t in techniques['techniques']} == {'T1660', 'T1476'}
    scan(soc, url='https://known-phish.example/login', text='Invented message with a link')
    coverage = soc.get('/attack/coverage?matrix=enterprise').json()
    from app.routers.attack import TACTIC_ORDER
    tactics = [t['tactic'] for t in coverage['tactics']]
    assert tactics == [t for t in TACTIC_ORDER['enterprise'] if t in tactics]
    cells = {t['technique_id']: t for tactic in coverage['tactics'] for t in tactic['techniques']}
    assert cells['T1566']['findings'] == 1 and cells['T1566']['incidents'] == 1
    assert cells['T1566.004']['findings'] == 0
    assert soc.get('/attack/coverage?matrix=enterprise&until=2000-01-01').json()['total_findings'] == 0
    detail = soc.get('/attack/techniques/T1660?matrix=mobile').json()
    assert detail['technique']['name'] == 'Phishing' and detail['findings'] == 1 and len(detail['incidents']) == 1
    assert soc.get('/attack/techniques/T1656').status_code == 404
    assert soc.get('/attack/coverage?matrix=ics').status_code == 400


def test_attack_endpoints_report_not_installed(client):
    response = client.get('/attack/techniques').json()
    assert response['installed'] is False and response['techniques'] == []
    assert response['copyright']


# ---------------------------------------------------------------- device risk API (design core-v2 §3.5, step 8)

def _device_findings(db, *, now=None):
    """Two invented devices: one with malware + network findings (13 points), one with an info finding."""
    import uuid as _uuid
    from datetime import timedelta, timezone as _tz
    from app.core import device_names as dn
    from app.core.findings import Finding
    from app.engines.host.pseudonyms import Pseudonymizer
    from app.services.findings import record_findings
    now = now or datetime.now(_tz.utc)
    pseudo = Pseudonymizer(bytes(range(32)))
    busy, quiet = pseudo.host_ref('invented-busy-pc'), pseudo.host_ref('invented-quiet-pc')

    def make(engine, domain, kind, severity, confidence, device, days, reasons, refs=()):
        return Finding.model_validate(dict(
            engine={'name': engine, 'version': 'test'}, domain=domain, kind=kind, severity=severity,
            confidence=confidence, indicators=list(refs), evidence={'reasons': reasons, 'details': {'device_ref': device}},
            observed_at=now - timedelta(days=days), created_at=now, source={'kind': 'import', 'ref': f'test:{_uuid.uuid4()}'}))
    record_findings(db, [
        make('malware.files', 'malware', 'known_bad_hash', 'high', 'corroborated', busy, 2, ['hash_list_malicious']),
        make('malware.files', 'malware', 'known_bad_hash', 'high', 'corroborated', busy, 3, ['hash_list_malicious']),
        make('network.windows', 'network', 'beaconing', 'high', 'corroborated', busy, 1, ['periodic_beaconing']),
        make('network.windows', 'network', 'rare_destination', 'info', 'single_signal', quiet, 1,
             ['rare_first_seen_destination']),
    ])
    db.commit()
    key = dn.load_server_key()
    return dn.wrap_ref(busy, 'device', key), dn.wrap_ref(quiet, 'device', key), busy


def test_device_risk_list_and_detail(soc, db):
    busy, quiet, _ = _device_findings(db)
    listing = soc.get('/device-risk').json()
    assert listing['version'] == 'device-risk-v1' and listing['total'] == 2
    assert [(d['device_ref'], d['points'], d['band']) for d in listing['results']] == [(busy, 13, 'high'), (quiet, 0, 'none')]
    assert listing['results'][0]['engines'] == ['malware.files', 'network.windows']
    assert listing['results'][0]['device_status'] is None
    detail = soc.get('/device-risk/detail', params={'device_ref': busy}).json()
    assert (detail['points'], detail['band'], detail['cross_engine']['points']) == (13, 'high', 3)
    assert [r['reason'] for r in detail['not_counted']] == ['repeat']
    assert set(detail['windows']) == {'malware.files', 'network.windows'}
    assert all(r['recommended_action'] is None for r in detail['counted'])   # texts are still draft
    assert all(r['from_revoked_device'] is None for r in detail['counted'])  # no devices table before 010


def test_device_risk_paging_and_unknown_device(soc, db):
    busy, quiet, _ = _device_findings(db)
    page = soc.get('/device-risk', params={'limit': 1, 'offset': 1}).json()
    assert [d['device_ref'] for d in page['results']] == [quiet]
    unknown = soc.get('/device-risk/detail', params={'device_ref': 'srv:' + 'f' * 32})
    assert unknown.status_code == 404 and unknown.json()['detail'] == 'not_found'
    assert soc.get('/device-risk', params={'limit': 0}).status_code == 400


@pytest.mark.parametrize('value', ['hmac:' + 'a' * 32, 'srv:' + 'A' * 32, 'srv:' + 'a' * 31, f'srv:{MARKER}',
                                   MARKER, ''])
def test_device_risk_rejects_anything_but_srv_without_echo(soc, db, value, caplog):
    response = soc.get('/device-risk/detail', params={'device_ref': value})
    assert response.status_code == 400 and response.json()['detail'] == 'invalid_input'
    assert MARKER not in response.text and MARKER not in caplog.text


def test_device_risk_endpoint_hmac_form_of_a_real_device_is_rejected(soc, db):
    _, _, endpoint = _device_findings(db)
    response = soc.get('/device-risk/detail', params={'device_ref': endpoint})
    assert response.status_code == 400 and endpoint not in response.text


def test_device_risk_requires_the_api_key(client, monkeypatch):
    from app.core import security
    monkeypatch.setattr(security, 'settings', replace(security.settings, api_key='server-only-test-key'))
    assert client.get('/device-risk').status_code == 401
    assert client.get('/device-risk/detail', params={'device_ref': 'srv:' + '0' * 32}).status_code == 401


def test_device_risk_is_read_only(soc):
    from app.main import app
    paths = {p: set(ops) for p, ops in app.openapi()['paths'].items() if p.startswith('/device-risk')}
    assert paths == {'/device-risk': {'get'}, '/device-risk/detail': {'get'}}
    for method in ('post', 'put', 'patch', 'delete'):
        assert getattr(soc, method)('/device-risk').status_code == 405
