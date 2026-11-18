"""Finding persistence, incident correlation and workflow (design core-v1 §3, §9.6, §9.7).

All messages, URLs and numbers are invented; .example domains are reserved and the
mobile numbers are placeholders. The only real values are the official hotlines
already recorded in app/core/brand_contacts.py.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.core.brand_contacts import BRAND_CONTACTS
from app.core.findings import Finding
from app.core.indicators import normalize
from app.models import (BrandDomain, CorrelationStoplist, FindingAttack, FindingIndicator, FindingRecord, Incident,
                        IncidentEvent, IncidentIndicator, IncidentLink, Indicator, IndicatorSighting)
from app.services.findings import record_findings, seed_correlation_stoplist, transition_incident
from app.services.registry import populate_registry

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
NBE_HOTLINE = BRAND_CONTACTS['National Bank of Egypt (NBE)']['phone']


def ref(kind, value, role='observed'):
    n = normalize(kind, value)
    return {'type': kind, 'value_hash': n.value_hash, 'value': None, 'role': role,
            'registered_domain_hash': n.registered_domain_hash}


def finding(*refs, severity='high', at=T0, kind='sms_phishing', brands=None):
    details = {'verdict': 'HIGH'}
    if brands:
        details['matched_brands'] = brands
    return Finding.model_validate(dict(
        engine={'name': 'phishing.analyze', 'version': 'test'}, domain='phishing', kind=kind, severity=severity,
        confidence='corroborated', indicators=list(refs),
        attack=[{'technique_id': 'T1566', 'matrix': 'enterprise', 'attack_version': '20.0', 'basis': 'phishing_message'}],
        evidence={'reasons': ['test'], 'details': details}, observed_at=at, created_at=at,
        source={'kind': 'scan', 'ref': 'scan_requests:0'}))


def link(url):
    host = normalize('url', url)
    domain = normalize('domain', url.split('/')[2])
    return [ref('url', url, 'delivery_link'),
            {'type': 'domain', 'value_hash': domain.value_hash, 'value': None, 'role': 'link_host',
             'registered_domain_hash': host.registered_domain_hash}]


def record(db, *findings_):
    records = record_findings(db, list(findings_))
    db.commit()
    return records


@pytest.fixture
def seeded(db):
    populate_registry(db)
    seed_correlation_stoplist(db)
    return db


def test_shared_url_groups_into_one_incident(seeded):
    a, = record(seeded, finding(*link('https://lure.example/pay')))
    b, = record(seeded, finding(*link('https://lure.example/pay'), at=T0 + timedelta(hours=2)))
    assert a.incident_id and a.incident_id == b.incident_id
    assert seeded.query(Incident).count() == 1
    incident = seeded.get(Incident, a.incident_id)
    assert incident.last_activity_at == (T0 + timedelta(hours=2)).replace(tzinfo=None)


def test_same_registered_domain_groups(seeded):
    # example.com is IANA-reserved and, unlike .example, has a public suffix parent.
    a, = record(seeded, finding(*link('https://a.example.com/x')))
    b, = record(seeded, finding(*link('https://b.example.com/y')))
    assert a.incident_id == b.incident_id


def unique_lure(n):
    return link(f'https://lure-{n}.example/')


def assert_separate(*records_):
    ids = [r.incident_id for r in records_]
    assert all(ids) and len(set(ids)) == len(ids)


def test_shared_hosting_does_not_group(seeded):
    shared = ['https://docs.google.com/document/d/one', 'https://docs.google.com/document/d/two',
              'https://docs.google.com/document/d/one', 'https://tenant.weebly.com/x', 'https://other.weebly.com/x']
    records_ = [record(seeded, finding(*link(url), *unique_lure(i)))[0] for i, url in enumerate(shared)]
    assert_separate(*records_)
    only_shared, = record(seeded, finding(*link('https://docs.google.com/document/d/one')))
    assert only_shared.incident_id is None  # no pivotable indicator (§3.2)


def test_official_brand_domain_does_not_group(seeded):
    official = seeded.query(BrandDomain).order_by(BrandDomain.id).first().domain
    a, = record(seeded, finding(*link(f'https://{official}/login'), *unique_lure(1)))
    b, = record(seeded, finding(*link(f'https://www.{official}/login'), *unique_lure(2)))
    assert_separate(a, b)


def test_official_brand_hotline_does_not_group_but_other_phone_does(seeded):
    assert seeded.query(CorrelationStoplist).filter_by(type='phone', reason='official_brand_contact',
                                                       value=NBE_HOTLINE).count() == 1
    # Invented messages quoting the real NBE hotline: the hotline is their only shared indicator.
    a, = record(seeded, finding(ref('phone', NBE_HOTLINE, 'quoted_contact'), *unique_lure(1)))
    b, = record(seeded, finding(ref('phone', NBE_HOTLINE, 'quoted_contact'), *unique_lure(2)))
    assert_separate(a, b)
    # The same two shapes sharing a non-official (placeholder) number do group.
    c, = record(seeded, finding(ref('phone', '01000000000', 'contact_phone'), *unique_lure(3)))
    d, = record(seeded, finding(ref('phone', '+20 100 000 0000', 'contact_phone'), *unique_lure(4)))
    assert c.incident_id and c.incident_id == d.incident_id


def test_stoplist_seeding_is_idempotent_and_preserves_analyst_rows(seeded):
    analyst = normalize('phone', '01000000001')
    seeded.add(CorrelationStoplist(type='phone', value_hash=analyst.value_hash, value=analyst.value,
                                   reason='analyst_added', seeded=False))
    seeded.add(CorrelationStoplist(type='domain', value_hash='e' * 64, value='retired.example',
                                   reason='shared_hosting', seeded=True))
    seeded.commit()
    before = sorted((r.type, r.value_hash, r.value, r.reason, r.brand, r.seeded)
                    for r in seeded.query(CorrelationStoplist) if r.value != 'retired.example')
    first = seed_correlation_stoplist(seeded)
    assert first['removed'] == 1 and first['added'] == 0
    second = seed_correlation_stoplist(seeded)
    assert second == dict(added=0, updated=0, removed=0, kept_analyst=0)
    after = sorted((r.type, r.value_hash, r.value, r.reason, r.brand, r.seeded) for r in seeded.query(CorrelationStoplist))
    assert after == before
    assert ('phone', analyst.value_hash, analyst.value, 'analyst_added', None, False) in after
    hotlines = {r.value for r in seeded.query(CorrelationStoplist).filter_by(reason='official_brand_contact')}
    assert hotlines == {c['phone'] for c in BRAND_CONTACTS.values()}


def test_multiple_matches_attach_to_oldest_and_link(seeded):
    a, = record(seeded, finding(*link('https://first.example/')))
    b, = record(seeded, finding(*link('https://second.example/'), at=T0 + timedelta(hours=1)))
    c, = record(seeded, finding(*link('https://first.example/'), *link('https://second.example/'),
                                at=T0 + timedelta(hours=2)))
    assert c.incident_id == a.incident_id != b.incident_id
    assert seeded.query(IncidentLink).filter_by(incident_id=a.incident_id, related_incident_id=b.incident_id,
                                                relation='related').count() == 1
    assert seeded.query(Incident).count() == 2  # never merged automatically


def test_resolved_incident_is_not_reopened_silently(seeded):
    a, = record(seeded, finding(*link('https://resolved.example/')))
    transition_incident(seeded, a.incident_id, 'resolved', resolution='true_positive'); seeded.commit()
    b, = record(seeded, finding(*link('https://resolved.example/'), at=T0 + timedelta(days=1)))
    assert b.incident_id != a.incident_id
    assert seeded.get(Incident, b.incident_id).reopened_from == a.incident_id
    assert seeded.get(Incident, a.incident_id).status == 'resolved'


@pytest.mark.parametrize('days,same', [(14, True), (15, False)])
def test_correlation_window_boundary(seeded, days, same):
    a, = record(seeded, finding(*link('https://window.example/')))
    b, = record(seeded, finding(*link('https://window.example/'), at=T0 + timedelta(days=days)))
    assert (a.incident_id == b.incident_id) is same


def test_low_severity_without_match_stays_unassigned_but_attaches_to_open_incident(seeded):
    low, = record(seeded, finding(*link('https://quiet.example/'), severity='low'))
    assert low.incident_id is None and seeded.query(Incident).count() == 0
    high, = record(seeded, finding(*link('https://quiet.example/'), severity='medium'))
    later, = record(seeded, finding(*link('https://quiet.example/'), severity='low'))
    assert later.incident_id == high.incident_id


def test_incident_severity_is_maximum_and_title_uses_brand(seeded):
    a, = record(seeded, finding(*link('https://sev.example/'), severity='medium', brands=['Invented Bank']))
    record(seeded, finding(*link('https://sev.example/'), severity='high'))
    record(seeded, finding(*link('https://sev.example/'), severity='medium'))
    incident = seeded.get(Incident, a.incident_id)
    assert incident.severity == 'high' and incident.title == 'sms phishing — Invented Bank'


def test_findings_persist_hash_only_with_links_and_sightings(seeded):
    f = finding(*link('https://persist.example/a'), ref('phone', '01000000002', 'contact_phone'))
    rec, = record(seeded, f)
    assert seeded.get(FindingRecord, f.id).severity == 'high'
    assert seeded.query(FindingIndicator).filter_by(finding_id=f.id).count() == 3
    assert seeded.query(FindingAttack).filter_by(finding_id=f.id).one().technique_id == 'T1566'
    assert all(i.value is None for i in seeded.query(Indicator))
    assert seeded.query(IndicatorSighting).filter_by(source_kind='scan', source_name='phishing.analyze').count() == 3
    assert seeded.query(IncidentIndicator).filter_by(incident_id=rec.incident_id).count() == 3
    assert seeded.query(IncidentEvent).filter_by(incident_id=rec.incident_id, action='created').count() == 1


def test_finding_without_pivot_creates_no_incident(seeded):
    rec, = record(seeded, finding())
    assert rec.incident_id is None


# ---------------------------------------------------------------- workflow (§9.7)

@pytest.fixture
def incident_id(seeded):
    rec, = record(seeded, finding(*link('https://workflow.example/')))
    return rec.incident_id


@pytest.mark.parametrize('path', [['investigating', 'resolved'], ['resolved']])
def test_allowed_transitions_write_events(seeded, incident_id, path):
    for status in path:
        transition_incident(seeded, incident_id, status, resolution='false_positive' if status == 'resolved' else None,
                            note='invented note')
    seeded.commit()
    incident = seeded.get(Incident, incident_id)
    assert incident.status == 'resolved' and incident.resolution == 'false_positive' and incident.resolved_at
    events = seeded.query(IncidentEvent).filter_by(incident_id=incident_id).order_by(IncidentEvent.id).all()
    assert [e.action for e in events] == ['created'] + ['status_change'] * len(path)
    assert all(e.actor == 'local-operator' for e in events[1:])


@pytest.mark.parametrize('first,second', [('investigating', 'open'), ('investigating', 'investigating'),
                                          ('investigating', 'closed')])
def test_forbidden_transitions(seeded, incident_id, first, second):
    transition_incident(seeded, incident_id, first)
    with pytest.raises(ValueError, match='invalid_transition'):
        transition_incident(seeded, incident_id, second)


def test_resolution_required_and_only_when_resolving(seeded, incident_id):
    with pytest.raises(ValueError, match='resolution_required'):
        transition_incident(seeded, incident_id, 'resolved')
    with pytest.raises(ValueError, match='resolution_required'):
        transition_incident(seeded, incident_id, 'resolved', resolution='fixed')
    with pytest.raises(ValueError, match='resolution_only_when_resolving'):
        transition_incident(seeded, incident_id, 'investigating', resolution='benign')


def test_reopen_requires_note(seeded, incident_id):
    transition_incident(seeded, incident_id, 'resolved', resolution='duplicate')
    with pytest.raises(ValueError, match='reopen_note_required'):
        transition_incident(seeded, incident_id, 'open', note='  ')
    transition_incident(seeded, incident_id, 'open', note='new evidence (invented)')
    seeded.commit()
    incident = seeded.get(Incident, incident_id)
    assert incident.status == 'open' and incident.resolution is None and incident.resolved_at is None
    assert seeded.query(IncidentEvent).filter_by(incident_id=incident_id, action='reopen').count() == 1


def test_unknown_incident(seeded):
    with pytest.raises(LookupError):
        transition_incident(seeded, 999, 'investigating')
