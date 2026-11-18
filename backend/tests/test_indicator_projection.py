"""Feed projection into the indicator store (design core-v1 §2.4, §9.5). Invented .example URLs only."""
import contextlib
import importlib.util
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

from app.core.indicators import normalize_url
from app.models import (BlacklistEntry, FeedObservation, FeedSnapshot, FeedUpdate, Indicator,
                        IndicatorSighting)
from app.services.feeds import activate_snapshot, expire_sources, rollback_snapshot
from app.services.indicators import sync_feed_indicators

ROOT = Path(__file__).resolve().parents[2]
FEED_MODELS = (BlacklistEntry, FeedObservation, FeedSnapshot, FeedUpdate)


def as_dt(value):
    return datetime(value.year, value.month, value.day)


def feed_dump(db):
    db.expire_all()
    return {model.__tablename__: sorted(tuple(getattr(row, c.name) for c in model.__table__.columns)
                                        for row in db.query(model).all()) for model in FEED_MODELS}


def projection_dump(db):
    db.expire_all()
    return (sorted((i.id, i.type, i.value_hash, i.value, i.registered_domain, i.first_seen, i.last_seen)
                   for i in db.query(Indicator).all()),
            sorted((s.id, s.indicator_id, s.source_kind, s.source_name, s.first_seen, s.last_seen, s.active, s.ref)
                   for s in db.query(IndicatorSighting).all()))


def assert_parity(db):
    observations = {}
    for observation in db.query(FeedObservation).all():
        observations.setdefault(observation.url_hash, {})[observation.source] = observation.last_seen
    for entry in db.query(BlacklistEntry).all():
        indicator = db.query(Indicator).filter_by(type='url', value_hash=entry.url_hash).one()
        sources = {**{entry.source: entry.last_seen}, **observations.get(entry.url_hash, {})}
        for source, last_seen in sources.items():
            sighting = db.query(IndicatorSighting).filter_by(indicator_id=indicator.id, source_kind='feed',
                                                             source_name=source).one()
            assert sighting.active == entry.is_active
            assert sighting.first_seen == as_dt(entry.first_seen)
            assert sighting.last_seen == as_dt(last_seen)
            assert sighting.ref == f'blacklist_entries:{entry.id}'
        if entry.is_active:
            assert db.query(IndicatorSighting).filter_by(indicator_id=indicator.id, source_name=entry.source,
                                                         active=True).count() == 1


def test_seeded_entries_project_with_matching_hashes(db):
    sync_feed_indicators(db)
    assert_parity(db)
    entry = db.query(BlacklistEntry).filter_by(domain='known-phish.example').one()
    url = db.query(Indicator).filter_by(type='url', value_hash=entry.url_hash).one()
    assert url.value == entry.url and url.registered_domain == 'known-phish.example'
    assert db.query(Indicator).filter_by(type='domain', value='known-phish.example').count() == 1
    assert url.value_hash == normalize_url(entry.url).value_hash


def test_activate_expire_and_rollback_keep_parity(db):
    old = datetime.now() - timedelta(days=10)
    first = activate_snapshot(db, 'openphish', ['https://old.example/a', 'https://overlap.example/'], captured_at=old)
    activate_snapshot(db, 'phishtank', ['https://overlap.example/', 'https://pt-only.example/'], captured_at=old)
    sync_feed_indicators(db); assert_parity(db)
    activate_snapshot(db, 'openphish', ['https://new.example/b', 'https://overlap.example/'])
    sync_feed_indicators(db); assert_parity(db)
    rollback_snapshot(db, first['version'])
    sync_feed_indicators(db); assert_parity(db)
    new = db.query(BlacklistEntry).filter_by(domain='new.example').one()
    assert not new.is_active
    expire_sources(db, date.today() + timedelta(days=31)); db.commit()
    sync_feed_indicators(db); assert_parity(db)
    overlap = db.query(Indicator).filter_by(type='url', value_hash=db.query(BlacklistEntry).filter_by(
        domain='overlap.example').one().url_hash).one()
    assert {s.source_name for s in db.query(IndicatorSighting).filter_by(indicator_id=overlap.id)} == {'openphish', 'phishtank'}


def test_sync_is_idempotent_and_never_touches_feed_tables(db):
    activate_snapshot(db, 'openphish', ['https://one.example/', 'https://two.example/x'])
    before = feed_dump(db)
    first = sync_feed_indicators(db)
    assert first['indicators_added'] > 0
    after_first = projection_dump(db)
    second = sync_feed_indicators(db)
    assert {k: v for k, v in second.items() if k != 'synced_at'} == dict.fromkeys(
        ['indicators_added', 'indicators_updated', 'sightings_added', 'sightings_updated', 'sightings_deactivated'], 0)
    assert projection_dump(db) == after_first
    assert feed_dump(db) == before


def test_shared_domain_aggregates_per_source(db):
    activate_snapshot(db, 'openphish', ['https://same.example/a', 'https://same.example/b'])
    sync_feed_indicators(db)
    domain = db.query(Indicator).filter_by(type='domain', value='same.example').one()
    sightings = db.query(IndicatorSighting).filter_by(indicator_id=domain.id).all()
    assert {s.source_name for s in sightings} == {'openphish'} and all(s.active for s in sightings)


def test_ip_host_becomes_ip_indicator(db):
    activate_snapshot(db, 'openphish', ['http://192.0.2.44/login'])
    sync_feed_indicators(db)
    assert db.query(Indicator).filter_by(type='ip', value='192.0.2.44').count() == 1
    assert db.query(Indicator).filter_by(type='domain', value='192.0.2.44').count() == 0


def test_feed_value_labels_existing_hash_only_indicator(db):
    entry = db.query(BlacklistEntry).filter_by(domain='known-phish.example').one()
    db.add(Indicator(type='url', value_hash=entry.url_hash, value=None, first_seen=datetime(2026, 1, 1),
                     last_seen=datetime(2026, 1, 1)))
    db.commit()
    sync_feed_indicators(db)
    assert db.query(Indicator).filter_by(type='url', value_hash=entry.url_hash).one().value == entry.url


def test_worker_sync_failure_leaves_feeds_unchanged(db, monkeypatch):
    sys.path.insert(0, str(ROOT / 'data/scripts'))
    try:
        spec = importlib.util.spec_from_file_location('manage_intelligence', ROOT / 'data/scripts/manage_intelligence.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ROOT / 'data/scripts'))
    monkeypatch.setattr(module, 'SessionLocal', lambda: contextlib.nullcontext(db))
    before = feed_dump(db)

    def broken(_db):
        _db.add(Indicator(type='url', value_hash='f' * 64, first_seen=datetime.now(), last_seen=datetime.now()))
        _db.flush()
        raise RuntimeError('boom')
    monkeypatch.setattr(module, 'sync_feed_indicators', broken)
    assert module.sync_indicators() == {'indicator_sync_error': 'RuntimeError'}
    assert feed_dump(db) == before
    assert db.query(Indicator).count() == 0
    monkeypatch.setattr(module, 'sync_feed_indicators', sync_feed_indicators)
    assert 'indicator_sync' in module.sync_indicators()
