"""Feed projection into the indicator store (design core-v1 §2.4).

`sync_feed_indicators` reads `blacklist_entries` and `feed_observations` and
upserts `indicators`/`indicator_sightings`. It never writes to a feed table and
never deletes a row. It runs after feed activation, expiry or rollback have
committed, in its own transaction, so a failure here cannot change feed state
or `/analyze` behaviour. Running it twice is a no-op.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from app.core.indicators import NormalizedIndicator, normalize_domain, normalize_ip, normalize_url
from app.models import BlacklistEntry, FeedObservation, Indicator, IndicatorSighting

FEED_KIND = 'feed'


def _as_datetime(value: date | datetime) -> datetime:
    return value if isinstance(value, datetime) else datetime(value.year, value.month, value.day)


def _host_indicator(host: str) -> NormalizedIndicator | None:
    try:
        return normalize_ip(host)
    except ValueError:
        pass
    try:
        return normalize_domain(host)
    except ValueError:
        return None


def _url_indicator(entry: BlacklistEntry) -> NormalizedIndicator:
    # value_hash must equal blacklist_entries.url_hash exactly, whatever the stored URL shape.
    host = _host_indicator(entry.domain)
    try:
        parsed = normalize_url(entry.url)
        parent, parent_hash = parsed.registered_domain, parsed.registered_domain_hash
    except ValueError:
        parent = host.registered_domain if host else None
        parent_hash = host.registered_domain_hash if host else None
    return NormalizedIndicator('url', entry.url, entry.url_hash, parent, parent_hash)


def _merge(target: dict, key, first_seen, last_seen, active, ref):
    current = target.get(key)
    if current is None:
        target[key] = {'first_seen': first_seen, 'last_seen': last_seen, 'active': active, 'ref': ref}
    else:
        current['first_seen'] = min(current['first_seen'], first_seen)
        current['last_seen'] = max(current['last_seen'], last_seen)
        current['active'] = current['active'] or active


def desired_feed_state(db):
    """Return ({(type, value_hash): NormalizedIndicator}, {((type, value_hash), source): state})."""
    observations: dict[str, dict[str, date]] = {}
    for observation in db.query(FeedObservation).all():
        observations.setdefault(observation.url_hash, {})[observation.source] = observation.last_seen
    indicators: dict[tuple, NormalizedIndicator] = {}
    sightings: dict[tuple, dict] = {}
    for entry in db.query(BlacklistEntry).order_by(BlacklistEntry.id).all():
        per_source = dict(observations.get(entry.url_hash, {}))
        per_source.setdefault(entry.source, entry.last_seen)
        url = _url_indicator(entry)
        host = _host_indicator(entry.domain)
        for indicator, ref in ((url, f'blacklist_entries:{entry.id}'), (host, None)):
            if indicator is None:
                continue
            key = (indicator.type, indicator.value_hash)
            indicators.setdefault(key, indicator)
            for source, last_seen in per_source.items():
                _merge(sightings, (key, source), _as_datetime(entry.first_seen), _as_datetime(last_seen),
                       bool(entry.is_active), ref)
    return indicators, sightings


def sync_feed_indicators(db) -> dict:
    indicators, sightings = desired_feed_state(db)
    stats = dict(indicators_added=0, indicators_updated=0, sightings_added=0, sightings_updated=0,
                 sightings_deactivated=0)
    existing = {(i.type, i.value_hash): i for i in db.query(Indicator).filter(
        Indicator.type.in_(['url', 'domain', 'ip'])).all()}
    bounds: dict[tuple, list] = {}
    for (key, _source), state in sightings.items():
        low_high = bounds.setdefault(key, [state['first_seen'], state['last_seen']])
        low_high[0] = min(low_high[0], state['first_seen'])
        low_high[1] = max(low_high[1], state['last_seen'])
    for key, normalized in indicators.items():
        first_seen, last_seen = bounds[key]
        row = existing.get(key)
        if row is None:
            row = Indicator(type=normalized.type, value_hash=normalized.value_hash, value=normalized.value,
                            registered_domain=normalized.registered_domain,
                            registered_domain_hash=normalized.registered_domain_hash,
                            first_seen=first_seen, last_seen=last_seen)
            db.add(row)
            existing[key] = row
            stats['indicators_added'] += 1
            continue
        changes = {}
        if row.value is None:
            changes['value'] = normalized.value  # a feed value may label an earlier hash-only sighting
        if row.registered_domain is None and normalized.registered_domain:
            changes['registered_domain'] = normalized.registered_domain
        if row.registered_domain_hash is None and normalized.registered_domain_hash:
            changes['registered_domain_hash'] = normalized.registered_domain_hash
        if first_seen < row.first_seen:
            changes['first_seen'] = first_seen
        if last_seen > row.last_seen:
            changes['last_seen'] = last_seen
        if changes:
            for name, value in changes.items():
                setattr(row, name, value)
            stats['indicators_updated'] += 1
    db.flush()
    current = {(s.indicator_id, s.source_name): s for s in db.query(IndicatorSighting).filter_by(source_kind=FEED_KIND).all()}
    wanted = set()
    for (key, source), state in sightings.items():
        indicator_id = existing[key].id
        wanted.add((indicator_id, source))
        row = current.get((indicator_id, source))
        if row is None:
            db.add(IndicatorSighting(indicator_id=indicator_id, source_kind=FEED_KIND, source_name=source, **state))
            stats['sightings_added'] += 1
            continue
        if any(getattr(row, name) != value for name, value in state.items()):
            for name, value in state.items():
                setattr(row, name, value)
            stats['sightings_updated'] += 1
    for pair, row in current.items():
        if pair not in wanted and row.active:
            row.active = False
            stats['sightings_deactivated'] += 1
    db.commit()
    return {**stats, 'synced_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}
