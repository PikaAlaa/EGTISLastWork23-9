"""Finding persistence, incident correlation and the incident workflow (design core-v1 §1.4, §3).

`record_findings` is the only writer of finding/incident rows. It flushes but does
not commit: the caller owns the transaction (for /analyze, the same transaction
as the scan record). Nothing here is read by the decision policy, and incident
state never feeds back into any verdict or threshold.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_

from app.core.brand_contacts import BRAND_CONTACTS
from app.core.findings import Finding, severity_rank
from app.core.indicators import normalize_domain, normalize_phone, sha256_hex
from app.core.settings import settings
from app.core.url_utils import registered_domain
from app.engines.threat_intel.blacklist_lookup import SHARED_HOSTING_DOMAINS
from app.models import (BrandDomain, CorrelationStoplist, FindingAttack, FindingIndicator, FindingRecord,
                        Incident, IncidentEvent, IncidentIndicator, IncidentLink, Indicator, IndicatorSighting)
from app.models.finding import INCIDENT_RESOLUTIONS

logger = logging.getLogger(__name__)
SYSTEM_ACTOR = 'etis'
LOCAL_OPERATOR = 'local-operator'
ACTIVE_STATUSES = ('open', 'investigating')
EXACT_PIVOT_TYPES = ('url', 'ip', 'hash', 'phone', 'email')
ALLOWED_TRANSITIONS = {('open', 'investigating'), ('open', 'resolved'), ('investigating', 'resolved'),
                       ('resolved', 'open')}


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- stoplist

def desired_stoplist() -> dict[tuple[str, str], dict]:
    """Seeded exclusions: shared-hosting registered domains and official brand contact numbers."""
    rows: dict[tuple[str, str], dict] = {}
    for host in sorted(SHARED_HOSTING_DOMAINS):
        parent = normalize_domain(host).registered_domain or host
        rows.setdefault(('domain', sha256_hex(parent)), dict(value=parent, reason='shared_hosting', brand=None))
    for brand, contact in sorted(BRAND_CONTACTS.items()):
        for field in ('phone', 'short_code', 'sms_sender_id'):
            value = contact.get(field)
            if not value:
                continue
            try:
                phone = normalize_phone(value)
            except ValueError:
                continue  # alphanumeric sender ids are not an indicator type in v1
            rows.setdefault(('phone', phone.value_hash),
                            dict(value=phone.value, reason='official_brand_contact', brand=brand))
    return rows


def seed_correlation_stoplist(db) -> dict:
    """Idempotent: seeded rows are replaced; analyst rows (seeded=False) are never overwritten."""
    desired = desired_stoplist()
    stats = dict(added=0, updated=0, removed=0, kept_analyst=0)
    existing = {(row.type, row.value_hash): row for row in db.query(CorrelationStoplist).all()}
    for key, row in existing.items():
        if row.seeded and key not in desired:
            db.delete(row)
            stats['removed'] += 1
    for key, wanted in desired.items():
        row = existing.get(key)
        if row is None:
            db.add(CorrelationStoplist(type=key[0], value_hash=key[1], seeded=True, **wanted))
            stats['added'] += 1
        elif not row.seeded:
            stats['kept_analyst'] += 1
        elif any(getattr(row, name) != value for name, value in wanted.items()):
            for name, value in wanted.items():
                setattr(row, name, value)
            stats['updated'] += 1
    db.commit()
    return stats


def _exclusions(db) -> tuple[set[tuple[str, str]], set[str]]:
    """Return (stoplisted (type, value_hash) pairs, excluded domain hashes)."""
    stop = {(row.type, row.value_hash) for row in db.query(CorrelationStoplist.type, CorrelationStoplist.value_hash)}
    domains = {value_hash for kind, value_hash in stop if kind == 'domain'}
    for (domain,) in db.query(BrandDomain.domain):
        domains.add(sha256_hex(domain.lower()))
        domains.add(sha256_hex(registered_domain(domain.lower())))
    return stop, domains


# ---------------------------------------------------------------- persistence

def _upsert_indicator(db, ref, observed: datetime) -> Indicator:
    row = db.query(Indicator).filter_by(type=ref.type, value_hash=ref.value_hash).one_or_none()
    if row is None:
        row = Indicator(type=ref.type, value_hash=ref.value_hash, value=ref.value, hash_algo=ref.hash_algo,
                        registered_domain_hash=ref.registered_domain_hash, first_seen=observed, last_seen=observed)
        db.add(row)
        db.flush()
        return row
    if row.value is None and ref.value is not None:
        row.value = ref.value
    if row.registered_domain_hash is None and ref.registered_domain_hash:
        row.registered_domain_hash = ref.registered_domain_hash
    row.first_seen = min(row.first_seen, observed)
    row.last_seen = max(row.last_seen, observed)
    return row


def _record_sighting(db, indicator: Indicator, finding: Finding, observed: datetime):
    row = db.query(IndicatorSighting).filter_by(indicator_id=indicator.id, source_kind=finding.source.kind,
                                                source_name=finding.engine.name).one_or_none()
    if row is None:
        db.add(IndicatorSighting(indicator_id=indicator.id, source_kind=finding.source.kind,
                                 source_name=finding.engine.name, first_seen=observed, last_seen=observed,
                                 active=True, ref=None))
    else:
        row.first_seen = min(row.first_seen, observed)
        row.last_seen = max(row.last_seen, observed)
        row.active = True


def record_findings(db, findings: list[Finding], scan_request_id: int | None = None) -> list[FindingRecord]:
    exclusions = _exclusions(db)
    records = []
    for finding in findings:
        observed = _naive_utc(finding.observed_at)
        record = FindingRecord(
            id=finding.id, schema_version=finding.schema_version, engine_name=finding.engine.name,
            engine_version=finding.engine.version, domain=finding.domain, kind=finding.kind,
            severity=finding.severity, confidence=finding.confidence,
            evidence=finding.evidence.model_dump(mode='json'), observed_at=observed,
            created_at=_naive_utc(finding.created_at), source_kind=finding.source.kind,
            source_ref=finding.source.ref, scan_request_id=scan_request_id)
        db.add(record)
        db.flush()
        indicators, seen_roles = [], set()
        for ref in finding.indicators:
            indicator = _upsert_indicator(db, ref, observed)
            if (indicator.id, ref.role) not in seen_roles:
                seen_roles.add((indicator.id, ref.role))
                db.add(FindingIndicator(finding_id=record.id, indicator_id=indicator.id, role=ref.role))
            if indicator not in indicators:
                indicators.append(indicator)
                _record_sighting(db, indicator, finding, observed)
        for technique in {(a.technique_id, a.matrix): a for a in finding.attack}.values():
            db.add(FindingAttack(finding_id=record.id, technique_id=technique.technique_id, matrix=technique.matrix,
                                 attack_version=technique.attack_version, basis=technique.basis))
        db.flush()
        _correlate(db, finding, record, indicators, exclusions)
        records.append(record)
    db.flush()
    return records


# ---------------------------------------------------------------- correlation

def pivot_keys(indicators: list[Indicator], exclusions) -> tuple[set[int], set[str]]:
    """Return (indicator ids for exact pivots, registered-domain hashes for domain pivots)."""
    stop, excluded_domains = exclusions
    exact, domains = set(), set()
    for indicator in indicators:
        if (indicator.type, indicator.value_hash) in stop:
            continue
        on_excluded_domain = bool({indicator.value_hash, indicator.registered_domain_hash} & excluded_domains) \
            if indicator.type in ('url', 'domain') else False
        if on_excluded_domain:
            continue
        if indicator.type in EXACT_PIVOT_TYPES:
            exact.add(indicator.id)
        elif indicator.type == 'domain':
            domains.add(indicator.registered_domain_hash or indicator.value_hash)
    return exact, domains


def matching_incidents(db, exact: set[int], domains: set[str], statuses, since: datetime) -> list[Incident]:
    conditions = []
    if exact:
        conditions.append(Indicator.id.in_(exact))
    if domains:
        conditions.append(and_(Indicator.type == 'domain', or_(Indicator.registered_domain_hash.in_(domains),
                                                               and_(Indicator.registered_domain_hash.is_(None),
                                                                    Indicator.value_hash.in_(domains)))))
    if not conditions:
        return []
    return (db.query(Incident).join(IncidentIndicator, IncidentIndicator.incident_id == Incident.id)
            .join(Indicator, Indicator.id == IncidentIndicator.indicator_id)
            .filter(or_(*conditions), Incident.status.in_(statuses), Incident.last_activity_at >= since)
            .distinct().order_by(Incident.opened_at, Incident.id).all())


def _title(finding: Finding) -> str:
    brands = finding.evidence.details.get('matched_brands') or []
    title = finding.kind.replace('_', ' ')
    return (title + ' — ' + str(brands[0]))[:255] if brands else title


def _attach(db, incident: Incident, finding: Finding, record: FindingRecord, indicators: list[Indicator]):
    record.incident_id = incident.id
    if severity_rank(finding.severity) > severity_rank(incident.severity):
        incident.severity = finding.severity
    incident.last_activity_at = max(incident.last_activity_at, record.observed_at)
    linked = {row.indicator_id for row in db.query(IncidentIndicator).filter_by(incident_id=incident.id)}
    for indicator in indicators:
        if indicator.id not in linked:
            db.add(IncidentIndicator(incident_id=incident.id, indicator_id=indicator.id))


def _correlate(db, finding: Finding, record: FindingRecord, indicators: list[Indicator], exclusions):
    exact, domains = pivot_keys(indicators, exclusions)
    if not exact and not domains:
        return None
    since = record.observed_at - timedelta(days=settings.correlation_window_days)
    active = matching_incidents(db, exact, domains, ACTIVE_STATUSES, since)
    if active:
        target = active[0]
        for other in active[1:]:
            if not db.query(IncidentLink).filter_by(incident_id=target.id, related_incident_id=other.id,
                                                    relation='related').count():
                db.add(IncidentLink(incident_id=target.id, related_incident_id=other.id, relation='related'))
        _attach(db, target, finding, record, indicators)
        return target
    if severity_rank(finding.severity) < severity_rank('medium'):
        return None
    resolved = matching_incidents(db, exact, domains, ('resolved',), since)
    incident = Incident(title=_title(finding), domain=finding.domain, severity=finding.severity, status='open',
                        reopened_from=resolved[-1].id if resolved else None,
                        opened_at=record.observed_at, last_activity_at=record.observed_at)
    db.add(incident)
    db.flush()
    db.add(IncidentEvent(incident_id=incident.id, actor=SYSTEM_ACTOR, from_status=None, to_status='open',
                         action='created', note=None, at=record.observed_at))
    _attach(db, incident, finding, record, indicators)
    return incident


# ---------------------------------------------------------------- workflow

def transition_incident(db, incident_id: int, to_status: str, *, resolution: str | None = None,
                        note: str | None = None, actor: str = LOCAL_OPERATOR, at: datetime | None = None) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise LookupError('incident_not_found')
    from_status = incident.status
    if (from_status, to_status) not in ALLOWED_TRANSITIONS:
        raise ValueError('invalid_transition')
    at = _naive_utc(at) if at else _naive_utc(datetime.now(timezone.utc))
    action = 'status_change'
    if to_status == 'resolved':
        if resolution not in INCIDENT_RESOLUTIONS:
            raise ValueError('resolution_required')
        incident.resolution, incident.resolved_at = resolution, at
    elif resolution is not None:
        raise ValueError('resolution_only_when_resolving')
    if from_status == 'resolved':
        if not (note and note.strip()):
            raise ValueError('reopen_note_required')
        incident.resolution, incident.resolved_at, action = None, None, 'reopen'
    incident.status = to_status
    db.add(IncidentEvent(incident_id=incident.id, actor=actor, from_status=from_status, to_status=to_status,
                         action=action, note=note, at=at))
    db.flush()
    return incident
