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
from app.services.attack import AttackValidator
from app.core.device_names import RefError, server_key_or_none, wrap_refs
from app.models import (BrandDomain, Campaign, CorrelationStoplist, FindingAttack, FindingDevice, FindingIndicator,
                        FindingRecord, Incident, IncidentEvent, IncidentIndicator, IncidentLink, Indicator,
                        IndicatorSighting)
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


AGENT_SOURCE_PREFIX = 'agent_devices:'


def _wrap_all(findings: list[Finding]) -> list[tuple[Finding, str | None]]:
    """Design core-v2 §3.2: replace every endpoint `hmac:` device/account ref with its stored
    `srv:` form before anything is written; refuse the whole call on a bad ref."""
    ref_fields = {'device_ref', 'host_ref', 'account_ref'}
    if not any(ref_fields & set(f.evidence.details) for f in findings):
        return [(f, None) for f in findings]
    key = server_key_or_none()
    if key is None:
        # Fail safe: refs are dropped, never stored as hmac:. Logged once per call, without values.
        logger.warning('server_ref_key_missing')
    wrapped = []
    for finding in findings:
        try:
            wrapped.append(wrap_refs(finding, key))
        except RefError as exc:
            logger.warning('finding_ref_rejected', extra={'reason': str(exc)})
            raise
    return wrapped


def record_findings(db, findings: list[Finding], scan_request_id: int | None = None) -> list[FindingRecord]:
    exclusions = _exclusions(db)
    validator = AttackValidator(db)
    records = []
    for finding, stored_device in _wrap_all(list(findings)):
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
        if stored_device is not None:
            attributed = 'agent' if finding.source.ref.startswith(AGENT_SOURCE_PREFIX) else 'engine_details'
            db.add(FindingDevice(finding_id=record.id, device_ref=stored_device, attributed_by=attributed))
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
            if not validator.accept(technique.technique_id, technique.matrix, technique.attack_version):
                continue
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


def add_incident_note(db, incident_id: int, note: str, *, actor: str = LOCAL_OPERATOR) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise LookupError('incident_not_found')
    if not (note and note.strip()):
        raise ValueError('note_required')
    db.add(IncidentEvent(incident_id=incident.id, actor=actor, from_status=incident.status,
                         to_status=incident.status, action='note', note=note,
                         at=_naive_utc(datetime.now(timezone.utc))))
    db.flush()
    return incident


def merge_incidents(db, source_id: int, target_id: int, *, note: str | None = None,
                    actor: str = LOCAL_OPERATOR) -> Incident:
    """Analyst merge (§3.2 step 4): findings and indicators move to the target; the source is
    resolved as a duplicate and linked `merged_into`. Never automatic."""
    if source_id == target_id:
        raise ValueError('cannot_merge_into_itself')
    source, target = db.get(Incident, source_id), db.get(Incident, target_id)
    if source is None or target is None:
        raise LookupError('incident_not_found')
    if source.status == 'resolved' or target.status == 'resolved':
        raise ValueError('merge_requires_active_incidents')
    at = _naive_utc(datetime.now(timezone.utc))
    db.query(FindingRecord).filter_by(incident_id=source.id).update({'incident_id': target.id},
                                                                      synchronize_session=False)
    linked = {row.indicator_id for row in db.query(IncidentIndicator).filter_by(incident_id=target.id)}
    for row in db.query(IncidentIndicator).filter_by(incident_id=source.id).all():
        if row.indicator_id not in linked:
            db.add(IncidentIndicator(incident_id=target.id, indicator_id=row.indicator_id))
    if severity_rank(source.severity) > severity_rank(target.severity):
        target.severity = source.severity
    target.last_activity_at = max(target.last_activity_at, source.last_activity_at)
    target.opened_at = min(target.opened_at, source.opened_at)
    db.add(IncidentLink(incident_id=source.id, related_incident_id=target.id, relation='merged_into'))
    previous = source.status
    source.status, source.resolution, source.resolved_at = 'resolved', 'duplicate', at
    db.add(IncidentEvent(incident_id=source.id, actor=actor, from_status=previous, to_status='resolved',
                         action='merged_into', note=note, at=at))
    db.add(IncidentEvent(incident_id=target.id, actor=actor, from_status=target.status, to_status=target.status,
                         action='merged_from', note=note, at=at))
    db.flush()
    return target


def create_campaign(db, name: str, description: str | None = None) -> Campaign:
    if not (name and name.strip()):
        raise ValueError('name_required')
    campaign = Campaign(name=name.strip(), description=description, status='active')
    db.add(campaign)
    db.flush()
    return campaign


def assign_campaign(db, campaign_id: int, incident_id: int, *, actor: str = LOCAL_OPERATOR) -> Incident:
    campaign, incident = db.get(Campaign, campaign_id), db.get(Incident, incident_id)
    if campaign is None or incident is None:
        raise LookupError('not_found')
    incident.campaign_id = campaign.id
    db.add(IncidentEvent(incident_id=incident.id, actor=actor, from_status=incident.status,
                         to_status=incident.status, action='campaign_assigned', note=str(campaign.id),
                         at=_naive_utc(datetime.now(timezone.utc))))
    db.flush()
    return incident


def incident_brands(db, incident_ids: list[int]) -> dict[int, list[str]]:
    brands: dict[int, set[str]] = {}
    if not incident_ids:
        return {}
    for incident_id, evidence in db.query(FindingRecord.incident_id, FindingRecord.evidence).filter(
            FindingRecord.incident_id.in_(incident_ids)):
        for brand in (evidence or {}).get('details', {}).get('matched_brands') or []:
            brands.setdefault(incident_id, set()).add(str(brand))
    return {key: sorted(value) for key, value in brands.items()}


def campaign_suggestions(db, limit: int = 500) -> list[dict]:
    """§3.3: suggest incident pairs that share a phone/email indicator, or a matched brand plus
    any pivotable indicator (regardless of the correlation window). Never auto-assigns."""
    incidents = db.query(Incident).order_by(Incident.last_activity_at.desc()).limit(limit).all()
    ids = [i.id for i in incidents]
    if len(ids) < 2:
        return []
    by_id = {i.id: i for i in incidents}
    brands = incident_brands(db, ids)
    exclusions = _exclusions(db)
    members: dict[int, set[int]] = {}
    indicators = {}
    for row, indicator in db.query(IncidentIndicator, Indicator).join(
            Indicator, Indicator.id == IncidentIndicator.indicator_id).filter(IncidentIndicator.incident_id.in_(ids)):
        members.setdefault(row.incident_id, set()).add(indicator.id)
        indicators[indicator.id] = indicator
    suggestions, seen = [], set()
    for a in ids:
        for b in ids:
            if a >= b or (a, b) in seen:
                continue
            ia, ib = by_id[a], by_id[b]
            if ia.campaign_id and ia.campaign_id == ib.campaign_id:
                continue
            shared = [indicators[i] for i in members.get(a, set()) & members.get(b, set())]
            exact, domains = pivot_keys(shared, exclusions)
            pivotable = [i for i in shared if i.id in exact or (i.type == 'domain' and
                         (i.registered_domain_hash or i.value_hash) in domains)]
            common_brands = sorted(set(brands.get(a, [])) & set(brands.get(b, [])))
            reason = None
            if any(i.type in ('phone', 'email') for i in pivotable):
                reason = 'shared_contact'
            elif common_brands and pivotable:
                reason = 'shared_brand_and_indicator'
            if reason:
                seen.add((a, b))
                suggestions.append({'incident_ids': [a, b], 'reason': reason, 'brands': common_brands,
                                    'shared_indicator_types': sorted({i.type for i in pivotable})})
    return suggestions
