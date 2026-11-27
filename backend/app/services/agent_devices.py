"""LAN agent pairing, batch ingestion and operator device management (design windows-agent-lan-v1 §4.1, §5, §7).

- Pairing codes and agent tokens are random, shown once, and stored only as SHA-256 digests.
- The endpoint `hmac:` device ref is wrapped to `srv:` with core v2's `wrap_ref` before anything is stored;
  the pairing response never echoes any device ref (core v2 §3.6 item 2).
- Batches pass the privacy gate (`agent_privacy.check_batch`) and then the unchanged `record_findings`, with
  `source = sensor, agent_devices:<device_id>:<batch_id>`; record_findings wraps device and account refs and
  writes `finding_devices` (attributed_by = agent). No `hmac:` ref is ever stored.
- Revocation keeps the device's Findings, which the operator API marks `from_revoked_device`; the purge of a
  revoked device's Findings is a separate, explicit, never-automatic operator action (owner decision Q3).
  The revoked row keeps its token digest so a later request with that token is answered `device_revoked`
  (design §4.1, F5); the token can never be used again and re-pairing replaces the digest.

Errors are fixed reason codes; logs carry reason codes and device ids only, never a token, code, ref or body.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, update
from sqlalchemy.exc import IntegrityError

from app.core.device_names import ENDPOINT_REF, RefError, ServerRefKeyError, load_server_key, wrap_ref
from app.core.findings import SourceRef
from app.core.settings import settings
from app.models import (AgentBatch, Device, DevicePairingToken, FindingDevice, FindingRecord, Incident)
from app.services import agent_privacy
from app.services.agent_schemas import (BATCH_SCHEMA, HEARTBEAT_SCHEMA, PAIR_SCHEMA, AgentRequestError)
from app.services.finding_expiry import AGENT_SENSOR_SIGHTINGS, SCAN_DERIVED_SIGHTINGS, expire_findings
from app.services.findings import ACTIVE_STATUSES, AGENT_SOURCE_PREFIX, record_findings

log = logging.getLogger(__name__)
PAIRING_TTL = timedelta(minutes=15)
SECRET_BYTES = 32
LABEL = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
REASON = re.compile(r'^[a-z0-9][a-z0-9_.:-]{0,99}$')
CERT_PIN = re.compile(r'^[0-9a-f]{64}$')
PAIR_ATTEMPTS_PER_MINUTE = 10
REF_ERRORS = {'ref_prefix_invalid': 'ref_prefix_invalid', 'device_ref_conflict': 'device_ref_conflict'}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_z(value: datetime | None) -> str | None:
    return value.replace(tzinfo=timezone.utc).isoformat() if value is not None else None


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def server_key() -> bytes:
    try:
        return load_server_key()
    except ServerRefKeyError:
        raise AgentRequestError(503, 'server_ref_key_missing') from None


def server_instance_id(key: bytes) -> str:
    """A stable, non-secret identifier of this server's ref key (never the key)."""
    return 'etis-' + hmac.new(key, b'server_instance\0', hashlib.sha256).hexdigest()[:16]


def agent_source_ref(device_id: int, batch_id: str) -> str:
    return f'{AGENT_SOURCE_PREFIX}{device_id}:{batch_id}'


class PairRateLimiter:
    """Per source IP: at most PAIR_ATTEMPTS_PER_MINUTE pairing attempts per 60 s, in memory only."""

    def __init__(self, limit: int = PAIR_ATTEMPTS_PER_MINUTE, window: float = 60.0):
        self.limit, self.window = limit, window
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = {}

    def allow(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.setdefault(ip or 'unknown', deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


pair_limiter = PairRateLimiter()


# ---------------------------------------------------------------- operator: invitations

def _pin(value: str) -> str | None:
    return value if CERT_PIN.match(value or '') else None


def create_invite(db, display_label: str | None) -> dict:
    if display_label is not None and not LABEL.match(display_label):
        raise AgentRequestError(400, 'invalid_input')
    code = secrets.token_urlsafe(SECRET_BYTES)
    now = utc_now()
    row = DevicePairingToken(code_hash=digest(code), display_label=display_label, created_at=now,
                             expires_at=now + PAIRING_TTL, used_at=None, failed_attempts=0, device_id=None)
    db.add(row)
    db.commit()
    log.info('agent_pairing_invite_created', extra={'invite_id': row.id})
    return {'invite_id': row.id, 'pairing_code': code, 'expires_at': iso_z(row.expires_at),
            'primary_cert_sha256': _pin(settings.agent_primary_cert_sha256),
            'next_cert_sha256': _pin(settings.agent_next_cert_sha256)}


# ---------------------------------------------------------------- agent: pairing and authentication

def pair(db, request, client_ip: str) -> dict:
    if not pair_limiter.allow(client_ip):
        raise AgentRequestError(429, 'rate_limited')
    if request.device_ref.startswith('srv:') or not ENDPOINT_REF.match(request.device_ref):
        raise AgentRequestError(400, 'invalid_input')
    key = server_key()                                   # fail closed before anything is read or stored
    now = utc_now()
    invite = db.query(DevicePairingToken).filter_by(code_hash=digest(request.pairing_code)).one_or_none()
    if invite is None or invite.used_at is not None:
        raise AgentRequestError(401, 'pairing_code_invalid')
    if invite.expires_at < now:
        raise AgentRequestError(401, 'pairing_code_expired')
    stored = wrap_ref(request.device_ref, 'device', key)
    claimed = db.execute(update(DevicePairingToken).where(DevicePairingToken.id == invite.id,
                                                          DevicePairingToken.used_at.is_(None))
                         .values(used_at=now)).rowcount
    if claimed != 1:
        db.rollback()
        raise AgentRequestError(401, 'pairing_code_invalid')
    token = secrets.token_urlsafe(SECRET_BYTES)
    device = db.query(Device).filter_by(device_ref=stored).one_or_none()
    repaired = device is not None
    if device is None:
        device = Device(device_ref=stored, display_label=invite.display_label, engine_versions={}, last_coverage={})
        db.add(device)
    device.token_hash = digest(token)
    device.agent_instance_id = request.agent_instance_id
    device.status = 'active'
    device.agent_version = request.agent_version
    device.notice_version_ack = request.notice_version_ack
    device.paired_at = now
    device.last_seen_at = now
    device.revoked_at = None
    device.revoked_reason = None
    db.flush()
    invite.device_id = device.id
    db.commit()
    log.info('agent_device_repaired' if repaired else 'agent_device_paired', extra={'device_id': device.id})
    return {'schema_version': PAIR_SCHEMA, 'device_id': device.id, 'agent_token': token,
            'server_instance_id': server_instance_id(key)}


def authenticate(db, authorization: str | None) -> Device:
    scheme, _, token = (authorization or '').partition(' ')
    if scheme != 'Bearer' or not token or len(token) > 200:
        raise AgentRequestError(401, 'token_invalid')
    device = db.query(Device).filter_by(token_hash=digest(token)).one_or_none()
    if device is None:
        raise AgentRequestError(401, 'token_invalid')
    if device.status != 'active':
        raise AgentRequestError(401, 'device_revoked')
    return device


# ---------------------------------------------------------------- agent: batches, heartbeat, unpair

def _seen(device: Device, request, now: datetime) -> None:
    device.last_seen_at = now
    device.agent_version = request.agent_version
    device.engine_versions = dict(request.engine_versions)
    device.last_coverage = request.coverage.model_dump(mode='json')


def ingest_batch(db, device: Device, request) -> dict:
    key = server_key()
    agent_privacy.check_batch(request.findings, device.device_ref, key)
    now = utc_now()
    received = {'schema_version': BATCH_SCHEMA, 'batch_id': request.batch_id, 'received_at': iso_z(now)}
    if db.query(AgentBatch.id).filter_by(device_id=device.id, batch_id=request.batch_id).first():
        _seen(device, request, now)
        db.commit()
        return {**received, 'duplicate_batch': True, 'accepted_findings': 0,
                'duplicate_findings': len(request.findings)}
    ids = [f.id for f in request.findings]
    known = {row.id for row in db.query(FindingRecord.id).filter(FindingRecord.id.in_(ids))} if ids else set()
    source = SourceRef(kind='sensor', ref=agent_source_ref(device.id, request.batch_id))
    new, duplicates = [], 0
    for finding in request.findings:
        if finding.id in known:
            duplicates += 1
            continue
        known.add(finding.id)
        new.append(finding.model_copy(update={'source': source}))
    try:
        record_findings(db, new)
        db.add(AgentBatch(batch_id=request.batch_id, device_id=device.id, sent_at=_naive(request.sent_at),
                          received_at=now, agent_version=request.agent_version,
                          engine_versions=dict(request.engine_versions),
                          coverage=request.coverage.model_dump(mode='json'), accepted_findings=len(new),
                          duplicate_findings=duplicates))
        _seen(device, request, now)
        db.commit()
    except RefError as exc:
        db.rollback()
        raise AgentRequestError(422, REF_ERRORS.get(str(exc), 'disallowed_evidence_field')) from None
    except IntegrityError:
        db.rollback()                                    # a concurrent retry of the same batch won the race
        return {**received, 'duplicate_batch': True, 'accepted_findings': 0, 'duplicate_findings': len(ids)}
    log.info('agent_batch_accepted', extra={'device_id': device.id, 'accepted': len(new)})
    return {**received, 'duplicate_batch': False, 'accepted_findings': len(new), 'duplicate_findings': duplicates}


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def heartbeat(db, device: Device, request) -> dict:
    now = utc_now()
    _seen(device, request, now)
    db.commit()
    return {'schema_version': HEARTBEAT_SCHEMA, 'received_at': iso_z(now)}


def _revoke(device: Device, reason: str) -> None:
    device.status = 'revoked'
    device.revoked_at = utc_now()
    device.revoked_reason = reason


def unpair(db, device: Device) -> dict:
    _revoke(device, 'user_uninstalled')
    db.commit()
    log.info('agent_device_unpaired', extra={'device_id': device.id})
    return {'status': 'revoked'}


# ---------------------------------------------------------------- operator: devices

def _device_or_404(db, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise AgentRequestError(404, 'not_found')
    return device


def _agent_prefix(device: Device) -> str:
    return f'{AGENT_SOURCE_PREFIX}{device.id}:'


def _device_findings(db, device: Device):
    return (db.query(FindingRecord).join(FindingDevice, FindingDevice.finding_id == FindingRecord.id)
            .filter(FindingDevice.device_ref == device.device_ref))


def _counts(db, device: Device) -> dict:
    rows = (_device_findings(db, device).with_entities(FindingRecord.severity, FindingRecord.domain,
                                                         func.count(FindingRecord.id))
            .group_by(FindingRecord.severity, FindingRecord.domain).all())
    by_severity, by_domain = {}, {}
    for severity, domain, count in rows:
        by_severity[severity] = by_severity.get(severity, 0) + count
        by_domain[domain] = by_domain.get(domain, 0) + count
    open_incidents = (_device_findings(db, device).join(Incident, Incident.id == FindingRecord.incident_id)
                      .filter(Incident.status.in_(ACTIVE_STATUSES))
                      .with_entities(func.count(func.distinct(Incident.id))).scalar() or 0)
    return {'findings_by_severity': by_severity, 'findings_by_domain': by_domain, 'open_incidents': open_incidents}


def device_summary(db, device: Device) -> dict:
    return {'id': device.id, 'device_ref': device.device_ref, 'display_label': device.display_label,
            'status': device.status, 'agent_version': device.agent_version,
            'engine_versions': device.engine_versions or {}, 'paired_at': iso_z(device.paired_at),
            'last_seen_at': iso_z(device.last_seen_at), 'revoked_at': iso_z(device.revoked_at),
            'revoked_reason': device.revoked_reason, 'last_coverage': device.last_coverage or {},
            'notice_version_ack': device.notice_version_ack, **_counts(db, device)}


def list_devices(db, status: str | None, limit: int, offset: int) -> dict:
    query = db.query(Device)
    if status is not None:
        if status not in ('active', 'revoked'):
            raise AgentRequestError(400, 'invalid_input')
        query = query.filter(Device.status == status)
    total = query.count()
    rows = query.order_by(Device.id).offset(offset).limit(limit).all()
    return {'total': total, 'limit': limit, 'offset': offset, 'items': [device_summary(db, d) for d in rows]}


def finding_item(record: FindingRecord, device: Device) -> dict:
    details = (record.evidence or {}).get('details') or {}
    from_agent = record.source_ref.startswith(_agent_prefix(device))
    account = details.get('account_ref')
    return {'id': record.id, 'engine': record.engine_name, 'domain': record.domain, 'kind': record.kind,
            'severity': record.severity, 'confidence': record.confidence, 'observed_at': iso_z(record.observed_at),
            'reasons': list((record.evidence or {}).get('reasons') or []),
            'account_ref': account if isinstance(account, str) and account.startswith(('srv:', 'sid:')) else None,
            'incident_id': record.incident_id, 'source': 'agent' if from_agent else 'import',
            'from_revoked_device': bool(from_agent and device.status == 'revoked')}


def device_detail(db, device_id: int, limit: int, offset: int) -> dict:
    device = _device_or_404(db, device_id)
    findings = _device_findings(db, device)
    total = findings.count()
    page = findings.order_by(FindingRecord.observed_at.desc(), FindingRecord.id).offset(offset).limit(limit).all()
    batches = (db.query(AgentBatch).filter_by(device_id=device.id).order_by(AgentBatch.received_at.desc())
               .limit(20).all())
    incident_ids = {r.incident_id for r in findings.filter(FindingRecord.incident_id.isnot(None))}
    incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).order_by(Incident.id).all() \
        if incident_ids else []
    return {
        **device_summary(db, device),
        'batches': [{'batch_id': b.batch_id, 'sent_at': iso_z(b.sent_at), 'received_at': iso_z(b.received_at),
                     'agent_version': b.agent_version, 'accepted_findings': b.accepted_findings,
                     'duplicate_findings': b.duplicate_findings} for b in batches],
        'findings': {'total': total, 'limit': limit, 'offset': offset,
                     'items': [finding_item(r, device) for r in page]},
        'incidents': [{'id': i.id, 'title': i.title, 'severity': i.severity, 'status': i.status} for i in incidents],
    }


def update_label(db, device_id: int, display_label: str) -> dict:
    if not LABEL.match(display_label):
        raise AgentRequestError(400, 'invalid_input')
    device = _device_or_404(db, device_id)
    device.display_label = display_label
    db.commit()
    return device_summary(db, device)


def revoke(db, device_id: int, reason: str | None) -> dict:
    if reason is not None and not REASON.match(reason):
        raise AgentRequestError(400, 'invalid_input')
    device = _device_or_404(db, device_id)
    if device.status != 'revoked':
        _revoke(device, reason or 'operator_revoked')
        db.commit()
        log.info('agent_device_revoked', extra={'device_id': device.id})
    return device_summary(db, device)


def purge_findings(db, device_id: int, since: datetime, reason: str) -> dict:
    """Explicit operator action on a revoked device only: Findings and batches received (or observed) at or
    after `since` are removed through the shared expiry; never called automatically."""
    if not REASON.match(reason):
        raise AgentRequestError(400, 'invalid_input')
    device = _device_or_404(db, device_id)
    if device.status != 'revoked':
        raise AgentRequestError(409, 'device_not_revoked')
    cutoff = _naive(since)
    batches = db.query(AgentBatch).filter(AgentBatch.device_id == device.id, AgentBatch.received_at >= cutoff).all()
    refs = [agent_source_ref(device.id, b.batch_id) for b in batches]
    from_device = FindingRecord.source_ref.startswith(_agent_prefix(device), autoescape=True)
    window = or_(FindingRecord.observed_at >= cutoff, FindingRecord.source_ref.in_(refs)) if refs \
        else FindingRecord.observed_at >= cutoff
    findings, indicators = expire_findings(db, finding_filter=from_device & window,
                                           derived=SCAN_DERIVED_SIGHTINGS + AGENT_SENSOR_SIGHTINGS)
    for batch in batches:
        db.delete(batch)
    db.commit()
    log.info('agent_device_findings_purged', extra={'device_id': device.id, 'findings': findings})
    return {'device_id': device.id, 'findings_purged': findings, 'indicators_removed': indicators,
            'batches_purged': len(batches), 'reason': reason}
