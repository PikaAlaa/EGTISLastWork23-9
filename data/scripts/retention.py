"""Delete scan records older than ETIS_RETENTION_DAYS, with their scan-derived core v1 data.

Design core-v1 §7.2: scan-derived findings are deleted with their scans. Deletion
is explicit rather than relying on ON DELETE CASCADE, because SQLite does not
enforce foreign keys here. Hash-only, scan-only indicators no longer referenced by
any finding or non-scan sighting are deleted too. Incidents and their events
remain; each incident gets a `findings_expired` event whose note is the number of
its findings removed, so the console can show them as expired by retention.

Malware engine (design malware-engine-v1 §7; step 14): malware_scans rows older than
ETIS_MALWARE_RETENTION_DAYS are deleted with their Findings (source ref
`malware_scans:<id>`), through the same clean-up. The malware engine's own sightings
(source kind `import`, source `malware.files`) count as scan-derived, so a hash seen
only by expired malware scans is removed; a hash also seen by another source (for
example a host `executed_file` Finding or a feed) is kept.

network.windows (design network-windows-v1 §7; step 12): network_windows_imports rows older than
ETIS_NETWORK_RETENTION_DAYS are deleted with their Findings (source ref `network_windows_imports:<id>`),
through the same clean-up and `findings_expired` events. Its own sightings (source kind `import`,
source `network.windows`) count as import-derived, so a destination hash seen only by expired imports
is removed; one also seen by a phishing Finding or a feed is kept (feed rows carry a plaintext value
and are never removed here).

LAN agent (design windows-agent-lan-v1 §7.3, owner decision Q2): agent-submitted `sensor` Findings (source ref
`agent_devices:<id>:<batch>`) expire under the existing per-engine settings ETIS_HOST_RETENTION_DAYS,
ETIS_MALWARE_RETENTION_DAYS and ETIS_NETWORK_RETENTION_DAYS (no agent setting). Sensor sightings count as
derived, so a hash-only indicator seen only by expired agent Findings is removed. Batches with no Finding left,
expired pairing invitations and revoked devices with nothing left are removed after the longest window.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.settings import settings
from sqlalchemy import and_
from app.models import (AgentBatch, Device, DevicePairingToken, ScanRequest, FindingRecord, MalwareScan,
                        NetworkWindowsImport)
# The shared expiry (moved to app/services/finding_expiry.py so the device purge can reuse it).
from app.services.finding_expiry import (HOST_ENGINE, MALWARE_ENGINE, NETWORK_WINDOWS_ENGINE, SCAN_DERIVED_SIGHTINGS,
                                         expire_findings as _expire_findings)
from app.services.findings import AGENT_SOURCE_PREFIX


def delete_expired(db,days=None,details=False):
    cutoff=datetime.now()-timedelta(days=settings.retention_days if days is None else days)
    rows=db.query(ScanRequest).filter(ScanRequest.submitted_at<cutoff).all()
    findings,indicators=_expire_findings(db,[row.id for row in rows])
    for row in rows:db.delete(row)
    db.commit()
    if details:return {'scans':len(rows),'findings':findings,'indicators':indicators}
    return len(rows)


def delete_expired_malware(db, days=None):
    """Delete malware scan records started before the cutoff, with their Findings and orphan indicators."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=settings.malware_retention_days if days is None else days)
    rows = db.query(MalwareScan).filter(MalwareScan.started_at < cutoff).all()
    refs = [f'malware_scans:{row.id}' for row in rows]
    findings, indicators = _expire_findings(db, finding_filter=and_(
        FindingRecord.engine_name == MALWARE_ENGINE, FindingRecord.source_ref.in_(refs))) if refs else (0, 0)
    for row in rows:
        db.delete(row)
    db.commit()
    return {'malware_scans': len(rows), 'findings': findings, 'indicators': indicators}


def delete_expired_network_windows(db, days=None):
    """Delete network.windows import records started before the cutoff, with their Findings and orphan indicators."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=settings.network_retention_days if days is None else days)
    rows = db.query(NetworkWindowsImport).filter(NetworkWindowsImport.started_at < cutoff).all()
    refs = [f'network_windows_imports:{row.id}' for row in rows]
    findings, indicators = _expire_findings(db, finding_filter=and_(
        FindingRecord.engine_name == NETWORK_WINDOWS_ENGINE, FindingRecord.source_ref.in_(refs))) if refs else (0, 0)
    for row in rows:
        db.delete(row)
    db.commit()
    return {'network_windows_imports': len(rows), 'findings': findings, 'indicators': indicators}


def delete_expired_agent_findings(db, host_days=None, malware_days=None, network_days=None, now=None):
    """Agent-submitted `sensor` Findings (windows-agent-lan-v1 §7.3, owner decision Q2): each engine's Findings
    expire under that engine's existing setting (ETIS_HOST_RETENTION_DAYS, ETIS_MALWARE_RETENTION_DAYS,
    ETIS_NETWORK_RETENTION_DAYS; no agent setting). Then batches with no Finding left, expired pairing
    invitations, and revoked devices with nothing left, once older than the longest of the three windows."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    days = {HOST_ENGINE: settings.host_retention_days if host_days is None else host_days,
            MALWARE_ENGINE: settings.malware_retention_days if malware_days is None else malware_days,
            NETWORK_WINDOWS_ENGINE: settings.network_retention_days if network_days is None else network_days}
    out = {'findings': 0, 'indicators': 0}
    for engine, keep in days.items():
        found, orphans = _expire_findings(db, finding_filter=and_(
            FindingRecord.source_kind == 'sensor', FindingRecord.engine_name == engine,
            FindingRecord.source_ref.startswith(AGENT_SOURCE_PREFIX, autoescape=True),
            FindingRecord.observed_at < now - timedelta(days=keep)))
        out['findings'] += found
        out['indicators'] += orphans
        out[engine] = found
    oldest = now - timedelta(days=max(days.values()))
    remaining = {ref for (ref,) in db.query(FindingRecord.source_ref).filter(
        FindingRecord.source_ref.startswith(AGENT_SOURCE_PREFIX, autoescape=True)).distinct()}
    batches = [b for b in db.query(AgentBatch).filter(AgentBatch.received_at < oldest)
               if f'{AGENT_SOURCE_PREFIX}{b.device_id}:{b.batch_id}' not in remaining]
    for batch in batches:
        db.delete(batch)
    db.flush()
    invites = db.query(DevicePairingToken).filter(DevicePairingToken.expires_at < now).delete(synchronize_session=False)
    devices = 0
    for device in db.query(Device).filter(Device.status == 'revoked', Device.revoked_at < oldest).all():
        prefix = f'{AGENT_SOURCE_PREFIX}{device.id}:'
        if db.query(AgentBatch.id).filter_by(device_id=device.id).first() or any(r.startswith(prefix) for r in remaining):
            continue
        db.query(DevicePairingToken).filter_by(device_id=device.id).delete(synchronize_session=False)
        db.delete(device)
        devices += 1
    db.commit()
    return {**out, 'agent_batches': len(batches), 'pairing_invites': invites, 'devices': devices}


if __name__=='__main__':
    with SessionLocal() as db:print({'deleted':delete_expired(db,details=True)})
    with SessionLocal() as db:print({'malware_deleted':delete_expired_malware(db)})
    with SessionLocal() as db:print({'network_windows_deleted':delete_expired_network_windows(db)})
    with SessionLocal() as db:print({'agent_deleted':delete_expired_agent_findings(db)})
