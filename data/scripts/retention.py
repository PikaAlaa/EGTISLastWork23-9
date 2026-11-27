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
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.settings import settings
from sqlalchemy import and_
from app.models import ScanRequest, FindingRecord, MalwareScan, NetworkWindowsImport
# The shared expiry (moved to app/services/finding_expiry.py so the device purge can reuse it).
from app.services.finding_expiry import (MALWARE_ENGINE, NETWORK_WINDOWS_ENGINE, SCAN_DERIVED_SIGHTINGS,
                                         expire_findings as _expire_findings)


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


if __name__=='__main__':
    with SessionLocal() as db:print({'deleted':delete_expired(db,details=True)})
    with SessionLocal() as db:print({'malware_deleted':delete_expired_malware(db)})
    with SessionLocal() as db:print({'network_windows_deleted':delete_expired_network_windows(db)})
