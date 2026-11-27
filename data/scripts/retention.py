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
from collections import Counter
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.settings import settings
from sqlalchemy import and_, not_, or_
from app.models import (ScanRequest, FindingRecord, FindingIndicator, FindingAttack, FindingDevice, Indicator, IndicatorSighting,
                        IncidentIndicator, IncidentEvent, MalwareScan, NetworkWindowsImport)

MALWARE_ENGINE = 'malware.files'
NETWORK_WINDOWS_ENGINE = 'network.windows'
# (source kind, source name) of sightings that exist only because of a scan; None matches any name.
SCAN_DERIVED_SIGHTINGS = (('scan', None), ('import', MALWARE_ENGINE), ('import', NETWORK_WINDOWS_ENGINE))


def _scan_derived():
    return or_(*[IndicatorSighting.source_kind == kind if name is None else
                 and_(IndicatorSighting.source_kind == kind, IndicatorSighting.source_name == name)
                 for kind, name in SCAN_DERIVED_SIGHTINGS])


def _expire_findings(db, scan_ids=None, finding_filter=None):
    if finding_filter is None:
        finding_filter = FindingRecord.scan_request_id.in_(scan_ids) if scan_ids else None
    findings = db.query(FindingRecord.id, FindingRecord.incident_id).filter(finding_filter).all()         if finding_filter is not None else []
    finding_ids = [row.id for row in findings]
    if not finding_ids:
        return 0, 0
    candidate_ids = {row.indicator_id for row in db.query(FindingIndicator.indicator_id).filter(
        FindingIndicator.finding_id.in_(finding_ids))}
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for incident_id, count in Counter(row.incident_id for row in findings if row.incident_id).items():
        db.add(IncidentEvent(incident_id=incident_id, actor='etis', from_status=None, to_status=None,
                             action='findings_expired', note=str(count), at=now))
    db.query(FindingAttack).filter(FindingAttack.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(FindingDevice).filter(FindingDevice.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(FindingIndicator).filter(FindingIndicator.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(FindingRecord).filter(FindingRecord.id.in_(finding_ids)).delete(synchronize_session=False)
    db.flush()
    orphans = []
    for indicator in db.query(Indicator).filter(Indicator.id.in_(candidate_ids)).all() if candidate_ids else []:
        still_used = db.query(FindingIndicator).filter_by(indicator_id=indicator.id).first()
        other_source = db.query(IndicatorSighting).filter(IndicatorSighting.indicator_id == indicator.id,
                                                          not_(_scan_derived())).first()
        if indicator.value is None and not still_used and not other_source:
            orphans.append(indicator.id)
    if orphans:
        db.query(IncidentIndicator).filter(IncidentIndicator.indicator_id.in_(orphans)).delete(synchronize_session=False)
        db.query(IndicatorSighting).filter(IndicatorSighting.indicator_id.in_(orphans)).delete(synchronize_session=False)
        db.query(Indicator).filter(Indicator.id.in_(orphans)).delete(synchronize_session=False)
    return len(finding_ids), len(orphans)


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
