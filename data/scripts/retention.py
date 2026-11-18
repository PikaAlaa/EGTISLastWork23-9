"""Delete scan records older than ETIS_RETENTION_DAYS, with their scan-derived core v1 data.

Design core-v1 §7.2: scan-derived findings are deleted with their scans. Deletion
is explicit rather than relying on ON DELETE CASCADE, because SQLite does not
enforce foreign keys here. Hash-only, scan-only indicators no longer referenced by
any finding or non-scan sighting are deleted too. Incidents and their events
remain; each incident gets a `findings_expired` event whose note is the number of
its findings removed, so the console can show them as expired by retention.
"""
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.settings import settings
from app.models import (ScanRequest, FindingRecord, FindingIndicator, FindingAttack, Indicator, IndicatorSighting,
                        IncidentIndicator, IncidentEvent)


def _expire_findings(db, scan_ids):
    findings = db.query(FindingRecord.id, FindingRecord.incident_id).filter(
        FindingRecord.scan_request_id.in_(scan_ids)).all() if scan_ids else []
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
    db.query(FindingIndicator).filter(FindingIndicator.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(FindingRecord).filter(FindingRecord.id.in_(finding_ids)).delete(synchronize_session=False)
    db.flush()
    orphans = []
    for indicator in db.query(Indicator).filter(Indicator.id.in_(candidate_ids)).all() if candidate_ids else []:
        still_used = db.query(FindingIndicator).filter_by(indicator_id=indicator.id).first()
        other_source = db.query(IndicatorSighting).filter(IndicatorSighting.indicator_id == indicator.id,
                                                          IndicatorSighting.source_kind != 'scan').first()
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
if __name__=='__main__':
    with SessionLocal() as db:print({'deleted':delete_expired(db,details=True)})
