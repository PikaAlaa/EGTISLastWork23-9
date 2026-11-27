"""Expire Findings with their scan-derived core data (design core-v1 §7.2), shared by retention and the
operator purge of a revoked agent device (windows-agent-lan-v1 §5.3, §7.3).

Moved unchanged from data/scripts/retention.py so the API can reuse it; retention.py imports it under its old
names. Deletion is explicit rather than relying on ON DELETE CASCADE, because SQLite does not enforce foreign
keys here. Hash-only indicators no longer referenced by any finding or by a sighting outside `derived` are
deleted. Incidents and their events remain; each incident gets a `findings_expired` event whose note is the
number of its findings removed.
"""
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import and_, not_, or_

from app.models import (FindingAttack, FindingDevice, FindingIndicator, FindingRecord, IncidentEvent,
                        IncidentIndicator, Indicator, IndicatorSighting)

MALWARE_ENGINE = 'malware.files'
NETWORK_WINDOWS_ENGINE = 'network.windows'
HOST_ENGINE = 'host.windows'
# Sightings of agent-submitted Findings (source kind `sensor`, design windows-agent-lan-v1 §7.3).
AGENT_SENSOR_SIGHTINGS = (('sensor', HOST_ENGINE), ('sensor', MALWARE_ENGINE), ('sensor', NETWORK_WINDOWS_ENGINE))
# (source kind, source name) of sightings that exist only because of a scan, an import or an agent batch;
# None matches any name. A hash-only indicator seen only through these is removed with its last Finding.
SCAN_DERIVED_SIGHTINGS = (('scan', None), ('import', MALWARE_ENGINE), ('import', NETWORK_WINDOWS_ENGINE))     + AGENT_SENSOR_SIGHTINGS


def derived_condition(derived=SCAN_DERIVED_SIGHTINGS):
    return or_(*[IndicatorSighting.source_kind == kind if name is None else
                 and_(IndicatorSighting.source_kind == kind, IndicatorSighting.source_name == name)
                 for kind, name in derived])


def expire_findings(db, scan_ids=None, finding_filter=None, derived=SCAN_DERIVED_SIGHTINGS):
    """Delete the matching Findings; return (findings deleted, orphan indicators deleted). Flushes, never commits."""
    if finding_filter is None:
        finding_filter = FindingRecord.scan_request_id.in_(scan_ids) if scan_ids else None
    findings = db.query(FindingRecord.id, FindingRecord.incident_id).filter(finding_filter).all() \
        if finding_filter is not None else []
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
                                                          not_(derived_condition(derived))).first()
        if indicator.value is None and not still_used and not other_source:
            orphans.append(indicator.id)
    if orphans:
        db.query(IncidentIndicator).filter(IncidentIndicator.indicator_id.in_(orphans)).delete(synchronize_session=False)
        db.query(IndicatorSighting).filter(IndicatorSighting.indicator_id.in_(orphans)).delete(synchronize_session=False)
        db.query(Indicator).filter(Indicator.id.in_(orphans)).delete(synchronize_session=False)
    return len(finding_ids), len(orphans)
