"""Device risk API, `device-risk-v1` (design core-v2 §3.5). Read-only.

Devices are identified only by their stored `srv:<32 hex>` ref (finding_devices); an endpoint
`hmac:` ref or any other form is rejected with `invalid_input` and never echoed. The score is
computed when read and never stored. Once the agent's `010_agent_devices` lands, the detail
joins `devices.status` and marks rows of a revoked device; until then `device_status` is null.
"""
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.models import FindingDevice, FindingRecord, Incident
from app.routers.soc_common import error, iso
from app.services.device_risk import VERSION, RiskInput, device_risk, engine_windows
from app.services.recommended_actions import CatalogueError, recommended_actions

router = APIRouter(tags=['device-risk'], dependencies=[Depends(verify_api_key)])
STORED_REF_PATTERN = r'^srv:[0-9a-f]{32}$'
BAND_ORDER = {'high': 3, 'elevated': 2, 'low': 1, 'none': 0}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _rows(db: Session, device_ref: str | None = None):
    query = (db.query(FindingDevice.device_ref, FindingRecord, Incident.resolution)
             .join(FindingRecord, FindingRecord.id == FindingDevice.finding_id)
             .outerjoin(Incident, Incident.id == FindingRecord.incident_id))
    if device_ref is not None:
        query = query.filter(FindingDevice.device_ref == device_ref)
    grouped: dict[str, list] = defaultdict(list)
    for ref, record, resolution in query:
        grouped[ref].append((record, resolution))
    return grouped


def _inputs(pairs) -> list[RiskInput]:
    return [RiskInput(finding_id=r.id, engine_name=r.engine_name, domain=r.domain, kind=r.kind, severity=r.severity,
                      confidence=r.confidence, observed_at=r.observed_at, incident_id=r.incident_id,
                      resolution=resolution) for r, resolution in pairs]


@router.get('/device-risk')
def list_device_risk(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                     db: Session = Depends(get_db_session)):
    now = _now()
    devices = []
    for ref, pairs in _rows(db).items():
        inputs = _inputs(pairs)
        risk = device_risk(inputs, now, windows=engine_windows({i.engine_name for i in inputs}))
        devices.append({'device_ref': ref, 'band': risk['band'], 'points': risk['points'],
                        'counted_findings': len(risk['counted']),
                        'engines': sorted({i.engine_name for i in inputs}),
                        'last_finding_at': iso(max(i.observed_at for i in inputs)), 'device_status': None})
    devices.sort(key=lambda d: (-BAND_ORDER[d['band']], -d['points'], d['device_ref']))
    return {'version': VERSION, 'computed_at': iso(now), 'total': len(devices),
            'results': devices[offset:offset + limit]}


@router.get('/device-risk/detail')
def device_risk_detail(device_ref: str = Query(..., pattern=STORED_REF_PATTERN),
                       db: Session = Depends(get_db_session)):
    pairs = _rows(db, device_ref).get(device_ref)
    if not pairs:
        return error(404, 'not_found')
    now = _now()
    inputs = _inputs(pairs)
    risk = device_risk(inputs, now, windows=engine_windows({i.engine_name for i in inputs}))
    records = {r.id: r for r, _ in pairs}
    for row in risk['counted']:
        try:
            actions = recommended_actions(records[row['finding_id']])
        except CatalogueError:
            actions = []
        row['recommended_action'] = actions[0] if actions else None
        row['from_revoked_device'] = None
    return {'device_ref': device_ref, 'computed_at': iso(now), 'device_status': None, **risk}
