"""Incidents and campaigns API for the SOC console (design core-v1 §3, §6).

Analyst actions write incident_events with actor `local-operator`. Nothing here is
read by the /analyze decision policy. Indicator values are returned for inert
display; URL values are never listed in bulk (§2.3) — only exact indicator lookup
returns a URL.
"""
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.models import (AttackTechnique, Campaign, FindingAttack, FindingIndicator, FindingRecord, Incident,
                        IncidentEvent, IncidentIndicator, IncidentLink, Indicator, IndicatorSighting)
from app.routers.soc_common import StrictBody, day_end, day_start, error, iso
from app.services import findings as service
from app.core.findings import SEVERITY_ORDER
from app.services.recommended_actions import CatalogueError, recommended_actions

router = APIRouter(tags=['incidents'], dependencies=[Depends(verify_api_key)])
Status = Literal['open', 'investigating', 'resolved']
Severity = Literal['info', 'low', 'medium', 'high', 'critical']
Domain = Literal['phishing', 'malware', 'network', 'host']
Resolution = Literal['true_positive', 'false_positive', 'benign', 'duplicate']


class IncidentUpdate(StrictBody):
    status: Status | None = None
    resolution: Resolution | None = None
    note: str | None = Field(default=None, max_length=2000)


class MergeRequest(StrictBody):
    into: int
    note: str | None = Field(default=None, max_length=2000)


class CampaignCreate(StrictBody):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)


class CampaignAssign(StrictBody):
    incident_id: int


def incident_summary(incident: Incident, finding_count: int, brands: list[str]) -> dict:
    return {'id': incident.id, 'title': incident.title, 'domain': incident.domain, 'severity': incident.severity,
            'status': incident.status, 'resolution': incident.resolution, 'campaign_id': incident.campaign_id,
            'reopened_from': incident.reopened_from, 'opened_at': iso(incident.opened_at),
            'last_activity_at': iso(incident.last_activity_at), 'resolved_at': iso(incident.resolved_at),
            'finding_count': finding_count, 'brands': brands}


def indicator_brief(indicator: Indicator, sources: list[str], roles: list[str]) -> dict:
    return {'id': indicator.id, 'type': indicator.type, 'value_hash': indicator.value_hash,
            # Bulk lists never carry URL values (§2.3); exact lookup does.
            'value': None if indicator.type == 'url' else indicator.value,
            'registered_domain': indicator.registered_domain, 'hash_algo': indicator.hash_algo,
            'sources': sources, 'roles': roles}


def _finding_actions(findings) -> dict[str, list]:
    """Recommended actions per finding (design core-v2 §2.3); read-only text, never executed."""
    try:
        return {f.id: recommended_actions(f) for f in findings}
    except CatalogueError:
        return {}


def _incident_actions(findings, actions: dict[str, list]) -> list:
    """Primary actions of the highest-severity findings, de-duplicated (§2.4)."""
    ranked = [f for f in findings if actions.get(f.id)]
    if not ranked:
        return []
    top = max((SEVERITY_ORDER.index(f.severity) for f in ranked if f.severity in SEVERITY_ORDER), default=-1)
    out, seen = [], set()
    for f in ranked:
        if f.severity in SEVERITY_ORDER and SEVERITY_ORDER.index(f.severity) == top:
            primary = actions[f.id][0]
            if (primary['en'], primary['ar']) not in seen:
                seen.add((primary['en'], primary['ar']))
                out.append(primary)
    return out


def incident_detail(db: Session, incident: Incident) -> dict:
    findings = db.query(FindingRecord).filter_by(incident_id=incident.id).order_by(FindingRecord.observed_at).all()
    finding_ids = [f.id for f in findings]
    attack_rows = db.query(FindingAttack).filter(FindingAttack.finding_id.in_(finding_ids)).all() if finding_ids else []
    names = {(t.technique_id, t.matrix, t.attack_version): t.name for t in db.query(AttackTechnique).filter(
        AttackTechnique.technique_id.in_({a.technique_id for a in attack_rows}))} if attack_rows else {}
    techniques: dict[tuple, dict] = {}
    per_finding: dict[str, list] = {}
    for row in attack_rows:
        key = (row.technique_id, row.matrix, row.attack_version)
        item = techniques.setdefault(key, {'technique_id': row.technique_id, 'matrix': row.matrix,
                                           'attack_version': row.attack_version, 'name': names.get(key), 'count': 0})
        item['count'] += 1
        per_finding.setdefault(row.finding_id, []).append({'technique_id': row.technique_id, 'matrix': row.matrix})
    indicator_rows = db.query(Indicator).join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id).filter(
        IncidentIndicator.incident_id == incident.id).order_by(Indicator.type, Indicator.id).all()
    ids = [i.id for i in indicator_rows]
    sources: dict[int, set] = {}
    for sighting in db.query(IndicatorSighting).filter(IndicatorSighting.indicator_id.in_(ids)) if ids else []:
        sources.setdefault(sighting.indicator_id, set()).add(sighting.source_kind)
    roles: dict[int, set] = {}
    for link in db.query(FindingIndicator).filter(FindingIndicator.finding_id.in_(finding_ids)) if finding_ids else []:
        roles.setdefault(link.indicator_id, set()).add(link.role)
    events = db.query(IncidentEvent).filter_by(incident_id=incident.id).order_by(IncidentEvent.at, IncidentEvent.id).all()
    expired = sum(int(e.note) for e in events if e.action == 'findings_expired' and (e.note or '').isdigit())
    links = db.query(IncidentLink).filter((IncidentLink.incident_id == incident.id) |
                                          (IncidentLink.related_incident_id == incident.id)).all()
    campaign = db.get(Campaign, incident.campaign_id) if incident.campaign_id else None
    brands = service.incident_brands(db, [incident.id]).get(incident.id, [])
    actions = _finding_actions(findings)
    return {
        **incident_summary(incident, len(findings), brands),
        'campaign': {'id': campaign.id, 'name': campaign.name} if campaign else None,
        'expired_findings': expired,
        'findings': [{'id': f.id, 'kind': f.kind, 'severity': f.severity, 'confidence': f.confidence,
                      'engine_name': f.engine_name, 'engine_version': f.engine_version,
                      'observed_at': iso(f.observed_at), 'source_kind': f.source_kind,
                      'reasons': (f.evidence or {}).get('reasons', []),
                      'verdict': ((f.evidence or {}).get('details') or {}).get('verdict'),
                      'attack': per_finding.get(f.id, []),
                      'recommended_actions': actions.get(f.id, [])} for f in findings],
        'recommended_actions': _incident_actions(findings, actions),
        'indicators': [indicator_brief(i, sorted(sources.get(i.id, [])), sorted(roles.get(i.id, [])))
                       for i in indicator_rows],
        'techniques': sorted(techniques.values(), key=lambda t: (t['matrix'], t['technique_id'])),
        'events': [{'id': e.id, 'actor': e.actor, 'action': e.action, 'from_status': e.from_status,
                    'to_status': e.to_status, 'note': e.note, 'at': iso(e.at)} for e in events],
        'links': [{'incident_id': l.incident_id, 'related_incident_id': l.related_incident_id,
                   'relation': l.relation} for l in links],
    }


@router.get('/incidents')
def list_incidents(status: Status | None = None, severity: Severity | None = None, domain: Domain | None = None,
                   brand: str | None = Query(default=None, max_length=255), since: date | None = None,
                   until: date | None = None, limit: int = Query(default=50, ge=1, le=200),
                   offset: int = Query(default=0, ge=0), db: Session = Depends(get_db_session)):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if domain:
        query = query.filter(Incident.domain == domain)
    if since:
        query = query.filter(Incident.last_activity_at >= day_start(since))
    if until:
        query = query.filter(Incident.last_activity_at <= day_end(until))
    incidents = query.order_by(Incident.last_activity_at.desc(), Incident.id.desc()).all()
    brands = service.incident_brands(db, [i.id for i in incidents])
    if brand:
        wanted = brand.strip().casefold()
        incidents = [i for i in incidents if any(wanted in b.casefold() for b in brands.get(i.id, []))]
    page = incidents[offset:offset + limit]
    counts = dict(db.query(FindingRecord.incident_id, func.count(FindingRecord.id)).filter(
        FindingRecord.incident_id.in_([i.id for i in page])).group_by(FindingRecord.incident_id)) if page else {}
    return {'total_matching': len(incidents), 'limit': limit, 'offset': offset,
            'results': [incident_summary(i, counts.get(i.id, 0), brands.get(i.id, [])) for i in page]}


@router.get('/incidents/{incident_id}')
def get_incident(incident_id: int, db: Session = Depends(get_db_session)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        return error(404, 'not_found')
    return incident_detail(db, incident)


@router.patch('/incidents/{incident_id}')
def update_incident(incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db_session)):
    try:
        if payload.status is not None:
            service.transition_incident(db, incident_id, payload.status, resolution=payload.resolution,
                                        note=payload.note)
        elif payload.note is not None and payload.resolution is None:
            service.add_incident_note(db, incident_id, payload.note)
        else:
            return error(400, 'invalid_input')
        db.commit()
    except LookupError:
        db.rollback(); return error(404, 'not_found')
    except ValueError as exc:
        db.rollback(); return error(409, str(exc))
    return incident_detail(db, db.get(Incident, incident_id))


@router.post('/incidents/{incident_id}/merge')
def merge_incident(incident_id: int, payload: MergeRequest, db: Session = Depends(get_db_session)):
    try:
        target = service.merge_incidents(db, incident_id, payload.into, note=payload.note)
        db.commit()
    except LookupError:
        db.rollback(); return error(404, 'not_found')
    except ValueError as exc:
        db.rollback(); return error(409, str(exc))
    return incident_detail(db, target)


@router.get('/campaigns')
def list_campaigns(db: Session = Depends(get_db_session)):
    counts = dict(db.query(Incident.campaign_id, func.count(Incident.id)).filter(
        Incident.campaign_id.isnot(None)).group_by(Incident.campaign_id))
    return {'results': [{'id': c.id, 'name': c.name, 'description': c.description, 'status': c.status,
                         'created_at': iso(c.created_at), 'incident_count': counts.get(c.id, 0)}
                        for c in db.query(Campaign).order_by(Campaign.id.desc())]}


@router.get('/campaigns/suggestions')
def suggest_campaigns(db: Session = Depends(get_db_session)):
    return {'results': service.campaign_suggestions(db)}


@router.post('/campaigns', status_code=201)
def new_campaign(payload: CampaignCreate, db: Session = Depends(get_db_session)):
    try:
        campaign = service.create_campaign(db, payload.name, payload.description)
        db.commit()
    except ValueError as exc:
        db.rollback(); return error(409, str(exc))
    return {'id': campaign.id, 'name': campaign.name, 'description': campaign.description,
            'status': campaign.status, 'created_at': iso(campaign.created_at), 'incident_count': 0}


@router.post('/campaigns/{campaign_id}/incidents')
def add_to_campaign(campaign_id: int, payload: CampaignAssign, db: Session = Depends(get_db_session)):
    try:
        incident = service.assign_campaign(db, campaign_id, payload.incident_id)
        db.commit()
    except LookupError:
        db.rollback(); return error(404, 'not_found')
    return incident_detail(db, incident)
