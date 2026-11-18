"""Indicator search and community review API (design core-v1 §2, §6).

Exact lookup only: the query value is normalized and hashed, then matched on
(type, value_hash). There is no substring search over hashed values and no bulk
export. The submitted query is never logged, stored or echoed in errors.
"""
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.indicators import normalize
from app.core.security import verify_api_key
from app.models import CommunityReport, FindingIndicator, FindingRecord, Incident, Indicator, IndicatorSighting
from app.routers.soc_common import StrictBody, error, iso
from app.services.indicators import review_community_report

router = APIRouter(tags=['indicators'], dependencies=[Depends(verify_api_key)])
IndicatorType = Literal['domain', 'url', 'ip', 'hash', 'phone', 'email']


class CommunityReview(StrictBody):
    status: Literal['confirmed', 'rejected']
    indicator_type: IndicatorType | None = None


def indicator_detail(db: Session, indicator: Indicator) -> dict:
    sightings = db.query(IndicatorSighting).filter_by(indicator_id=indicator.id).order_by(
        IndicatorSighting.last_seen.desc()).all()
    rows = db.query(FindingRecord, FindingIndicator.role).join(
        FindingIndicator, FindingIndicator.finding_id == FindingRecord.id).filter(
        FindingIndicator.indicator_id == indicator.id).order_by(FindingRecord.observed_at.desc()).limit(100).all()
    incident_ids = sorted({f.incident_id for f, _ in rows if f.incident_id})
    incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).all() if incident_ids else []
    return {
        'id': indicator.id, 'type': indicator.type, 'value': indicator.value, 'value_hash': indicator.value_hash,
        'hash_algo': indicator.hash_algo, 'registered_domain': indicator.registered_domain,
        'first_seen': iso(indicator.first_seen), 'last_seen': iso(indicator.last_seen),
        'sightings': [{'source_kind': s.source_kind, 'source_name': s.source_name, 'first_seen': iso(s.first_seen),
                       'last_seen': iso(s.last_seen), 'active': s.active} for s in sightings],
        'findings': [{'id': f.id, 'kind': f.kind, 'severity': f.severity, 'confidence': f.confidence,
                      'observed_at': iso(f.observed_at), 'incident_id': f.incident_id, 'role': role}
                     for f, role in rows],
        'incidents': [{'id': i.id, 'title': i.title, 'status': i.status, 'severity': i.severity}
                      for i in sorted(incidents, key=lambda i: i.id)],
    }


@router.get('/indicators')
def lookup_indicator(type: IndicatorType, q: str = Query(min_length=1, max_length=2048),
                     hash_algo: Literal['sha256', 'sha1', 'md5'] | None = None,
                     db: Session = Depends(get_db_session)):
    try:
        normalized = normalize(type, q, hash_algo if type == 'hash' else None)
    except ValueError:
        return error(400, 'invalid_input')
    indicator = db.query(Indicator).filter_by(type=normalized.type, value_hash=normalized.value_hash).one_or_none()
    return {'type': normalized.type, 'found': indicator is not None,
            'indicator': indicator_detail(db, indicator) if indicator else None}


@router.get('/indicators/{indicator_id}')
def get_indicator(indicator_id: int, db: Session = Depends(get_db_session)):
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        return error(404, 'not_found')
    return indicator_detail(db, indicator)


def report_row(report: CommunityReport) -> dict:
    return {'id': report.id, 'reported_value': report.reported_value, 'reporter_note': report.reporter_note,
            'status': report.status, 'submitted_at': iso(report.submitted_at), 'reviewed_at': iso(report.reviewed_at)}


@router.get('/community-reports')
def list_community_reports(status: Literal['pending', 'confirmed', 'rejected'] | None = None,
                           limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db_session)):
    query = db.query(CommunityReport)
    if status:
        query = query.filter(CommunityReport.status == status)
    return {'total_matching': query.count(),
            'results': [report_row(r) for r in query.order_by(CommunityReport.submitted_at.desc()).limit(limit)]}


@router.patch('/community-reports/{report_id}')
def review_report(report_id: int, payload: CommunityReview, db: Session = Depends(get_db_session)):
    try:
        report, indicator = review_community_report(db, report_id, payload.status, payload.indicator_type)
        db.commit()
    except LookupError:
        db.rollback(); return error(404, 'not_found')
    except ValueError as exc:
        db.rollback()
        code = str(exc)
        return error(409 if code in ('already_reviewed', 'indicator_type_required') else 400,
                     code if code in ('already_reviewed', 'indicator_type_required') else 'invalid_input')
    return {**report_row(report), 'indicator_id': indicator.id if indicator else None}
