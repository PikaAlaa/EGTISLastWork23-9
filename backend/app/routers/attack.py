"""ATT&CK coverage API (design core-v1 §4, §6).

Reads the local catalogue only. Technique URLs are returned as data for inert
display; the console never links to or fetches them. Every response carries the
MITRE copyright statement from data/attack-lock.json.
"""
import json
from datetime import date
from functools import lru_cache
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.models import AttackTechnique, FindingAttack, FindingRecord, Incident
from app.routers.soc_common import day_end, day_start, error
from app.services.attack import LOCK_PATH

router = APIRouter(prefix='/attack', tags=['attack'], dependencies=[Depends(verify_api_key)])
Matrix = Literal['enterprise', 'mobile']
# Tactic order from the x-mitre-matrix objects of the pinned v20.0 files.
TACTIC_ORDER = {
    'enterprise': ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
                   'privilege-escalation', 'stealth', 'defense-impairment', 'credential-access', 'discovery',
                   'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'],
    'mobile': ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion',
               'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control',
               'exfiltration', 'impact', 'network-effects', 'remote-service-effects'],
}


@lru_cache(maxsize=1)
def lock() -> dict:
    data = json.loads(LOCK_PATH.read_text(encoding='utf-8'))
    return {'attack_version': data['version'], 'copyright': data['copyright_statement']}


def header(matrix: str, installed: bool) -> dict:
    return {'matrix': matrix, 'installed': installed, **lock()}


def ordered_tactics(matrix: str, seen: set[str]) -> list[str]:
    known = TACTIC_ORDER[matrix]
    return [t for t in known if t in seen] + sorted(seen - set(known))


def technique_row(t: AttackTechnique) -> dict:
    return {'technique_id': t.technique_id, 'name': t.name, 'tactics': t.tactics, 'platforms': t.platforms,
            'url': t.url}


@router.get('/techniques')
def list_techniques(matrix: Matrix = 'enterprise', db: Session = Depends(get_db_session)):
    rows = db.query(AttackTechnique).filter_by(matrix=matrix, attack_version=lock()['attack_version']).order_by(
        AttackTechnique.technique_id).all()
    return {**header(matrix, bool(rows)), 'tactics': ordered_tactics(matrix, {t for r in rows for t in r.tactics}),
            'techniques': [technique_row(r) for r in rows]}


@router.get('/coverage')
def coverage(matrix: Matrix = 'enterprise', since: date | None = None, until: date | None = None,
             db: Session = Depends(get_db_session)):
    version = lock()['attack_version']
    query = db.query(FindingAttack.technique_id, func.count(FindingAttack.finding_id),
                     func.count(func.distinct(FindingRecord.incident_id))).join(
        FindingRecord, FindingRecord.id == FindingAttack.finding_id).filter(
        FindingAttack.matrix == matrix, FindingAttack.attack_version == version)
    if since:
        query = query.filter(FindingRecord.observed_at >= day_start(since))
    if until:
        query = query.filter(FindingRecord.observed_at <= day_end(until))
    counts = {technique: (findings, incidents) for technique, findings, incidents in
              query.group_by(FindingAttack.technique_id)}
    rows = db.query(AttackTechnique).filter_by(matrix=matrix, attack_version=version).order_by(
        AttackTechnique.technique_id).all()
    catalogued = {r.technique_id for r in rows}
    grid = {}
    for row in rows:
        findings, incidents = counts.get(row.technique_id, (0, 0))
        for tactic in row.tactics or ['unassigned']:
            grid.setdefault(tactic, []).append({**technique_row(row), 'findings': findings, 'incidents': incidents})
    return {**header(matrix, bool(rows)),
            'since': since.isoformat() if since else None, 'until': until.isoformat() if until else None,
            'total_findings': sum(f for f, _ in counts.values()),
            'tactics': [{'tactic': t, 'techniques': grid[t]} for t in ordered_tactics(matrix, set(grid))],
            'uncatalogued': [{'technique_id': t, 'findings': f, 'incidents': i}
                             for t, (f, i) in sorted(counts.items()) if t not in catalogued]}


@router.get('/techniques/{technique_id}')
def technique_detail(technique_id: str, matrix: Matrix = 'enterprise', limit: int = Query(default=50, ge=1, le=200),
                     db: Session = Depends(get_db_session)):
    version = lock()['attack_version']
    row = db.query(AttackTechnique).filter_by(technique_id=technique_id, matrix=matrix, attack_version=version).first()
    findings = db.query(FindingRecord).join(FindingAttack, FindingAttack.finding_id == FindingRecord.id).filter(
        FindingAttack.technique_id == technique_id, FindingAttack.matrix == matrix).all()
    if row is None and not findings:
        return error(404, 'not_found')
    incident_ids = sorted({f.incident_id for f in findings if f.incident_id})
    incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).order_by(
        Incident.last_activity_at.desc()).limit(limit).all() if incident_ids else []
    return {**header(matrix, row is not None), 'technique_id': technique_id,
            'technique': technique_row(row) if row else None, 'findings': len(findings),
            'incidents': [{'id': i.id, 'title': i.title, 'status': i.status, 'severity': i.severity,
                           'last_activity_at': i.last_activity_at.isoformat()} for i in incidents]}
