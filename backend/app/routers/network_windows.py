"""network.windows import API for the console (design network-windows-v1 §6.7, §6.8, §7; step 13).

Read-only. Imports are started only by the local command data/scripts/import_network_windows.py:
no endpoint accepts an upload, a body, a path or a file, starts an import or changes a system
setting. Responses carry counts, versions, coverage and the non-content evidence fields of each
Finding, copied field by field from fixed allow-lists: never a domain, IP, port per event,
process, user or computer name, or path. Destinations appear only as the hash-only indicators of
the core tables (other console pages).
"""
import threading
import time

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.engines.network_windows import engine as nw_engine
from app.models import AttackTechnique, FindingAttack, FindingRecord, NetworkWindowsImport
from app.routers.soc_common import error, iso

router = APIRouter(prefix='/network/windows', tags=['network'], dependencies=[Depends(verify_api_key)])

DETAIL_FIELDS = ('detection', 'reason_codes', 'events', 'combined_with', 'device_ref', 'rule_validation',
                 'baseline', 'process_category', 'attack_basis')
VALUE_FIELDS = ('score', 'threshold', 'label_length', 'label_entropy', 'consonant_run', 'digit_share',
                'burst_domains', 'events', 'median_gap_s', 'dispersion', 'span_s', 'port', 'baseline',
                'distinct_labels', 'median_label_length', 'mean_label_entropy', 'txt_queries', 'max_name_length',
                'signs')
LIST_FIELDS = ('list', 'title', 'version', 'licence', 'link')
FILE_FIELDS = ('source', 'sha256', 'size', 'records')
COVERAGE_FIELDS = ('detections', 'not_visible', 'not_run', 'baseline', 'import_hours', 'firewall_time_basis')
HEALTH_TTL_SECONDS = 300
_health_lock = threading.Lock()
_health_cache: dict = {}


def _pick(source, fields) -> dict:
    source = source if isinstance(source, dict) else {}
    return {name: source.get(name) for name in fields if name in source}


def _coverage(coverage) -> dict:
    coverage = coverage if isinstance(coverage, dict) else {}
    out = _pick(coverage, COVERAGE_FIELDS)
    out['sources'] = {name: {'records': (info or {}).get('records', 0), 'hours': (info or {}).get('hours')}
                      for name, info in (coverage.get('sources') or {}).items()}
    return out


def import_summary(row: NetworkWindowsImport) -> dict:
    counts = row.counts or {}
    return {'id': row.id, 'started_at': iso(row.started_at), 'finished_at': iso(row.finished_at),
            'engine_version': row.engine_version, 'manifest_sha256': row.manifest_sha256,
            'lists_lock_sha256': row.lists_lock_sha256, 'span_first': iso(row.span_first),
            'span_last': iso(row.span_last), 'files': [_pick(f, FILE_FIELDS) for f in row.files or []],
            'counts': {'events': counts.get('events') or {}, 'skipped': counts.get('skipped') or {},
                       'alerts': counts.get('alerts', 0)},
            'coverage': _coverage(row.coverage), 'findings_by_kind': row.findings_by_kind or {}}


def finding_view(record: FindingRecord, attack: list[dict]) -> dict:
    evidence = record.evidence or {}
    details = evidence.get('details') or {}
    window = details.get('window') or {}
    return {
        'id': record.id, 'kind': record.kind, 'severity': record.severity, 'confidence': record.confidence,
        'observed_at': iso(record.observed_at), 'incident_id': record.incident_id,
        'engine_version': record.engine_version, 'reasons': list(evidence.get('reasons') or []),
        **_pick(details, DETAIL_FIELDS),
        'window': {'first': window.get('first'), 'last': window.get('last')},
        'values': _pick(details.get('values'), VALUE_FIELDS),
        'lists': [_pick(item, LIST_FIELDS) for item in details.get('lists') or []],
        'attack': attack,
    }


@router.get('/imports')
def list_imports(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
                 db: Session = Depends(get_db_session)):
    total = db.query(func.count(NetworkWindowsImport.id)).scalar() or 0
    rows = db.query(NetworkWindowsImport).order_by(NetworkWindowsImport.started_at.desc(),
                                                   NetworkWindowsImport.id.desc()).offset(offset).limit(limit).all()
    return {'total_matching': total, 'limit': limit, 'offset': offset, 'results': [import_summary(r) for r in rows]}


@router.get('/imports/{import_id}')
def import_detail(import_id: int, db: Session = Depends(get_db_session)):
    row = db.get(NetworkWindowsImport, import_id)
    if row is None:
        return error(404, 'not_found')
    records = db.query(FindingRecord).filter(
        FindingRecord.engine_name == nw_engine.ENGINE_NAME,
        FindingRecord.source_ref == f'{nw_engine.SOURCE_PREFIX}{row.id}').order_by(
        FindingRecord.observed_at, FindingRecord.id).all()
    ids = [r.id for r in records]
    attack_rows = db.query(FindingAttack).filter(FindingAttack.finding_id.in_(ids)).order_by(
        FindingAttack.technique_id).all() if ids else []
    names = {(t.technique_id, t.matrix, t.attack_version): t.name for t in db.query(AttackTechnique).filter(
        AttackTechnique.technique_id.in_({a.technique_id for a in attack_rows}))} if attack_rows else {}
    attack: dict[str, list] = {}
    for item in attack_rows:
        attack.setdefault(item.finding_id, []).append({
            'technique_id': item.technique_id, 'matrix': item.matrix, 'attack_version': item.attack_version,
            'basis': item.basis, 'name': names.get((item.technique_id, item.matrix, item.attack_version))})
    return {**import_summary(row), 'findings': [finding_view(r, attack.get(r.id, [])) for r in records]}


def _local_health() -> dict:
    """Cached for a few minutes: verifying the manifest and lists reads local files."""
    now = time.monotonic()
    with _health_lock:
        cached = _health_cache.get('value')
        if cached is not None and now - _health_cache['at'] < HEALTH_TTL_SECONDS:
            return cached
        engine = nw_engine.load_engine()
        value = {**engine.health(), 'version': engine.version}
        _health_cache.update(value=value, at=now)
        return value


@router.get('/health')
def health(db: Session = Depends(get_db_session)):
    from app.engines.registry import registry
    registered = nw_engine.ENGINE_NAME in registry.names()
    if registered:
        engine = registry.get(nw_engine.ENGINE_NAME)
        report = {**engine.health({}), 'version': engine.version}
    else:
        report = _local_health()
    last = db.query(NetworkWindowsImport).order_by(NetworkWindowsImport.started_at.desc(),
                                                   NetworkWindowsImport.id.desc()).first()
    return {'engine': nw_engine.ENGINE_NAME, 'domain': 'network',
            'source': 'registered_engine' if registered else 'local_files', **report,
            'imports_start_from': 'data/scripts/import_network_windows.py',
            'last_import': None if last is None else {'id': last.id, 'started_at': iso(last.started_at),
                                                      'engine_version': last.engine_version}}
