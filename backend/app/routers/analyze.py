import hashlib
import logging
from typing import Literal
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session
from app.core.database import get_db_session
from app.core.settings import settings
from app.core.security import verify_api_key
from app.core.rate_limit import limiter
from app.engines.risk_scoring import calculate_final_risk_score
from app.models.scan import ScanRequest, ScanResult

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/analyze', tags=['analyze'])
class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    url: str | None = Field(default=None, max_length=2048)
    text: str | None = Field(default=None, max_length=5000)
class AnalyzeResponse(BaseModel):
    verdict: Literal['LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE']
    final_score: float
    decisive_reason: str
    supporting_signals: list[str]
    checked_links: list[dict]
    links_truncated: bool
    text_finding: dict | None
    analysis_complete: bool
    checks_unavailable: list[str]
    policy_version: str
    timing_ms: float
    saved: bool
    save_error: str | None

@router.post('', response_model=AnalyzeResponse, dependencies=[Depends(verify_api_key)])
@limiter.limit(settings.rate_limit)
def analyze(request: Request, payload: AnalyzeRequest, db: Session = Depends(get_db_session)):
    result = calculate_final_risk_score(text=payload.text, url=payload.url, db=db)
    try:
        digest = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest() if value else None
        scan = ScanRequest(url_hash=digest(payload.url), text_hash=digest(payload.text),
                           input_type='both' if payload.url and payload.text else 'url' if payload.url else 'text')
        db.add(scan)
        db.flush()
        db.add(ScanResult(scan_request_id=scan.id, verdict=result['verdict'], final_score=result['final_score'],
                          analysis_complete=result['analysis_complete'], engine_breakdown={
                              'reason': result['decisive_reason'], 'signals': result['supporting_signals'],
                              'unavailable': result['checks_unavailable'], 'policy': result['policy_version'],
                              'model': (result['text_finding'] or {}).get('version')}))
        db.commit()
        result.update(saved=True, save_error=None)
    except Exception:
        db.rollback()
        # No exception string/traceback: driver errors may contain request values.
        logger.warning('scan_persistence_failed')
        result.update(saved=False, save_error='scan_not_saved')
    return result
