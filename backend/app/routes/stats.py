from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_api_key
from app.engines.ml import model_available
from app.models import BlacklistEntry, ScanResult
from app.schemas import StatsResponse

router = APIRouter(tags=["statistics"], dependencies=[Depends(require_api_key)])


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> dict:
    source_rows = db.execute(select(BlacklistEntry.source, func.count(BlacklistEntry.id)).group_by(BlacklistEntry.source)).all()
    verdict_rows = db.execute(select(ScanResult.verdict, func.count(ScanResult.id)).group_by(ScanResult.verdict)).all()
    return {
        "blacklist_total": db.scalar(select(func.count(BlacklistEntry.id))) or 0,
        "blacklist_by_source": {name: count for name, count in source_rows},
        "scans_total": db.scalar(select(func.count(ScanResult.id))) or 0,
        "verdict_counts": {name: count for name, count in verdict_rows},
        "model_available": model_available(),
    }
