from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_api_key
from app.models import BlacklistEntry
from app.schemas import ThreatPage

router = APIRouter(tags=["threat intelligence"])


@router.get("/threats", response_model=ThreatPage, dependencies=[Depends(require_api_key)])
def list_threats(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    source: str | None = None,
    domain: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    filters = []
    if source:
        filters.append(BlacklistEntry.source == source)
    if domain:
        filters.append(BlacklistEntry.domain.contains(domain.casefold()))
    total = db.scalar(select(func.count(BlacklistEntry.id)).where(*filters)) or 0
    items = db.scalars(
        select(BlacklistEntry)
        .where(*filters)
        .order_by(BlacklistEntry.last_seen.desc(), BlacklistEntry.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"items": items, "page": page, "page_size": page_size, "total": total}
