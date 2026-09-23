from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_api_key
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze

router = APIRouter(tags=["analysis"])


@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
def analyze_input(payload: AnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    return analyze(payload, db)
