from __future__ import annotations

from sqlalchemy.orm import Session

from app.engines.blacklist import calculate_blacklist_score
from app.engines.ml import calculate_ml_score
from app.engines.risk_scoring import calculate_final_risk_score
from app.engines.rule_based import calculate_rule_based_score
from app.models import ScanRequest as ScanRequestModel, ScanResult
from app.schemas import AnalyzeRequest


def analyze(payload: AnalyzeRequest, db: Session) -> dict:
    rule_result = calculate_rule_based_score(text=payload.text, url=payload.url)
    engine_details = {
        "rule_based": rule_result,
        "blacklist": calculate_blacklist_score(db, payload.url),
        "ml": calculate_ml_score(payload.text),
    }
    score_result = calculate_final_risk_score(engine_details)

    saved = False
    save_error = None
    try:
        request_row = ScanRequestModel(text=payload.text, url=payload.url)
        request_row.result = ScanResult(
            final_score=score_result["final_score"],
            verdict=score_result["verdict"],
            engine_details=engine_details,
            weighted_contributions=score_result["weighted_contributions"],
        )
        db.add(request_row)
        db.commit()
        saved = True
    except Exception:
        db.rollback()
        save_error = "Result calculated, but persistence failed"

    return {**score_result, "engine_details": engine_details, "saved": saved, "save_error": save_error}
