"""Shared helpers for the SOC console routers (design core-v1 §6).

Errors use the existing {error, detail} shape with fixed codes; no request value is
ever echoed. Indicator values are returned as plain data for inert display only.
"""
from datetime import date, datetime, time

from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

ERRORS = {404: 'NotFound', 409: 'Conflict', 400: 'InvalidScanInputError'}


class StrictBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


def error(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={'error': ERRORS.get(status, 'Error'), 'detail': detail})


def iso(value: datetime | date | None) -> str | None:
    return value.isoformat() if value is not None else None


def day_start(value: date | None) -> datetime | None:
    return datetime.combine(value, time.min) if value else None


def day_end(value: date | None) -> datetime | None:
    return datetime.combine(value, time.max) if value else None
