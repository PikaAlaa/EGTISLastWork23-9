from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalyzeRequest(BaseModel):
    text: str | None = Field(default=None, max_length=20_000)
    url: str | None = Field(default=None, max_length=4_096)

    @model_validator(mode="after")
    def require_content(self):
        self.text = self.text.strip() if self.text else None
        self.url = self.url.strip() if self.url else None
        if not self.text and not self.url:
            raise ValueError("At least one of text or url is required")
        return self


class AnalyzeResponse(BaseModel):
    final_score: float
    verdict: Literal["LOW", "MEDIUM", "HIGH"]
    reason: str
    engines_applied: list[str]
    weighted_contributions: dict[str, float]
    engine_details: dict[str, Any]
    saved: bool
    save_error: str | None = None


class ThreatItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    domain: str
    source: str
    brand_target: str | None
    first_seen: date
    last_seen: date


class ThreatPage(BaseModel):
    items: list[ThreatItem]
    page: int
    page_size: int
    total: int


class StatsResponse(BaseModel):
    blacklist_total: int
    blacklist_by_source: dict[str, int]
    scans_total: int
    verdict_counts: dict[str, int]
    model_available: bool
