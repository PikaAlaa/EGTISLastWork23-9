"""Privacy-minimizing scan records. Raw submissions and matched snippets are not persisted."""
from datetime import datetime
from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

SCAN_VERDICTS = ('LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE')
class ScanRequest(Base):
    __tablename__ = 'scan_requests'
    id: Mapped[int] = mapped_column(primary_key=True)
    url_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    text_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_type: Mapped[str] = mapped_column(String(16), default='unknown')
    submitted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    result: Mapped['ScanResult | None'] = relationship(back_populates='scan_request', uselist=False, cascade='all, delete-orphan')
class ScanResult(Base):
    __tablename__ = 'scan_results'
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_request_id: Mapped[int] = mapped_column(ForeignKey('scan_requests.id'), unique=True)
    rule_based_score: Mapped[float] = mapped_column(Float, default=0)
    blacklist_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    lstm_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    final_score: Mapped[float] = mapped_column(Float, default=0)
    verdict: Mapped[str] = mapped_column(String(16))
    engine_breakdown: Mapped[dict] = mapped_column(JSON)  # version IDs and reason codes only
    analysis_complete: Mapped[bool] = mapped_column(Boolean, default=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    scan_request: Mapped[ScanRequest] = relationship(back_populates='result')
