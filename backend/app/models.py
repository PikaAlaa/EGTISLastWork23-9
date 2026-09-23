from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .core.database import Base


class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    source: Mapped[str] = mapped_column(String(50), index=True)
    brand_target: Mapped[str | None] = mapped_column(String(150), nullable=True)
    first_seen: Mapped[date] = mapped_column(Date)
    last_seen: Mapped[date] = mapped_column(Date)


class EgyptianBrand(Base):
    __tablename__ = "egyptian_brands"

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(80), default="Uncategorized")
    domains: Mapped[list["BrandDomain"]] = relationship(back_populates="brand", cascade="all, delete-orphan")


class BrandDomain(Base):
    __tablename__ = "brand_domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_id: Mapped[int] = mapped_column(ForeignKey("egyptian_brands.id", ondelete="CASCADE"))
    domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    verified_date: Mapped[date] = mapped_column(Date)
    brand: Mapped[EgyptianBrand] = relationship(back_populates="domains")


class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    text: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    result: Mapped["ScanResult | None"] = relationship(back_populates="request", uselist=False, cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("scan_requests.id", ondelete="CASCADE"), unique=True)
    final_score: Mapped[float] = mapped_column(Float)
    verdict: Mapped[str] = mapped_column(String(10), index=True)
    engine_details: Mapped[dict] = mapped_column(JSON)
    weighted_contributions: Mapped[dict] = mapped_column(JSON)
    request: Mapped[ScanRequest] = relationship(back_populates="result")


class CommunityReport(Base):
    __tablename__ = "community_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FeedUpdate(Base):
    __tablename__ = "feed_updates"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(80))
    rows_added: Mapped[int] = mapped_column(Integer, default=0)
    rows_updated: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
