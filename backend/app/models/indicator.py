"""Indicator (IOC) store (design core-v1 §2, §7.1).

A read-side projection of the feed tables plus scan, analyst and sensor sightings.
`/analyze` never reads these tables; `blacklist_entries` and `feed_observations`
remain the source of truth for lookups, expiry and rollback.

Scan-derived indicators keep `value` NULL (hash only). `value` holds plaintext
only for feed, analyst or sensor indicators.
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Indicator(Base):
    __tablename__ = 'indicators'
    __table_args__ = (UniqueConstraint('type', 'value_hash', name='uq_indicators_type_value_hash'),
                      Index('ix_indicators_registered_domain', 'registered_domain'),
                      Index('ix_indicators_registered_domain_hash', 'registered_domain_hash'))

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    hash_algo: Mapped[str | None] = mapped_column(String(16), nullable=True)
    registered_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registered_domain_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class IndicatorSighting(Base):
    __tablename__ = 'indicator_sightings'
    __table_args__ = (UniqueConstraint('indicator_id', 'source_kind', 'source_name',
                                       name='uq_indicator_sightings_source'),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey('indicators.id', ondelete='CASCADE'),
                                              index=True, nullable=False)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_name: Mapped[str] = mapped_column(String(50), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ref: Mapped[str | None] = mapped_column(String(200), nullable=True)


class CorrelationStoplist(Base):
    __tablename__ = 'correlation_stoplist'
    __table_args__ = (UniqueConstraint('type', 'value_hash', name='uq_correlation_stoplist_type_value_hash'),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str] = mapped_column(String(50), nullable=False)
    brand: Mapped[str | None] = mapped_column(String(255), nullable=True)
    seeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
