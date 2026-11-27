"""Findings, incidents and campaigns (design core-v1 §1, §3, §7.1).

Rows are written only by app.services.findings.record_findings. Nothing here is
read by the /analyze decision policy. Datetimes are stored as naive UTC.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

INCIDENT_STATUSES = ('open', 'investigating', 'resolved')
INCIDENT_RESOLUTIONS = ('true_positive', 'false_positive', 'benign', 'duplicate')


class Campaign(Base):
    __tablename__ = 'campaigns'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default='active', nullable=False)


class Incident(Base):
    __tablename__ = 'incidents'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default='open', index=True, nullable=False)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey('campaigns.id', ondelete='SET NULL'), nullable=True)
    reopened_from: Mapped[int | None] = mapped_column(ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class FindingRecord(Base):
    __tablename__ = 'findings'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    engine_name: Mapped[str] = mapped_column(String(100), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    scan_request_id: Mapped[int | None] = mapped_column(ForeignKey('scan_requests.id', ondelete='CASCADE'),
                                                        index=True, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey('incidents.id', ondelete='SET NULL'),
                                                    index=True, nullable=True)


class FindingIndicator(Base):
    __tablename__ = 'finding_indicators'
    finding_id: Mapped[str] = mapped_column(ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey('indicators.id', ondelete='CASCADE'), primary_key=True)
    role: Mapped[str] = mapped_column(String(100), primary_key=True)


class FindingAttack(Base):
    __tablename__ = 'finding_attack'
    finding_id: Mapped[str] = mapped_column(ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    matrix: Mapped[str] = mapped_column(String(16), primary_key=True)
    attack_version: Mapped[str] = mapped_column(String(16), nullable=False)
    basis: Mapped[str] = mapped_column(String(100), nullable=False)


class FindingDevice(Base):
    """Stored device of a finding (design core-v2 §3.2): always the server-wrapped `srv:` ref.

    Written only by record_findings after wrap_refs; device refs never pivot incidents.
    """
    __tablename__ = 'finding_devices'
    finding_id: Mapped[str] = mapped_column(ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True)
    device_ref: Mapped[str] = mapped_column(String(37), index=True, nullable=False)
    attributed_by: Mapped[str] = mapped_column(String(32), nullable=False)


class IncidentIndicator(Base):
    __tablename__ = 'incident_indicators'
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey('indicators.id', ondelete='CASCADE'), primary_key=True)


class IncidentLink(Base):
    __tablename__ = 'incident_links'
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True)
    related_incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True)
    relation: Mapped[str] = mapped_column(String(16), primary_key=True)


class IncidentEvent(Base):
    __tablename__ = 'incident_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id', ondelete='CASCADE'), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
