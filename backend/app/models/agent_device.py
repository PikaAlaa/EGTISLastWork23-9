"""LAN agent devices, one-use pairing invitations and received batches (design windows-agent-lan-v1 §4.1, §7.1).

`devices.device_ref` stores only the server-wrapped `srv:<32 hex>` form (core v2 §3.2, owner decision Q1);
no endpoint `hmac:` ref, computer name, user name or address is stored. Secrets are stored only as SHA-256
digests (`token_hash`, `code_hash`). Agent Findings live in the core tables with source ref
`agent_devices:<device_id>:<batch_id>`. Datetimes are stored as naive UTC.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

DEVICE_STATUSES = ('active', 'revoked')


class Device(Base):
    __tablename__ = 'devices'
    __table_args__ = (UniqueConstraint('device_ref', name='uq_devices_device_ref'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_ref: Mapped[str] = mapped_column(String(37), nullable=False)
    display_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    agent_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_versions: Mapped[dict] = mapped_column(JSON, nullable=False)
    last_coverage: Mapped[dict] = mapped_column(JSON, nullable=False)
    notice_version_ack: Mapped[str] = mapped_column(String(32), nullable=False)
    paired_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)


class DevicePairingToken(Base):
    __tablename__ = 'device_pairing_tokens'
    __table_args__ = (UniqueConstraint('code_hash', name='uq_device_pairing_tokens_code_hash'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    display_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    device_id: Mapped[int | None] = mapped_column(ForeignKey('devices.id'), nullable=True)


class AgentBatch(Base):
    __tablename__ = 'agent_batches'
    __table_args__ = (UniqueConstraint('device_id', 'batch_id', name='uq_agent_batches_device_batch'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    device_id: Mapped[int] = mapped_column(ForeignKey('devices.id'), nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_versions: Mapped[dict] = mapped_column(JSON, nullable=False)
    coverage: Mapped[dict] = mapped_column(JSON, nullable=False)
    accepted_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    duplicate_findings: Mapped[int] = mapped_column(Integer, nullable=False)
