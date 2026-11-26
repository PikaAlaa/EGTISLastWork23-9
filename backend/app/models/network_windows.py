"""network.windows import records (design network-windows-v1 §6.7, §7; step 11).

One row per run of data/scripts/import_network_windows.py: times, the engine version, the
shipped-manifest and list-lock versions, the covered span, input-file SHA-256s and sizes,
counts per source and event id, coverage and Findings by kind. No domain, address, port per
event, process, user or computer name, path or file name is stored here; Findings and their
hash-only indicators live in the core tables with source ref `network_windows_imports:<id>`.
Datetimes are stored as naive UTC.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class NetworkWindowsImport(Base):
    __tablename__ = 'network_windows_imports'
    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    engine_version: Mapped[str] = mapped_column(String(200), nullable=False)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lists_lock_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    span_first: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    span_last: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    files: Mapped[list] = mapped_column(JSON, nullable=False)
    counts: Mapped[dict] = mapped_column(JSON, nullable=False)
    coverage: Mapped[dict] = mapped_column(JSON, nullable=False)
    findings_by_kind: Mapped[dict] = mapped_column(JSON, nullable=False)
