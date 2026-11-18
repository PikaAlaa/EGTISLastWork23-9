"""Local ATT&CK technique catalogue (design core-v1 §4.1, §7.1).

Only attack-pattern objects that are neither revoked nor deprecated are stored.
Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are
registered trademarks of The MITRE Corporation.
"""
from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AttackTechnique(Base):
    __tablename__ = 'attack_techniques'
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    matrix: Mapped[str] = mapped_column(String(16), primary_key=True)
    attack_version: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactics: Mapped[list] = mapped_column(JSON, nullable=False)
    platforms: Mapped[list] = mapped_column(JSON, nullable=False)
    stix_id: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)
