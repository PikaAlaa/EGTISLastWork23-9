"""Finding schema `finding-v1` (design core-v1 §1): the one contract every engine emits.

A Finding is evidence, never a verdict. Confidence is categorical because ETIS
scores are indicator strengths, not calibrated probabilities. `evidence.details`
must hold only non-content values (versions, strengths, thresholds, reason
codes), never submitted text, URLs or matched snippets.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.indicators import HASH_LENGTHS

SCHEMA_VERSION = 'finding-v1'
FindingDomain = Literal['phishing', 'malware', 'network', 'host']
Severity = Literal['info', 'low', 'medium', 'high', 'critical']
Confidence = Literal['confirmed', 'corroborated', 'single_signal', 'undetermined']
IndicatorType = Literal['domain', 'url', 'ip', 'hash', 'phone', 'email']
SourceKind = Literal['scan', 'feed', 'analyst', 'community', 'sensor', 'import']
SEVERITY_ORDER = ('info', 'low', 'medium', 'high', 'critical')
_SHA256 = r'^[0-9a-f]{64}$'
_CODE = r'^[a-z0-9][a-z0-9_.:-]{0,99}$'


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class EngineRef(_Strict):
    name: str = Field(pattern=r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$', max_length=100)
    version: str = Field(min_length=1, max_length=200)


class IndicatorRef(_Strict):
    type: IndicatorType
    value_hash: str = Field(pattern=_SHA256)
    value: str | None = Field(default=None, max_length=2048)
    role: str = Field(pattern=_CODE)
    hash_algo: Literal['sha256', 'sha1', 'md5'] | None = None
    # Hash of the registered domain for url/domain indicators, so domain
    # correlation (§3.1) works without storing a scan-derived domain in plaintext.
    registered_domain_hash: str | None = Field(default=None, pattern=_SHA256)

    @model_validator(mode='after')
    def _hash_algo_matches_type(self):
        if (self.type == 'hash') != (self.hash_algo is not None):
            raise ValueError('hash_algo_required_only_for_hash')
        if self.type == 'hash' and self.value is not None and len(self.value) != HASH_LENGTHS[self.hash_algo]:
            raise ValueError('hash_length_mismatch')
        if self.registered_domain_hash is not None and self.type not in ('url', 'domain'):
            raise ValueError('registered_domain_only_for_domain_types')
        return self


class AttackRef(_Strict):
    technique_id: str = Field(pattern=r'^T\d{4}(\.\d{3})?$')
    matrix: Literal['enterprise', 'mobile']
    attack_version: str = Field(pattern=r'^\d+\.\d+$')
    basis: str = Field(pattern=_CODE)


class Evidence(_Strict):
    reasons: list[str] = Field(default_factory=list, max_length=100)
    details: dict = Field(default_factory=dict)

    @field_validator('reasons')
    @classmethod
    def _reason_codes(cls, reasons):
        for reason in reasons:
            if not re.match(_CODE, reason):
                raise ValueError('invalid_reason_code')
        return reasons


class SourceRef(_Strict):
    kind: SourceKind
    ref: str = Field(min_length=1, max_length=200)


class Finding(_Strict):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: Literal['finding-v1'] = SCHEMA_VERSION
    engine: EngineRef
    domain: FindingDomain
    kind: str = Field(pattern=_CODE)
    severity: Severity
    confidence: Confidence
    indicators: list[IndicatorRef] = Field(default_factory=list, max_length=200)
    attack: list[AttackRef] = Field(default_factory=list, max_length=50)
    evidence: Evidence = Field(default_factory=Evidence)
    observed_at: AwareDatetime
    created_at: AwareDatetime
    source: SourceRef
    incident_id: int | None = None

    @field_validator('id')
    @classmethod
    def _uuid4(cls, value):
        if uuid.UUID(value).version != 4 or str(uuid.UUID(value)) != value:
            raise ValueError('id_must_be_uuid4')
        return value


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
