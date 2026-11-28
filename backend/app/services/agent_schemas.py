"""Strict wire schemas for the LAN agent API (design windows-agent-lan-v1 §5.1, §10 step 2).

Every model forbids unknown fields and is strict. Requests are parsed from the raw body in JSON mode, so
datetimes arrive as ISO strings, and duplicate JSON keys are refused. Errors carry fixed reason codes only and
never echo a submitted value. The privacy rules on Finding contents live in `agent_privacy`.
"""
from __future__ import annotations

import json
import uuid
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

from app.core.findings import Finding

PAIR_SCHEMA = 'agent-pair-v1'
BATCH_SCHEMA = 'agent-batch-v1'
HEARTBEAT_SCHEMA = 'agent-heartbeat-v1'
UNPAIR_SCHEMA = 'agent-unpair-v1'
NOTICE_VERSION = 'pdpl-notice-v1'
AGENT_ENGINES = ('host.windows', 'malware.files', 'network.windows')
ENGINE_DOMAINS = {'host.windows': 'host', 'malware.files': 'malware', 'network.windows': 'network'}
MAX_BODY_BYTES = 512 * 1024
MAX_FINDINGS = 100

AgentEngine = Literal['host.windows', 'malware.files', 'network.windows']
Version = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,199}$')]
AgentVersion = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$')]
Code = Annotated[str, StringConstraints(pattern=r'^[a-z0-9][a-z0-9_.:-]{0,99}$')]
KeyToken = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$')]
PairingCode = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]{20,128}$')]
Count = Annotated[int, Field(ge=0, le=1_000_000_000)]


class AgentRequestError(ValueError):
    """Fixed reason code and HTTP status; never carries request content."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


def _uuid4(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise ValueError('uuid4_required') from None
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError('uuid4_required')
    return value


class SourceCoverage(_Strict):
    status: Literal['read', 'unreadable_or_absent', 'not_configured']
    records: Count = 0
    hours: Annotated[float, Field(ge=0, le=100_000)] | None = None


class EngineCoverage(_Strict):
    sources: dict[KeyToken, SourceCoverage] = Field(default_factory=dict, max_length=32)
    detections: dict[KeyToken, Literal['visible', 'partial', 'not_visible', 'no_baseline', 'inactive']] = Field(
        default_factory=dict, max_length=200)
    health: list[Code] = Field(default_factory=list, max_length=20)


class QueueStatus(_Strict):
    queued_batches: Count = 0
    queued_findings: Count = 0
    queue_overflow_batches_dropped: Count = 0
    queue_overflow_findings_dropped: Count = 0
    queue_expired_findings_count: Count = 0
    local_rejected_batches_count: Count = 0


class AgentCoverage(_Strict):
    engines: dict[AgentEngine, EngineCoverage] = Field(default_factory=dict)
    queue_status: QueueStatus = Field(default_factory=QueueStatus)


class AgentPairRequest(_Strict):
    schema_version: Literal['agent-pair-v1']
    pairing_code: PairingCode
    device_ref: Annotated[str, StringConstraints(max_length=64)]
    agent_instance_id: str
    agent_version: AgentVersion
    notice_version_ack: Literal['pdpl-notice-v1']

    @field_validator('agent_instance_id')
    @classmethod
    def _instance_uuid4(cls, value):
        return _uuid4(value)


class AgentBatchRequest(_Strict):
    schema_version: Literal['agent-batch-v1']
    batch_id: str
    sent_at: AwareDatetime
    agent_version: AgentVersion
    engine_versions: dict[AgentEngine, Version] = Field(default_factory=dict)
    coverage: AgentCoverage = Field(default_factory=AgentCoverage)
    findings: list[Finding] = Field(default_factory=list, max_length=MAX_FINDINGS)

    @field_validator('batch_id')
    @classmethod
    def _batch_uuid4(cls, value):
        return _uuid4(value)

    @field_validator('findings')
    @classmethod
    def _agent_engines_only(cls, findings):
        """Gate 2: only the three agent engines, each with its own domain."""
        for finding in findings:
            if ENGINE_DOMAINS.get(finding.engine.name) != finding.domain:
                raise ValueError('engine_not_allowed')
        return findings


class AgentHeartbeatRequest(_Strict):
    schema_version: Literal['agent-heartbeat-v1']
    sent_at: AwareDatetime
    agent_version: AgentVersion
    engine_versions: dict[AgentEngine, Version] = Field(default_factory=dict)
    coverage: AgentCoverage = Field(default_factory=AgentCoverage)


class AgentUnpairRequest(_Strict):
    schema_version: Literal['agent-unpair-v1']


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate_key')
        out[key] = value
    return out


def parse_request(model: type[_Strict], raw: bytes):
    """Validate a raw JSON body against `model`. Raises AgentRequestError with a fixed code."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise AgentRequestError(400, 'invalid_input')
    if len(raw) > MAX_BODY_BYTES:
        raise AgentRequestError(413, 'limit_exceeded')
    try:
        data = json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AgentRequestError(400, 'invalid_input') from None
    if not isinstance(data, dict):
        raise AgentRequestError(400, 'invalid_input')
    if model is AgentPairRequest and data.get('notice_version_ack') != NOTICE_VERSION:
        raise AgentRequestError(400, 'notice_ack_required')
    if model is AgentBatchRequest and isinstance(data.get('findings'), list) and len(data['findings']) > MAX_FINDINGS:
        raise AgentRequestError(413, 'limit_exceeded')
    try:
        return model.model_validate_json(bytes(raw))
    except ValidationError:
        raise AgentRequestError(400, 'invalid_input') from None
