"""Stateless local URL scoring adapter and check protocol for browser extension v1.

Design: docs/design/browser-extension-v1.md (§0, §1, §2, §2.2, §4, §6, §7, §9 step 2).
Runs the existing URL-only decision-v2 policy (`calculate_final_risk_score` with
`text=None`) using the unchanged models, thresholds, brand rules and offline
blacklist tables. Never writes to ScanRequest, ScanResult, FindingRecord,
Indicator, Incident or any log stream, and never echoes the URL or its hash.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from app.engines import risk_scoring
from app.engines.threat_intel.blacklist_lookup import blacklist_health
from app.services.extension_config import (
    ALLOWED_REASON_CODES,
    CHECK_SCHEMA_VERSION,
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PROTOCOL_MISMATCH,
    ERROR_SERVICE_UNAVAILABLE,
    EXPECTED_POLICY_VERSION,
    MAX_BODY_BYTES,
    UNAVAILABLE_COMPONENT_CODES,
    ExtensionInputError,
    current_url_model_candidate,
    validate_extension_url,
    validate_identifier,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ExtensionCheckRequest(_StrictModel):
    schema_version: str
    url: str
    request_ref: str


class ExtensionCheckResponse(_StrictModel):
    schema_version: Literal['extension-check-v1'] = CHECK_SCHEMA_VERSION
    request_ref: str
    server_instance_id: str
    verdict: Literal['LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE']
    decisive_reason: str
    supporting_signals: list[str]
    unavailable_components: list[str]
    policy_version: str
    url_model_version: str | None


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ExtensionInputError(ERROR_INPUT_INVALID)
        obj[key] = value
    return obj


def parse_json_body(raw_body: bytes) -> dict[str, object]:
    """Enforce MAX_BODY_BYTES and strict duplicate-key-free JSON object parsing."""
    if not isinstance(raw_body, (bytes, bytearray)):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    if len(raw_body) > MAX_BODY_BYTES:
        raise ExtensionInputError(ERROR_LIMIT_EXCEEDED)
    if not raw_body:
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    try:
        text = bytes(raw_body).decode('utf-8')
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except ExtensionInputError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ExtensionInputError(ERROR_INPUT_INVALID) from None
    if not isinstance(parsed, dict):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    return parsed


def parse_check_request(raw_body: bytes) -> ExtensionCheckRequest:
    """Validate a raw POST /extension/v1/check JSON payload without echoing input."""
    data = parse_json_body(raw_body)
    schema_version = data.get('schema_version')
    if isinstance(schema_version, str) and schema_version != CHECK_SCHEMA_VERSION:
        raise ExtensionInputError(ERROR_PROTOCOL_MISMATCH)
    try:
        req = ExtensionCheckRequest.model_validate(data)
    except ValidationError:
        raise ExtensionInputError(ERROR_INPUT_INVALID) from None
    validate_identifier(req.request_ref)
    validate_extension_url(req.url)
    return req


def evaluate_extension_url(
    db,
    request: ExtensionCheckRequest,
    *,
    server_instance_id: str,
) -> ExtensionCheckResponse:
    """Run the pure URL-only decision-v2 policy without persistence or logging.

    Verdict, decisive_reason and supporting_signals come directly from
    `calculate_final_risk_score(text=None, url=cleaned_url, db=db)`.
    If all analysis components (both blacklist/database and the URL model) are
    unavailable, raises ExtensionInputError(ERROR_SERVICE_UNAVAILABLE) so an
    offline or broken backend never masquerades as a completed check (§2.2).
    """
    validate_identifier(request.request_ref)
    validate_identifier(server_instance_id)
    cleaned_url = validate_extension_url(request.url)

    try:
        result = risk_scoring.calculate_final_risk_score(
            text=None,
            url=cleaned_url,
            db=db,
            sender_type=None,
        )
    except ExtensionInputError:
        raise
    except Exception:
        raise ExtensionInputError(ERROR_SERVICE_UNAVAILABLE) from None
    finally:
        cleaned_url = ''

    links = result.get('checked_links') or []
    first_link = links[0] if links else {}
    url_model_ran = (
        first_link.get('url_model_probability') is not None
        and first_link.get('url_model_threshold') is not None
    )

    raw_unavailable = list(result.get('checks_unavailable') or [])
    if not url_model_ran and 'url_model_unavailable' not in raw_unavailable:
        raw_unavailable.append('url_model_unavailable')

    blacklist_ok = bool(first_link.get('analysis_complete'))
    if db is None:
        blacklist_ok = False
        if 'database_unavailable' not in raw_unavailable:
            raw_unavailable.append('database_unavailable')
    else:
        try:
            health = blacklist_health(db)
            if not health.get('available'):
                blacklist_ok = False
                reason = health.get('reason') or 'database_unavailable'
                if reason not in raw_unavailable:
                    raw_unavailable.append(reason)
        except Exception:
            blacklist_ok = False
            if 'database_unavailable' not in raw_unavailable:
                raw_unavailable.append('database_unavailable')

    if not blacklist_ok and not url_model_ran:
        # §2.2: "If all analysis components are unavailable, show unavailable regardless of any transport success."
        raise ExtensionInputError(ERROR_SERVICE_UNAVAILABLE)

    unavailable_components = sorted({
        code for code in raw_unavailable if code in UNAVAILABLE_COMPONENT_CODES
    })
    decisive_reason = str(result.get('decisive_reason') or '')
    if decisive_reason not in ALLOWED_REASON_CODES:
        raise ExtensionInputError(ERROR_SERVICE_UNAVAILABLE)

    supporting_signals = [
        code for code in (result.get('supporting_signals') or [])
        if isinstance(code, str) and code in ALLOWED_REASON_CODES
    ]
    verdict = result.get('verdict')
    if verdict not in ('LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE'):
        raise ExtensionInputError(ERROR_SERVICE_UNAVAILABLE)

    policy_version = str(result.get('policy_version') or EXPECTED_POLICY_VERSION)
    model_version = current_url_model_candidate() if url_model_ran else None

    return ExtensionCheckResponse(
        schema_version=CHECK_SCHEMA_VERSION,
        request_ref=request.request_ref,
        server_instance_id=server_instance_id,
        verdict=verdict,
        decisive_reason=decisive_reason,
        supporting_signals=supporting_signals,
        unavailable_components=unavailable_components,
        policy_version=policy_version,
        url_model_version=model_version,
    )
