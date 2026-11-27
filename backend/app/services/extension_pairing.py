"""In-memory pairing, one-use secret exchange, revocation and token scope enforcement.

Design: docs/design/browser-extension-v1.md (§2.2, §2.3, §2.4, §7, §9 step 3).
Stores only SHA-256 digests of the one-use pairing secret and the active extension
bearer token, the operator-approved extension Origin, extension_instance_id, and
revocation state. Never stores or logs any URL, URL hash, check timestamp, result
or plaintext secret/token. Restarting the process rotates server_instance_id and
requires re-pairing.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import threading
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from app.services.extension_config import (
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PAIRING_INVALID,
    ERROR_PAIRING_REQUIRED,
    ERROR_PROTOCOL_MISMATCH,
    EXTENSION_TOKEN_BYTES,
    MAX_CONCURRENT_CHECKS,
    PAIR_MAX_FAILED_ATTEMPTS,
    PAIR_SCHEMA_VERSION,
    PAIR_SECRET_BYTES,
    PAIR_SECRET_TTL_SECONDS,
    RATE_LIMIT_PER_MINUTE,
    ExtensionInputError,
    validate_extension_origin,
    validate_identifier,
)
from app.services.extension_scoring import parse_json_body


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _new_server_instance_id() -> str:
    return 'srv_' + secrets.token_hex(16)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class OperatorPairingApproveRequest(_StrictModel):
    extension_origin: str


class ExtensionPairRequest(_StrictModel):
    schema_version: str
    pairing_secret: str
    extension_instance_id: str


class ExtensionPairResponse(_StrictModel):
    schema_version: Literal['extension-pair-v1'] = PAIR_SCHEMA_VERSION
    extension_token: str
    server_instance_id: str
    extension_instance_id: str


@dataclass
class _PendingSecret:
    secret_sha256: str
    approved_origin: str
    expires_at: float
    failed_attempts: int = 0


@dataclass
class _ActivePairing:
    token_sha256: str | None
    approved_origin: str
    extension_instance_id: str
    revoked: bool = False


class ExtensionPairingStore:
    """Thread-safe local pairing and rate-budget manager with zero URL/check history."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._server_instance_id = _new_server_instance_id()
        self._pending: _PendingSecret | None = None
        self._active: _ActivePairing | None = None
        self._window_started_at: float = 0.0
        self._window_count: int = 0
        self._in_flight_checks: int = 0

    @property
    def server_instance_id(self) -> str:
        return self._server_instance_id

    def reset_for_restart(self) -> None:
        """Simulate a fresh server restart: rotates server_instance_id and clears state."""
        with self._lock:
            self._server_instance_id = _new_server_instance_id()
            self._pending = None
            self._active = None
            self._window_started_at = 0.0
            self._window_count = 0
            self._in_flight_checks = 0

    def status(self) -> dict[str, object]:
        with self._lock:
            paired = bool(self._active and not self._active.revoked and self._active.token_sha256)
            revoked = bool(self._active and self._active.revoked)
            origin = self._active.approved_origin if self._active else (
                self._pending.approved_origin if self._pending else None
            )
            return {
                'paired': paired,
                'revoked': revoked,
                'approved_origin': origin,
                'server_instance_id': self._server_instance_id,
            }

    def issue_pairing_secret(self, raw_body: bytes, *, now: float | None = None) -> dict[str, object]:
        """Operator action: approve an exact extension Origin and mint a one-use secret."""
        data = parse_json_body(raw_body)
        try:
            req = OperatorPairingApproveRequest.model_validate(data)
        except ValidationError:
            raise ExtensionInputError(ERROR_INPUT_INVALID) from None
        approved_origin = validate_extension_origin(req.extension_origin)
        current_time = time.monotonic() if now is None else float(now)
        secret = secrets.token_urlsafe(PAIR_SECRET_BYTES)
        secret_digest = _sha256_hex(secret)
        with self._lock:
            self._pending = _PendingSecret(
                secret_sha256=secret_digest,
                approved_origin=approved_origin,
                expires_at=current_time + PAIR_SECRET_TTL_SECONDS,
                failed_attempts=0,
            )
            # Issuing a new pairing secret invalidates any previous token until pairing completes.
            if self._active is not None:
                self._active.token_sha256 = None
                self._active.revoked = True
            return {
                'pairing_secret': secret,
                'extension_origin': approved_origin,
                'expires_in_seconds': PAIR_SECRET_TTL_SECONDS,
                'server_instance_id': self._server_instance_id,
            }

    def revoke(self) -> dict[str, object]:
        """Operator action: revoke the current extension token and clear pending secrets."""
        with self._lock:
            self._pending = None
            if self._active is not None:
                self._active.token_sha256 = None
                self._active.revoked = True
            else:
                self._active = _ActivePairing(
                    token_sha256=None,
                    approved_origin='',
                    extension_instance_id='',
                    revoked=True,
                )
            return {
                'status': 'revoked',
                'server_instance_id': self._server_instance_id,
            }

    def exchange_pairing_secret(
        self,
        origin: str | None,
        raw_body: bytes,
        *,
        now: float | None = None,
    ) -> ExtensionPairResponse:
        """Exchange the one-use secret for a revocable token bound to the approved Origin."""
        validated_origin = validate_extension_origin(origin)
        data = parse_json_body(raw_body)
        schema_version = data.get('schema_version')
        if isinstance(schema_version, str) and schema_version != PAIR_SCHEMA_VERSION:
            raise ExtensionInputError(ERROR_PROTOCOL_MISMATCH)
        try:
            req = ExtensionPairRequest.model_validate(data)
        except ValidationError:
            raise ExtensionInputError(ERROR_INPUT_INVALID) from None
        validate_identifier(req.extension_instance_id)
        if not (16 <= len(req.pairing_secret) <= 128) or req.pairing_secret != req.pairing_secret.strip():
            raise ExtensionInputError(ERROR_PAIRING_INVALID)

        current_time = time.monotonic() if now is None else float(now)
        candidate_digest = _sha256_hex(req.pairing_secret)

        with self._lock:
            pending = self._pending
            if pending is None:
                raise ExtensionInputError(ERROR_PAIRING_REQUIRED)
            if current_time > pending.expires_at or pending.failed_attempts >= PAIR_MAX_FAILED_ATTEMPTS:
                self._pending = None
                raise ExtensionInputError(ERROR_PAIRING_INVALID)

            origin_ok = hmac.compare_digest(validated_origin, pending.approved_origin)
            secret_ok = hmac.compare_digest(candidate_digest, pending.secret_sha256)
            if not (origin_ok and secret_ok):
                pending.failed_attempts += 1
                if pending.failed_attempts >= PAIR_MAX_FAILED_ATTEMPTS:
                    self._pending = None
                raise ExtensionInputError(ERROR_PAIRING_INVALID)

            # One-use secret: consume immediately.
            self._pending = None
            token = secrets.token_urlsafe(EXTENSION_TOKEN_BYTES)
            self._active = _ActivePairing(
                token_sha256=_sha256_hex(token),
                approved_origin=validated_origin,
                extension_instance_id=req.extension_instance_id,
                revoked=False,
            )
            return ExtensionPairResponse(
                schema_version=PAIR_SCHEMA_VERSION,
                extension_token=token,
                server_instance_id=self._server_instance_id,
                extension_instance_id=req.extension_instance_id,
            )

    @contextmanager
    def authorized_check(
        self,
        origin: str | None,
        authorization: str | None,
        *,
        x_api_key: str | None = None,
        now: float | None = None,
    ):
        """Verify exact Origin, dedicated Bearer token scope, rate budget and concurrency."""
        validated_origin = validate_extension_origin(origin)
        # Never allow the general X-API-Key on extension check endpoints (§2.2).
        if x_api_key is not None:
            raise ExtensionInputError(ERROR_PAIRING_INVALID)

        with self._lock:
            active = self._active
            if active is None:
                raise ExtensionInputError(ERROR_PAIRING_REQUIRED)
            if active.revoked or not active.token_sha256:
                raise ExtensionInputError(ERROR_PAIRING_INVALID)

        if not isinstance(authorization, str) or not authorization.startswith('Bearer '):
            raise ExtensionInputError(ERROR_PAIRING_REQUIRED)
        raw_token = authorization[len('Bearer '):]
        if not raw_token or raw_token != raw_token.strip() or ' ' in raw_token or not (16 <= len(raw_token) <= 128):
            raise ExtensionInputError(ERROR_PAIRING_INVALID)

        token_digest = _sha256_hex(raw_token)
        current_time = time.monotonic() if now is None else float(now)

        with self._lock:
            active = self._active
            if active is None or active.revoked or not active.token_sha256:
                raise ExtensionInputError(ERROR_PAIRING_INVALID)
            origin_ok = hmac.compare_digest(validated_origin, active.approved_origin)
            token_ok = hmac.compare_digest(token_digest, active.token_sha256)
            if not (origin_ok and token_ok):
                raise ExtensionInputError(ERROR_PAIRING_INVALID)

            if current_time - self._window_started_at >= 60.0 or current_time < self._window_started_at:
                self._window_started_at = current_time
                self._window_count = 0
            if self._window_count >= RATE_LIMIT_PER_MINUTE:
                raise ExtensionInputError(ERROR_LIMIT_EXCEEDED)
            if self._in_flight_checks >= MAX_CONCURRENT_CHECKS:
                raise ExtensionInputError(ERROR_LIMIT_EXCEEDED)
            self._window_count += 1
            self._in_flight_checks += 1

        try:
            yield self._server_instance_id
        finally:
            with self._lock:
                self._in_flight_checks = max(0, self._in_flight_checks - 1)


pairing_store = ExtensionPairingStore()
