"""Local browser extension v1 API router: pairing, revocation and stateless check.

Design: docs/design/browser-extension-v1.md (§2.2, §2.3, §2.4, §6, §7, §9 step 3).
- Literal Host header `127.0.0.1:8000` is enforced on every route.
- Exact operator-approved `chrome-extension://<id>` Origin is enforced on `/pair` and `/check`.
- No wildcard CORS, Origin reflection, `null`-origin exemption or cookie/X-API-Key fallback.
- All responses carry `Cache-Control: no-store`.
- All errors return fixed error codes without echoing any submitted value or logging URLs/hashes.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.services.extension_config import (
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PAIRING_INVALID,
    ERROR_PAIRING_REQUIRED,
    ERROR_PROTOCOL_MISMATCH,
    ERROR_SERVICE_UNAVAILABLE,
    MAX_BODY_BYTES,
    ExtensionInputError,
    validate_extension_origin,
    validate_host_header,
)
from app.services.extension_pairing import pairing_store
from app.services.extension_scoring import evaluate_extension_url, parse_check_request

router = APIRouter(prefix='/extension/v1', tags=['extension'])
NO_STORE_HEADERS = {'Cache-Control': 'no-store'}
_EXTENSION_LOG_MARKERS = ('/extension/v1', 'extension/v1')


class ExtensionAccessLogFilter(logging.Filter):
    """Drop uvicorn access-log and app log records touching /extension/v1/* (design §7, §9 #4)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            raw_msg = str(record.msg or '')
            if any(marker in raw_msg for marker in _EXTENSION_LOG_MARKERS):
                return False
            args = record.args
            if isinstance(args, tuple):
                for item in args:
                    if isinstance(item, str) and any(marker in item for marker in _EXTENSION_LOG_MARKERS):
                        return False
            elif isinstance(args, dict):
                for item in args.values():
                    if isinstance(item, str) and any(marker in item for marker in _EXTENSION_LOG_MARKERS):
                        return False
            rendered = record.getMessage()
            if any(marker in rendered for marker in _EXTENSION_LOG_MARKERS):
                return False
        except Exception:
            return False
        return True


_LOG_FILTER = ExtensionAccessLogFilter()


def install_extension_log_filter() -> ExtensionAccessLogFilter:
    """Attach ExtensionAccessLogFilter idempotently to uvicorn and root loggers."""
    for name in ('uvicorn.access', 'uvicorn.error', 'uvicorn', 'fastapi', ''):
        target_logger = logging.getLogger(name)
        if not any(isinstance(f, ExtensionAccessLogFilter) for f in target_logger.filters):
            target_logger.addFilter(_LOG_FILTER)
    return _LOG_FILTER


install_extension_log_filter()


def _json_response(status_code: int, content: dict[str, object]) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=content, headers=NO_STORE_HEADERS)


def _error_status(code: str, *, forbidden: bool = False) -> int:
    if forbidden:
        return 403
    if code in (ERROR_PAIRING_REQUIRED, ERROR_PAIRING_INVALID):
        return 401
    if code in (ERROR_INPUT_INVALID, ERROR_PROTOCOL_MISMATCH):
        return 400
    if code == ERROR_LIMIT_EXCEEDED:
        return 413
    return 503


def _error_response(code: str, *, status_code: int | None = None, forbidden: bool = False) -> JSONResponse:
    status = status_code if status_code is not None else _error_status(code, forbidden=forbidden)
    return _json_response(status, {'error': code, 'detail': code})


async def _read_bounded_body(request: Request) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise ExtensionInputError(ERROR_LIMIT_EXCEEDED)
        chunks.append(chunk)
    return b''.join(chunks)


def _enforce_host_and_no_query(request: Request) -> None:
    validate_host_header(request.headers.get('host'))
    if request.url.query:
        raise ExtensionInputError(ERROR_INPUT_INVALID)


@router.post('/pairing-secret', dependencies=[Depends(verify_api_key)])
async def create_pairing_secret(request: Request):
    """Operator-only local endpoint to approve an exact extension Origin and mint a one-use secret."""
    try:
        validate_host_header(request.headers.get('host'))
    except ExtensionInputError as exc:
        return _error_response(exc.code, forbidden=True)
    if request.url.query:
        return _error_response(ERROR_INPUT_INVALID, status_code=400)
    try:
        raw_body = await _read_bounded_body(request)
        payload = pairing_store.issue_pairing_secret(raw_body)
        return _json_response(200, payload)
    except ExtensionInputError as exc:
        return _error_response(exc.code)
    except Exception:
        return _error_response(ERROR_SERVICE_UNAVAILABLE, status_code=503)


@router.post('/revoke', dependencies=[Depends(verify_api_key)])
async def revoke_extension_pairing(request: Request):
    """Operator-only local endpoint to revoke the active extension token."""
    try:
        validate_host_header(request.headers.get('host'))
    except ExtensionInputError as exc:
        return _error_response(exc.code, forbidden=True)
    if request.url.query:
        return _error_response(ERROR_INPUT_INVALID, status_code=400)
    return _json_response(200, pairing_store.revoke())


@router.get('/status', dependencies=[Depends(verify_api_key)])
async def extension_pairing_status(request: Request):
    """Operator-only local endpoint returning pairing status (zero URL/check history)."""
    try:
        validate_host_header(request.headers.get('host'))
    except ExtensionInputError as exc:
        return _error_response(exc.code, forbidden=True)
    if request.url.query:
        return _error_response(ERROR_INPUT_INVALID, status_code=400)
    return _json_response(200, pairing_store.status())


@router.post('/pair')
async def pair_extension(request: Request):
    """Exchange a one-use pairing secret for a token bound to the operator-approved extension Origin."""
    try:
        validate_host_header(request.headers.get('host'))
        origin = validate_extension_origin(request.headers.get('origin'))
    except ExtensionInputError as exc:
        return _error_response(exc.code, forbidden=True)
    if request.url.query:
        return _error_response(ERROR_INPUT_INVALID, status_code=400)
    try:
        raw_body = await _read_bounded_body(request)
        response = pairing_store.exchange_pairing_secret(origin, raw_body)
        return _json_response(200, response.model_dump(mode='json'))
    except ExtensionInputError as exc:
        return _error_response(exc.code)
    except Exception:
        return _error_response(ERROR_SERVICE_UNAVAILABLE, status_code=503)


@router.post('/check')
async def check_extension_url(request: Request, db: Session = Depends(get_db_session)):
    """Stateless URL check for the paired extension; never persists or logs URLs or hashes."""
    try:
        validate_host_header(request.headers.get('host'))
        origin = validate_extension_origin(request.headers.get('origin'))
    except ExtensionInputError as exc:
        return _error_response(exc.code, forbidden=True)
    if request.url.query:
        return _error_response(ERROR_INPUT_INVALID, status_code=400)

    try:
        with pairing_store.authorized_check(
            origin,
            request.headers.get('authorization'),
            x_api_key=request.headers.get('x-api-key'),
        ) as server_instance_id:
            raw_body = await _read_bounded_body(request)
            check_req = parse_check_request(raw_body)
            result = evaluate_extension_url(db, check_req, server_instance_id=server_instance_id)
            return _json_response(200, result.model_dump(mode='json'))
    except ExtensionInputError as exc:
        return _error_response(exc.code)
    except Exception:
        return _error_response(ERROR_SERVICE_UNAVAILABLE, status_code=503)
