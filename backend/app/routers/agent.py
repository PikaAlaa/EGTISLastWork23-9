"""LAN agent ingestion API `/agent/v1/*` (design windows-agent-lan-v1 §5.1, §5.2, §10 step 3).

Authenticated only by a per-device bearer token (`/pair` by a one-use pairing code); `X-API-Key` is never
accepted here, and these routes are never exposed through the console proxy. Bodies are read with a hard
limit, parsed strictly, and refused with fixed reason codes that never echo a submitted value. Every
response carries `Cache-Control: no-store`.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.services import agent_devices as service
from app.services.agent_schemas import (MAX_BODY_BYTES, AgentBatchRequest, AgentHeartbeatRequest, AgentPairRequest,
                                        AgentRequestError, AgentUnpairRequest, parse_request)

router = APIRouter(prefix='/agent/v1', tags=['agent'])
NO_STORE = {'Cache-Control': 'no-store'}
log = logging.getLogger(__name__)


def respond(status: int, content: dict) -> JSONResponse:
    return JSONResponse(status_code=status, content=content, headers=NO_STORE)


def refuse(status: int, code: str) -> JSONResponse:
    return respond(status, {'error': code, 'detail': code})


async def read_body(request: Request, limit: int = MAX_BODY_BYTES) -> bytes:
    if request.url.query:
        raise AgentRequestError(400, 'invalid_input')
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise AgentRequestError(413, 'limit_exceeded')
        chunks.append(chunk)
    return b''.join(chunks)


async def _handle(request: Request, db: Session, model, action, authenticated: bool = True) -> JSONResponse:
    try:
        raw = await read_body(request)
        device = service.authenticate(db, request.headers.get('authorization')) if authenticated else None
        parsed = parse_request(model, raw)
        return respond(200, action(device, parsed))
    except AgentRequestError as exc:
        db.rollback()
        return refuse(exc.status, exc.code)
    except SQLAlchemyError:
        db.rollback()
        log.warning('agent_request_database_unavailable')
        return refuse(503, 'database_unavailable')
    except Exception:
        db.rollback()
        log.warning('agent_request_failed')
        return refuse(503, 'service_unavailable')


@router.post('/pair')
async def pair(request: Request, db: Session = Depends(get_db_session)):
    client_ip = request.client.host if request.client else 'unknown'
    return await _handle(request, db, AgentPairRequest, lambda _, req: service.pair(db, req, client_ip),
                         authenticated=False)


@router.post('/batches')
async def batches(request: Request, db: Session = Depends(get_db_session)):
    return await _handle(request, db, AgentBatchRequest, lambda device, req: service.ingest_batch(db, device, req))


@router.post('/heartbeat')
async def heartbeat(request: Request, db: Session = Depends(get_db_session)):
    return await _handle(request, db, AgentHeartbeatRequest, lambda device, req: service.heartbeat(db, device, req))


@router.post('/unpair')
async def unpair(request: Request, db: Session = Depends(get_db_session)):
    return await _handle(request, db, AgentUnpairRequest, lambda device, _: service.unpair(db, device))
