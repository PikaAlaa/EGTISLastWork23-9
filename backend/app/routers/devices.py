"""Operator device management `/devices/*` (design windows-agent-lan-v1 §5.3, §10 step 3).

`X-API-Key` only (reached through the console proxy as `/api/devices/*`); the agent bearer token is never
accepted here. Device and account references are shown and accepted only in the stored `srv:<32 hex>` form
(or well-known `sid:S-1-5-18/-19/-20`), never `hmac:`. Bodies are strict; errors are fixed codes; every
response carries `Cache-Control: no-store`.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_api_key
from app.routers.agent import read_body, refuse, respond
from app.services import agent_devices as service
from app.services.agent_schemas import AgentRequestError, parse_request

router = APIRouter(prefix='/devices', tags=['devices'], dependencies=[Depends(verify_api_key)])
OPERATOR_BODY_BYTES = 4096
Label = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_.-]{1,64}$')]
Reason = Annotated[str, StringConstraints(pattern=r'^[a-z0-9][a-z0-9_.:-]{0,99}$')]


class _Body(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class InviteBody(_Body):
    display_label: Label | None = None


class LabelBody(_Body):
    display_label: Label


class RevokeBody(_Body):
    reason: Reason | None = None


class PurgeBody(_Body):
    since: AwareDatetime
    reason: Reason


async def _body(request: Request, model, empty_ok: bool = False):
    raw = await read_body(request, OPERATOR_BODY_BYTES)
    if not raw and empty_ok:
        return model()
    return parse_request(model, raw)


def _run(db, action):
    try:
        return action()
    except AgentRequestError as exc:
        db.rollback()
        return refuse(exc.status, exc.code)


@router.get('')
def list_devices(db: Session = Depends(get_db_session), status: str | None = Query(default=None),
                 limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    return _run(db, lambda: respond(200, service.list_devices(db, status, limit, offset)))


@router.get('/{device_id}')
def device_detail(device_id: int, db: Session = Depends(get_db_session),
                  limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    return _run(db, lambda: respond(200, service.device_detail(db, device_id, limit, offset)))


@router.post('/pairing-invites')
async def create_invite(request: Request, db: Session = Depends(get_db_session)):
    try:
        body = await _body(request, InviteBody, empty_ok=True)
    except AgentRequestError as exc:
        return refuse(exc.status, exc.code)
    return _run(db, lambda: respond(200, service.create_invite(db, body.display_label)))


@router.patch('/{device_id}')
async def update_device(device_id: int, request: Request, db: Session = Depends(get_db_session)):
    try:
        body = await _body(request, LabelBody)
    except AgentRequestError as exc:
        return refuse(exc.status, exc.code)
    return _run(db, lambda: respond(200, service.update_label(db, device_id, body.display_label)))


@router.post('/{device_id}/revoke')
async def revoke_device(device_id: int, request: Request, db: Session = Depends(get_db_session)):
    try:
        body = await _body(request, RevokeBody, empty_ok=True)
    except AgentRequestError as exc:
        return refuse(exc.status, exc.code)
    return _run(db, lambda: respond(200, service.revoke(db, device_id, body.reason)))


@router.post('/{device_id}/purge-findings')
async def purge_findings(device_id: int, request: Request, db: Session = Depends(get_db_session)):
    try:
        body = await _body(request, PurgeBody)
    except AgentRequestError as exc:
        return refuse(exc.status, exc.code)
    return _run(db, lambda: respond(200, service.purge_findings(db, device_id, body.since, body.reason)))
