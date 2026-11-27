"""Shared device names and server-side reference wrapping (design core-v2 §3.2, owner decisions Q13, Q16, Q17, Q19).

Two references exist for a device (and an account):

1. the **endpoint** ref, `hmac:<32 hex>`, computed where logs or files are read with the host
   pseudonym key (`app.engines.host.pseudonyms.Pseudonymizer`);
2. the **stored** ref, `srv:<32 hex>`, computed on the machine that holds the database with
   the server-only key `ETIS_SERVER_REF_KEY` before anything is stored.

Every device name goes through `local_device_name`, so the agent, the standalone commands
and the host import name one PC the same way. Nothing here resolves a name or contacts
anything; keys never appear in errors, logs or reprs.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import platform
import re
import socket
from pathlib import Path

SERVER_KEY_ENV = 'ETIS_SERVER_REF_KEY'
MIN_SERVER_KEY_BYTES = 32
ENDPOINT_REF = re.compile(r'^hmac:[0-9a-f]{32}$')
STORED_REF = re.compile(r'^srv:[0-9a-f]{32}$')
WELL_KNOWN_ACCOUNT_REFS = frozenset({'sid:S-1-5-18', 'sid:S-1-5-19', 'sid:S-1-5-20'})
PURPOSES = ('device', 'account')
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class RefError(ValueError):
    """Raised with a fixed reason code; never carries a reference, a name or a key."""


class ServerRefKeyError(RuntimeError):
    """Raised with `server_ref_key_missing` when no usable server key is configured."""


# ---------------------------------------------------------------- names

def local_device_name(raw) -> str | None:
    """The text before the first dot, stripped and lower-cased; None when empty.

    Applied alike to `socket.gethostname()`, `COMPUTERNAME`, `--device-name` and the EVTX
    `Computer` field. It cannot repair a NetBIOS name that Windows truncated (design V12).
    """
    if not isinstance(raw, str):
        return None
    short = raw.strip().split('.')[0].strip().lower()
    return short or None


def this_pc_name() -> str | None:
    """This PC's name in the fixed source order: gethostname(), COMPUTERNAME, platform.node()."""
    sources = (socket.gethostname, lambda: os.environ.get('COMPUTERNAME'), platform.node)
    for source in sources:
        try:
            name = local_device_name(source())
        except OSError:
            name = None
        if name:
            return name
    return None


def endpoint_device_ref(pseudonymizer, raw_name) -> str | None:
    """`hmac:` device ref of a raw name, or None when the name is empty."""
    name = local_device_name(raw_name)
    return pseudonymizer.host_ref(name) if name else None


def attach_device_ref(finding, host_key: bytes | None, raw_name=None):
    """Copy of `finding` with `evidence.details.device_ref` set to this PC's endpoint ref.

    Used by the agent wrapper and by standalone `scan_files.py` (Q16), after the engine ran,
    so the engine and its frozen rule stay unchanged. Without a host key or a name the
    finding is returned unchanged (no device).
    """
    if not host_key:
        return finding
    from app.engines.host.pseudonyms import Pseudonymizer
    ref = endpoint_device_ref(Pseudonymizer(host_key), raw_name if raw_name is not None else this_pc_name())
    if ref is None:
        return finding
    details = {**finding.evidence.details, 'device_ref': ref}
    evidence = finding.evidence.model_copy(update={'details': details})
    return finding.model_copy(update={'evidence': evidence})


# ---------------------------------------------------------------- server key and wrap

def load_server_key(env_file=None) -> bytes:
    """`ETIS_SERVER_REF_KEY` from the environment, else from the ignored `.env`. Never a default."""
    value = os.getenv(SERVER_KEY_ENV, '').strip()
    if not value:
        path = Path(env_file) if env_file is not None else PROJECT_ROOT / '.env'
        if path.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(path).get(SERVER_KEY_ENV) or '').strip()
    try:
        key = bytes.fromhex(value)
    except ValueError:
        key = b''
    if len(key) < MIN_SERVER_KEY_BYTES:
        raise ServerRefKeyError('server_ref_key_missing')
    return key


def server_key_or_none() -> bytes | None:
    """The server key for `record_findings`, or None when it is not configured."""
    try:
        return load_server_key()
    except ServerRefKeyError:
        return None


def load_host_key_optional(env_file=None) -> bytes | None:
    """`ETIS_HOST_PSEUDONYM_KEY` from the environment, else from `env_file` (default the project
    `.env`); None when absent or too short. Used to attach endpoint device refs (Q16)."""
    from app.engines.host.pseudonyms import KEY_ENV, MIN_KEY_BYTES
    value = os.getenv(KEY_ENV, '').strip()
    if not value:
        path = Path(env_file) if env_file is not None else PROJECT_ROOT / '.env'
        if path.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(path).get(KEY_ENV) or '').strip()
    try:
        key = bytes.fromhex(value)
    except ValueError:
        return None
    return key if len(key) >= MIN_KEY_BYTES else None


DEVICE_FIELDS = ('device_ref', 'host_ref')
ACCOUNT_FIELDS = ('account_ref',)
REF_FIELDS = DEVICE_FIELDS + ACCOUNT_FIELDS


def wrap_detail_refs(details: dict, key: bytes | None) -> tuple[dict, str | None, bool]:
    """(new details, stored device ref or None, changed) for one Finding's `evidence.details`.

    Accepts only endpoint `hmac:` refs (and well-known `sid:` account refs); a `srv:` ref is
    refused (`ref_prefix_invalid`) because only the server makes that form, and differing
    `device_ref`/`host_ref` are refused (`device_ref_conflict`). With `key` None every
    device and account ref is removed, so no `hmac:` ref is ever stored.
    """
    present = {f: details[f] for f in REF_FIELDS if details.get(f) is not None}
    if not present:
        return details, None, False
    for field, value in present.items():
        if not isinstance(value, str):
            raise RefError('ref_format_invalid')
        if value.startswith('srv:'):
            raise RefError('ref_prefix_invalid')
        if field in ACCOUNT_FIELDS and value in WELL_KNOWN_ACCOUNT_REFS:
            continue
        if not ENDPOINT_REF.match(value):
            raise RefError('ref_format_invalid')
    devices = {present[f] for f in DEVICE_FIELDS if f in present}
    if len(devices) > 1:
        raise RefError('device_ref_conflict')
    out = dict(details)
    if key is None:
        for field in present:
            out.pop(field)
        return out, None, True
    for field, value in present.items():
        out[field] = wrap_ref(value, 'account' if field in ACCOUNT_FIELDS else 'device', key)
    stored = next((out[f] for f in DEVICE_FIELDS if f in present), None)
    return out, stored, True


def wrap_refs(finding, key: bytes | None):
    """(Finding with stored refs, stored device ref or None). The Finding is frozen: a copy is built."""
    details, stored, changed = wrap_detail_refs(finding.evidence.details, key)
    if not changed:
        return finding, None
    evidence = finding.evidence.model_copy(update={'details': details})
    return finding.model_copy(update={'evidence': evidence}), stored


def wrap_ref(ref: str, purpose: str, key: bytes) -> str:
    """Stored `srv:` form of an endpoint `hmac:` ref; well-known `sid:` account refs unchanged."""
    if purpose not in PURPOSES:
        raise RefError('ref_purpose_invalid')
    if not isinstance(key, bytes) or len(key) < MIN_SERVER_KEY_BYTES:
        raise ServerRefKeyError('server_ref_key_missing')
    if not isinstance(ref, str):
        raise RefError('ref_format_invalid')
    if purpose == 'account' and ref in WELL_KNOWN_ACCOUNT_REFS:
        return ref
    if ref.startswith('srv:'):
        raise RefError('ref_prefix_invalid')
    if not ENDPOINT_REF.match(ref):
        raise RefError('ref_format_invalid')
    digest = hmac.new(key, f'{purpose}\0{ref}'.encode('utf-8'), hashlib.sha256).hexdigest()
    return 'srv:' + digest[:32]
