"""Convert device and account refs stored before core v2 to their server-wrapped srv: form (design core-v2 §3.2, Q20).

    python data/scripts/rewrap_device_refs.py

Run once after scripts/initialize.py has created ETIS_SERVER_REF_KEY. For every stored finding
whose evidence still holds an endpoint `hmac:` device_ref, host_ref or account_ref, it rewrites
them with the same wrap used by record_findings and fills finding_devices. Values already in
`srv:` or well-known `sid:` form are left as they are, so a second run changes nothing. A
finding whose refs cannot be wrapped (conflicting device_ref and host_ref, or a malformed
value) is counted and left untouched. Only counts are printed; no reference is ever printed.

Migration 009 cannot do this because a migration must not need a secret. Offline: no network
call; when run as a script, socket connections are blocked in this process.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.core.device_names import (DEVICE_FIELDS, REF_FIELDS, STORED_REF, RefError, ServerRefKeyError,  # noqa: E402
                                   load_server_key, wrap_detail_refs)

EXIT_OK, EXIT_REFUSED = 0, 2
AGENT_SOURCE_PREFIX = 'agent_devices:'


def block_network() -> None:
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_rewrap_device_refs')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


def _stored_device(details: dict) -> str | None:
    return next((details[f] for f in DEVICE_FIELDS if isinstance(details.get(f), str) and STORED_REF.match(details[f])),
                None)


def rewrap(db, key: bytes) -> dict:
    from app.models import FindingDevice, FindingRecord
    counts = Counter()
    for record in db.query(FindingRecord).order_by(FindingRecord.id):
        evidence = record.evidence or {}
        details = evidence.get('details') or {}
        if not any(details.get(f) is not None for f in REF_FIELDS):
            continue
        counts['findings_with_refs'] += 1
        pending = {f: details[f] for f in REF_FIELDS
                   if isinstance(details.get(f), str) and details[f].startswith('hmac:')}
        if pending:
            # Only the hmac: fields are wrapped; srv: and sid: values stay as they are.
            try:
                wrapped, _, _ = wrap_detail_refs(pending, key)
            except RefError as exc:
                counts[f'skipped_{exc}'] += 1
                continue
            new_details = {**details, **wrapped}
            devices = {new_details[f] for f in DEVICE_FIELDS if new_details.get(f) is not None}
            if len(devices) > 1:
                counts['skipped_device_ref_conflict'] += 1
                continue
            record.evidence = {**evidence, 'details': new_details}
            details = new_details
            counts['rewritten'] += 1
        else:
            counts['already_stored_form'] += 1
        stored = _stored_device(details)
        if stored and db.get(FindingDevice, record.id) is None:
            attributed = 'agent' if (record.source_ref or '').startswith(AGENT_SOURCE_PREFIX) else 'engine_details'
            db.add(FindingDevice(finding_id=record.id, device_ref=stored, attributed_by=attributed))
            counts['finding_devices_added'] += 1
    db.commit()
    return dict(sorted(counts.items()))


def main(argv=None, *, session_factory=None, env_file=None, out=None) -> int:
    out = out or sys.stdout
    try:
        key = load_server_key(env_file)
    except ServerRefKeyError as exc:
        print(f'refused: {exc} (run scripts/initialize.py to create it in the ignored .env)', file=sys.stderr)
        return EXIT_REFUSED
    if session_factory is None:
        from app.core.database import SessionLocal as session_factory
    with session_factory() as db:
        counts = rewrap(db, key)
    print(json.dumps({'rewrap_device_refs': counts}, indent=2), file=out)
    return EXIT_OK


if __name__ == '__main__':
    block_network()
    sys.exit(main(sys.argv[1:]))
