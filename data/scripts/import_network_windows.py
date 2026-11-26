"""Import Windows network logs the owner exported into network.windows (design network-windows-v1 §1.3, §6, §7).

    python data/scripts/import_network_windows.py --dns-evtx C:\\exports\\dns.evtx
        [--firewall-log C:\\exports\\pfirewall.log] [--sysmon-evtx C:\\exports\\sysmon.evtx]
        [--snapshots var\\network-snapshots\\snapshot-....jsonl] [--local-net 192.168.1.0/24]
        [--device-name NAME] [--utc-offset +02:00]

The engine runs only when its shipped-item manifest (data/network-windows-shipped.json) verifies.
Without one, the command refuses before reading any file and reports the health reason. Files
are read in place and never copied. Names are replaced by keyed references right after reading
(ETIS_HOST_PSEUDONYM_KEY, created by scripts/initialize.py in the ignored .env). Findings go
through the core record_findings path, together with one network_windows_imports row that holds
counts, digests and coverage only. Records that did not alert are counted and dropped. Nothing
is printed about destinations.

Read-only: it never turns a log on, changes a firewall setting or creates a scheduled task, and
it makes no network call. When run as a script, socket connections are blocked in this process.
Exported DNS and firewall logs are personal data (browsing history): keep them private.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.engines.host.pseudonyms import KEY_ENV, MIN_KEY_BYTES, HostKeyError, Pseudonymizer  # noqa: E402
from app.engines.host.pseudonyms import parse_local_nets  # noqa: E402
from app.engines.network_windows import engine as nw_engine  # noqa: E402
from app.engines.network_windows.devices import DeviceNameError, default_device_name, pseudonymise  # noqa: E402
from app.engines.network_windows.readers import NetworkWindowsInputError, read_import  # noqa: E402
from app.engines.registry import Observation  # noqa: E402

EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE = 0, 2, 3
OFFSET = re.compile(r'^([+-])(\d{2}):(\d{2})$')
WARNING = ('Note: exported DNS and firewall logs are personal data (browsing history). Keep them private '
           'and never share them. ETIS stores only counts, digests and the alerted destinations as hashes.')


def block_network() -> None:
    """Process-wide: no socket may connect while the command runs."""
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_import_network_windows')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


def load_key(env_file=None) -> bytes:
    """The host key from the environment, else from the ignored `.env`. Never a default key."""
    value = os.getenv(KEY_ENV, '').strip()
    if not value:
        path = Path(env_file) if env_file is not None else ROOT / '.env'
        if path.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(path).get(KEY_ENV) or '').strip()
    try:
        key = bytes.fromhex(value)
    except ValueError:
        key = b''
    if len(key) < MIN_KEY_BYTES:
        raise HostKeyError('host_pseudonym_key_missing')
    return key


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--dns-evtx', action='append', default=[])
    parser.add_argument('--firewall-log', action='append', default=[])
    parser.add_argument('--sysmon-evtx', action='append', default=[])
    parser.add_argument('--snapshots', action='append', default=[])
    parser.add_argument('--local-net', action='append', default=[])
    parser.add_argument('--device-name')
    parser.add_argument('--utc-offset', help='time zone of pfirewall.log times, e.g. +02:00 (default: this PC)')
    args = parser.parse_args(argv)
    if not (args.dns_evtx or args.firewall_log or args.sysmon_evtx or args.snapshots):
        parser.error('give at least one input file')
    return args


def _offset(value: str | None):
    if value is None:
        return None
    match = OFFSET.match(value)
    if not match:
        raise ValueError('invalid_utc_offset')
    sign = 1 if match.group(1) == '+' else -1
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    if delta > timedelta(hours=14):
        raise ValueError('invalid_utc_offset')
    return timezone(sign * delta)


def _naive(value: str | datetime | None):
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def run_import(args, *, db, engine, pseudonymizer, out, local_nets=(), local_tz=None) -> dict:
    from app.engines.network_windows.store import indicator_domain_hashes
    from app.models import NetworkWindowsImport
    from app.services.findings import record_findings

    result = read_import(args.dns_evtx, args.firewall_log, args.sysmon_evtx, args.snapshots,
                         local_nets=local_nets, local_tz=local_tz)
    pseudonymise(result, pseudonymizer, args.device_name or default_device_name())
    started = datetime.now(timezone.utc)
    row = NetworkWindowsImport(started_at=_naive(started), engine_version=engine.version,
                               manifest_sha256=engine.shipped.sha256 if engine.shipped else None,
                               lists_lock_sha256=engine.lists.lock_sha256 if engine.shipped_lists else None,
                               files=[], counts={}, coverage={}, findings_by_kind={})
    db.add(row)
    db.flush()
    try:
        outcome = engine.process(Observation(
            kind=nw_engine.OBSERVATION_KIND, source_ref=f'{nw_engine.SOURCE_PREFIX}{row.id}', observed_at=started,
            data={'read': result, 'local_nets': local_nets, 'indicator_domain_hashes': indicator_domain_hashes(db)}))
        record_findings(db, outcome.findings)
        summary = result.summary()
        spans = [t for span in summary['spans'].values() for t in span]
        by_kind = dict(sorted(Counter(f.kind for f in outcome.findings).items()))
        row.finished_at = _naive(datetime.now(timezone.utc))
        row.span_first, row.span_last = (_naive(min(spans)), _naive(max(spans))) if spans else (None, None)
        row.files = summary['files']
        row.counts = {'events': summary['counts'], 'skipped': summary['skipped'], 'alerts': outcome.alerts,
                      'records_dropped': len(result.dns) + len(result.connections)}
        row.coverage = {**outcome.coverage, 'not_run': outcome.not_run}
        row.findings_by_kind = by_kind
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        # Non-alerting records are dropped with the import (§7): nothing below keeps them.
        result.dns.clear()
        result.connections.clear()
        result.process_hashes.clear()
    report = {'network_windows_import_id': row.id, 'engine_version': engine.version, 'findings_by_kind': by_kind,
              'events': row.counts['events'], 'skipped': row.counts['skipped'],
              'not_visible': row.coverage['not_visible'], 'not_run': row.coverage['not_run']}
    print(json.dumps(report, indent=2), file=out)
    print(WARNING, file=out)
    return report


def main(argv=None, *, session_factory=None, engine=None, target_registry=None, out=None, env_file=None) -> int:
    args = parse_args(argv)
    out = out or sys.stdout
    try:
        key = load_key(env_file)
    except HostKeyError as exc:
        print(f'refused: {exc} (run scripts/initialize.py to create it in the ignored .env)', file=sys.stderr)
        return EXIT_REFUSED
    try:
        local_nets, local_tz = parse_local_nets(args.local_net), _offset(args.utc_offset)
    except ValueError as exc:   # fixed codes only: invalid_local_net, invalid_utc_offset
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    engine = engine if engine is not None else nw_engine.load_engine()
    if not engine.registrable:
        print('unavailable: ' + json.dumps(engine.health()), file=sys.stderr)
        return EXIT_UNAVAILABLE
    if target_registry is None:
        from app.engines.registry import registry as target_registry
    if nw_engine.ENGINE_NAME in target_registry.names():
        if target_registry.get(nw_engine.ENGINE_NAME) is not engine:
            print('refused: engine_already_registered', file=sys.stderr)
            return EXIT_REFUSED
    elif nw_engine.register(target_registry, engine) is None:
        print('unavailable: ' + json.dumps(engine.health()), file=sys.stderr)
        return EXIT_UNAVAILABLE
    if session_factory is None:
        from app.core.database import SessionLocal as session_factory
    try:
        with session_factory() as db:
            run_import(args, db=db, engine=engine, pseudonymizer=Pseudonymizer(key), out=out,
                       local_nets=local_nets, local_tz=local_tz)
    except (NetworkWindowsInputError, DeviceNameError) as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    return EXIT_OK


if __name__ == '__main__':
    block_network()
    sys.exit(main())
