"""Scan files the user names on their own PC with the malware.files engine (design malware-engine-v1 §1.2, §6.1, §7).

    python data/scripts/scan_files.py --path <file or folder> [--recursive]
    python data/scripts/scan_files.py --find <path_ref> --path <folder>

Scan: walks the target with the read-only walker, loads layer a (hash lists pinned by
data/malware-hashlists-lock.json) and layer b (YARA rules pinned by data/yara-lock.json), and layer c
only when a model under ml/models/malware/ passes its lock (otherwise `model: none`). The engine is
registered here, never at import. Findings go through the core record_findings path with one
malware_scans row (times, versions, counts). The local paths of flagged files are printed to this
terminal only: they are never logged, stored or sent.

Find: recomputes path_ref for every file under the folder (reparse points are not followed) and prints
the paths that match, to this terminal only.

Read-only: nothing is executed, deleted, moved, copied or quarantined; use your installed antivirus for
remediation. The command refuses to run without ETIS_MALWARE_PSEUDONYM_KEY (scripts/initialize.py
creates it in the ignored .env) and makes no network call; when run as a script, socket connections are
blocked in this process.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.core.indicators import sha256_hex  # noqa: E402
from app.engines.malware import engine as malware_engine  # noqa: E402
from app.engines.malware.engine import ENGINE_NAME, OBSERVATION_KIND, SOURCE_PREFIX  # noqa: E402
from app.engines.malware.hashlists import HashListError, specs_from_lock  # noqa: E402
from app.core.device_names import load_host_key_optional  # noqa: E402
from app.engines.malware.paths import MalwareKeyError, PathContext, PathPseudonymizer, load_key  # noqa: E402
from app.engines.malware.walker import WalkError, is_reparse_point, walk  # noqa: E402
from app.engines.registry import Observation  # noqa: E402

MODEL_DIR = malware_engine.MODEL_DIR
PATH_REF = re.compile(r'^hmac:[0-9a-f]{32}$')
EXIT_OK, EXIT_REFUSED, EXIT_NO_LAYER = 0, 2, 3


def block_network() -> None:
    """Process-wide: no socket may connect while the command runs."""
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_scan_files')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


load_model = malware_engine.load_model


def build_engine(model_loader=None, hashes_lock: Path = malware_engine.HASHLISTS_LOCK,
                 yara_lock: Path = malware_engine.YARA_LOCK, model_dir: Path = MODEL_DIR, root: Path = ROOT):
    try:
        specs = specs_from_lock(hashes_lock, root)
    except HashListError:
        specs = []
    model, expected = load_model(model_dir, model_loader)
    return malware_engine.load_engine(specs, model, expected, yara_lock=yara_lock, hashes_lock=hashes_lock)


def _utc_naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def run_scan(target, recursive: bool, *, db, engine, pseudonymizer, context, out, host_key=None) -> dict:
    from app.core.device_names import attach_device_ref
    from app.models import MalwareScan
    from app.services.findings import record_findings

    walked = walk(target, recursive=recursive)
    started = datetime.now(timezone.utc)
    row = MalwareScan(started_at=_utc_naive(started), engine_version=engine.version, yara_lock=engine.yara_lock,
                      hashes_lock=engine.hashes_lock, model_id=engine.model_id, counts={}, findings_by_kind={})
    db.add(row)
    db.flush()
    try:
        outcome = engine.scan(Observation(kind=OBSERVATION_KIND, source_ref=f'{SOURCE_PREFIX}{row.id}',
                                          observed_at=started, data={'files': walked.files,
                                                                     'pseudonymizer': pseudonymizer,
                                                                     'path_context': context}))
        # Design core-v2 §3.2 (Q16): the endpoint device ref of this PC, attached after the engine ran
        # (the frozen engine is unchanged) and wrapped to srv: by record_findings. No host key, no device.
        record_findings(db, [attach_device_ref(f, host_key) for f in outcome.findings])
        by_kind = dict(sorted(Counter(f.kind for f in outcome.findings).items()))
        row.finished_at = _utc_naive(datetime.now(timezone.utc))
        row.counts = {'walk': walked.counts, 'engine': outcome.counts}
        row.findings_by_kind = by_kind
        db.commit()
    except Exception:
        db.rollback()
        raise
    summary = {'malware_scan_id': row.id, 'engine_version': engine.version, 'findings_by_kind': by_kind,
               'walk': walked.counts, 'engine': outcome.counts}
    print(json.dumps(summary, indent=2), file=out)
    if outcome.findings:
        paths_by_hash: dict[str, list[str]] = {}
        for item in walked.files:
            paths_by_hash.setdefault(sha256_hex(item.hashes.sha256.lower()), []).append(item.path)
        print('\nFlagged files (shown on this terminal only; paths are never stored or logged):', file=out)
        for finding in outcome.findings:
            details = finding.evidence.details
            print(f'- {finding.kind} severity={finding.severity} confidence={finding.confidence} '
                  f'path_ref={details["path_ref"]}', file=out)
            for path in paths_by_hash.get(finding.indicators[0].value_hash, []):
                print(f'    {path}', file=out)
        print('\nETIS only reads files. Use your installed antivirus to check or remove them.', file=out)
    return summary


def find_path_ref(path_ref: str, folder, pseudonymizer) -> list[str]:
    """Paths under `folder` whose path_ref equals `path_ref`. Reparse points are never followed."""
    found, stack = [], [os.path.abspath(os.fspath(folder))]
    try:
        if is_reparse_point(os.lstat(stack[0])):
            return []
    except OSError:
        raise WalkError('target_unreadable') from None
    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
        except OSError:
            continue
        if is_reparse_point(st):
            continue
        if stat.S_ISREG(st.st_mode):
            if pseudonymizer.path_ref(current) == path_ref:
                found.append(current)
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        try:
            with os.scandir(current) as entries:
                stack.extend(sorted((e.path for e in entries), reverse=True))
        except OSError:
            continue
    return found


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Scan local files with the ETIS malware.files engine (read-only).')
    parser.add_argument('--path', required=True, help='file or folder to scan, or the folder to search with --find')
    parser.add_argument('--recursive', action='store_true', help='include sub-folders')
    parser.add_argument('--find', metavar='PATH_REF', help='print the local paths whose path_ref matches')
    return parser.parse_args(argv)


def main(argv=None, *, session_factory=None, engine=None, target_registry=None, context=None, out=None,
         env_file=None, model_loader=None) -> int:
    args = parse_args(argv)
    out = out or sys.stdout
    try:
        key = load_key(env_file)
    except MalwareKeyError as exc:
        print(f'refused: {exc} (run scripts/initialize.py to create it in the ignored .env)', file=sys.stderr)
        return EXIT_REFUSED
    context = context or PathContext.from_system()
    pseudonymizer = PathPseudonymizer(key, context)
    if args.find is not None:
        if not PATH_REF.match(args.find):
            print('refused: invalid_path_ref', file=sys.stderr)
            return EXIT_REFUSED
        try:
            found = find_path_ref(args.find, args.path, pseudonymizer)
        except WalkError as exc:
            print(f'refused: {exc}', file=sys.stderr)
            return EXIT_REFUSED
        print(f'{len(found)} file(s) with this path_ref (shown on this terminal only):', file=out)
        for path in found:
            print(f'    {path}', file=out)
        return EXIT_OK

    if target_registry is None:
        from app.engines.registry import registry as target_registry
    engine = engine if engine is not None else build_engine(model_loader)
    if target_registry.names().count(ENGINE_NAME):
        registered = target_registry.get(ENGINE_NAME)
        if registered is not engine:
            print('refused: engine_already_registered', file=sys.stderr)
            return EXIT_REFUSED
    elif malware_engine.register(target_registry, engine) is None:
        print('refused: no_layer_available ' + json.dumps(engine.health()), file=sys.stderr)
        return EXIT_NO_LAYER
    if session_factory is None:
        from app.core.database import SessionLocal as session_factory
    try:
        with session_factory() as db:
            run_scan(args.path, args.recursive, db=db, engine=engine, pseudonymizer=pseudonymizer,
                     context=context, out=out, host_key=load_host_key_optional(env_file))
    except WalkError as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    finally:
        engine.close()
    return EXIT_OK


if __name__ == '__main__':
    block_network()
    sys.exit(main())
