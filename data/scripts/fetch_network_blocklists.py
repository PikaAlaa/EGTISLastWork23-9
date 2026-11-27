"""Fetch the network.windows N1 IP list and pin it (design network-windows-v1 §2.2, §9 step 5, §10 decision 1).

Run manually, only with the owner's approval:

    python data/scripts/fetch_network_blocklists.py            # download both lists, write the lock
    python data/scripts/fetch_network_blocklists.py --verify-only   # download nothing, check files vs lock

The app and the import never run this. Only one fixed abuse.ch URL is requested: the Feodo
Tracker "Botnet C2 IP Blocklist (recommended)", plain text (CC0, abuse.ch terms of use §3.4,
re-read 27 November 2026, docs/data-licences.md). The SSL Blacklist IP list is not fetched: its
file header says it was deprecated on 2025-01-03 (design §2.2 note of 27 November 2026).

No other host, no SSL Blacklist, no URLhaus, no aggressive variant, no API key, no upload. Each request is a plain
HTTPS GET with a generic user agent; nothing about the PC is sent and no redirect is followed.
A body is accepted only if it is text: no NUL byte, no executable or archive header, UTF-8, and
within a size limit. Files are written via a `.part` file under ignored
data/external/network-blocklists/, and data/network-blocklists-lock.json records source URL,
fetch time, size, SHA-256, IP row count, declared format, the list's own "Last updated" header
(`list_last_updated`) and the licence statement. The lock is
then loaded back with the engine's own loader, so a file the engine would refuse fails here.
Errors are printed as reason codes; list content is never printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.engines.network_windows import blocklists  # noqa: E402

LOCK = ROOT / 'data' / 'network-blocklists-lock.json'
DESTINATION = 'data/external/network-blocklists'
USER_AGENT = 'ETIS-Local-Research/0.2'
MAX_BYTES = 8 * 1024 * 1024
TERMS_URL = 'https://abuse.ch/terms-of-use/'
TERMS_READ = '2026-11-27'
LICENCE_STATEMENT = ('CC0: abuse.ch terms of use §3.4 "Feodo Tracker, SSL Blacklist, and YARAify are free to use '
                     'without limitations according to Creative Commons principles (CC0)"; re-read 2026-11-27 '
                     '(page last updated 21 October 2026).')
SOURCES = (
    {'name': 'feodo_tracker', 'host': 'feodotracker.abuse.ch',
     'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
     'page': 'https://feodotracker.abuse.ch/blocklist/', 'file': 'feodotracker_ipblocklist_recommended.txt',
     'format': 'ip_lines'},
)
NOT_FETCHED = {'ssl_blacklist': 'IP list deprecated on 2025-01-03 (its file header, seen 2026-11-27)'}
REFUSED_PREFIXES = (b'MZ', b'\x7fELF', b'PK\x03\x04', b'\x1f\x8b', b'%PDF', b'#!', b'\xca\xfe\xba\xbe',
                    b'\xcf\xfa\xed\xfe', b'Rar!', b'7z\xbc\xaf')
TEXT_TYPES = ('text/plain', 'text/csv', 'application/octet-stream')


class FetchError(RuntimeError):
    """Carries a fixed reason code only."""


def check_source(source: dict) -> None:
    parts = urlsplit(source['url'])
    if (parts.scheme != 'https' or parts.hostname != source['host'] or parts.port is not None
            or parts.query or parts.fragment or not parts.hostname.endswith('.abuse.ch')
            or source['name'] not in blocklists.ALLOWED):
        raise FetchError('source_not_allowed')


def check_text(body: bytes, content_type: str | None = None) -> None:
    """Refuse anything that is not plain text (design: plain text or CSV only, nothing executable)."""
    if content_type is not None:
        kind = content_type.split(';')[0].strip().lower()
        if kind and kind not in TEXT_TYPES:
            raise FetchError('not_text_content_type')
    if len(body) > MAX_BYTES:
        raise FetchError('download_too_large')
    if body.lstrip(b'\xef\xbb\xbf').startswith(REFUSED_PREFIXES):
        raise FetchError('executable_or_archive_refused')
    if b'\x00' in body:
        raise FetchError('binary_refused')
    try:
        body.decode('utf-8')
    except UnicodeDecodeError:
        raise FetchError('not_utf8_text') from None


def http_get(session, source: dict) -> bytes:
    check_source(source)
    with session.get(source['url'], headers={'User-Agent': USER_AGENT, 'Accept': 'text/plain'},
                     timeout=(10, 60), stream=True, allow_redirects=False) as response:
        if 300 <= response.status_code < 400:
            raise FetchError('redirect_refused')
        if response.status_code != 200:
            raise FetchError(f'http_status_{response.status_code}')
        body = bytearray()
        for chunk in response.iter_content(1 << 16):
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise FetchError('download_too_large')
        body = bytes(body)
        check_text(body, response.headers.get('Content-Type'))
        return body


def write_checked(target: Path, body: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + '.part')
    try:
        partial.write_bytes(body)
        os.replace(partial, target)
    finally:
        if partial.exists():
            partial.unlink()
    if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != hashlib.sha256(body).hexdigest():
        raise FetchError('removed_after_write')


def lock_entry(source: dict, body: bytes, fetched_at: str, root: Path) -> dict:
    spec = blocklists.ListSpec(name=source['name'], url=source['url'], fetched_at=fetched_at,
                               path=root / DESTINATION / source['file'], size=len(body),
                               sha256=hashlib.sha256(body).hexdigest(), rows=0, format=source['format'])
    ips, ignored = blocklists.parse_list(spec, body)
    return {'name': source['name'], 'url': source['url'], 'page': source['page'], 'fetched_at': fetched_at,
            'file': source['file'], 'size': len(body), 'sha256': spec.sha256, 'rows': len(ips),
            'format': source['format'], 'comment': '#', 'list_last_updated': blocklists.parse_last_updated(body),
            'ignored': ignored}


def build_lock(entries: list[dict]) -> dict:
    return {'schema': 'network-blocklists-lock-v1', 'destination': DESTINATION,
            'licence': LICENCE_STATEMENT, 'terms_url': TERMS_URL, 'terms_read': TERMS_READ,
            'approval': 'owner approval of 2026-11-27: Feodo Tracker IP list only (design §2.2)',
            'not_fetched': NOT_FETCHED,
            'use': 'network.windows N1 exact IP matching only; never to train, tune or evaluate a model',
            'lists': entries}


def verify(lock_path: Path = LOCK, root: Path = ROOT) -> blocklists.Blocklists:
    loaded = blocklists.load(lock_path, root)
    if loaded.errors:
        raise FetchError('verify_failed:' + ','.join(f'{n}={r}' for n, r in sorted(loaded.errors.items())))
    return loaded


def fetch(session, lock_path: Path = LOCK, root: Path = ROOT, now: datetime | None = None) -> dict:
    entries = []
    for source in SOURCES:
        body = http_get(session, source)
        fetched_at = (now or datetime.now(timezone.utc)).strftime('%Y-%m-%dT%H:%M:%SZ')
        write_checked(root / DESTINATION / source['file'], body)
        entries.append(lock_entry(source, body, fetched_at, root))
    lock = build_lock(entries)
    lock_path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    verify(lock_path, root)
    return lock


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--verify-only', action='store_true', help='download nothing; check files against the lock')
    args = parser.parse_args(argv)
    try:
        if not args.verify_only:
            import requests
            with requests.Session() as session:
                session.trust_env = False
                fetch(session)
        loaded = verify()
    except (FetchError, blocklists.BlocklistError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    except OSError:
        print('error: network_or_file_error', file=sys.stderr)
        return 1
    for name, spec in sorted(loaded.lists.items()):
        print(f'{name}: rows={spec.rows} size={spec.size} sha256={spec.sha256[:12]} fetched_at={spec.fetched_at} '
              f'list_last_updated={spec.list_last_updated}')
    ages = loaded.ages()
    print(f"fetch age days: {ages['fetch_age_days']}  source age days: {ages['source_age_days']}")
    for reason in loaded.health():
        print(f'health: {reason}')
    print(f'lock sha256: {loaded.lock_sha256}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
