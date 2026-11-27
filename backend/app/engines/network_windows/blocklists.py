"""Offline IP blocklists for N1 (design network-windows-v1 §2.2, §6.8, §10 decision 1).

The loader accepts only abuse.ch **Feodo Tracker** and **SSL Blacklist** IP lists (CC0, abuse.ch
terms of use §3.4, re-read 27 November 2026). v1 fetches and pins Feodo Tracker alone: the SSL
Blacklist IP list was found deprecated on 2025-01-03 (its file header), so it is not fetched (§2.2
note of 27 November 2026). URLhaus and any other list are refused. This module
only loads files already on disk; nothing here downloads anything, and the import never
fetches. The fetch command is a later step that needs the owner's approval, and the list
formats are still to verify (§11 L1-L2). The loader therefore accepts two simple, declared
formats and refuses everything else.

Lock `data/network-blocklists-lock.json` (absent until the owner approves a fetch):

    {"destination": "data/external/network-blocklists",
     "lists": [{"name": "feodo_tracker" | "ssl_blacklist", "url": "https://...", "fetched_at": "<UTC ISO>",
                "file": "<name inside destination>", "size": <bytes>, "sha256": "<hex>", "rows": <IP rows>,
                "format": "ip_lines" | "csv", optional "column": <0-based>, "delimiter": ",",
                "comment": "#", optional "list_last_updated": "<UTC ISO>" (the list's own header)}]}

Health (§6.8 note of 27 November 2026) reports two ages: our fetch age (`blocklists_stale` after
7 days) and the source's own age from its "Last updated" header (`blocklist_source_stale` after
30 days). The second is informational only; it changes no detection rule.

A list loads only if its size, SHA-256 and IP row count equal the lock; otherwise it is
refused with a reason code and the other list still loads. Exact IP matching only: CIDR
ranges and non-IP rows are counted and ignored, and local addresses are never matched.
Errors carry reason codes only.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.engines.network_windows.readers import locality, normalise_ip

ROOT = Path(__file__).resolve().parents[4]
LOCK = ROOT / 'data' / 'network-blocklists-lock.json'
STALE_AFTER = timedelta(days=7)
SOURCE_STALE_AFTER = timedelta(days=30)
_LAST_UPDATED = re.compile(r'^#\s*Last updated:\s*(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC(?=[ \t#]|$)', re.MULTILINE)
LICENCE = 'CC0 (abuse.ch terms of use §3.4)'
ALLOWED = {
    'feodo_tracker': {'title': 'abuse.ch Feodo Tracker IP blocklist', 'link': 'https://feodotracker.abuse.ch/blocklist/'},
    'ssl_blacklist': {'title': 'abuse.ch SSL Blacklist IP list', 'link': 'https://sslbl.abuse.ch/blacklist/'},
}
FORMATS = ('ip_lines', 'csv')
MAX_LIST_BYTES = 64 * 1024 * 1024


class BlocklistError(ValueError):
    """Raised with a fixed reason code; never carries list content or paths."""


@dataclass(frozen=True)
class ListSpec:
    name: str
    url: str
    fetched_at: str
    path: Path = field(repr=False)
    size: int
    sha256: str
    rows: int
    format: str
    column: int = 0
    delimiter: str = ','
    comment: str = '#'
    list_last_updated: str | None = None

    @property
    def version(self) -> str:
        return f'{self.fetched_at}+sha256:{self.sha256[:12]}'

    def attribution(self) -> dict:
        info = ALLOWED[self.name]
        return {'list': self.name, 'title': info['title'], 'version': self.version, 'licence': LICENCE,
                'link': info['link']}


@dataclass
class Blocklists:
    lists: dict[str, ListSpec] = field(default_factory=dict)
    ips: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    errors: dict[str, str] = field(default_factory=dict)
    ignored: dict[str, dict[str, int]] = field(default_factory=dict)
    lock_sha256: str | None = None

    def lookup(self, ip: str) -> tuple[str, ...]:
        return self.ips.get(normalise_ip(ip) or '', ())

    def attribution(self, name: str) -> dict:
        return self.lists[name].attribution()

    def ages(self, now: datetime | None = None) -> dict:
        """Days since our newest fetch and since the newest source "Last updated" header (None if unknown)."""
        now = now or datetime.now(timezone.utc)
        fetched = [_parse_time(s.fetched_at) for s in self.lists.values()]
        updated = [_parse_time(s.list_last_updated) for s in self.lists.values() if s.list_last_updated]
        days = lambda moments: round((now - max(moments)).total_seconds() / 86400, 2) if moments else None  # noqa: E731
        return {'fetch_age_days': days(fetched), 'source_age_days': days(updated)}

    def health(self, now: datetime | None = None) -> list[str]:
        if not self.lists:
            return ['blocklists_missing']
        now = now or datetime.now(timezone.utc)
        out = []
        if now - max(_parse_time(s.fetched_at) for s in self.lists.values()) > STALE_AFTER:
            out.append('blocklists_stale')
        updated = [_parse_time(s.list_last_updated) for s in self.lists.values() if s.list_last_updated]
        if updated and now - max(updated) > SOURCE_STALE_AFTER:
            out.append('blocklist_source_stale')
        return out


def parse_last_updated(data: bytes) -> str | None:
    """The list's own `# Last updated: YYYY-MM-DD HH:MM:SS UTC` header as UTC ISO, or None."""
    match = _LAST_UPDATED.search(data[:4096].decode('utf-8', errors='replace'))
    return f'{match.group(1)}T{match.group(2)}Z' if match else None


def _parse_time(value: str) -> datetime:
    moment = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if moment.tzinfo is None:
        raise ValueError('naive time')
    return moment.astimezone(timezone.utc)


def read_lock(lock_path: Path = LOCK, root: Path = ROOT) -> tuple[list[ListSpec], str | None]:
    """Specs from the lock and the lock's own SHA-256; a missing lock gives no lists."""
    lock_path = Path(lock_path)
    if not lock_path.is_file():
        return [], None
    raw = lock_path.read_bytes()
    try:
        lock = json.loads(raw.decode('utf-8'))
        base = (Path(root) / lock['destination']).resolve()
        specs, names = [], set()
        for entry in lock['lists']:
            name = entry['name']
            if name not in ALLOWED:
                raise BlocklistError('blocklist_not_allowed')
            if name in names or entry['format'] not in FORMATS:
                raise BlocklistError('blocklist_invalid_lock')
            names.add(name)
            path = (base / entry['file']).resolve()
            if base not in path.parents:
                raise BlocklistError('blocklist_invalid_lock')
            if not str(entry['url']).startswith('https://') or len(str(entry['sha256'])) != 64:
                raise BlocklistError('blocklist_invalid_lock')
            _parse_time(entry['fetched_at'])
            last_updated = entry.get('list_last_updated')
            if last_updated is not None:
                _parse_time(last_updated)
            specs.append(ListSpec(
                name=name, url=entry['url'], fetched_at=entry['fetched_at'], path=path, size=int(entry['size']),
                sha256=str(entry['sha256']).lower(), rows=int(entry['rows']), format=entry['format'],
                column=int(entry.get('column', 0)), delimiter=str(entry.get('delimiter', ',')),
                comment=str(entry.get('comment', '#')), list_last_updated=last_updated))
    except BlocklistError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise BlocklistError('blocklist_invalid_lock') from None
    return specs, hashlib.sha256(raw).hexdigest()


def _verified_bytes(spec: ListSpec) -> bytes:
    try:
        size = spec.path.stat().st_size
    except OSError:
        raise BlocklistError('blocklist_missing') from None
    if size != spec.size or size > MAX_LIST_BYTES:
        raise BlocklistError('blocklist_size_mismatch')
    data = spec.path.read_bytes()
    if hashlib.sha256(data).hexdigest() != spec.sha256:
        raise BlocklistError('blocklist_sha256_mismatch')
    return data


def parse_list(spec: ListSpec, data: bytes) -> tuple[set[str], dict[str, int]]:
    """IP rows of one list file, and counts of what was ignored."""
    text = data.decode('utf-8-sig', errors='replace')
    ignored = {'comment_or_blank': 0, 'not_ip': 0, 'range': 0, 'local': 0}
    if spec.format == 'ip_lines':
        values = [line.strip().split()[0] if line.strip() else '' for line in text.splitlines()]
        lines = text.splitlines()
    else:
        lines = text.splitlines()
        values = []
        for line in lines:
            if not line.strip() or line.lstrip().startswith(spec.comment):
                values.append('')
                continue
            row = next(csv.reader(io.StringIO(line), delimiter=spec.delimiter), [])
            values.append(row[spec.column].strip().strip('"') if len(row) > spec.column else None)
    ips: set[str] = set()
    for line, value in zip(lines, values):
        if not line.strip() or line.lstrip().startswith(spec.comment):
            ignored['comment_or_blank'] += 1
            continue
        if value and '/' in value:
            try:
                ipaddress.ip_network(value, strict=False)
                ignored['range'] += 1
                continue
            except ValueError:
                pass
        ip = normalise_ip(value)
        if ip is None:
            ignored['not_ip'] += 1
        elif locality(ip) != 'outside':
            ignored['local'] += 1
        else:
            ips.add(ip)
    return ips, ignored


def load(lock_path: Path = LOCK, root: Path = ROOT) -> Blocklists:
    """Load every list of the lock that verifies. A bad lock raises; a bad list is skipped."""
    specs, lock_sha = read_lock(lock_path, root)
    out = Blocklists(lock_sha256=lock_sha)
    index: dict[str, set[str]] = {}
    for spec in specs:
        try:
            ips, ignored = parse_list(spec, _verified_bytes(spec))
            if len(ips) != spec.rows:
                raise BlocklistError('blocklist_row_count_mismatch')
        except BlocklistError as exc:
            out.errors[spec.name] = str(exc)
            continue
        out.lists[spec.name] = spec
        out.ignored[spec.name] = ignored
        for ip in ips:
            index.setdefault(ip, set()).add(spec.name)
    out.ips = {ip: tuple(sorted(names)) for ip, names in index.items()}
    return out
