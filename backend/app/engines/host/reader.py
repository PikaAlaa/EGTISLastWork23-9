"""EVTX reader and event normalisation (design host-engine-v1 §1.2-1.4).

Reads local `.evtx` files in place with the pinned `evtx` parser and turns each record into
a flat dictionary named after Windows' own fields. Limits are checked before parsing where
possible (file sizes) and fail closed otherwise (event count). Errors and logs carry reason
codes only, never paths or event values. Nothing here resolves or contacts any address.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import struct
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

import evtx

logger = logging.getLogger(__name__)

MAX_EVENTS = int(os.getenv('ETIS_HOST_MAX_EVENTS', '2000000'))
MAX_BYTES = int(os.getenv('ETIS_HOST_MAX_BYTES', str(1024 ** 3)))
TABLE = 'logs'
SYSTEM_FIELDS = ('Channel', 'Provider', 'EventID', 'TimeCreated', 'EventRecordID', 'Computer')
_FILE_HEADER, _CHUNK = 4096, 65536
_FIELD_NAME = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-]{0,127}$')


class HostInputError(ValueError):
    """Raised with a fixed reason code; never carries input values or paths."""


@dataclass(frozen=True)
class FileSummary:
    sha256: str
    size: int
    events: int


@dataclass
class ReadResult:
    records: list[dict] = field(default_factory=list)
    files: list[FileSummary] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)  # (channel, event id) -> events


def _local_file(value) -> Path:
    text = os.fspath(value)
    if '://' in text or text.startswith(('\\\\', '//')):
        raise HostInputError('evtx_not_local_file')
    path = Path(text)
    if not path.exists():
        raise HostInputError('evtx_not_found')
    if not path.is_file():
        raise HostInputError('evtx_not_local_file')
    return path


def _check_header(path: Path, size: int) -> None:
    """Reject non-EVTX and truncated files before handing them to the parser."""
    with path.open('rb') as handle:
        header = handle.read(_FILE_HEADER)
    if len(header) < 128 or header[:8] != b'ElfFile\0':
        raise HostInputError('evtx_corrupt')
    header_block, chunks = struct.unpack_from('<HH', header, 40)
    if header_block != _FILE_HEADER:
        raise HostInputError('evtx_corrupt')
    if size < _FILE_HEADER + chunks * _CHUNK or (size - _FILE_HEADER) % _CHUNK:
        raise HostInputError('evtx_truncated')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _open_parser(path: Path):
    # Local file path only; the parser is never given a URL or a remote stream.
    return evtx.PyEvtxParser(str(path), validate_checksums=True, indent=False)


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return _text(value.get('#text'))
    if isinstance(value, list):
        parts = [_text(v) for v in value]
        return '\n'.join(p for p in parts if p is not None)
    return str(value)


def _flatten_data(section, out: dict) -> None:
    """EventData children are fields; UserData has one wrapper element holding the fields."""
    if not isinstance(section, dict):
        if section is not None:
            out.setdefault('Data', _text(section))
        return
    for key, value in section.items():
        if key.startswith('#'):
            continue
        if isinstance(value, dict) and '#text' not in value and any(not k.startswith('#') for k in value):
            _flatten_data(value, out)
            continue
        text = _text(value)
        if text is not None:
            out[key] = text


def _utc(value: str | None, fallback: str | None) -> str | None:
    for candidate in (value, fallback):
        if not candidate:
            continue
        text = candidate.replace(' UTC', '').strip()
        try:
            moment = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return None


def normalise(document: dict, record_id: int | None = None, timestamp: str | None = None) -> dict:
    """Flatten one parsed EVTX record (`evtx` JSON) into Windows-named fields."""
    event = document.get('Event', {})
    system = event.get('System', {}) or {}
    out: dict = {}
    _flatten_data(event.get('EventData'), out)
    _flatten_data(event.get('UserData'), out)
    provider = system.get('Provider') or {}
    attributes = provider.get('#attributes', {}) if isinstance(provider, dict) else {}
    event_id = _text(system.get('EventID'))
    raw_record = _text(system.get('EventRecordID'))
    created = system.get('TimeCreated') or {}
    created_at = created.get('#attributes', {}).get('SystemTime') if isinstance(created, dict) else None
    out.update({
        'Channel': _text(system.get('Channel')),
        'Provider': attributes.get('Name'),
        'EventID': int(event_id) if event_id and event_id.strip().isdigit() else None,
        'TimeCreated': _utc(created_at, timestamp),
        'EventRecordID': int(raw_record) if raw_record and raw_record.isdigit() else record_id,
        'Computer': _text(system.get('Computer')),
    })
    return out


def _records(path: Path) -> Iterator[dict]:
    try:
        parser = _open_parser(path)
        for item in parser.records_json():
            yield normalise(json.loads(item['data']), item.get('event_record_id'), item.get('timestamp'))
    except HostInputError:
        raise
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        logger.warning('host_evtx_parse_failed')
        raise HostInputError('evtx_corrupt') from None


def read_files(paths: Iterable, max_events: int | None = None, max_bytes: int | None = None) -> ReadResult:
    """Read every file of one import. Limits apply to the whole import."""
    max_events = MAX_EVENTS if max_events is None else max_events
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    files = [_local_file(p) for p in paths]
    sizes = [p.stat().st_size for p in files]
    if sum(sizes) > max_bytes:
        raise HostInputError('evtx_too_large')
    for path, size in zip(files, sizes):
        _check_header(path, size)
    result = ReadResult()
    for path, size in zip(files, sizes):
        events = 0
        for record in _records(path):
            if len(result.records) >= max_events:
                raise HostInputError('evtx_too_many_events')
            result.records.append(record)
            result.counts[(record['Channel'], record['EventID'])] += 1
            events += 1
        result.files.append(FileSummary(sha256=_sha256(path), size=size, events=events))
    return result


@dataclass
class EventTable:
    connection: sqlite3.Connection
    columns: tuple[str, ...]
    skipped_fields: int
    database: str = ':memory:'


@contextmanager
def event_table(records: list[dict]) -> Iterator[EventTable]:
    """Load records into an in-memory SQLite table `logs`; the database is closed on exit."""
    names, folded, skipped = [], set(), set()
    for record in records:
        for key in record:
            if key in names or key in skipped:
                continue
            # SQLite column names are case-insensitive: a second spelling of a name is skipped.
            if _FIELD_NAME.match(key) and key.lower() not in folded:
                names.append(key)
                folded.add(key.lower())
            else:
                skipped.add(key)
    connection = sqlite3.connect(':memory:')
    try:
        quoted = ', '.join(f'"{name}"' for name in names)
        connection.execute(f'CREATE TABLE {TABLE} (_etis_row INTEGER PRIMARY KEY, {quoted})')
        placeholders = ', '.join('?' for _ in names)
        connection.executemany(f'INSERT INTO {TABLE} ({quoted}) VALUES ({placeholders})',
                               ([record.get(name) for name in names] for record in records))
        yield EventTable(connection=connection, columns=tuple(names), skipped_fields=len(skipped))
    finally:
        connection.close()
