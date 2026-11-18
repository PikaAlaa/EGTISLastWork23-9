"""Zeek `conn.log` and `dns.log` parsers (design network-engine-v1 §1.1, §7.1).

Accepts Zeek's TSV format (with `#fields` header) and JSON lines. Size is checked before
reading; the row limit fails closed instead of silently truncating. Malformed data lines
are counted and skipped. Errors and logs carry reason codes only, never values, paths or
addresses. Nothing here resolves or contacts any address.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

MAX_BYTES = int(os.getenv('ETIS_NETWORK_MAX_BYTES', str(500 * 1024 * 1024)))
MAX_ROWS = int(os.getenv('ETIS_NETWORK_MAX_ROWS', '1000000'))
CONN_REQUIRED = ('ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto')
DNS_REQUIRED = ('ts', 'query', 'answers')
_INT = {'id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts', 'orig_ip_bytes',
        'resp_pkts', 'resp_ip_bytes'}
_FLOAT = {'ts', 'duration'}
_BOOL = {'local_orig', 'local_resp'}


class NetworkInputError(ValueError):
    """Raised with a fixed reason code; never carries input values."""


@dataclass(frozen=True)
class ConnRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    conn_state: str | None = None
    local_orig: bool | None = None
    local_resp: bool | None = None
    missed_bytes: int | None = None
    history: str | None = None
    orig_pkts: int | None = None
    orig_ip_bytes: int | None = None
    resp_pkts: int | None = None
    resp_ip_bytes: int | None = None


@dataclass(frozen=True)
class DnsRecord:
    ts: float
    query: str | None
    answers: tuple[str, ...] = ()


@dataclass
class ParseResult:
    log_type: str
    format: str
    records: list = field(default_factory=list)
    malformed: int = 0
    data_lines: int = 0


_CONN_ATTRS = {'ts': 'ts', 'uid': 'uid', 'id.orig_h': 'orig_h', 'id.orig_p': 'orig_p', 'id.resp_h': 'resp_h',
               'id.resp_p': 'resp_p', 'proto': 'proto', 'service': 'service', 'duration': 'duration',
               'orig_bytes': 'orig_bytes', 'resp_bytes': 'resp_bytes', 'conn_state': 'conn_state',
               'local_orig': 'local_orig', 'local_resp': 'local_resp', 'missed_bytes': 'missed_bytes',
               'history': 'history', 'orig_pkts': 'orig_pkts', 'orig_ip_bytes': 'orig_ip_bytes',
               'resp_pkts': 'resp_pkts', 'resp_ip_bytes': 'resp_ip_bytes'}


def _scalar(name: str, value):
    """Convert one field; None means unset. Raises ValueError for a malformed value."""
    if value is None:
        return None
    if name in _FLOAT:
        number = float(value)
        if number != number or number in (float('inf'), float('-inf')) or number < 0:
            raise ValueError
        return number
    if name in _INT:
        number = int(value)
        if number < 0 or (name.endswith('_p') and number > 65535):
            raise ValueError
        return number
    if name in _BOOL:
        if isinstance(value, bool):
            return value
        if value in ('T', 'F'):
            return value == 'T'
        raise ValueError
    return str(value)


def _conn_record(fields: dict) -> ConnRecord:
    for name in CONN_REQUIRED:
        if fields.get(name) is None:
            raise ValueError
    values = {_CONN_ATTRS[name]: _scalar(name, fields.get(name)) for name in _CONN_ATTRS}
    for host in ('orig_h', 'resp_h'):
        values[host] = ipaddress.ip_address(values[host]).compressed
    values['proto'] = values['proto'].lower()
    if values['service'] == '':
        values['service'] = None
    return ConnRecord(**values)


def _dns_record(fields: dict) -> DnsRecord:
    if fields.get('ts') is None:
        raise ValueError
    answers = fields.get('answers') or ()
    if isinstance(answers, str):
        answers = (answers,)
    query = fields.get('query')
    return DnsRecord(ts=_scalar('ts', fields['ts']), query=str(query).lower().rstrip('.') if query else None,
                     answers=tuple(str(a) for a in answers))


def _tsv_rows(lines: Iterator[str], log_type: str, result: ParseResult) -> Iterator[dict]:
    separator, set_separator, empty, unset = '\t', ',', '(empty)', '-'
    names: list[str] | None = None
    for raw in lines:
        line = raw.rstrip('\r\n')
        if not line:
            continue
        if line.startswith('#'):
            key, _, rest = line[1:].partition(separator if not line.startswith('#separator') else ' ')
            if key == 'separator':
                separator = rest.encode().decode('unicode_escape')
            elif key == 'set_separator':
                set_separator = rest
            elif key == 'empty_field':
                empty = rest
            elif key == 'unset_field':
                unset = rest
            elif key == 'path' and rest != log_type:
                raise NetworkInputError('wrong_log_type')
            elif key == 'fields':
                names = rest.split(separator)
            continue
        if names is None:
            raise NetworkInputError('missing_fields_header')
        result.data_lines += 1
        parts = line.split(separator)
        if len(parts) != len(names):
            result.malformed += 1
            continue
        row = {}
        for name, value in zip(names, parts):
            if value == unset:
                row[name] = None
            elif value == empty:
                row[name] = () if name == 'answers' else ''
            elif name == 'answers':
                row[name] = tuple(value.split(set_separator))
            else:
                row[name] = value
        yield row
    if names is None:
        raise NetworkInputError('missing_fields_header')


def _json_rows(lines: Iterator[str], result: ParseResult) -> Iterator[dict]:
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        result.data_lines += 1
        try:
            row = json.loads(line)
        except ValueError:
            result.malformed += 1
            continue
        if not isinstance(row, dict):
            result.malformed += 1
            continue
        yield row


def parse_lines(lines: Iterable[str], log_type: str, max_rows: int = MAX_ROWS) -> ParseResult:
    """Parse an iterable of text lines. `log_type` is 'conn' or 'dns'."""
    if log_type not in ('conn', 'dns'):
        raise NetworkInputError('unsupported_log_type')
    iterator = iter(lines)
    first = None
    for candidate in iterator:
        if candidate.strip():
            first = candidate
            break
    if first is None:
        raise NetworkInputError('empty_input')
    chained = _chain(first, iterator)
    fmt = 'tsv' if first.lstrip().startswith('#') else 'json' if first.lstrip().startswith('{') else None
    if fmt is None:
        raise NetworkInputError('unrecognized_format')
    result = ParseResult(log_type=log_type, format=fmt)
    rows = _tsv_rows(chained, log_type, result) if fmt == 'tsv' else _json_rows(chained, result)
    build = _conn_record if log_type == 'conn' else _dns_record
    required = CONN_REQUIRED if log_type == 'conn' else DNS_REQUIRED
    for row in rows:
        if result.data_lines > max_rows:
            raise NetworkInputError('row_limit_exceeded')
        if fmt == 'tsv' and not set(required) <= set(row):
            raise NetworkInputError('missing_required_fields')
        try:
            result.records.append(build(row))
        except (ValueError, TypeError, KeyError):
            result.malformed += 1
    if result.data_lines > max_rows:  # also counts malformed lines skipped inside the reader
        raise NetworkInputError('row_limit_exceeded')
    return result


def _chain(first: str, rest: Iterator[str]) -> Iterator[str]:
    yield first
    yield from rest


def parse_file(path: str | Path, log_type: str, max_bytes: int = MAX_BYTES, max_rows: int = MAX_ROWS) -> ParseResult:
    """Read a local log in place. The size limit is enforced before any line is read."""
    path = Path(path)
    if not path.is_file():
        raise NetworkInputError('input_not_found')
    if path.stat().st_size > max_bytes:
        raise NetworkInputError('size_limit_exceeded')
    with path.open('r', encoding='utf-8', errors='strict', newline='') as handle:
        try:
            return parse_lines(handle, log_type, max_rows=max_rows)
        except UnicodeDecodeError:
            raise NetworkInputError('invalid_encoding') from None
