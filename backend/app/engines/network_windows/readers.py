"""Readers for the DNS Client log, `pfirewall.log`, Sysmon 1/3/22 and connection snapshots (design network-windows-v1 §1, §8.1).

Inputs are local files the owner exported; they are read in place and never copied. EVTX
files go through the host engine's pinned reader (`app.engines.host.reader`); the firewall
log is parsed here with the standard library from its `#Fields:` header, and any header
this reader does not know is refused (fail closed). Limits are checked before parsing
where possible (total bytes) and fail closed otherwise (record counts).

Field names and formats rely on (design §11, recorded in this step):
- DNS Client: provider manifest read locally with `wevtutil gp Microsoft-Windows-DNS-Client
  /ge /gm:true` and `Get-WinEvent -ListProvider` on 26 November 2026 (W1-W2): 3006
  (QueryName, QueryType, QueryOptions, ...), 3008 (QueryName, QueryType, QueryOptions,
  QueryStatus, QueryResults), 3020 v0-v2 (QueryName, QueryType, NetworkIndex,
  InterfaceIndex, Status, QueryResults, ClientPID from v1).
- `pfirewall.log`: the field list, `#Time Format` values and the `pid` field are **not**
  documented on the Microsoft Learn logging page (W5 stays to verify); hence the reader is
  header-driven and refuses unknown header names and directives.
- Sysmon: the channel `Microsoft-Windows-Sysmon/Operational` is verified on the Sysmon
  page; the event 1/3/22 field names are **not** listed there (W8-W9 stay to verify). A
  record missing a required field is counted and skipped, never guessed.

In-memory records keep values (they are what later steps evaluate) but hide them from
`repr`; image paths are reduced to the lower-cased file name at read time. Errors and logs
carry reason codes only, never paths, names or addresses. Nothing is resolved or contacted.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import ntpath
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Iterable

import idna

from app.engines.host import reader as host_reader

logger = logging.getLogger(__name__)

DNS_CHANNEL = 'Microsoft-Windows-DNS-Client/Operational'
DNS_EVENTS = frozenset({3006, 3008, 3020})
SYSMON_CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
SYSMON_EVENTS = frozenset({1, 3, 22})

MAX_BYTES = int(os.getenv('ETIS_NETWORK_WINDOWS_MAX_BYTES', str(1024 ** 3)))
MAX_DNS_EVENTS = int(os.getenv('ETIS_NETWORK_WINDOWS_MAX_DNS_EVENTS', '2000000'))
MAX_FIREWALL_LINES = int(os.getenv('ETIS_NETWORK_WINDOWS_MAX_FIREWALL_LINES', '2000000'))
MAX_SYSMON_EVENTS = int(os.getenv('ETIS_NETWORK_WINDOWS_MAX_SYSMON_EVENTS', '1000000'))
MAX_SNAPSHOT_ROWS = int(os.getenv('ETIS_NETWORK_WINDOWS_MAX_SNAPSHOT_ROWS', '2000000'))
SNAPSHOT_KEYS = frozenset({'v', 'time', 'protocol', 'state', 'direction', 'local_ip', 'local_port', 'remote_ip',
                           'remote_port', 'pid', 'image_name'})
MAX_LINE_CHARS = 4096

FIREWALL_FIELDS = ('date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'size',
                   'tcpflags', 'tcpsyn', 'tcpack', 'tcpwin', 'icmptype', 'icmpcode', 'info', 'path', 'pid')
FIREWALL_REQUIRED = ('date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'path')
FIREWALL_DIRECTIVES = ('version', 'software', 'time format', 'fields')
FIREWALL_ACTIONS = {'ALLOW': 'allowed', 'DROP': 'dropped'}
FIREWALL_PATHS = {'SEND': 'outbound', 'RECEIVE': 'inbound'}
PROTOCOL_NUMBERS = {'1': 'icmp', '6': 'tcp', '17': 'udp', '58': 'icmpv6'}
PORTED = frozenset({'tcp', 'udp'})

SYSMON_REQUIRED = {
    1: ('ProcessGuid', 'Hashes'),
    3: ('Protocol', 'Initiated', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort'),
    22: ('QueryName',),
}
_SHA256 = re.compile(r'(?:^|,)\s*SHA256=([0-9A-Fa-f]{64})\s*(?:,|$)')
_PROTOCOL = re.compile(r'^[a-z0-9]{1,16}$')
_LABEL = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')
_CGNAT = ipaddress.ip_network('100.64.0.0/10')
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
_ULA = ipaddress.ip_network('fc00::/7')


class NetworkWindowsInputError(ValueError):
    """Raised with a fixed reason code; never carries input values or paths."""


@dataclass(frozen=True)
class DnsRecord:
    """One DNS query or response (DNS Client 3006/3008/3020 or Sysmon 22), UTC."""
    time: str
    source: str                      # dns_client | sysmon22
    event_id: int
    query_name: str = field(repr=False)          # lower-case A-label form, no trailing dot
    query_type: int | None = None                # None when the source has no type (Sysmon 22)
    status: int | None = None                    # None for 3006 (query started)
    answers: tuple[str, ...] = field(default=(), repr=False)   # IP answers only
    pid: int | None = None
    image_name: str | None = field(default=None, repr=False)   # file name only, lower-case
    process_guid: str | None = field(default=None, repr=False)
    computer: str | None = field(default=None, repr=False)
    device_ref: str | None = None    # set by devices.pseudonymise, which also drops `computer`


@dataclass(frozen=True)
class ConnRecord:
    """One connection (firewall line or Sysmon 3), UTC."""
    time: str
    source: str                      # firewall | sysmon3 | snapshot
    direction: str                   # outbound | inbound | unknown
    action: str                      # allowed | dropped | observed (Sysmon)
    protocol: str
    remote_ip: str = field(repr=False)
    remote_local: bool = field(repr=False)
    remote_port: int | None = field(default=None, repr=False)
    local_port: int | None = field(default=None, repr=False)
    pid: int | None = None
    remote_name: str | None = field(default=None, repr=False)
    image_name: str | None = field(default=None, repr=False)
    process_guid: str | None = field(default=None, repr=False)
    user: str | None = field(default=None, repr=False)
    computer: str | None = field(default=None, repr=False)
    device_ref: str | None = None    # set by devices.pseudonymise, which also drops `computer` and `user`
    account_ref: str | None = None


@dataclass(frozen=True)
class InputFile:
    source: str                      # dns_client | firewall | sysmon | snapshot
    sha256: str
    size: int
    records: int


@dataclass
class ReadResult:
    dns: list[DnsRecord] = field(default_factory=list, repr=False)
    connections: list[ConnRecord] = field(default_factory=list, repr=False)
    process_hashes: dict[str, str] = field(default_factory=dict, repr=False)   # ProcessGuid -> sha256
    files: list[InputFile] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)    # (source, event id or action) -> records kept
    skipped: Counter = field(default_factory=Counter)   # (source, reason code) -> records skipped
    spans: dict[str, tuple[str, str]] = field(default_factory=dict)
    firewall_time_basis: str | None = None              # utc | local_assumed | local_given

    def summary(self) -> dict:
        """Counts and file digests only; safe to store or log (no names, addresses or paths)."""
        return {
            'files': [vars(f) for f in self.files],
            'counts': {f'{s}:{k}': n for (s, k), n in sorted(self.counts.items(), key=str)},
            'skipped': {f'{s}:{k}': n for (s, k), n in sorted(self.skipped.items(), key=str)},
            'spans': {s: list(v) for s, v in sorted(self.spans.items())},
            'firewall_time_basis': self.firewall_time_basis,
        }


# ----------------------------------------------------------------- shared helpers

def locality(address: str | None, local_nets: tuple = ()) -> str:
    """'local' (design §1.4: RFC 1918, loopback, link-local, multicast, broadcast, CGNAT,
    ULA, `--local-net`), 'outside', or 'unknown' (not an address)."""
    if not address:
        return 'unknown'
    try:
        ip = ipaddress.ip_address(address.split('%')[0])
    except ValueError:
        return 'unknown'
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return 'unknown'
    if any(ip in net for net in local_nets if net.version == ip.version):
        return 'local'
    if ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return 'local'
    if ip.version == 4 and (ip == ipaddress.IPv4Address('255.255.255.255') or ip in _CGNAT
                            or any(ip in n for n in _RFC1918)):
        return 'local'
    if ip.version == 6 and ip in _ULA:
        return 'local'
    return 'outside'


def normalise_ip(value: str | None) -> str | None:
    """Canonical text of an IP (IPv4-mapped IPv6 unwrapped, zone dropped), or None."""
    text = (value or '').strip()
    if not text or text == '-':
        return None
    try:
        ip = ipaddress.ip_address(text.split('%')[0])
    except ValueError:
        return None
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    return str(ip)


def normalise_name(value: str | None) -> str | None:
    """Query name in lower-case A-label form without trailing dot (design §1.4), or None.

    Labels may hold underscores (service names such as `_ldap._tcp`). Unicode labels are
    converted with IDNA (UTS 46). Invalid names (empty label, > 63 per label, > 253 total)
    return None; nothing is resolved.
    """
    text = (value or '').strip().rstrip('.')
    if not text or text == '-':
        return None
    labels = []
    for label in text.split('.'):
        if not label.isascii():
            try:
                label = idna.encode(label, uts46=True).decode('ascii')
            except idna.IDNAError:
                return None
        label = label.lower()
        if not _LABEL.match(label):
            return None
        labels.append(label)
    name = '.'.join(labels)
    return name if len(name) <= 253 else None


def parse_answers(value: str | None) -> tuple[str, ...]:
    """IP answers from a `QueryResults` string; non-IP tokens (CNAME entries) are dropped.

    The string's exact format is not documented on a page read for this design (to verify,
    W2/W9): it is split on ';' and each token's last whitespace-separated part is tried as
    an IP, so `::ffff:198.51.100.7;` and `type:  5 cname.example;` are both handled.
    """
    out: list[str] = []
    for token in (value or '').split(';'):
        parts = token.split()
        ip = normalise_ip(parts[-1]) if parts else None
        if ip and ip not in out:
            out.append(ip)
    return tuple(out)


def _int(value) -> int | None:
    text = str(value).strip() if value is not None else ''
    if not text or text == '-':
        return None
    try:
        return int(text, 16) if text.lower().startswith('0x') else int(text)
    except ValueError:
        return None


def _port(value) -> int | None:
    number = _int(value)
    return number if number is not None and 0 <= number <= 65535 else None


def _image_name(value: str | None) -> str | None:
    text = (value or '').strip()
    if not text or text == '-':
        return None
    return ntpath.basename(text).lower() or None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _local_files(paths: Iterable, source: str) -> list[Path]:
    files = []
    for value in paths or ():
        try:
            files.append(host_reader._local_file(value))
        except host_reader.HostInputError as exc:
            raise NetworkWindowsInputError(f'{source}_{str(exc).removeprefix("evtx_")}') from None
    return files


def _span(result: ReadResult, source: str, when: str) -> None:
    start, end = result.spans.get(source, (when, when))
    result.spans[source] = (min(start, when), max(end, when))


# ----------------------------------------------------------------- EVTX sources

def _read_evtx(path: Path, source: str, limit: int) -> list[dict]:
    try:
        return host_reader.read_files([path], max_events=limit, max_bytes=path.stat().st_size).records
    except host_reader.HostInputError as exc:
        code = str(exc).removeprefix('evtx_')
        if code == 'too_many_events':
            raise NetworkWindowsInputError(f'{source}_too_many_events') from None
        raise NetworkWindowsInputError(f'{source}_evtx_{code}') from None


def _dns_client_record(raw: dict) -> DnsRecord | str:
    event_id = raw.get('EventID')
    name = normalise_name(raw.get('QueryName'))
    if name is None:
        return 'invalid_query_name'
    status_field = 'Status' if event_id == 3020 else 'QueryStatus'
    return DnsRecord(
        time=raw['TimeCreated'], source='dns_client', event_id=event_id, query_name=name,
        query_type=_int(raw.get('QueryType')),
        status=None if event_id == 3006 else _int(raw.get(status_field)),
        answers=() if event_id == 3006 else parse_answers(raw.get('QueryResults')),
        pid=_int(raw.get('ClientPID')), computer=raw.get('Computer'))


def read_dns_client(paths: Iterable, result: ReadResult, limit: int) -> None:
    for path in _local_files(paths, 'dns_client'):
        kept = 0
        for raw in _read_evtx(path, 'dns_client', limit):
            if raw.get('Channel') != DNS_CHANNEL:
                result.skipped[('dns_client', 'other_channel')] += 1
                continue
            if raw.get('EventID') not in DNS_EVENTS:
                result.skipped[('dns_client', 'other_event')] += 1
                continue
            if not raw.get('TimeCreated'):
                result.skipped[('dns_client', 'no_time')] += 1
                continue
            record = _dns_client_record(raw)
            if isinstance(record, str):
                result.skipped[('dns_client', record)] += 1
                continue
            if len(result.dns) >= limit:
                raise NetworkWindowsInputError('dns_client_too_many_events')
            result.dns.append(record)
            result.counts[('dns_client', record.event_id)] += 1
            _span(result, 'dns_client', record.time)
            kept += 1
        result.files.append(InputFile('dns_client', _sha256(path), path.stat().st_size, kept))


def _sysmon_record(raw: dict, local_nets: tuple):
    event_id = raw['EventID']
    if any(not (raw.get(name) or '').strip() for name in SYSMON_REQUIRED[event_id]):
        return 'missing_field'
    guid = (raw.get('ProcessGuid') or '').strip() or None
    if event_id == 1:
        match = _SHA256.search(raw['Hashes'])
        return (guid, match.group(1).lower()) if match else 'no_sha256'
    if event_id == 22:
        name = normalise_name(raw['QueryName'])
        if name is None:
            return 'invalid_query_name'
        return DnsRecord(
            time=raw['TimeCreated'], source='sysmon22', event_id=22, query_name=name, query_type=None,
            status=_int(raw.get('QueryStatus')), answers=parse_answers(raw.get('QueryResults')),
            pid=_int(raw.get('ProcessId')), image_name=_image_name(raw.get('Image')), process_guid=guid,
            computer=raw.get('Computer'))
    initiated = raw['Initiated'].strip().lower()
    if initiated not in ('true', 'false'):
        return 'malformed_value'
    outbound = initiated == 'true'
    remote = normalise_ip(raw['DestinationIp'] if outbound else raw['SourceIp'])
    remote_port = _port(raw['DestinationPort'] if outbound else raw['SourcePort'])
    local_port = _port(raw['SourcePort'] if outbound else raw['DestinationPort'])
    protocol = raw['Protocol'].strip().lower()
    if remote is None or remote_port is None or local_port is None or not _PROTOCOL.match(protocol):
        return 'malformed_value'
    return ConnRecord(
        time=raw['TimeCreated'], source='sysmon3', direction='outbound' if outbound else 'inbound',
        action='observed', protocol=protocol, remote_ip=remote,
        remote_local=locality(remote, local_nets) == 'local', remote_port=remote_port, local_port=local_port,
        pid=_int(raw.get('ProcessId')),
        remote_name=normalise_name(raw.get('DestinationHostname')) if outbound else None,
        image_name=_image_name(raw.get('Image')), process_guid=guid,
        user=(raw.get('User') or '').strip() or None, computer=raw.get('Computer'))


def read_sysmon(paths: Iterable, result: ReadResult, limit: int, local_nets: tuple = ()) -> None:
    kept_total = 0
    for path in _local_files(paths, 'sysmon'):
        kept = 0
        for raw in _read_evtx(path, 'sysmon', limit):
            if raw.get('Channel') != SYSMON_CHANNEL:
                result.skipped[('sysmon', 'other_channel')] += 1
                continue
            if raw.get('EventID') not in SYSMON_EVENTS:
                result.skipped[('sysmon', 'other_event')] += 1
                continue
            if not raw.get('TimeCreated'):
                result.skipped[('sysmon', 'no_time')] += 1
                continue
            record = _sysmon_record(raw, local_nets)
            if isinstance(record, str):
                result.skipped[('sysmon', record)] += 1
                continue
            if kept_total >= limit:
                raise NetworkWindowsInputError('sysmon_too_many_events')
            kept_total += 1
            kept += 1
            if isinstance(record, tuple):
                guid, digest = record
                if guid:
                    result.process_hashes[guid] = digest
            elif isinstance(record, DnsRecord):
                result.dns.append(record)
            else:
                result.connections.append(record)
            result.counts[('sysmon', raw['EventID'])] += 1
            _span(result, 'sysmon', raw['TimeCreated'])
        result.files.append(InputFile('sysmon', _sha256(path), path.stat().st_size, kept))


# ----------------------------------------------------------------- firewall log

def _decode(path: Path) -> Iterable[str]:
    with path.open('rb') as probe:
        bom = probe.read(2)
    encoding = 'utf-16' if bom in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig'
    with path.open('r', encoding=encoding, errors='replace', newline='') as handle:
        for line in handle:
            yield line.rstrip('\r\n')


def _firewall_time(date: str, clock: str, basis: str, local_tz: tzinfo | None) -> str | None:
    try:
        moment = datetime.strptime(f'{date} {clock}', '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None
    if basis == 'utc':
        moment = moment.replace(tzinfo=timezone.utc)
    elif local_tz is not None:
        moment = moment.replace(tzinfo=local_tz)
    else:
        moment = moment.astimezone()   # the importing PC's own zone (design §6.5: import on that PC)
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _firewall_record(values: dict, basis: str, local_tz, local_nets: tuple) -> ConnRecord | str:
    action = FIREWALL_ACTIONS.get(values['action'].upper())
    if action is None:
        return 'other_action'
    when = _firewall_time(values['date'], values['time'], basis, local_tz)
    if when is None:
        return 'malformed_line'
    protocol = values['protocol'].lower()
    protocol = PROTOCOL_NUMBERS.get(protocol, protocol)
    if not _PROTOCOL.match(protocol):
        return 'malformed_line'
    direction = FIREWALL_PATHS.get(values['path'].upper(), 'unknown')
    src, dst = normalise_ip(values['src-ip']), normalise_ip(values['dst-ip'])
    if src is None or dst is None:
        return 'malformed_line'
    ports = [_port(values['src-port']), _port(values['dst-port'])]
    if protocol in PORTED and None in ports:
        return 'malformed_line'
    # SEND: this PC is the source. RECEIVE: this PC is the destination. Otherwise the remote
    # side is the non-local address when exactly one side is local.
    if direction == 'unknown':
        src_local, dst_local = (locality(a, local_nets) == 'local' for a in (src, dst))
        if src_local == dst_local:
            return 'unknown_direction'
        local_is_src = src_local
    else:
        local_is_src = direction == 'outbound'
    remote, remote_port, local_port = ((dst, ports[1], ports[0]) if local_is_src else (src, ports[0], ports[1]))
    return ConnRecord(
        time=when, source='firewall', direction=direction, action=action, protocol=protocol, remote_ip=remote,
        remote_local=locality(remote, local_nets) == 'local', remote_port=remote_port, local_port=local_port,
        pid=_int(values.get('pid')))


def read_firewall(paths: Iterable, result: ReadResult, limit: int, local_nets: tuple = (),
                  local_tz: tzinfo | None = None) -> None:
    lines_total = 0
    bases = set()
    for path in _local_files(paths, 'firewall'):
        fields: tuple[str, ...] | None = None
        basis = 'local_given' if local_tz is not None else 'local_assumed'
        kept = 0
        for line in _decode(path):
            if not line.strip():
                continue
            if line.startswith('#'):
                directive, _, value = line[1:].partition(':')
                directive = directive.strip().lower()
                if directive not in FIREWALL_DIRECTIVES:
                    raise NetworkWindowsInputError('firewall_unknown_header')
                if directive == 'fields':
                    names = tuple(value.split())
                    if any(n not in FIREWALL_FIELDS for n in names) or len(set(names)) != len(names):
                        raise NetworkWindowsInputError('firewall_unknown_header')
                    if any(n not in names for n in FIREWALL_REQUIRED):
                        raise NetworkWindowsInputError('firewall_missing_field')
                    fields = names
                elif directive == 'time format':
                    kind = value.strip().lower()
                    if kind == 'utc':
                        basis = 'utc'
                    elif kind == 'local':
                        basis = 'local_given' if local_tz is not None else 'local_assumed'
                    else:
                        raise NetworkWindowsInputError('firewall_unknown_time_format')
                continue
            if fields is None:
                raise NetworkWindowsInputError('firewall_no_fields_header')
            lines_total += 1
            if lines_total > limit:
                raise NetworkWindowsInputError('firewall_too_many_lines')
            parts = line.split(' ')
            if len(line) > MAX_LINE_CHARS or len(parts) != len(fields):
                result.skipped[('firewall', 'malformed_line')] += 1
                continue
            record = _firewall_record(dict(zip(fields, parts)), basis, local_tz, local_nets)
            if isinstance(record, str):
                result.skipped[('firewall', record)] += 1
                continue
            bases.add(basis)
            result.connections.append(record)
            result.counts[('firewall', record.action)] += 1
            _span(result, 'firewall', record.time)
            kept += 1
        result.files.append(InputFile('firewall', _sha256(path), path.stat().st_size, kept))
    if bases:
        result.firewall_time_basis = bases.pop() if len(bases) == 1 else 'mixed'


# ----------------------------------------------------------------- connection snapshots

def _snapshot_record(line: str, local_nets: tuple) -> ConnRecord | str:
    try:
        row = json.loads(line)
    except ValueError:
        return 'malformed_row'
    if not isinstance(row, dict) or set(row) != SNAPSHOT_KEYS or row.get('v') != 1 or row.get('protocol') != 'tcp':
        return 'malformed_row'
    if row.get('direction') not in ('outbound', 'inbound'):
        return 'malformed_row'
    when = host_reader._utc(row.get('time') if isinstance(row.get('time'), str) else None, None)
    remote = normalise_ip(row['remote_ip'] if isinstance(row['remote_ip'], str) else None)
    ports = [_port(row['remote_port']), _port(row['local_port'])]
    if when is None or remote is None or None in ports:
        return 'malformed_row'
    image = row.get('image_name')
    return ConnRecord(
        time=when, source='snapshot', direction=row['direction'], action='observed', protocol='tcp',
        remote_ip=remote, remote_local=locality(remote, local_nets) == 'local', remote_port=ports[0],
        local_port=ports[1], pid=_int(row.get('pid')), image_name=_image_name(image if isinstance(image, str) else None))


def read_snapshots(paths: Iterable, result: ReadResult, limit: int, local_nets: tuple = ()) -> None:
    """JSON-lines files written by data/scripts/snapshot_connections.py; unknown row shapes are counted."""
    rows_total = 0
    for path in _local_files(paths, 'snapshot'):
        kept = 0
        for line in _decode(path):
            if not line.strip():
                continue
            rows_total += 1
            if rows_total > limit:
                raise NetworkWindowsInputError('snapshot_too_many_rows')
            record = _snapshot_record(line, local_nets) if len(line) <= MAX_LINE_CHARS else 'malformed_row'
            if isinstance(record, str):
                result.skipped[('snapshot', record)] += 1
                continue
            result.connections.append(record)
            result.counts[('snapshot', record.direction)] += 1
            _span(result, 'snapshot', record.time)
            kept += 1
        result.files.append(InputFile('snapshot', _sha256(path), path.stat().st_size, kept))


# ----------------------------------------------------------------- one import

def read_import(dns_evtx: Iterable = (), firewall_logs: Iterable = (), sysmon_evtx: Iterable = (),
                snapshots: Iterable = (), *, local_nets: tuple = (), local_tz: tzinfo | None = None,
                max_bytes: int | None = None, max_dns_events: int | None = None,
                max_firewall_lines: int | None = None, max_sysmon_events: int | None = None,
                max_snapshot_rows: int | None = None) -> ReadResult:
    """Read every file of one import (design §1.3). Limits apply to the whole import."""
    dns_evtx, firewall_logs, sysmon_evtx = list(dns_evtx or ()), list(firewall_logs or ()), list(sysmon_evtx or ())
    snapshots = list(snapshots or ())
    groups = (('dns_client', dns_evtx), ('firewall', firewall_logs), ('sysmon', sysmon_evtx), ('snapshot', snapshots))
    total = sum(p.stat().st_size for source, values in groups for p in _local_files(values, source))
    if total > (MAX_BYTES if max_bytes is None else max_bytes):
        raise NetworkWindowsInputError('import_too_large')
    result = ReadResult()
    read_dns_client(dns_evtx, result, MAX_DNS_EVENTS if max_dns_events is None else max_dns_events)
    read_firewall(firewall_logs, result, MAX_FIREWALL_LINES if max_firewall_lines is None else max_firewall_lines,
                  local_nets, local_tz)
    read_sysmon(sysmon_evtx, result, MAX_SYSMON_EVENTS if max_sysmon_events is None else max_sysmon_events,
                local_nets)
    read_snapshots(snapshots, result, MAX_SNAPSHOT_ROWS if max_snapshot_rows is None else max_snapshot_rows,
                   local_nets)
    if result.skipped:
        logger.info('network_windows_records_skipped', extra={'skipped': sum(result.skipped.values())})
    return result
