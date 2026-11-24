"""Test-only writer for tiny EVTX files built from invented events (design host-engine-v1 §8.1).

Produces a structurally valid EVTX file (file header, one or more 64 KiB chunks, records
encoded as template-free binary XML, CRC32 checksums) so the real parser path is
exercised without recording any real machine. Every value written comes from the test.
"""
from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone

CHUNK_SIZE = 65536
CHUNK_HEADER = 512
FILE_HEADER = 4096
_EPOCH_DELTA = 116444736000000000  # 100 ns intervals between 1601-01-01 and 1970-01-01


def filetime(moment: datetime) -> int:
    return int(moment.timestamp() * 10_000_000) + _EPOCH_DELTA


def _name_hash(name: str) -> int:
    value = 0
    for ch in name:
        value = (value * 65599 + ord(ch)) & 0xFFFFFFFF
    return value & 0xFFFF


class _Xml:
    """Template-free binary XML; names are written inline at their own chunk offset."""

    def __init__(self, base: int):
        self.base, self.out = base, bytearray()

    def _name(self, name: str) -> None:
        offset = self.base + len(self.out) + 4
        self.out += struct.pack('<I', offset)
        self.out += struct.pack('<IHH', 0, _name_hash(name), len(name)) + name.encode('utf-16-le') + b'\0\0'

    def _value(self, text: str) -> None:
        self.out += bytes([0x05, 0x01]) + struct.pack('<H', len(text)) + text.encode('utf-16-le')

    def element(self, name: str, attrs: dict | None = None, text: str | None = None, children=None) -> None:
        attrs = attrs or {}
        self.out += bytes([0x41 if attrs else 0x01])  # no dependency id outside templates
        size_at = len(self.out)
        self.out += b'\0\0\0\0'
        self._name(name)
        if attrs:
            list_at = len(self.out)
            self.out += b'\0\0\0\0'
            items = list(attrs.items())
            for index, (key, value) in enumerate(items):
                self.out += bytes([0x46 if index < len(items) - 1 else 0x06])
                self._name(key)
                self._value(str(value))
            struct.pack_into('<I', self.out, list_at, len(self.out) - list_at - 4)
        if text is None and not children:
            self.out += b'\x03'
        else:
            self.out += b'\x02'
            if text is not None:
                self._value(str(text))
            for child in children or ():
                child(self)
            self.out += b'\x04'
        struct.pack_into('<I', self.out, size_at, len(self.out) - size_at - 4)


def _event_xml(base: int, event: dict) -> bytes:
    xml = _Xml(base)
    xml.out += bytes([0x0F, 0x01, 0x01, 0x00])
    when = event['time'].astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    system = [
        lambda x: x.element('Provider', {'Name': event.get('provider', 'ETIS-Invented')}),
        lambda x: x.element('EventID', {'Qualifiers': event['qualifiers']} if 'qualifiers' in event else None,
                            text=str(event['event_id'])),
        lambda x: x.element('TimeCreated', {'SystemTime': when}),
        lambda x: x.element('EventRecordID', text=str(event['record_id'])),
        lambda x: x.element('Channel', text=event['channel']),
        lambda x: x.element('Computer', text=event.get('computer', 'INVENTED-PC')),
    ]
    data = [(lambda k, v: (lambda x: x.element('Data', {'Name': k}, text=v)))(k, v)
            for k, v in event.get('data', {}).items()]
    body = [lambda x: x.element('System', children=system)]
    if data:
        body.append(lambda x: x.element('EventData', children=data))
    if 'user_data' in event:  # (wrapper element name, {field: value}), as in 1102 LogFileCleared
        wrapper, fields = event['user_data']
        inner = [(lambda k, v: (lambda x: x.element(k, text=v)))(k, str(v)) for k, v in fields.items()]
        body.append(lambda x: x.element('UserData', children=[lambda y: y.element(wrapper, children=inner)]))
    xml.element('Event', {'xmlns': 'http://schemas.microsoft.com/win/2004/08/events/event'}, children=body)
    xml.out += b'\x00'
    return bytes(xml.out)


def _chunk(events: list[dict]) -> bytes:
    chunk = bytearray(CHUNK_SIZE)
    offset, last_offset = CHUNK_HEADER, CHUNK_HEADER
    for event in events:
        body = _event_xml(offset + 24, event)
        size = 24 + len(body) + 4
        if offset + size > CHUNK_SIZE:
            raise ValueError('chunk_full')
        record = struct.pack('<IIQQ', 0x00002A2A, size, event['record_id'], filetime(event['time'])) + body
        record += struct.pack('<I', size)
        chunk[offset:offset + size] = record
        last_offset, offset = offset, offset + size
    first, last = events[0]['record_id'], events[-1]['record_id']
    chunk[0:8] = b'ElfChnk\0'
    struct.pack_into('<QQQQIII', chunk, 8, first, last, first, last, 128, last_offset, offset)
    struct.pack_into('<I', chunk, 52, zlib.crc32(bytes(chunk[CHUNK_HEADER:offset])))
    struct.pack_into('<I', chunk, 124, zlib.crc32(bytes(chunk[0:120]) + bytes(chunk[128:CHUNK_HEADER])))
    return bytes(chunk)


def build_evtx(events: list[dict], per_chunk: int = 100) -> bytes:
    """Events: dicts with time (aware datetime), event_id, record_id, channel, data, provider, computer,
    optional qualifiers and user_data."""
    groups = [events[i:i + per_chunk] for i in range(0, len(events), per_chunk)] or [[]]
    chunks = [_chunk(group) for group in groups if group]
    header = bytearray(FILE_HEADER)
    header[0:8] = b'ElfFile\0'
    next_id = (events[-1]['record_id'] + 1) if events else 1
    struct.pack_into('<QQQIHHHH', header, 8, 0, max(len(chunks) - 1, 0), next_id, 128, 2, 3, FILE_HEADER,
                     len(chunks))
    struct.pack_into('<I', header, 124, zlib.crc32(bytes(header[0:120])))
    return bytes(header) + b''.join(chunks)
