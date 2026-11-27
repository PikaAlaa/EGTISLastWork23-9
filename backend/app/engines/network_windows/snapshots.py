"""Local TCP connection snapshots (design network-windows-v1 §1.1, §8.2).

Reads the owner's own TCP connection table once through `GetExtendedTcpTable` (Iphlpapi.dll,
through `ctypes`, standard library only) and turns it into JSON-lines rows for
`data/scripts/snapshot_connections.py`. Only reads: nothing here kills, blocks, resets or
contacts a connection or process. The process image is resolved read-only
(`PROCESS_QUERY_LIMITED_INFORMATION` + `QueryFullProcessImageNameW`) and reduced to the
lower-cased file name; the path is never kept.

Facts relied on (design §11 W11, read 26 November 2026):
- GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved=0) returns
  ERROR_INSUFFICIENT_BUFFER and the needed size in pdwSize when the buffer is too small
  (verified, learn.microsoft.com .../nf-iphlpapi-getextendedtcptable).
- MIB_TCPROW_OWNER_PID: dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort,
  dwOwningPid, ports in network byte order; MIB_TCP6ROW_OWNER_PID: ucLocalAddr[16],
  dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState,
  dwOwningPid; MIB_TCP_STATE 1..12 (verified on the two row pages).
- TCP_TABLE_OWNER_PID_ALL = 5: the TCP_TABLE_CLASS page returned 404, so the value is
  **to verify**; the parser refuses a table whose rows do not look like the documented rows.

UDP endpoints are not read: they have no remote address, so no detection can use them.
Rows without a remote endpoint (listeners, unspecified addresses) are used only to decide
direction (a connection whose local port is listening is inbound) and are not written.
"""
from __future__ import annotations

import ipaddress
import ntpath
import struct
from datetime import datetime, timezone
from typing import Callable, Iterable

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5            # to verify (W11): TCP_TABLE_CLASS page not available
ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0
ROW4, ROW6 = 24, 56
STATES = {1: 'closed', 2: 'listen', 3: 'syn_sent', 4: 'syn_received', 5: 'established', 6: 'fin_wait1',
          7: 'fin_wait2', 8: 'close_wait', 9: 'closing', 10: 'last_ack', 11: 'time_wait', 12: 'delete_tcb'}
ROW_VERSION = 1
MAX_TABLE_BYTES = 64 * 1024 * 1024


class SnapshotError(RuntimeError):
    """Raised with a fixed reason code; never carries addresses, names or paths."""


def _port(raw: bytes) -> int:
    return int.from_bytes(raw[:2], 'big')


def parse_table(buffer: bytes, family: int) -> list[dict]:
    """Rows of a MIB_TCPTABLE_OWNER_PID / MIB_TCP6TABLE_OWNER_PID buffer."""
    if len(buffer) < 4:
        raise SnapshotError('snapshot_table_unexpected')
    (count,) = struct.unpack_from('<I', buffer, 0)
    size = ROW4 if family == AF_INET else ROW6
    if 4 + count * size > len(buffer):
        raise SnapshotError('snapshot_table_unexpected')
    rows = []
    for index in range(count):
        at = 4 + index * size
        if family == AF_INET:
            state, = struct.unpack_from('<I', buffer, at)
            local = ipaddress.IPv4Address(buffer[at + 4:at + 8])
            lport = _port(buffer[at + 8:at + 12])
            remote = ipaddress.IPv4Address(buffer[at + 12:at + 16])
            rport = _port(buffer[at + 16:at + 20])
            pid, = struct.unpack_from('<I', buffer, at + 20)
        else:
            local = ipaddress.IPv6Address(buffer[at:at + 16])
            lport = _port(buffer[at + 20:at + 24])
            remote = ipaddress.IPv6Address(buffer[at + 24:at + 40])
            rport = _port(buffer[at + 44:at + 48])
            state, pid = struct.unpack_from('<II', buffer, at + 48)
        if state not in STATES:
            raise SnapshotError('snapshot_table_unexpected')
        rows.append({'state': STATES[state], 'local_ip': local, 'local_port': lport, 'remote_ip': remote,
                     'remote_port': rport, 'pid': pid})
    return rows


def _windows_table(family: int) -> bytes:   # pragma: no cover - Windows only, never run in tests
    import ctypes
    from ctypes import wintypes
    function = ctypes.WinDLL('Iphlpapi.dll').GetExtendedTcpTable
    function.restype = wintypes.DWORD
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG,
                         ctypes.c_int, wintypes.ULONG]
    size = wintypes.DWORD(0)
    for _ in range(5):
        buffer = ctypes.create_string_buffer(max(size.value, 4))
        status = function(buffer, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
        if status == NO_ERROR:
            return buffer.raw[:size.value] if size.value else buffer.raw
        if status != ERROR_INSUFFICIENT_BUFFER or size.value > MAX_TABLE_BYTES:
            break
    raise SnapshotError('snapshot_table_unavailable')


def _windows_image_name(pid: int) -> str | None:   # pragma: no cover - Windows only, never run in tests
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    handle = kernel.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION, read-only
    if not handle:
        return None
    try:
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return image_name(buffer.value)
    finally:
        kernel.CloseHandle(handle)


def image_name(path: str | None) -> str | None:
    text = (path or '').strip()
    return ntpath.basename(text).lower() or None if text else None


def snapshot_rows(table: Callable[[int], bytes] = _windows_table,
                  image: Callable[[int], str | None] = _windows_image_name,
                  now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> list[dict]:
    """One snapshot: rows for TCP connections that have a remote endpoint."""
    moment = now().astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    rows = [(family, row) for family in (AF_INET, AF_INET6) for row in parse_table(table(family), family)]
    listening = {(family, row['local_port']) for family, row in rows if row['state'] == 'listen'}
    names: dict[int, str | None] = {}
    out = []
    for family, row in rows:
        remote = row['remote_ip']
        if row['state'] == 'listen' or remote.is_unspecified or row['remote_port'] == 0:
            continue
        pid = row['pid']
        if pid not in names:
            names[pid] = image(pid) if pid > 4 else None
        out.append({
            'v': ROW_VERSION, 'time': moment, 'protocol': 'tcp', 'state': row['state'],
            'direction': 'inbound' if (family, row['local_port']) in listening else 'outbound',
            'local_ip': str(row['local_ip']), 'local_port': row['local_port'],
            'remote_ip': str(remote), 'remote_port': row['remote_port'], 'pid': pid,
            'image_name': names[pid],
        })
    return out


def row_keys() -> Iterable[str]:
    return ('v', 'time', 'protocol', 'state', 'direction', 'local_ip', 'local_port', 'remote_ip', 'remote_port',
            'pid', 'image_name')
