"""Connection snapshot command and reader (design network-windows-v1 §1.1, §8.1-8.2, §8.10).

The connection-table and process-name calls are replaced by fakes built from invented rows
(RFC 5737 / private addresses); the real tables of this PC are never read.
"""
import importlib.util
import io
import ipaddress
import json
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.engines.network_windows import snapshots
from app.engines.network_windows.readers import NetworkWindowsInputError, read_import

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'data' / 'scripts' / 'snapshot_connections.py'
NOW = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)


def _load():
    spec = importlib.util.spec_from_file_location('etis_snapshot_connections', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


command = _load()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def _p(port):
    return port.to_bytes(2, 'big') + b'\0\0'


def row4(state, local, lport, remote, rport, pid):
    return (struct.pack('<I', state) + ipaddress.IPv4Address(local).packed + _p(lport)
            + ipaddress.IPv4Address(remote).packed + _p(rport) + struct.pack('<I', pid))


def row6(state, local, lport, remote, rport, pid):
    return (ipaddress.IPv6Address(local).packed + struct.pack('<I', 0) + _p(lport)
            + ipaddress.IPv6Address(remote).packed + struct.pack('<I', 0) + _p(rport) + struct.pack('<II', state, pid))


def table(rows):
    return struct.pack('<I', len(rows)) + b''.join(rows)


V4 = [
    row4(2, '0.0.0.0', 3389, '0.0.0.0', 0, 900),                          # listener (direction only)
    row4(5, '192.168.1.20', 50000, '203.0.113.10', 443, 4242),            # outbound
    row4(5, '192.168.1.20', 3389, '198.51.100.20', 51515, 900),           # inbound to the listener
    row4(11, '192.168.1.20', 50001, '203.0.113.11', 8443, 4242),          # time_wait, still a connection
    row4(5, '127.0.0.1', 50002, '127.0.0.1', 50003, 4),                   # loopback, system pid
]
V6 = [row6(5, 'fd00::20', 50010, '2001:db8::10', 443, 4242), row6(2, '::', 445, '::', 0, 4)]


def fake_table(family):
    return table(V4 if family == snapshots.AF_INET else V6)


def fake_image(pid):
    return snapshots.image_name('C:\\Users\\invented-user\\AppData\\Invented\\Invented-Agent.EXE')


def test_parse_table_reads_documented_row_layouts():
    rows = snapshots.parse_table(table(V4), snapshots.AF_INET)
    assert rows[1] == {'state': 'established', 'local_ip': ipaddress.IPv4Address('192.168.1.20'), 'local_port': 50000,
                       'remote_ip': ipaddress.IPv4Address('203.0.113.10'), 'remote_port': 443, 'pid': 4242}
    six = snapshots.parse_table(table(V6), snapshots.AF_INET6)
    assert six[0]['remote_ip'] == ipaddress.IPv6Address('2001:db8::10') and six[0]['local_port'] == 50010
    assert six[1]['state'] == 'listen'


@pytest.mark.parametrize('buffer', [b'', b'\x01\0\0\0', table([row4(99, '192.168.1.2', 1, '203.0.113.1', 2, 3)])])
def test_unexpected_tables_are_refused(buffer):
    with pytest.raises(snapshots.SnapshotError, match='^snapshot_table_unexpected$'):
        snapshots.parse_table(buffer, snapshots.AF_INET)


def test_snapshot_rows_keep_connections_with_a_remote_and_file_names_only():
    rows = snapshots.snapshot_rows(table=fake_table, image=fake_image, now=lambda: NOW)
    assert [(r['remote_ip'], r['direction'], r['state']) for r in rows] == [
        ('203.0.113.10', 'outbound', 'established'), ('198.51.100.20', 'inbound', 'established'),
        ('203.0.113.11', 'outbound', 'time_wait'), ('127.0.0.1', 'outbound', 'established'),
        ('2001:db8::10', 'outbound', 'established')]
    assert all(set(r) == set(snapshots.row_keys()) for r in rows)
    assert rows[0]['image_name'] == 'invented-agent.exe' and rows[3]['image_name'] is None   # pid 4: not resolved
    assert all('invented-user' not in json.dumps(r) for r in rows)


def test_command_writes_only_under_its_folder_and_never_overwrites(tmp_path):
    out_dir = tmp_path / 'var' / 'network-snapshots'
    out = io.StringIO()
    assert command.main([], out_dir=out_dir, table=fake_table, image=fake_image, now=lambda: NOW, out=out) == 0
    (written,) = out_dir.iterdir()
    assert written.name == 'snapshot-20260105T100000000000Z.jsonl'
    assert [p for p in tmp_path.rglob('*') if p.is_file()] == [written]
    assert len(written.read_text(encoding='utf-8').splitlines()) == 5
    assert '203.0.113' not in out.getvalue() and '5 connections' in out.getvalue()
    with pytest.raises(FileExistsError):
        command.main([], out_dir=out_dir, table=fake_table, image=fake_image, now=lambda: NOW, out=io.StringIO())


def test_command_reports_a_failed_table_read(tmp_path):
    def broken(family):
        raise snapshots.SnapshotError('snapshot_table_unavailable')
    out = io.StringIO()
    assert command.main([], out_dir=tmp_path / 'snaps', table=broken, out=out) == 2
    assert 'snapshot_table_unavailable' in out.getvalue() and not (tmp_path / 'snaps').exists()


def test_snapshot_code_never_kills_blocks_or_connects():
    module = (ROOT / 'backend/app/engines/network_windows/snapshots.py').read_text(encoding='utf-8')
    text = module + SCRIPT.read_text(encoding='utf-8')
    for forbidden in ('TerminateProcess', 'SetTcpEntry', 'subprocess', 'schtasks', 'netsh', 'wevtutil', 'os.kill',
                      'Set-NetFirewallProfile', 'PROCESS_TERMINATE', 'urllib', 'requests'):
        assert forbidden not in text, forbidden
    assert 'socket' not in module   # the script only imports socket to block it
    assert command.OUT_DIR == ROOT / 'var' / 'network-snapshots'
    assert 'var/' in (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()


def test_reader_reads_command_output_and_counts_bad_rows(tmp_path):
    out_dir = tmp_path / 'snaps'
    command.main([], out_dir=out_dir, table=fake_table, image=fake_image, now=lambda: NOW, out=io.StringIO())
    (path,) = out_dir.iterdir()
    good = path.read_text(encoding='utf-8').splitlines()[0]
    extra = json.loads(good) | {'user': 'invented-user'}
    with path.open('a', encoding='utf-8') as handle:
        handle.write('not json\n' + json.dumps(extra) + '\n' + good.replace('"tcp"', '"udp"') + '\n'
                     + good.replace('"outbound"', '"sideways"') + '\n' + good.replace('443', '70000') + '\n')
    result = read_import(snapshots=[path])
    outbound = result.connections[0]
    assert (outbound.source, outbound.direction, outbound.action, outbound.protocol, outbound.remote_ip,
            outbound.remote_port, outbound.local_port, outbound.pid, outbound.image_name, outbound.remote_local) == (
        'snapshot', 'outbound', 'observed', 'tcp', '203.0.113.10', 443, 50000, 4242, 'invented-agent.exe', False)
    assert len(result.connections) == 5 and result.connections[3].remote_local is True
    assert result.skipped == {('snapshot', 'malformed_row'): 5}
    assert result.counts == {('snapshot', 'outbound'): 4, ('snapshot', 'inbound'): 1}
    assert result.files[0].source == 'snapshot' and result.spans['snapshot'][0] == '2026-01-05T10:00:00.000000Z'
    assert '192.168.1.20' not in str(result.summary())
    with pytest.raises(NetworkWindowsInputError, match='^snapshot_too_many_rows$'):
        read_import(snapshots=[path], max_snapshot_rows=3)
