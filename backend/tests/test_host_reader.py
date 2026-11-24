"""EVTX reader and event normalisation (design host-engine-v1 §1.2-1.4, §8.1-8.2, §8.9).

EVTX files are generated in tmp_path from invented events by the test-only writer; no real
log, machine or dataset is used.
"""
import logging
import socket
import sqlite3
from pathlib import Path

import pytest

from app.engines.host import reader
from app.engines.host.reader import HostInputError, event_table, read_files
from host_fixtures import CHANNEL_SAMPLES, event, write_evtx

ROOT = Path(__file__).resolve().parents[2]
MARKER = 'invented-marker-7731'


def by_id(records):
    return {r['EventID']: r for r in records}


def test_every_channel_sample_normalises_to_flat_fields(tmp_path):
    path = write_evtx(tmp_path / 'all.evtx', [dict(e) for e in CHANNEL_SAMPLES])
    result = read_files([path])
    records = by_id(result.records)
    assert set(records) == {4625, 7045, 4104, 5001, 106, 1149, 1, 4688, 4648}
    failed = records[4625]
    assert failed == {
        'Channel': 'Security', 'Provider': 'Microsoft-Windows-Security-Auditing', 'EventID': 4625,
        'TimeCreated': '2026-01-05T10:00:00.000000Z', 'EventRecordID': 1, 'Computer': 'INVENTED-PC',
        'TargetUserName': 'invented-user', 'TargetDomainName': 'INVENTED-PC', 'LogonType': '3',
        'IpAddress': '203.0.113.9', 'WorkstationName': 'INVENTED-WS'}
    assert records[4104]['ScriptBlockText'] == 'Write-Output invented'
    assert records[7045]['Channel'] == 'System' and records[7045]['ImagePath'] == 'C:\\Invented\\svc.exe'
    assert records[1]['Hashes'].endswith('SHA256=' + '3' * 64)
    assert records[4688]['ParentProcessName'] == 'C:\\Windows\\explorer.exe'
    assert records[4648]['TargetServerName'] == 'localhost'
    assert records[5001]['Channel'] == 'Microsoft-Windows-Windows Defender/Operational'
    assert [r['EventRecordID'] for r in result.records] == list(range(1, 10))


def test_event_id_with_qualifiers_and_user_data_are_flattened(tmp_path):
    cleared = event(1102, provider='Microsoft-Windows-Eventlog')
    cleared['user_data'] = ('LogFileCleared', {'SubjectUserName': 'invented-admin', 'SubjectUserSid': 'S-1-5-21-1-2-3-1001'})
    service = event(7045, channel='System', provider='Service Control Manager', at=1, ServiceName='InventedSvc')
    service['qualifiers'] = '16384'
    records = by_id(read_files([write_evtx(tmp_path / 'u.evtx', [cleared, service])]).records)
    assert records[1102]['SubjectUserName'] == 'invented-admin'
    assert records[1102]['SubjectUserSid'] == 'S-1-5-21-1-2-3-1001'
    assert records[7045]['EventID'] == 7045 and records[7045]['ServiceName'] == 'InventedSvc'


def test_multiple_chunks_and_files_are_read_in_order(tmp_path):
    first = write_evtx(tmp_path / 'a.evtx', [event(4625, at=i) for i in range(5)], per_chunk=2)
    second = write_evtx(tmp_path / 'b.evtx', [event(7045, channel='System', at=10 + i) for i in range(3)])
    result = read_files([first, second])
    assert [r['EventID'] for r in result.records] == [4625] * 5 + [7045] * 3
    assert [f.events for f in result.files] == [5, 3]
    assert all(len(f.sha256) == 64 and f.size > 0 for f in result.files)
    assert result.counts == {('Security', 4625): 5, ('System', 7045): 3}


def test_system_fields_win_over_event_data_fields_with_the_same_name(tmp_path):
    spoof = event(4625, Channel='Invented', EventID='9999', TargetUserName='invented-user')
    record = read_files([write_evtx(tmp_path / 's.evtx', [spoof])]).records[0]
    assert record['Channel'] == 'Security' and record['EventID'] == 4625


def test_corrupt_and_truncated_files_fail_with_reason_codes(tmp_path):
    junk = tmp_path / 'junk.evtx'
    junk.write_bytes(b'NotAnEvtx' + bytes(5000))
    with pytest.raises(HostInputError) as exc:
        read_files([junk])
    assert str(exc.value) == 'evtx_corrupt'

    good = write_evtx(tmp_path / 'good.evtx', [event(4625, at=i) for i in range(3)])
    cut = tmp_path / 'cut.evtx'
    cut.write_bytes(good.read_bytes()[:4096 + 30000])
    with pytest.raises(HostInputError) as exc:
        read_files([cut])
    assert str(exc.value) == 'evtx_truncated'

    garbled = tmp_path / 'garbled.evtx'
    data = bytearray(good.read_bytes())
    data[4096 + 512 + 24:4096 + 512 + 64] = b'\xee' * 40  # damage the first record's binary XML
    garbled.write_bytes(bytes(data))
    with pytest.raises(HostInputError) as exc:
        read_files([garbled])
    assert str(exc.value) == 'evtx_corrupt'


def test_size_limit_is_enforced_before_parsing(tmp_path, monkeypatch):
    path = write_evtx(tmp_path / 'a.evtx', [event(4625)])
    calls = []
    monkeypatch.setattr(reader, '_open_parser', lambda p: calls.append(p))
    with pytest.raises(HostInputError) as exc:
        read_files([path, path], max_bytes=path.stat().st_size * 2 - 1)
    assert str(exc.value) == 'evtx_too_large' and calls == []


def test_event_limit_fails_closed_across_the_whole_import(tmp_path):
    a = write_evtx(tmp_path / 'a.evtx', [event(4625, at=i) for i in range(3)])
    b = write_evtx(tmp_path / 'b.evtx', [event(4625, at=i) for i in range(3)])
    assert len(read_files([a, b], max_events=6).records) == 6
    with pytest.raises(HostInputError) as exc:
        read_files([a, b], max_events=5)
    assert str(exc.value) == 'evtx_too_many_events'


def test_default_limits_match_the_design():
    assert reader.MAX_EVENTS == 2_000_000 and reader.MAX_BYTES == 1024 ** 3


@pytest.mark.parametrize('target', ['http://203.0.113.9/x.evtx', '\\\\INVENTED-SRV\\share\\x.evtx', 'dir', 'missing'])
def test_only_existing_local_regular_files_are_accepted(tmp_path, target):
    (tmp_path / 'dir').mkdir()
    path = tmp_path / target if target in ('dir', 'missing') else target
    with pytest.raises(HostInputError) as exc:
        read_files([path])
    assert str(exc.value) in {'evtx_not_local_file', 'evtx_not_found'}
    if target == 'missing':
        assert str(exc.value) == 'evtx_not_found'
    elif target != 'dir':
        assert str(exc.value) == 'evtx_not_local_file'


def test_errors_and_logs_never_carry_paths_or_values(tmp_path, caplog):
    path = tmp_path / f'{MARKER}.evtx'
    path.write_bytes(b'NotAnEvtx' + bytes(5000))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(HostInputError) as exc:
        read_files([path])
    assert MARKER not in str(exc.value) and MARKER not in repr(exc.value) and MARKER not in caplog.text


def test_input_files_are_read_in_place_and_left_unchanged(tmp_path):
    path = write_evtx(tmp_path / 'a.evtx', [event(4625)])
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    read_files([path])
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ['a.evtx']


def test_reading_needs_no_network(tmp_path, monkeypatch):
    path = write_evtx(tmp_path / 'a.evtx', [dict(e) for e in CHANNEL_SAMPLES])

    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    monkeypatch.setattr(socket, 'socket', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    assert len(read_files([path]).records) == len(CHANNEL_SAMPLES)


def test_parser_library_is_used_only_by_the_reader_for_local_files():
    users = sorted(str(p.relative_to(ROOT)).replace('\\', '/') for p in (ROOT / 'backend/app').rglob('*.py')
                   if 'import evtx' in p.read_text(encoding='utf-8') or 'from evtx' in p.read_text(encoding='utf-8'))
    assert users == ['backend/app/engines/host/reader.py']
    source = (ROOT / 'backend/app/engines/host/reader.py').read_text(encoding='utf-8')
    assert 'PyEvtxParser(str(' in source and 'requests' not in source and 'urllib' not in source


def test_runtime_requirements_pin_the_parser():
    lines = (ROOT / 'requirements-runtime.txt').read_text(encoding='utf-8').splitlines()
    assert 'evtx==0.15.0' in lines


def test_event_table_is_in_memory_queryable_and_gone_after_the_import(tmp_path):
    records = read_files([write_evtx(tmp_path / 'a.evtx', [dict(e) for e in CHANNEL_SAMPLES])]).records
    records[0]['bad"name; DROP'] = 'x'
    with event_table(records) as table:
        connection = table.connection
        assert table.database == ':memory:'
        rows = connection.execute('SELECT "EventRecordID" FROM logs WHERE "EventID" = 4625 AND "LogonType" = ?',
                                  ('3',)).fetchall()
        assert rows == [(1,)]
        assert connection.execute('SELECT COUNT(*) FROM logs').fetchone() == (len(CHANNEL_SAMPLES),)
        assert 'bad"name; DROP' not in table.columns and table.skipped_fields == 1
        assert connection.execute('SELECT "TargetServerName" FROM logs WHERE "EventID" = 4648').fetchone() == ('localhost',)
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute('SELECT 1')
