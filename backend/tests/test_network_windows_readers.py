"""DNS Client, firewall and Sysmon readers (design network-windows-v1 §1, §7, §8.1, §8.8, §8.10).

All inputs are invented and generated in tmp_path; no real log or export is read.
"""
import logging
import socket
from datetime import timedelta, timezone
from pathlib import Path

import pytest

from app.engines.network_windows import readers
from app.engines.network_windows.readers import (NetworkWindowsInputError, locality, normalise_name,
                                                 parse_answers, read_import)
from app.engines.host.pseudonyms import parse_local_nets
from network_windows_fixtures import (FIREWALL_HEADER, connection, event, firewall_line, process_create,
                                      query_completed, query_response, query_started, sysmon_query,
                                      write_evtx, write_firewall)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'backend' / 'app' / 'engines' / 'network_windows' / 'readers.py'
PLUS2 = timezone(timedelta(hours=2))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


# ----------------------------------------------------------------- DNS Client

def test_dns_client_events_normalise_to_records(tmp_path):
    path = write_evtx(tmp_path / 'dns.evtx', [
        query_started('Mail.Invented.Example.', at=0, qtype=1),
        query_completed('mail.invented.example', at=1, qtype=1, status=0,
                        results='::ffff:203.0.113.5;198.51.100.7;'),
        query_response('cdn.invented.example', at=2, qtype=28, status=0,
                       results='type:  5 edge.invented.example;2001:db8::7;', pid=4242),
        query_response('nx-invented.example', at=3, qtype=1, status=9003, results=''),
        query_response('old-build.invented.example', at=4, qtype=1, status=0, results='203.0.113.9;'),
    ])
    result = read_import(dns_evtx=[path])
    started, completed, response, nxdomain, no_pid = result.dns
    assert (started.event_id, started.query_name, started.query_type, started.status, started.answers) == (
        3006, 'mail.invented.example', 1, None, ())
    assert completed.answers == ('203.0.113.5', '198.51.100.7') and completed.status == 0
    assert response.answers == ('2001:db8::7',) and response.query_type == 28 and response.pid == 4242
    assert nxdomain.status == 9003 and nxdomain.answers == ()
    assert no_pid.pid is None   # 3020 version 0 has no ClientPID
    assert all(r.source == 'dns_client' and r.computer == 'INVENTED-PC' for r in result.dns)
    assert started.time == '2026-01-05T10:00:00.000000Z'
    assert result.counts == {('dns_client', 3006): 1, ('dns_client', 3008): 1, ('dns_client', 3020): 3}
    assert result.spans['dns_client'] == ('2026-01-05T10:00:00.000000Z', '2026-01-05T10:00:04.000000Z')
    (summary,) = result.files
    assert summary.source == 'dns_client' and summary.records == 5 and len(summary.sha256) == 64


def test_dns_client_skips_other_channels_events_and_invalid_names(tmp_path):
    path = write_evtx(tmp_path / 'dns.evtx', [
        query_started('ok.invented.example'),
        event(3009, channel=readers.DNS_CHANNEL, provider='Microsoft-Windows-DNS-Client', at=1, QueryName='x.example'),
        event(4625, at=2, TargetUserName='invented-user'),
        query_started('bad..invented.example', at=3),
        query_started('a' * 64 + '.example', at=4),
    ])
    result = read_import(dns_evtx=[path])
    assert [r.query_name for r in result.dns] == ['ok.invented.example']
    assert result.skipped == {('dns_client', 'other_event'): 1, ('dns_client', 'other_channel'): 1,
                              ('dns_client', 'invalid_query_name'): 2}


@pytest.mark.parametrize('raw, expected', [
    ('Invented.EXAMPLE.', 'invented.example'),
    ('_ldap._tcp.dc.invented.example', '_ldap._tcp.dc.invented.example'),
    ('bücher.invented.example', 'xn--bcher-kva.invented.example'),
    ('wpad', 'wpad'),
    ('', None), ('-', None), ('a..b', None), ('-bad.example', None), ('x' * 64 + '.example', None),
    ('.'.join(['a' * 63] * 4), None),   # 255 characters > 253
    ('has space.example', None),
])
def test_query_name_normalisation(raw, expected):
    assert normalise_name(raw) == expected


def test_answers_keep_ip_tokens_only():
    assert parse_answers('type:  5 cname.invented.example;::ffff:203.0.113.5;203.0.113.5;2001:db8::1;') == (
        '203.0.113.5', '2001:db8::1')
    assert parse_answers(None) == () and parse_answers('') == ()


# ----------------------------------------------------------------- Sysmon

def test_sysmon_3_22_and_1_normalise(tmp_path):
    path = write_evtx(tmp_path / 'sysmon.evtx', [
        process_create(at=0),
        connection(at=1),
        connection(at=2, initiated='false', src='198.51.100.20', sport=51515, dst='192.168.1.20', dport=3389,
                   hostname='-'),
        sysmon_query('C2.Invented.Example', at=3, status=0, results='::ffff:203.0.113.10;'),
    ])
    result = read_import(sysmon_evtx=[path])
    assert result.process_hashes == {'{inv-guid-1}': 'a' * 64}
    outbound, inbound = result.connections
    assert (outbound.direction, outbound.action, outbound.protocol, outbound.remote_ip, outbound.remote_port,
            outbound.local_port, outbound.remote_local, outbound.remote_name) == (
        'outbound', 'observed', 'tcp', '203.0.113.10', 443, 50000, False, 'c2.invented.example')
    assert outbound.image_name == 'invented-agent.exe'          # file name only, never the path
    assert outbound.pid == 4242 and outbound.process_guid == '{inv-guid-1}'
    assert (inbound.direction, inbound.remote_ip, inbound.remote_port, inbound.local_port, inbound.remote_name) == (
        'inbound', '198.51.100.20', 51515, 3389, None)
    (query,) = result.dns
    assert (query.source, query.event_id, query.query_name, query.query_type, query.status, query.answers) == (
        'sysmon22', 22, 'c2.invented.example', None, 0, ('203.0.113.10',))
    assert query.image_name == 'invented-agent.exe'
    assert result.counts == {('sysmon', 1): 1, ('sysmon', 3): 2, ('sysmon', 22): 1}


def test_sysmon_missing_or_malformed_fields_are_counted_not_guessed(tmp_path):
    incomplete = connection(at=0)
    del incomplete['data']['DestinationIp']
    path = write_evtx(tmp_path / 'sysmon.evtx', [
        incomplete,
        connection(at=1, initiated='maybe'),
        connection(at=2, dport=70000),
        connection(at=3, dst='not-an-ip'),
        process_create(at=4, sha256='z' * 64),
        sysmon_query('bad..name', at=5),
        event(5, channel=readers.SYSMON_CHANNEL, provider='Microsoft-Windows-Sysmon', at=6, ProcessGuid='{g}'),
        connection(at=7),
    ])
    result = read_import(sysmon_evtx=[path])
    assert len(result.connections) == 1 and result.dns == [] and result.process_hashes == {}
    assert result.skipped == {('sysmon', 'missing_field'): 1, ('sysmon', 'malformed_value'): 3,
                              ('sysmon', 'no_sha256'): 1, ('sysmon', 'invalid_query_name'): 1,
                              ('sysmon', 'other_event'): 1}


# ----------------------------------------------------------------- firewall log

def test_firewall_lines_follow_the_fields_header(tmp_path):
    path = write_firewall(tmp_path / 'pfirewall.log', [
        firewall_line(time='10:00:00', action='ALLOW', path='SEND'),
        firewall_line(time='10:00:01', action='DROP', protocol='UDP', src='198.51.100.9', dst='192.168.1.20',
                      sport='53', dport='61000', path='RECEIVE', pid='-'),
        firewall_line(time='10:00:02', action='ALLOW', protocol='ICMP', sport='-', dport='-', path='SEND'),
        firewall_line(time='10:00:03', action='ALLOW', protocol='6', path='SEND'),
    ])
    result = read_import(firewall_logs=[path], local_tz=PLUS2)
    send, receive, icmp, numbered = result.connections
    assert (send.time, send.direction, send.action, send.protocol, send.remote_ip, send.remote_port,
            send.local_port, send.pid, send.remote_local) == (
        '2026-01-05T08:00:00.000000Z', 'outbound', 'allowed', 'tcp', '203.0.113.10', 443, 50000, 4242, False)
    assert (receive.direction, receive.action, receive.protocol, receive.remote_ip, receive.remote_port,
            receive.local_port, receive.pid) == ('inbound', 'dropped', 'udp', '198.51.100.9', 53, 61000, None)
    assert icmp.protocol == 'icmp' and icmp.remote_port is None and icmp.local_port is None
    assert numbered.protocol == 'tcp'
    assert result.counts == {('firewall', 'allowed'): 3, ('firewall', 'dropped'): 1}
    assert result.firewall_time_basis == 'local_given'
    assert result.files[0].source == 'firewall' and result.files[0].records == 4


def test_firewall_malformed_lines_and_other_actions_are_counted(tmp_path):
    path = write_firewall(tmp_path / 'pfirewall.log', [
        firewall_line(),
        'not a firewall line\n',
        firewall_line(date='2026-13-40'),
        firewall_line(src='999.1.1.1'),
        firewall_line(dport='-'),                       # TCP without a port
        firewall_line(action='INFO-EVENTS-LOST'),
        firewall_line(path='FORWARD', src='192.168.1.20', dst='192.168.1.30'),   # direction unknown, both local
        firewall_line(path='FORWARD'),                  # one side local: remote is the other side
        firewall_line(protocol='T C P!'),
        'x' * 5000 + '\n',
    ])
    result = read_import(firewall_logs=[path], local_tz=timezone.utc)
    assert len(result.connections) == 2
    assert result.connections[1].direction == 'unknown' and result.connections[1].remote_ip == '203.0.113.10'
    assert result.skipped == {('firewall', 'malformed_line'): 6, ('firewall', 'other_action'): 1,
                              ('firewall', 'unknown_direction'): 1}


@pytest.mark.parametrize('header, code', [
    ('#Fields: date time action protocol src-ip dst-ip src-port dst-port path invented-field\n',
     'firewall_unknown_header'),
    ('#Fields: date time action protocol src-ip dst-ip src-port src-port dst-port path\n', 'firewall_unknown_header'),
    ('#Fields: date time action protocol src-ip dst-ip src-port dst-port\n', 'firewall_missing_field'),
    ('#Invented-Directive: 1\n', 'firewall_unknown_header'),
    ('#Time Format: Mars\n#Fields: date time action protocol src-ip dst-ip src-port dst-port path\n',
     'firewall_unknown_time_format'),
    ('', 'firewall_no_fields_header'),
])
def test_firewall_unknown_headers_are_refused(tmp_path, header, code):
    path = write_firewall(tmp_path / 'pfirewall.log', [firewall_line()], header=header)
    with pytest.raises(NetworkWindowsInputError) as caught:
        read_import(firewall_logs=[path])
    assert str(caught.value) == code


def test_firewall_time_basis_utc_assumed_local_and_utf16(tmp_path):
    utc = write_firewall(tmp_path / 'utc.log', [firewall_line(time='10:00:00')],
                         header=FIREWALL_HEADER.replace('Local', 'UTC'))
    result = read_import(firewall_logs=[utc])
    assert result.connections[0].time == '2026-01-05T10:00:00.000000Z' and result.firewall_time_basis == 'utc'
    assumed = read_import(firewall_logs=[write_firewall(tmp_path / 'local.log', [firewall_line()])])
    assert assumed.firewall_time_basis == 'local_assumed' and len(assumed.connections) == 1
    wide = write_firewall(tmp_path / 'wide.log', [firewall_line()], encoding='utf-16')
    assert len(read_import(firewall_logs=[wide], local_tz=PLUS2).connections) == 1
    both = read_import(firewall_logs=[utc, tmp_path / 'local.log'])
    assert both.firewall_time_basis == 'mixed'


def test_a_second_fields_header_resets_the_columns(tmp_path):
    short = '#Fields: date time action protocol src-ip dst-ip src-port dst-port path\n'
    path = write_firewall(tmp_path / 'pfirewall.log', [
        firewall_line(), short, '2026-01-05 10:00:05 DROP TCP 198.51.100.9 192.168.1.20 4444 445 RECEIVE\n'])
    result = read_import(firewall_logs=[path], local_tz=timezone.utc)
    assert [c.action for c in result.connections] == ['allowed', 'dropped']
    assert result.connections[1].pid is None


# ----------------------------------------------------------------- locality

@pytest.mark.parametrize('address, expected', [
    ('10.1.2.3', 'local'), ('172.16.0.1', 'local'), ('192.168.1.1', 'local'), ('127.0.0.1', 'local'),
    ('169.254.1.1', 'local'), ('224.0.0.251', 'local'), ('239.255.255.250', 'local'),
    ('255.255.255.255', 'local'), ('100.64.0.1', 'local'), ('100.127.255.254', 'local'), ('fd00::1', 'local'),
    ('fe80::1%12', 'local'), ('ff02::fb', 'local'), ('::1', 'local'), ('::ffff:192.168.1.5', 'local'),
    ('203.0.113.10', 'outside'), ('100.128.0.1', 'outside'), ('2001:db8::1', 'outside'),
    ('0.0.0.0', 'unknown'), ('::', 'unknown'), ('', 'unknown'), (None, 'unknown'), ('nope', 'unknown'),
])
def test_locality(address, expected):
    assert locality(address) == expected


def test_local_net_option_marks_destinations_local(tmp_path):
    nets = parse_local_nets(['203.0.113.0/24'])
    assert locality('203.0.113.10', nets) == 'local'
    path = write_firewall(tmp_path / 'pfirewall.log', [firewall_line()])
    assert read_import(firewall_logs=[path], local_nets=nets, local_tz=PLUS2).connections[0].remote_local is True


# ----------------------------------------------------------------- inputs and limits

def test_inputs_must_be_existing_local_files(tmp_path):
    for value, code in (('https://invented.example/dns.evtx', 'dns_client_not_local_file'),
                        ('\\\\invented-server\\share\\dns.evtx', 'dns_client_not_local_file'),
                        (str(tmp_path / 'missing.evtx'), 'dns_client_not_found'),
                        (str(tmp_path), 'dns_client_not_local_file')):
        with pytest.raises(NetworkWindowsInputError) as caught:
            read_import(dns_evtx=[value])
        assert str(caught.value) == code
    with pytest.raises(NetworkWindowsInputError, match='^firewall_not_found$'):
        read_import(firewall_logs=[tmp_path / 'missing.log'])


def test_corrupt_evtx_is_refused_with_a_reason_code(tmp_path):
    bad = tmp_path / 'bad.evtx'
    bad.write_bytes(b'not an evtx file' * 300)
    with pytest.raises(NetworkWindowsInputError, match='^sysmon_evtx_corrupt$'):
        read_import(sysmon_evtx=[bad])


def test_limits_fail_closed(tmp_path):
    dns_path = write_evtx(tmp_path / 'dns.evtx', [query_started(f'q{i}.invented.example', at=i) for i in range(3)])
    sysmon_path = write_evtx(tmp_path / 'sysmon.evtx', [connection(at=i) for i in range(3)])
    fw_path = write_firewall(tmp_path / 'pfirewall.log', [firewall_line() for _ in range(3)])
    with pytest.raises(NetworkWindowsInputError, match='^import_too_large$'):
        read_import(dns_evtx=[dns_path], firewall_logs=[fw_path], max_bytes=dns_path.stat().st_size)
    with pytest.raises(NetworkWindowsInputError, match='^dns_client_too_many_events$'):
        read_import(dns_evtx=[dns_path], max_dns_events=2)
    with pytest.raises(NetworkWindowsInputError, match='^dns_client_too_many_events$'):
        read_import(dns_evtx=[dns_path, dns_path], max_dns_events=5)
    with pytest.raises(NetworkWindowsInputError, match='^sysmon_too_many_events$'):
        read_import(sysmon_evtx=[sysmon_path, sysmon_path], max_sysmon_events=5)
    with pytest.raises(NetworkWindowsInputError, match='^firewall_too_many_lines$'):
        read_import(firewall_logs=[fw_path], max_firewall_lines=2, local_tz=PLUS2)
    ok = read_import(dns_evtx=[dns_path], firewall_logs=[fw_path], sysmon_evtx=[sysmon_path],
                     max_dns_events=3, max_firewall_lines=3, max_sysmon_events=3, local_tz=PLUS2)
    assert (len(ok.dns), len(ok.connections)) == (3, 6)
    assert [f.source for f in ok.files] == ['dns_client', 'firewall', 'sysmon']


# ----------------------------------------------------------------- privacy and read-only

MARKERS = ('MARKER-PC-7731', 'marker-user-7731', 'marker-dir-7731', 'marker-query-7731', '192.168.77.31',
           'tmp_path_marker')


def test_no_name_path_or_address_leaks_into_summary_repr_errors_or_logs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    folder = tmp_path / 'tmp_path_marker'
    folder.mkdir()
    image = 'C:\\Users\\marker-user-7731\\marker-dir-7731\\invented-agent.exe'
    dns_path = write_evtx(folder / 'dns.evtx', [
        query_response('marker-query-7731.invented.example', computer='MARKER-PC-7731',
                       results='192.168.77.31;'),
        query_started('bad..marker-query-7731', at=1, computer='MARKER-PC-7731'),
    ])
    sysmon_path = write_evtx(folder / 'sysmon.evtx', [
        connection(computer='MARKER-PC-7731', image=image, user='MARKER-PC-7731\\marker-user-7731',
                   src='192.168.77.31', hostname='marker-query-7731.invented.example'),
        sysmon_query('marker-query-7731.invented.example', at=1, image=image, computer='MARKER-PC-7731'),
    ])
    fw_path = write_firewall(folder / 'pfirewall.log', [firewall_line(src='192.168.77.31'), 'broken line\n'])
    result = read_import(dns_evtx=[dns_path], firewall_logs=[fw_path], sysmon_evtx=[sysmon_path], local_tz=PLUS2)
    assert len(result.dns) == 2 and len(result.connections) == 2
    assert all(r.image_name in (None, 'invented-agent.exe') for r in [*result.dns, *result.connections])
    exposed = [repr(result), str(result.summary()), *map(repr, result.dns), *map(repr, result.connections),
               caplog.text]
    bad = folder / 'bad.evtx'
    bad.write_bytes(b'x' * 5000)
    for call in (lambda: read_import(sysmon_evtx=[bad]),
                 lambda: read_import(dns_evtx=[folder / 'marker-query-7731.evtx']),
                 lambda: read_import(firewall_logs=[write_firewall(folder / 'h.log', [], header='#Fields: marker-user-7731\n')])):
        with pytest.raises(NetworkWindowsInputError) as caught:
            call()
        exposed.append(str(caught.value))
    joined = '\n'.join(exposed)
    for marker in MARKERS:
        assert marker not in joined, marker


def test_readers_never_change_the_system_or_import_network_modules():
    text = SOURCE.read_text(encoding='utf-8')
    for forbidden in ('subprocess', 'wevtutil', 'netsh', 'Set-NetFirewallProfile', 'schtasks', 'requests',
                      'urllib', 'socket', 'os.system', 'shutil', 'unlink', 'write_text', 'write_bytes'):
        assert forbidden not in text.replace('`wevtutil gp', ''), forbidden
