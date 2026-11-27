"""Device pseudonyms and coverage report for network.windows (design network-windows-v1 §1.2, §6.5, §8.8).

Invented inputs only; sockets are blocked.
"""
import socket
from dataclasses import asdict
from datetime import timezone

import pytest

from app.engines.host.pseudonyms import Pseudonymizer
from app.engines.network_windows.devices import (DeviceNameError, coverage_report, default_device_name,
                                                 pseudonymise)
from app.engines.network_windows.readers import read_import
from network_windows_fixtures import (connection, firewall_line, query_response, query_started, sysmon_query,
                                      write_evtx, write_firewall)

KEY, OTHER = bytes(range(32)), bytes(range(1, 33))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def _import(tmp_path, dns=(), firewall=(), sysmon=()):
    tmp_path.mkdir(parents=True, exist_ok=True)
    kwargs = {}
    if dns:
        kwargs['dns_evtx'] = [write_evtx(tmp_path / 'dns.evtx', list(dns))]
    if firewall:
        kwargs['firewall_logs'] = [write_firewall(tmp_path / 'pfirewall.log', list(firewall))]
    if sysmon:
        kwargs['sysmon_evtx'] = [write_evtx(tmp_path / 'sysmon.evtx', list(sysmon))]
    return read_import(local_tz=timezone.utc, **kwargs)


def test_device_ref_equals_the_host_engine_host_ref(tmp_path):
    result = _import(tmp_path, dns=[query_started('a.invented.example', computer='INVENTED-PC.corp.invented.example')],
                     sysmon=[connection(computer='invented-pc', user='INVENTED-PC\\invented-user')],
                     firewall=[firewall_line()])
    pseudonymise(result, Pseudonymizer(KEY), device_name='Invented-PC')
    host_ref = Pseudonymizer(KEY).host_ref('INVENTED-PC')
    assert host_ref.startswith('hmac:')
    assert {r.device_ref for r in [*result.dns, *result.connections]} == {host_ref}
    sysmon, = [c for c in result.connections if c.source == 'sysmon3']
    assert sysmon.account_ref == Pseudonymizer(KEY).account_ref(name='invented-user', domain='INVENTED-PC')
    assert Pseudonymizer(OTHER).host_ref('INVENTED-PC') != host_ref


def test_names_are_dropped_and_well_known_accounts_keep_their_sid(tmp_path):
    result = _import(tmp_path, sysmon=[connection(computer='MARKER-PC-7731', user='NT AUTHORITY\\SYSTEM'),
                                       connection(at=1, computer='MARKER-PC-7731', user='MARKER-PC-7731\\marker-user'),
                                       sysmon_query('q.invented.example', at=2, computer='MARKER-PC-7731')])
    pseudonymise(result, Pseudonymizer(KEY))
    assert result.connections[0].account_ref == 'sid:S-1-5-18'
    text = repr([asdict(r) for r in [*result.dns, *result.connections]])
    assert 'MARKER' not in text.upper() and 'marker-user' not in text


def test_sources_without_a_computer_name_need_a_device_name(tmp_path):
    result = _import(tmp_path, firewall=[firewall_line()])
    with pytest.raises(DeviceNameError, match='^device_name_missing$'):
        pseudonymise(result, Pseudonymizer(KEY))
    pseudonymise(result, Pseudonymizer(KEY), device_name='INVENTED-PC')
    assert result.connections[0].device_ref == Pseudonymizer(KEY).host_ref('INVENTED-PC')


def test_default_device_name_reads_the_environment(monkeypatch):
    # Design core-v2 §3.2 (owner decision Q17): gethostname() first, then COMPUTERNAME, then
    # platform.node(), all through local_device_name (lower-case short name).
    import socket
    monkeypatch.setattr(socket, 'gethostname', lambda: '')
    monkeypatch.setenv('COMPUTERNAME', 'INVENTED-PC')
    assert default_device_name() == 'invented-pc'
    monkeypatch.setattr(socket, 'gethostname', lambda: 'Invented-Host.corp.example')
    assert default_device_name() == 'invented-host'


def test_device_ref_is_the_same_for_every_name_shape(tmp_path):
    # EVTX Computer, COMPUTERNAME and gethostname() shapes of one PC give one endpoint ref.
    from app.core.device_names import endpoint_device_ref
    refs = {endpoint_device_ref(Pseudonymizer(KEY), name) for name in ('PC-01', 'pc-01.corp.example', 'PC-01.', ' pc-01 ')}
    assert len(refs) == 1 and refs == {Pseudonymizer(KEY).host_ref('pc-01')}


def _states(report):
    return report['detections']


def test_coverage_with_every_source_and_a_full_baseline(tmp_path):
    result = _import(tmp_path, dns=[query_response('a.invented.example', results='203.0.113.5;'),
                                    query_response('b.invented.example', at=49 * 3600)],
                     firewall=[firewall_line()], sysmon=[connection()])
    report = coverage_report(result)
    assert _states(report) == {'N1': 'visible', 'N2': 'inactive', 'N3': 'visible', 'N4': 'visible',
                               'N5': 'visible', 'N6': 'visible', 'N7': 'visible', 'N8': 'visible', 'N9': 'visible'}
    assert report['baseline'] == '24h' and report['import_hours'] >= 48 and report['not_visible'] == []
    assert report['sources']['dns_client']['records'] == 2 and report['sources']['snapshot'] == {'records': 0}


def test_coverage_marks_missing_sources_not_visible(tmp_path):
    dns_only = coverage_report(_import(tmp_path / 'a', dns=[query_response('a.invented.example',
                                                                            results='203.0.113.5;')]))
    assert _states(dns_only) == {'N1': 'partial', 'N2': 'inactive', 'N3': 'visible', 'N4': 'visible',
                                      'N5': 'visible', 'N6': 'partial', 'N7': 'not_visible', 'N8': 'visible',
                                      'N9': 'no_baseline'}
    fw_only = coverage_report(_import(tmp_path / 'b', firewall=[firewall_line()]))
    assert fw_only['not_visible'] == ['N3', 'N4', 'N5', 'N8']
    assert _states(fw_only)['N1'] == 'partial' and _states(fw_only)['N7'] == 'no_baseline'
    sysmon22 = coverage_report(_import(tmp_path / 'c', sysmon=[sysmon_query('a.invented.example')]))
    assert _states(sysmon22)['N8'] == 'partial'      # Sysmon 22 has no query type: TXT sign not visible
    no_answers = coverage_report(_import(tmp_path / 'd', dns=[query_started('a.invented.example')]))
    assert _states(no_answers)['N1'] == 'not_visible'
    empty = coverage_report(read_import())
    assert empty['not_visible'] == ['N1', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9']


def test_coverage_holds_no_names_or_addresses(tmp_path):
    result = _import(tmp_path, dns=[query_response('marker-query.invented.example', results='203.0.113.77;',
                                                   computer='MARKER-PC')],
                     sysmon=[connection(computer='MARKER-PC', src='192.168.77.31')])
    text = repr(coverage_report(pseudonymise(result, Pseudonymizer(KEY))))
    for marker in ('marker', 'MARKER', '203.0.113.77', '192.168.77.31', 'hmac:'):
        assert marker not in text
