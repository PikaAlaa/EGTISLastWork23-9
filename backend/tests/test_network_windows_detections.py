"""Detections N1-N9 (design network-windows-v1 §2.1, §6.1, §8.3).

Table-driven positives and negatives at each fixed constant, on invented in-memory records:
RFC 5737 addresses, a private LAN and `.example` names only. Sockets are blocked.
"""
import socket
from datetime import datetime, timedelta, timezone

import pytest

from app.core.indicators import sha256_hex
from app.engines.network_windows import detections as d
from app.engines.network_windows.readers import ConnRecord, DnsRecord, ReadResult

T0 = datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc)
DEV = 'hmac:' + '1' * 32
C2 = '203.0.113.66'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def ts(seconds):
    return (T0 + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def q(name, at=0.0, status=None, qtype=1, answers=(), source='dns_client', event_id=3006, device=DEV, guid=None):
    return DnsRecord(time=ts(at), source=source, event_id=event_id if source == 'dns_client' else 22,
                     query_name=name, query_type=qtype if source == 'dns_client' else None, status=status,
                     answers=tuple(answers), process_guid=guid, device_ref=device)


def c(ip, port=443, at=0.0, action='allowed', direction='outbound', source='firewall', protocol='tcp', local=False,
      name=None, device=DEV, guid=None):
    return ConnRecord(time=ts(at), source=source, direction=direction, action=action, protocol=protocol, remote_ip=ip,
                      remote_local=local, remote_port=port, local_port=50000, remote_name=name, process_guid=guid,
                      device_ref=device)


def result(dns=(), conns=()):
    r = ReadResult()
    r.dns, r.connections = list(dns), list(conns)
    return r


def popular_of(*names):
    ranks = {n: i + 1 for i, n in enumerate(names)}
    return lambda domain: ranks.get(domain)


NOT_POPULAR = popular_of()


def alerts(res, detection):
    return [a for a in res.alerts if a.detection == detection]


# ----------------------------------------------------------------- N1

def test_n1_reason_codes_by_action_and_answer_only():
    lists = {C2: ('feodo_tracker',), '198.51.100.66': ('feodo_tracker',)}
    res = d.run(result(dns=[q('c2.invented.example', at=7200, event_id=3008, status=0,
                              answers=['198.51.100.66', '192.168.1.1'])],
                       conns=[c(C2, at=0), c(C2, at=10, action='dropped'), c('192.168.1.50', local=True),
                              c('203.0.113.5', at=20)]),
                ip_lists=lambda ip: lists.get(ip, ()))
    n1 = alerts(res, 'N1')
    assert [(a.dest, sorted(a.reasons)) for a in n1] == [
        (C2, ['blocklist_ip_connection', 'blocklist_ip_dropped']),
        ('198.51.100.66', ['blocklist_ip_dns_answer'])]
    assert n1[0].details['lists'] == ['feodo_tracker'] and n1[0].events == 2 and n1[0].hour == '2026-01-05T00'
    assert n1[1].details['lists'] == ['feodo_tracker'] and n1[1].dest_type == 'ip'


def test_n1_does_not_run_without_lists_and_n2_is_inactive():
    res = d.run(result(conns=[c(C2)]))
    assert res.not_run['N1'] == 'blocklists_missing' and res.not_run['N2'] == 'inactive_in_v1'
    assert alerts(res, 'N1') == []


def test_alerts_group_per_fixed_utc_hour():
    res = d.run(result(conns=[c(C2, at=0), c(C2, at=3599), c(C2, at=3600)]), ip_lists=lambda ip: ('x',))
    assert [(a.hour, a.events) for a in alerts(res, 'N1')] == [('2026-01-05T00', 2), ('2026-01-05T01', 1)]


# ----------------------------------------------------------------- N3, N4

def test_n3_matches_registered_domain_hashes_only():
    hashes = frozenset({sha256_hex('phish-invented.example')})
    res = d.run(result(dns=[q('login.phish-invented.example'), q('phish-invented.example.other.example', at=1),
                            q('wpad', at=2)]), indicator_domain_hashes=hashes)
    (alert,) = alerts(res, 'N3')
    assert alert.dest == 'phish-invented.example' and alert.reasons == {'indicator_store_domain_match'}
    assert d.run(result(dns=[q('a.invented.example')])).not_run['N3'] == 'indicator_store_unavailable'


def test_n4_scores_the_inert_bare_host_url_against_the_threshold():
    seen = []

    def score(url):
        seen.append(url)
        return {'https://pay.bad-invented.example/': 0.9870690448552604,
                'https://pay.ok-invented.example/': 0.98706904}.get(url, 0.0)
    res = d.run(result(dns=[q('pay.bad-invented.example'), q('pay.ok-invented.example', at=1),
                            q('pay.bad-invented.example', at=2)]),
                url_score=score, url_threshold=0.9870690448552604)
    (alert,) = alerts(res, 'N4')
    assert alert.dest == 'bad-invented.example' and alert.details == {'score': 0.987069,
                                                                      'threshold': 0.9870690448552604}
    assert sorted(seen) == ['https://pay.bad-invented.example/', 'https://pay.ok-invented.example/']
    assert d.run(result(dns=[q('a.invented.example')])).not_run['N4'] == 'url_model_unavailable'


# ----------------------------------------------------------------- N5

def test_entropy_and_consonant_run():
    assert d.entropy('aaaa') == 0 and round(d.entropy('ab'), 6) == 1.0
    assert d.longest_consonant_run('abcdfgeijklm') == 5 and d.longest_consonant_run('abcdfeghijkl') == 4


@pytest.mark.parametrize('label, expected', [
    ('bcdfghjklmnp', True),     # 12 distinct: entropy 3.585 >= 3.5, consonant run 12
    ('bcdfghjklmn', False),     # 11 distinct: entropy 3.459 < 3.5
    ('abcdfgeijklm', True),     # consonant run 5
    ('abcdfeghijkl', False),    # consonant run 4, no digits
    ('a1b2c3d4e5f6ghaeiouo', True),    # digit share 6/20 = 0.30
    ('a1b2c3d4e5fxghaeiouo', False),   # digit share 5/20 = 0.25
])
def test_dga_like_constants(label, expected):
    assert d.entropy(label) >= 3.5 or not expected
    assert d.dga_like(label) is expected


def test_dga_length_boundary(monkeypatch):
    monkeypatch.setattr(d, 'N5_MIN_ENTROPY', 0.0)
    assert d.dga_like('bcdfghjkl') is False and d.dga_like('bcdfghjklm') is True   # 9 vs 10


def test_n5_single_name_and_popular_exclusion():
    res = d.run(result(dns=[q('bcdfghjklmnp.example'), q('www.bcdfghjklmnq.example', at=1)]),
                popular_rank=popular_of('bcdfghjklmnq.example'))
    (alert,) = alerts(res, 'N5')
    assert alert.dest == 'bcdfghjklmnp.example' and alert.reasons == {'dga_like_domain'}
    assert alert.details['label_length'] == 12 and alert.details['consonant_run'] == 12
    assert d.run(result(dns=[q('bcdfghjklmnp.example')])).not_run['N5'] == 'popular_list_missing'


DGA_LABELS = ['bcdfghjklmn' + ch for ch in 'pqrstvwxz'] + ['qwrtzpsdfghk', 'zxcvbnmlkjhg']


@pytest.mark.parametrize('count, window, burst', [(10, 590, True), (9, 590, False), (10, 601, False)])
def test_n5_nxdomain_burst(count, window, burst):
    step = window / (count - 1)
    records = [q(f'{label}.example', at=i * step, status=9003, event_id=3008)
               for i, label in enumerate(DGA_LABELS[:count])]
    res = d.run(result(dns=records), popular_rank=NOT_POPULAR)
    n5 = alerts(res, 'N5')
    assert len({a.dest for a in n5}) == count
    assert all(('dga_nxdomain_burst' in a.reasons) is burst for a in n5)
    if burst:
        assert all(a.details['burst_domains'] == 10 for a in n5)


def test_n5_burst_needs_name_does_not_exist():
    records = [q(f'{label}.example', at=i, status=0, event_id=3008) for i, label in enumerate(DGA_LABELS[:10])]
    res = d.run(result(dns=records), popular_rank=NOT_POPULAR)
    assert not any('dga_nxdomain_burst' in a.reasons for a in res.alerts)


# ----------------------------------------------------------------- N6

def beacon(count, gap, jitter=()):
    times, at = [], 0.0
    for i in range(count):
        times.append(at)
        at += gap + (jitter[i] if i < len(jitter) else 0)
    return [c('203.0.113.20', port=8443, at=t) for t in times]


@pytest.mark.parametrize('records, fires', [
    (beacon(10, 300), True),                    # 10 events over 45 min, gap 300 s
    (beacon(9, 300), False),                    # 9 events
    (beacon(10, 180), False),                   # span 27 min < 30 min
    (beacon(31, 9), False),                     # median gap 9 s < 10 s
    (beacon(10, 3601), False),                  # median gap > 3,600 s
    (beacon(11, 300, jitter=[30] * 4 + [0] * 6), True),     # jittered gaps (330 s x4, 300 s x6): median 300, MAD 0
])
def test_n6_beaconing_constants(records, fires):
    res = d.run(result(conns=records))
    assert bool(alerts(res, 'N6')) is fires


def test_n6_dispersion_boundary():
    # 20 gaps: ten of 100 s and ten of `other` -> median (100 + other) / 2, MAD (other - 100) / 2.
    # other = 120 -> dispersion 0.0909 (fires); other = 125 -> 0.111 (does not fire).
    def series(other):
        gaps = [100, other] * 10
        at, out = 0.0, []
        for gap in [0] + gaps:
            at += gap
            out.append(c('203.0.113.21', port=443, at=at))
        return out
    assert alerts(d.run(result(conns=series(120))), 'N6')
    assert not alerts(d.run(result(conns=series(125))), 'N6')
    (alert,) = alerts(d.run(result(conns=series(120))), 'N6')
    assert alert.details['events'] == 21 and alert.details['dispersion'] == 0.0909 and alert.details['port'] == 443 and alert.dest == '203.0.113.21'


def test_n6_skips_local_inbound_and_popular_names():
    local = [c('192.168.1.9', at=i * 300, local=True) for i in range(10)]
    inbound = [c('203.0.113.30', at=i * 300, direction='inbound') for i in range(10)]
    popular = [c('203.0.113.31', at=i * 300, source='sysmon3', action='observed', name='www.big-invented.example')
               for i in range(10)]
    res = d.run(result(conns=local + inbound + popular), popular_rank=popular_of('big-invented.example'))
    assert alerts(res, 'N6') == []


def test_n6_falls_back_to_dns_only_without_connection_sources():
    dns = [q('sync.beacon-invented.example', at=i * 300) for i in range(10)]
    (alert,) = alerts(d.run(result(dns=dns), popular_rank=NOT_POPULAR), 'N6')
    assert alert.dest_type == 'domain' and alert.dest == 'beacon-invented.example'
    assert d.run(result(dns=dns)).not_run['N6'] == 'popular_list_missing'
    with_conns = d.run(result(dns=dns, conns=[c('203.0.113.1')]), popular_rank=NOT_POPULAR)
    assert alerts(with_conns, 'N6') == []


# ----------------------------------------------------------------- N7

@pytest.mark.parametrize('port, fires', [(4444, True), (443, False), (8443, False), (3478, False), (3481, False),
                                         (3482, True), (853, False), (5228, False), (8081, True)])
def test_n7_port_set_without_baseline(port, fires):
    res = d.run(result(conns=[c('203.0.113.40', port=port)]))
    assert bool(alerts(res, 'N7')) is fires
    if fires:
        assert alerts(res, 'N7')[0].details == {'port': port, 'baseline': 'none'}


def test_n7_baseline_47h_vs_48h():
    hour = 3600
    first = c('203.0.113.41', port=4444, at=hour)            # inside the first 24 h
    later = c('203.0.113.42', port=4444, at=30 * hour)       # same (device, port): baseline
    new = c('203.0.113.43', port=5555, at=30 * hour)
    end_47 = c('203.0.113.44', port=443, at=47 * hour)
    res47 = d.run(result(conns=[c('203.0.113.45', port=443, at=0), first, later, new, end_47]))
    assert res47.baseline == 'none' and len(alerts(res47, 'N7')) == 3
    res48 = d.run(result(conns=[c('203.0.113.45', port=443, at=0), first, later, new,
                                c('203.0.113.44', port=443, at=48 * hour)]))
    assert res48.baseline == '24h'
    (alert,) = alerts(res48, 'N7')
    assert alert.dest == '203.0.113.43' and alert.details == {'port': 5555, 'baseline': '24h'}


def test_n7_ignores_dropped_inbound_local_and_unknown_direction():
    conns = [c('203.0.113.50', port=4444, action='dropped'), c('203.0.113.50', port=4444, direction='inbound'),
             c('192.168.1.5', port=4444, local=True), c('203.0.113.50', port=4444, direction='unknown'),
             c('203.0.113.50', port=None, protocol='icmp')]
    assert alerts(d.run(result(conns=conns)), 'N7') == []


# ----------------------------------------------------------------- N8

def labels(count, length, at=0.0, step=1.0, domain='tunnel-invented.example', qtype=1, alphabet='abcdefghijkl'):
    out = []
    for i in range(count):
        body = f'{i:04d}' + alphabet * ((length // len(alphabet)) + 1)
        out.append(q(f'{body[:length]}.{domain}', at=at + i * step, qtype=qtype))
    return out


def n8(records, **kwargs):
    return alerts(d.run(result(dns=records), popular_rank=kwargs.pop('popular', NOT_POPULAR), **kwargs), 'N8')


def test_n8_long_labels_49_vs_50_and_length_24_vs_25():
    (alert,) = n8(labels(50, 25))
    assert 'dns_long_labels' in alert.reasons and alert.details['distinct_labels'] == 50
    assert not any('dns_long_labels' in a.reasons for a in n8(labels(49, 25)))
    assert not any('dns_long_labels' in a.reasons for a in n8(labels(50, 24)))


def test_n8_high_entropy_labels():
    (alert,) = n8(labels(50, 20, alphabet='abcdefghijklmnop'))
    assert alert.reasons == {'dns_high_entropy_labels'} and alert.details['mean_label_entropy'] >= 3.8
    assert n8(labels(50, 20, alphabet='ab')) == []


def test_n8_window_is_ten_minutes():
    assert n8(labels(50, 25, step=600 / 49))
    assert n8(labels(50, 25, step=601 / 49)) == []


def test_n8_txt_19_vs_20_and_names_119_vs_120():
    txt = [q(f'x{i}.txt-invented.example', at=i, qtype=16) for i in range(20)]
    (alert,) = n8(txt)
    assert alert.reasons == {'dns_txt_burst'} and alert.details['txt_queries'] == 20
    assert n8(txt[:19]) == []
    base = '.long-invented.example'
    assert n8([q('a' * (119 - len(base)) + base)]) == []
    (long,) = n8([q('a' * (120 - len(base)) + base)])
    assert long.reasons == {'dns_very_long_name'} and long.details['max_name_length'] == 120


def test_n8_two_signs_and_only_the_registered_domain_is_kept():
    records = labels(50, 30, alphabet='ab') + [q('t.tunnel-invented.example', at=100 + i, qtype=16) for i in range(20)]
    (alert,) = n8(records)
    assert alert.reasons == {'dns_long_labels', 'dns_txt_burst'} and alert.details['signs'] == 2
    assert alert.dest == 'tunnel-invented.example' and alert.ips == set()


def test_n8_skips_popular_and_sysmon_only_has_no_txt_sign():
    assert n8(labels(50, 30), popular=popular_of('tunnel-invented.example')) == []
    sysmon = [q(f'x{i}.txt-invented.example', at=i, source='sysmon22') for i in range(20)]
    assert n8(sysmon) == []


# ----------------------------------------------------------------- N9

def test_n9_first_seen_after_the_baseline():
    hour = 3600
    records = [q('old-invented.example', at=0), q('old-invented.example', at=30 * hour),
               q('new-invented.example', at=30 * hour), q('pop.top-invented.example', at=30 * hour),
               q('www.ranked-invented.example', at=30 * hour), q('end-invented.example', at=48 * hour)]
    conns = [c('203.0.113.70', at=30 * hour), c('203.0.113.71', at=30 * hour, source='sysmon3', name='n.invented.example')]
    ranks = {'top-invented.example': 5, 'ranked-invented.example': 1_000_001}
    res = d.run(result(dns=records, conns=conns), popular_rank=ranks.get)
    found = sorted((a.dest_type, a.dest) for a in alerts(res, 'N9'))
    assert found == [('domain', 'end-invented.example'), ('domain', 'new-invented.example'),
                     ('domain', 'ranked-invented.example'), ('ip', '203.0.113.70')]
    assert all(a.details == {'baseline': '24h'} for a in alerts(res, 'N9'))


def test_n9_emits_nothing_without_a_baseline():
    res = d.run(result(dns=[q('a-invented.example'), q('b-invented.example', at=47 * 3600)]),
                popular_rank=NOT_POPULAR)
    assert alerts(res, 'N9') == [] and res.not_run['N9'] == 'no_baseline'


# ----------------------------------------------------------------- coverage, privacy, determinism

def test_detections_without_their_source_are_not_visible():
    res = d.run(result(conns=[c(C2)]), ip_lists=lambda ip: (), indicator_domain_hashes=frozenset(),
                url_score=lambda u: 1.0, url_threshold=0.5, popular_rank=NOT_POPULAR)
    assert {k: v for k, v in res.not_run.items()} == {'N2': 'inactive_in_v1', 'N3': 'not_visible',
                                                      'N4': 'not_visible', 'N5': 'not_visible',
                                                      'N8': 'not_visible', 'N9': 'no_baseline'}


def test_alert_repr_hides_destinations_and_process_ids():
    res = d.run(result(conns=[c(C2, guid='{marker-guid}')]), ip_lists=lambda ip: ('x',))
    (alert,) = res.alerts
    assert C2 not in repr(alert) and 'marker-guid' not in repr(alert)
    assert alert.process_guids == {'{marker-guid}'} and alert.dest_hash == sha256_hex(C2)
    assert res.counts == {('N1', 'blocklist_ip_connection'): 1}


def test_split_name_skips_local_names():
    assert d.split_name('a.b.invented.example') == ('invented.example', 'invented')
    assert d.split_name('www.invented.co.uk') == ('invented.co.uk', 'invented')
    assert d.split_name('wpad') is None and d.split_name('printer.local') is None


def test_query_events_fall_back_from_3006_to_3008_to_3020():
    both = [q('a.invented.example', event_id=3006), q('a.invented.example', event_id=3008),
            q('a.invented.example', event_id=3020), q('b.invented.example', source='sysmon22')]
    assert [(r.source, r.event_id) for r in d.query_events(both)] == [('dns_client', 3006), ('sysmon22', 22)]
    assert [r.event_id for r in d.query_events(both[1:3])] == [3008]
    assert [r.event_id for r in d.query_events(both[2:3])] == [3020]
