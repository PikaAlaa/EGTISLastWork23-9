"""Offline blocklist loader and lock format (design network-windows-v1 §2.2, §6.8, §8.4).

Every list is invented (RFC 5737 addresses) and written to tmp_path; nothing is fetched.
"""
import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.engines.network_windows import blocklists, detections
from app.engines.network_windows.blocklists import BlocklistError, load, read_lock
from app.engines.network_windows.readers import ConnRecord, ReadResult

ROOT = Path(__file__).resolve().parents[2]
FEODO = '# invented Feodo-style list\n203.0.113.66\n203.0.113.67\n\n198.51.100.0/24\n192.168.1.1\nnot-an-ip\n'
SSLBL = '# invented SSLBL-style csv\n# Firstseen,DstIP,DstPort\n2026-01-01 00:00:00,203.0.113.67,443\n' \
        '2026-01-01 00:00:00,198.51.100.9,8443\n'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def write_lists(root, feodo=FEODO, sslbl=SSLBL, **overrides):
    folder = root / 'data' / 'external' / 'network-blocklists'
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'feodo.txt').write_bytes(feodo.encode())
    (folder / 'sslbl.csv').write_bytes(sslbl.encode())
    entries = [
        {'name': 'feodo_tracker', 'url': 'https://feodotracker.abuse.ch/invented.txt',
         'fetched_at': '2026-01-05T00:00:00Z', 'file': 'feodo.txt', 'size': len(feodo.encode()),
         'sha256': hashlib.sha256(feodo.encode()).hexdigest(), 'rows': 2, 'format': 'ip_lines'},
        {'name': 'ssl_blacklist', 'url': 'https://sslbl.abuse.ch/invented.csv',
         'fetched_at': '2026-01-03T00:00:00Z', 'file': 'sslbl.csv', 'size': len(sslbl.encode()),
         'sha256': hashlib.sha256(sslbl.encode()).hexdigest(), 'rows': 2, 'format': 'csv', 'column': 1},
    ]
    for index, changes in overrides.items():
        entries[int(index[1:])].update(changes)
    lock = root / 'data' / 'network-blocklists-lock.json'
    lock.write_text(json.dumps({'destination': 'data/external/network-blocklists', 'lists': entries}),
                    encoding='utf-8')
    return lock


def test_lists_load_with_exact_ip_matching_and_attribution(tmp_path):
    lock = write_lists(tmp_path)
    lists = load(lock, tmp_path)
    assert sorted(lists.lists) == ['feodo_tracker', 'ssl_blacklist'] and lists.errors == {}
    assert lists.lookup('203.0.113.66') == ('feodo_tracker',)
    assert lists.lookup('203.0.113.67') == ('feodo_tracker', 'ssl_blacklist')
    assert lists.lookup('::ffff:198.51.100.9') == ('ssl_blacklist',)
    assert lists.lookup('198.51.100.10') == () and lists.lookup('192.168.1.1') == () and lists.lookup('x') == ()
    assert lists.ignored['feodo_tracker'] == {'comment_or_blank': 2, 'not_ip': 1, 'range': 1, 'local': 1}
    assert lists.ignored['ssl_blacklist']['comment_or_blank'] == 2
    sha = hashlib.sha256(FEODO.encode()).hexdigest()
    assert lists.attribution('feodo_tracker') == {
        'list': 'feodo_tracker', 'title': 'abuse.ch Feodo Tracker IP blocklist',
        'version': f'2026-01-05T00:00:00Z+sha256:{sha[:12]}', 'licence': 'CC0 (abuse.ch terms of use §3.4)',
        'link': 'https://feodotracker.abuse.ch/blocklist/'}
    assert lists.lock_sha256 == hashlib.sha256(lock.read_bytes()).hexdigest()


@pytest.mark.parametrize('change, code', [
    ({'size': 1}, 'blocklist_size_mismatch'),
    ({'sha256': '0' * 64}, 'blocklist_sha256_mismatch'),
    ({'rows': 3}, 'blocklist_row_count_mismatch'),
    ({'file': 'absent.txt'}, 'blocklist_missing'),
])
def test_a_list_that_does_not_match_its_pin_is_refused_alone(tmp_path, change, code):
    lists = load(write_lists(tmp_path, e0=change), tmp_path)
    assert lists.errors == {'feodo_tracker': code} and list(lists.lists) == ['ssl_blacklist']
    assert lists.lookup('203.0.113.66') == ()


@pytest.mark.parametrize('change, code', [
    ({'name': 'urlhaus'}, 'blocklist_not_allowed'),
    ({'name': 'ssl_blacklist'}, 'blocklist_invalid_lock'),          # duplicate
    ({'file': '../../escape.txt'}, 'blocklist_invalid_lock'),
    ({'format': 'json'}, 'blocklist_invalid_lock'),
    ({'url': 'http://feodotracker.abuse.ch/x'}, 'blocklist_invalid_lock'),
    ({'fetched_at': '2026-01-05T00:00:00'}, 'blocklist_invalid_lock'),   # no time zone
    ({'sha256': 'abc'}, 'blocklist_invalid_lock'),
])
def test_bad_locks_are_refused(tmp_path, change, code):
    with pytest.raises(BlocklistError) as caught:
        read_lock(write_lists(tmp_path, e0=change), tmp_path)
    assert str(caught.value) == code


def test_missing_lock_means_no_lists_and_health_reports_it(tmp_path):
    lists = load(tmp_path / 'absent.json', tmp_path)
    assert lists.lists == {} and lists.lock_sha256 is None and lists.health() == ['blocklists_missing']
    assert read_lock(tmp_path / 'absent.json', tmp_path) == ([], None)


def test_staleness_uses_the_newest_list(tmp_path):
    lists = load(write_lists(tmp_path), tmp_path)
    assert lists.health(datetime(2026, 1, 12, 0, 0, tzinfo=timezone.utc)) == []
    assert lists.health(datetime(2026, 1, 12, 0, 1, tzinfo=timezone.utc)) == ['blocklists_stale']


def test_n1_uses_the_loaded_lists(tmp_path):
    lists = load(write_lists(tmp_path), tmp_path)
    result = ReadResult()
    result.connections = [ConnRecord(time='2026-01-05T10:00:00.000000Z', source='firewall', direction='outbound',
                                     action='allowed', protocol='tcp', remote_ip='203.0.113.67', remote_local=False,
                                     remote_port=443, local_port=50000, device_ref='hmac:' + '1' * 32)]
    (alert,) = detections.run(result, ip_lists=lists.lookup).alerts
    assert alert.details['lists'] == ['feodo_tracker', 'ssl_blacklist']
    assert alert.reasons == {'blocklist_ip_connection'}


def test_repository_ships_a_feodo_only_lock_and_ignores_the_list_folder():
    # Design §2.2 note of 27 November 2026: Feodo Tracker alone; the SSL Blacklist IP list is deprecated.
    assert blocklists.LOCK == ROOT / 'data' / 'network-blocklists-lock.json'
    specs, lock_sha = read_lock(blocklists.LOCK, ROOT)
    assert [s.name for s in specs] == ['feodo_tracker'] and len(lock_sha) == 64
    (feodo,) = specs
    assert feodo.url == 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt'
    assert feodo.format == 'ip_lines' and feodo.list_last_updated is not None
    lock = json.loads(blocklists.LOCK.read_text(encoding='utf-8'))
    assert lock['destination'] == 'data/external/network-blocklists' and 'CC0' in lock['licence']
    assert set(lock['not_fetched']) == {'ssl_blacklist'}
    assert 'data/external/network-blocklists/' in (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()
    text = Path(blocklists.__file__).read_text(encoding='utf-8')
    for forbidden in ('urllib', 'requests', 'http.client', 'socket', 'subprocess', 'urlopen'):
        assert forbidden not in text, forbidden
