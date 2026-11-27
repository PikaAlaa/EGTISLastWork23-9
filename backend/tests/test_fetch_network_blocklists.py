"""Blocklist fetch command, its lock and list ages, end to end through the engine
(design network-windows-v1 §2.2 incl. the note of 27 November 2026, §6.8, §8.4, §9 step 5).

The HTTP session is a fake; sockets are blocked. Every list and header is invented and every
address is from 203.0.113.0/24 (RFC 5737 TEST-NET-3).
"""
import hashlib
import importlib.util
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.engines.network_windows import blocklists
from app.engines.network_windows import engine as nw
from app.engines.network_windows.readers import ConnRecord, InputFile, ReadResult
from app.engines.registry import Observation
from network_windows_fixtures import write_shipped

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch_network_blocklists',
                                              ROOT / 'data/scripts/fetch_network_blocklists.py')
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)

NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt'


def invented_list(*ips, updated='2026-11-20 08:00:00'):
    header = '########\n# invented Feodo-style list (recommended)\n'
    if updated:
        header += f'# Last updated: {updated} UTC\n'
    body = header + '#\n# DstIP\n' + ''.join(f'{ip}\n' for ip in ips) + f'# END {len(ips)} entries\n'
    return body.encode()


FEODO = invented_list('203.0.113.10', '203.0.113.11', '203.0.113.0/28')
DEV = 'hmac:' + '1' * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


class Response:
    def __init__(self, body, status=200, content_type='text/plain'):
        self.body, self.status_code, self.headers = body, status, {'Content-Type': content_type}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, size):
        for start in range(0, len(self.body), size):
            yield self.body[start:start + size]


class Session:
    def __init__(self, body=FEODO, **response):
        self.body, self.response, self.calls = body, response, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.body, **self.response)


def do_fetch(tmp_path, session=None):
    session = session or Session()
    lock = tmp_path / 'data' / 'network-blocklists-lock.json'
    lock.parent.mkdir(parents=True, exist_ok=True)
    return session, lock, fetcher.fetch(session, lock, tmp_path, now=NOW)


def test_only_the_feodo_tracker_url_is_requested_without_redirects_or_pc_data(tmp_path):
    session, _, _ = do_fetch(tmp_path)
    assert [url for url, _ in session.calls] == [FEODO_URL]
    _, kwargs = session.calls[0]
    assert kwargs['allow_redirects'] is False and 'params' not in kwargs and 'data' not in kwargs
    assert kwargs['headers'] == {'User-Agent': fetcher.USER_AGENT, 'Accept': 'text/plain'}
    assert [s['name'] for s in fetcher.SOURCES] == ['feodo_tracker']
    assert 'ssl_blacklist' in fetcher.NOT_FETCHED
    assert not any(host in s['url'] for s in fetcher.SOURCES for host in ('sslbl', 'urlhaus', 'aggressive'))


def test_lock_records_size_sha256_rows_last_updated_and_licence_in_the_ignored_folder(tmp_path):
    _, lock_path, lock = do_fetch(tmp_path)
    assert json.loads(lock_path.read_text(encoding='utf-8')) == lock
    assert lock['destination'] == 'data/external/network-blocklists' and 'CC0' in lock['licence']
    assert lock['not_fetched'] == fetcher.NOT_FETCHED
    (feodo,) = lock['lists']
    assert (feodo['size'], feodo['sha256'], feodo['rows']) == (len(FEODO), hashlib.sha256(FEODO).hexdigest(), 2)
    assert feodo['ignored']['range'] == 1 and feodo['fetched_at'] == '2026-11-27T12:00:00Z'
    assert feodo['list_last_updated'] == '2026-11-20T08:00:00Z'
    folder = tmp_path / 'data' / 'external' / 'network-blocklists'
    assert [p.name for p in folder.iterdir()] == ['feodotracker_ipblocklist_recommended.txt']
    assert (folder / 'feodotracker_ipblocklist_recommended.txt').read_bytes() == FEODO


@pytest.mark.parametrize('text, expected', [
    (b'# Last updated: 2026-03-04 14:28:39 UTC   #\n203.0.113.10\n', '2026-03-04T14:28:39Z'),
    (b'#Last updated:2026-03-04 14:28:39 UTC\n', '2026-03-04T14:28:39Z'),  # whitespace is optional
    (b'# Last updated: 2026-03-04 14:28:39\n', None),               # no zone: not trusted
    (b'# Last updated: 2026-03-04 14:28:39 UTC+2\n', None),         # not plain UTC
    (b'203.0.113.10\n# Last updated: 2026-03-04 14:28:39 UTC\n', '2026-03-04T14:28:39Z'),
    (b'# invented list without a date\n203.0.113.10\n', None),
])
def test_last_updated_header_parsing(text, expected):
    assert blocklists.parse_last_updated(text) == expected


def test_a_list_without_a_header_pins_null_and_reports_no_source_age(tmp_path):
    _, lock_path, lock = do_fetch(tmp_path, Session(invented_list('203.0.113.10', updated=None)))
    assert lock['lists'][0]['list_last_updated'] is None
    loaded = fetcher.verify(lock_path, tmp_path)
    assert loaded.ages(NOW) == {'fetch_age_days': 0.0, 'source_age_days': None}
    assert loaded.health(NOW + timedelta(days=60)) == ['blocklists_stale']


@pytest.mark.parametrize('updated, days_later, ages, health', [
    ('2026-10-28 12:00:00', 0, (0.0, 30.0), []),                                    # exactly 30 days: not stale
    ('2026-10-28 11:59:00', 0, (0.0, 30.0), ['blocklist_source_stale']),            # just over 30 days
    ('2026-03-04 14:28:39', 0, (0.0, 267.9), ['blocklist_source_stale']),           # as seen on 2026-11-27
    ('2026-11-26 12:00:00', 8, (8.0, 9.0), ['blocklists_stale']),                  # our copy old, source fresh
    ('2026-03-04 14:28:39', 8, (8.0, 275.9), ['blocklists_stale', 'blocklist_source_stale']),
])
def test_health_reports_fetch_age_and_source_age_separately(tmp_path, updated, days_later, ages, health):
    _, lock_path, _ = do_fetch(tmp_path, Session(invented_list('203.0.113.10', updated=updated)))
    loaded = fetcher.verify(lock_path, tmp_path)
    when = NOW + timedelta(days=days_later)
    got = loaded.ages(when)
    assert (got['fetch_age_days'], round(got['source_age_days'], 1)) == ages
    assert loaded.health(when) == health


def test_an_empty_published_list_pins_zero_rows_and_still_loads(tmp_path):
    _, lock_path, lock = do_fetch(tmp_path, Session(invented_list()))
    assert lock['lists'][0]['rows'] == 0
    loaded = fetcher.verify(lock_path, tmp_path)
    assert list(loaded.lists) == ['feodo_tracker'] and loaded.lookup('203.0.113.10') == ()


def test_an_invalid_last_updated_in_the_lock_is_refused(tmp_path):
    _, lock_path, lock = do_fetch(tmp_path)
    lock['lists'][0]['list_last_updated'] = 'yesterday'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(blocklists.BlocklistError, match='blocklist_invalid_lock'):
        blocklists.load(lock_path, tmp_path)


@pytest.mark.parametrize('body, content_type, code', [
    (b'MZ\x90\x00invented', 'text/plain', 'executable_or_archive_refused'),
    (b'PK\x03\x04invented', 'text/plain', 'executable_or_archive_refused'),
    (b'#!/bin/sh\n203.0.113.10\n', 'text/plain', 'executable_or_archive_refused'),
    (b'203.0.113.10\x00\n', 'text/plain', 'binary_refused'),
    (b'203.0.113.10\n\xff\xfe\n', 'text/plain', 'not_utf8_text'),
    (b'203.0.113.10\n', 'application/x-msdownload', 'not_text_content_type'),
    (b'<html>203.0.113.10</html>', 'text/html', 'not_text_content_type'),
])
def test_non_text_bodies_are_refused_and_nothing_is_written(tmp_path, body, content_type, code):
    with pytest.raises(fetcher.FetchError, match=code):
        do_fetch(tmp_path, Session(body, content_type=content_type))
    assert not (tmp_path / 'data' / 'external').exists()
    assert not (tmp_path / 'data' / 'network-blocklists-lock.json').exists()


@pytest.mark.parametrize('status, code', [(302, 'redirect_refused'), (404, 'http_status_404')])
def test_redirects_and_errors_stop_the_fetch(tmp_path, status, code):
    with pytest.raises(fetcher.FetchError, match=code):
        do_fetch(tmp_path, Session(status=status))


def test_oversized_download_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fetcher, 'MAX_BYTES', 20)
    with pytest.raises(fetcher.FetchError, match='download_too_large'):
        do_fetch(tmp_path)


@pytest.mark.parametrize('url', ['http://feodotracker.abuse.ch/x.txt', 'https://urlhaus.abuse.ch/x.txt',
                                 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
                                 'https://feodotracker.abuse.ch.invalid/x.txt', 'https://feodotracker.abuse.ch/x?k=1'])
def test_sources_other_than_the_pinned_host_are_refused(url):
    with pytest.raises(fetcher.FetchError, match='source_not_allowed'):
        fetcher.check_source({**fetcher.SOURCES[0], 'url': url})


def test_verify_only_detects_a_changed_file(tmp_path):
    _, lock_path, _ = do_fetch(tmp_path)
    (tmp_path / 'data' / 'external' / 'network-blocklists' / 'feodotracker_ipblocklist_recommended.txt').write_bytes(
        FEODO.replace(b'203.0.113.11', b'203.0.113.12'))
    with pytest.raises(fetcher.FetchError, match='feodo_tracker=blocklist_sha256_mismatch'):
        fetcher.verify(lock_path, tmp_path)


def test_fetched_lock_drives_n1_through_the_engine_with_attribution_version_and_ages(tmp_path):
    _, lock_path, _ = do_fetch(tmp_path, Session(invented_list('203.0.113.10', '203.0.113.11',
                                                               updated='2026-03-04 14:28:39')))
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    manifest = write_shipped(tmp_path, lists=[('feodo_tracker', lock_sha)])
    eng = nw.load_engine(manifest, tmp_path, lock=lock_path, url_scorer=None, popular=tmp_path / 'absent.csv')
    assert eng.shipped_lists == ('feodo_tracker',) and f'+lists:{lock_sha[:12]}+' in eng.version
    health = eng.health({'now': NOW + timedelta(days=1)})
    assert 'blocklists_missing' not in health['reasons'] and 'blocklists_stale' not in health['reasons']
    assert health['reasons'][-1] == 'blocklist_source_stale'
    assert health['blocklist_ages']['fetch_age_days'] == 1.0 and health['blocklist_ages']['source_age_days'] > 30
    later = eng.health({'now': NOW + timedelta(days=8)})['reasons']
    assert 'blocklists_stale' in later and later.index('blocklists_stale') < later.index('blocklist_source_stale')

    def conn(ip, port):
        return ConnRecord(time='2026-11-27T13:00:00.000000Z', source='firewall', direction='outbound',
                          action='allowed', protocol='tcp', remote_ip=ip, remote_local=False, remote_port=443,
                          local_port=port, process_guid=None, device_ref=DEV)

    def n1_findings(eng):
        result = ReadResult()
        result.connections = [conn('203.0.113.11', 50000), conn('203.0.113.99', 50001)]
        result.files = [InputFile('firewall', 'e' * 64, 10, 2)]
        outcome = eng.process(Observation(kind=nw.OBSERVATION_KIND, source_ref='network_windows_imports:1',
                                          observed_at=NOW, data={'read': result}))
        return [f for f in outcome.findings if f.evidence.details['detection'] == 'N1']

    n1 = n1_findings(eng)
    assert len(n1) == 1 and (n1[0].kind, n1[0].severity) == ('known_bad_destination', 'high')
    (attribution,) = n1[0].evidence.details['lists']
    assert attribution['list'] == 'feodo_tracker' and attribution['licence'] == 'CC0 (abuse.ch terms of use §3.4)'
    assert attribution['version'].endswith('+sha256:' + hashlib.sha256(lock_path.parent.joinpath(
        'external', 'network-blocklists', 'feodotracker_ipblocklist_recommended.txt').read_bytes()).hexdigest()[:12])
    assert '203.0.113.11' not in json.dumps(n1[0].evidence.details)

    # Source staleness is informational only: the same list with a fresh header gives the same N1 Finding.
    fresh_root = tmp_path / 'fresh'
    _, fresh_lock, _ = do_fetch(fresh_root, Session(invented_list('203.0.113.10', '203.0.113.11')))
    fresh_sha = hashlib.sha256(fresh_lock.read_bytes()).hexdigest()
    fresh = nw.load_engine(write_shipped(fresh_root, lists=[('feodo_tracker', fresh_sha)]), fresh_root,
                           lock=fresh_lock, url_scorer=None, popular=fresh_root / 'absent.csv')
    assert 'blocklist_source_stale' not in fresh.health({'now': NOW})['reasons']
    def summary(findings):
        return [(f.kind, f.severity, f.confidence, f.attack) for f in findings]

    assert summary(n1_findings(fresh)) == summary(n1)
