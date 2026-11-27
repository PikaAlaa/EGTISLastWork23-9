"""network.windows import API (design network-windows-v1 §6.7, §6.8, §7; step 13).

The scratch database is seeded only through data/scripts/import_network_windows.py on invented logs,
an invented blocklist and an invented shipped-item manifest in tmp_path (helpers shared with the
step 11 tests). Every non-loopback connection and name lookup is blocked.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.findings import Finding
from app.core.indicators import sha256_hex
from app.engines.network_windows import engine as nw_engine
from app.engines.registry import EngineRegistry
from app.routers import network_windows as nw_router
from app.services.findings import record_findings
from test_malware_api import block_outbound
from test_network_windows_import_command import C2, MARKERS, build_engine, command, inputs, run

T9 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    block_outbound(monkeypatch)
    nw_router._health_cache.clear()


@pytest.fixture
def seeded(db, tmp_path):
    phish = Finding.model_validate(dict(
        engine={'name': 'phishing.analyze', 'version': 'invented-1'}, domain='phishing', kind='phishing_url',
        severity='high', confidence='corroborated',
        indicators=[{'type': 'domain', 'value_hash': sha256_hex('phish-invented.example'), 'value': None,
                     'role': 'link_host', 'registered_domain_hash': sha256_hex('phish-invented.example')}],
        observed_at=T9, created_at=T9, source={'kind': 'scan', 'ref': 'scan_requests:1'}))
    record_findings(db, [phish])
    db.commit()
    engine, registry = build_engine(tmp_path / 'root'), EngineRegistry()
    for name in ('a', 'b'):
        folder = tmp_path / name
        folder.mkdir()
        code, out = run(folder, db, inputs(folder), engine=engine, registry=registry)
        assert code == command.EXIT_OK
    return SimpleNamespace(engine=engine, tmp_path=tmp_path)


def test_import_list_is_paginated_newest_first(client, seeded):
    body = client.get('/network/windows/imports').json()
    assert body['total_matching'] == 2 and [i['id'] for i in body['results']] == [2, 1]
    first = body['results'][0]
    assert first['engine_version'] == seeded.engine.version
    assert first['findings_by_kind'] == {'known_bad_destination': 1, 'phishing_domain_lookup': 1}
    assert first['counts']['events'] == {'dns_client:3020': 2, 'firewall:allowed': 2}
    assert [f['source'] for f in first['files']] == ['dns_client', 'firewall']
    assert set(first['files'][0]) == {'source', 'sha256', 'size', 'records'}
    assert first['coverage']['detections']['N1'] == 'visible' and first['coverage']['not_run']['N2'] == 'inactive_in_v1'
    assert first['coverage']['sources']['dns_client']['records'] == 2
    page = client.get('/network/windows/imports', params={'limit': 1, 'offset': 1}).json()
    assert [i['id'] for i in page['results']] == [1]
    assert client.get('/network/windows/imports', params={'limit': 0}).status_code == 400


def test_import_detail_carries_findings_attribution_and_incident_links(client, seeded):
    body = client.get('/network/windows/imports/1').json()
    by_kind = {f['kind']: f for f in body['findings']}
    n1, n3 = by_kind['known_bad_destination'], by_kind['phishing_domain_lookup']
    assert (n1['severity'], n1['confidence'], n1['detection'], n1['reason_codes']) == (
        'high', 'single_signal', 'N1', ['blocklist_ip_connection'])
    assert n1['lists'] == [{'list': 'feodo_tracker', 'title': 'abuse.ch Feodo Tracker IP blocklist',
                            'version': n1['lists'][0]['version'], 'licence': 'CC0 (abuse.ch terms of use §3.4)',
                            'link': 'https://feodotracker.abuse.ch/blocklist/'}]
    # Stored refs are always the server-wrapped srv: form (design core-v2 §3.2).
    assert n1['device_ref'].startswith('srv:') and n1['attack'] == [] and n1['values'] == {}
    assert (n3['severity'], n3['detection']) == ('medium', 'N3') and n3['incident_id'] is not None
    assert client.get(f"/incidents/{n3['incident_id']}").status_code == 200
    assert client.get('/network/windows/imports/999').status_code == 404
    assert client.get('/network/windows/imports/abc').status_code == 400


def test_no_marker_reaches_any_api_response(client, seeded, monkeypatch):
    monkeypatch.setattr(nw_engine, 'load_engine', lambda: nw_engine.NetworkWindowsEngine(None))
    paths = ['/network/windows/imports', '/network/windows/imports/1', '/network/windows/imports/2',
             '/network/windows/health', '/incidents', '/indicators?type=ip&q=' + C2]
    responses = [client.get(p) for p in paths]
    responses += [client.get(f"/incidents/{i['id']}") for i in client.get('/incidents').json()['results']]
    assert all(r.status_code in (200, 400, 404) for r in responses)
    for response in responses:
        for marker in MARKERS + (str(seeded.tmp_path),):
            assert marker not in response.text, marker


def test_network_windows_routes_are_read_only(client):
    from app.main import app
    spec = app.openapi()['paths']
    paths = {path: set(ops) for path, ops in spec.items() if path.startswith('/network')}
    assert paths == {'/network/windows/imports': {'get'}, '/network/windows/imports/{import_id}': {'get'},
                     '/network/windows/health': {'get'}}
    params = [p['name'] for path, ops in spec.items() if path.startswith('/network')
              for op in ops.values() for p in op.get('parameters', [])]
    assert sorted(params) == ['import_id', 'limit', 'offset', 'x-api-key', 'x-api-key', 'x-api-key']
    assert not any('requestBody' in op for path, ops in spec.items() if path.startswith('/network')
                   for op in ops.values())
    for method in ('post', 'put', 'patch', 'delete'):
        for path in ('/network/windows/imports', '/network/windows/imports/1', '/network/windows/health',
                     '/network/windows/import'):
            assert getattr(client, method)(path).status_code in (404, 405)


def test_health_without_a_shipped_manifest_reports_unavailable_and_is_cached(client, monkeypatch, tmp_path):
    calls, real = [], nw_engine.load_engine

    def fake():
        calls.append(1)
        return real(tmp_path / 'absent.json', tmp_path, lock=tmp_path / 'absent-lock.json',
                                     url_scorer=None)
    monkeypatch.setattr(nw_engine, 'load_engine', fake)
    body = client.get('/network/windows/health').json()
    assert body['engine'] == 'network.windows' and body['source'] == 'local_files' and body['available'] is False
    assert body['status'] == 'rules_missing' and body['rules_detail'] == 'shipped_manifest_missing'
    assert body['last_import'] is None and body['imports_start_from'] == 'data/scripts/import_network_windows.py'
    assert body['version'].startswith('netwin-v1+rules:none')
    client.get('/network/windows/health')
    assert len(calls) == 1


def test_health_uses_the_registered_engine_when_present(client, seeded, monkeypatch):
    from app.engines.registry import registry
    monkeypatch.setattr(registry, '_engines', {**registry._engines, 'network.windows': seeded.engine})
    body = client.get('/network/windows/health').json()
    assert body['source'] == 'registered_engine' and body['available'] is True
    assert body['shipped_lists'] == ['feodo_tracker'] and body['last_import']['id'] == 2
    assert body['reasons'] == ['blocklists_stale', 'url_model_unavailable']  # invented list fetched 2026-01-04


def test_the_real_app_does_not_register_the_engine():
    from app.engines.registry import registry
    assert 'network.windows' not in registry.names()


# ---------------------------------------------------------------- console page (design §6.7)

def test_console_page_strings_exist_in_both_languages_and_cover_every_code():
    import re
    from app.engines.network_windows import detections
    from test_console_i18n import AR, EN, flatten
    page = (ROOT / 'etis-frontend/src/pages/NetworkWindowsPage.tsx').read_text(encoding='utf-8')
    used = set(re.findall(r"""(?<![A-Za-z0-9_])t\(\s*'([a-zA-Z0-9_.-]+)'""", page))
    assert {'nav.network', 'network.intro', 'network.coverageNote', 'network.help.privacy'} <= used
    engine_source = (ROOT / 'backend/app/engines/network_windows/engine.py').read_text(encoding='utf-8')
    detection_source = (ROOT / 'backend/app/engines/network_windows/detections.py').read_text(encoding='utf-8')
    rules_detail = set(re.findall(r"NetworkWindowsEngineError\('((?:shipped|selection|freeze)_[a-z_]+)'\)", engine_source))
    not_run = set(re.findall(r"'([a-z_]+)'", detection_source.split('def run(', 1)[1])) & {
        'inactive_in_v1', 'not_visible', 'blocklists_missing', 'indicator_store_unavailable', 'url_model_unavailable',
        'popular_list_missing', 'no_baseline'}
    for name, data in (('en', EN), ('ar', AR)):
        keys = flatten(data)
        assert not sorted(k for k in used if k not in keys), name
        assert {f'network.reason.{c}' for codes in detections.REASONS.values() for c in codes} <= keys, name
        assert {f'network.detection.{d}' for d in detections.DETECTIONS} <= keys, name
        assert {f'network.health.{r}' for r in nw_engine.HEALTH_ORDER} <= keys, name
        assert {f'network.rulesDetail.{r}' for r in rules_detail} <= keys and len(rules_detail) == 6, name
        assert {f'network.notRun.{r}' for r in not_run | {'not_shipped'}} <= keys, name
        assert {f'soc.kind.{k}' for k in set(nw_engine.KINDS.values())} <= keys, name
        assert {f'soc.role.{r}' for r in ('remote_endpoint', 'resolved_name', 'connecting_process')} <= keys, name


def test_console_page_links_only_to_the_two_list_pages_and_shows_commands_as_text():
    import re
    page = (ROOT / 'etis-frontend/src/pages/NetworkWindowsPage.tsx').read_text(encoding='utf-8')
    assert re.findall(r"https://[^'\s]+", page) == ['https://feodotracker.abuse.ch/blocklist/',
                                                      'https://sslbl.abuse.ch/blacklist/']
    assert page.count('<Link') == 1 and 'LIST_LINKS.has(list.link)' in page
    for forbidden in ('window.open', 'dangerouslySetInnerHTML', 'fetch(', 'XMLHttpRequest', 'method:'):
        assert forbidden not in page, forbidden
    client = (ROOT / 'etis-frontend/src/api/client.ts').read_text(encoding='utf-8')
    block = client.split('network.windows imports', 1)[1]
    assert 'method' not in block and block.count('request<') == 3
