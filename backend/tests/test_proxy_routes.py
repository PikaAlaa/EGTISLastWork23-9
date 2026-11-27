"""Same-origin proxy (etis-frontend/server.mjs) with the SOC console routes (design core-v1 §6, §9.11).

Spawns the real proxy on loopback against a local stub backend; nothing leaves the machine.
"""
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which('node')
pytestmark = pytest.mark.skipif(NODE is None, reason='node is required to run the proxy')
KEY = 'proxy-test-key'
INVENTED_REF = 'srv:' + '0a' * 16   # invented device pseudonym, not a real device


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Stub(http.server.BaseHTTPRequestHandler):
    seen = []

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length).decode() if length else ''
        Stub.seen.append({'method': self.command, 'path': self.path, 'body': body,
                          'key': self.headers.get('X-API-Key')})
        payload = json.dumps({'ok': True}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = _handle

    def log_message(self, *args):
        pass


@pytest.fixture(scope='module')
def proxy():
    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stub)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    port = free_port()
    env = {**os.environ, 'ETIS_API_KEY': KEY, 'PORT': str(port), 'ETIS_WEB_HOST': '127.0.0.1',
           'ETIS_BACKEND_URL': f'http://127.0.0.1:{backend.server_address[1]}'}
    process = subprocess.Popen([NODE, 'server.mjs'], cwd=ROOT / 'etis-frontend', env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                break
        except OSError:
            if process.poll() is not None:
                pytest.fail('proxy exited: ' + process.stderr.read())
            time.sleep(0.1)
    yield port
    process.terminate(); process.wait(timeout=10)
    backend.shutdown()


def call(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    data = json.dumps(body).encode() if body is not None else None
    connection.request(method, path, body=data, headers={'Host': f'127.0.0.1:{port}', **(headers or {})})
    response = connection.getresponse()
    text = response.read().decode(errors='replace')
    connection.close()
    return response.status, text


@pytest.mark.parametrize('method,path', [
    ('GET', '/api/incidents?status=open'), ('GET', '/api/incidents/12'), ('PATCH', '/api/incidents/12'),
    ('POST', '/api/incidents/12/merge'), ('GET', '/api/campaigns'), ('POST', '/api/campaigns'),
    ('GET', '/api/campaigns/suggestions'), ('POST', '/api/campaigns/3/incidents'),
    ('GET', '/api/indicators?type=domain&q=lure.example'), ('GET', '/api/indicators/5'),
    ('GET', '/api/community-reports'), ('PATCH', '/api/community-reports/2'),
    ('GET', '/api/attack/techniques?matrix=mobile'), ('GET', '/api/attack/techniques/T1566.002'),
    ('GET', '/api/attack/coverage'), ('POST', '/api/analyze'), ('GET', '/api/threats'),
    ('GET', '/api/malware/scans?limit=10&offset=0'), ('GET', '/api/malware/scans/3'), ('GET', '/api/malware/health'),
    ('GET', '/api/network/windows/imports?limit=10&offset=0'), ('GET', '/api/network/windows/imports/3'),
    ('GET', '/api/network/windows/health'),
    ('GET', '/api/extension/v1/status'), ('POST', '/api/extension/v1/pairing-secret'), ('POST', '/api/extension/v1/revoke'),
    # Core v2 (design core-v2 §2.4, §3.5): read-only, GET only.
    ('GET', '/api/recommended-actions'), ('GET', '/api/device-risk?limit=50&offset=0'),
    ('GET', f'/api/device-risk/detail?device_ref={INVENTED_REF}'),
])
def test_listed_routes_are_forwarded_with_server_key(proxy, method, path):
    Stub.seen.clear()
    body = {'note': 'invented'} if method in ('POST', 'PATCH') else None
    status, _ = call(proxy, method, path, body)
    assert status == 200
    forwarded = Stub.seen[-1]
    assert forwarded['method'] == method and forwarded['path'] == path[4:] and forwarded['key'] == KEY
    if body is not None:
        assert json.loads(forwarded['body']) == body


@pytest.mark.parametrize('method,path,expected', [
    ('GET', '/api/incidents/abc', 404), ('GET', '/api/admin', 404), ('GET', '/api/indicators/export', 404),
    ('GET', '/api/attack/techniques/../../etc', 404), ('DELETE', '/api/incidents/1', 405),
    ('PATCH', '/api/indicators/1', 405), ('POST', '/api/attack/coverage', 405), ('GET', '/api/incidents/1/merge', 405),
    ('POST', '/api/malware/scans', 405), ('DELETE', '/api/malware/scans/1', 405), ('PUT', '/api/malware/health', 405),
    ('PATCH', '/api/malware/scans/1', 405), ('POST', '/api/malware/scan', 404), ('GET', '/api/malware/scans/x', 404),
    ('POST', '/api/network/windows/imports', 405), ('DELETE', '/api/network/windows/imports/1', 405),
    ('PUT', '/api/network/windows/health', 405), ('POST', '/api/network/windows/import', 404),
    ('GET', '/api/network/windows/imports/x', 404), ('GET', '/api/network/flows', 404),
    ('POST', '/api/extension/v1/pair', 404), ('POST', '/api/extension/v1/check', 404),
    ('DELETE', '/api/extension/v1/status', 405),
    ('POST', '/api/recommended-actions', 405), ('DELETE', '/api/recommended-actions', 405),
    ('POST', '/api/device-risk', 405), ('PATCH', '/api/device-risk/detail', 405), ('PUT', '/api/device-risk', 405),
    ('GET', '/api/recommended-actions/blacklist_exact', 404), ('GET', f'/api/device-risk/{INVENTED_REF}', 404),
    ('GET', '/api/device-risk/detail/x', 404), ('GET', '/api/devices', 404), ('GET', '/api/devices/1', 404),
])
def test_unlisted_paths_and_methods_are_refused_without_forwarding(proxy, method, path, expected):
    Stub.seen.clear()
    status, _ = call(proxy, method, path, {'x': 1} if method in ('POST', 'PATCH') else None)
    assert status == expected and Stub.seen == []


def test_host_and_origin_checks_still_apply(proxy):
    Stub.seen.clear()
    assert call(proxy, 'GET', '/api/incidents', headers={'Host': 'evil.example'})[0] == 403
    assert call(proxy, 'PATCH', '/api/incidents/1', {'note': 'x'},
                headers={'Origin': 'http://evil.example'})[0] == 403
    assert Stub.seen == []


def test_console_paths_serve_the_single_page_app(proxy):
    if not (ROOT / 'etis-frontend/dist/index.html').is_file():
        pytest.skip('frontend not built yet')
    for path in ('/incidents', '/indicators', '/attack', '/scan', '/files', '/network', '/devices'):
        status, text = call(proxy, 'GET', path)
        assert status == 200 and '<div id="root">' in text
