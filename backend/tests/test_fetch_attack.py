"""ATT&CK fetch script: pinned files only, SHA-256 verified, mismatches discarded. No network access."""
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch_attack', ROOT / 'data/scripts/fetch_attack.py')
fetch = importlib.util.module_from_spec(spec); spec.loader.exec_module(fetch)
PAYLOAD = b'{"type": "bundle", "objects": []}'


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        for start in range(0, len(self.body), 7):
            yield self.body[start:start + 7]


class FakeSession:
    def __init__(self, body):
        self.body, self.urls = body, []

    def get(self, url, **_):
        self.urls.append(url)
        return contextlib.nullcontext(FakeResponse(self.body))


def entry(body=PAYLOAD, **overrides):
    data = dict(collection='mobile', file='mobile-attack-20.0.json', size=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                url=fetch.ALLOWED_PREFIX + 'master/mobile-attack/mobile-attack-20.0.json')
    data.update(overrides)
    return data


def test_committed_lock_pins_exactly_two_files_with_hashes():
    lock = fetch.load_lock()
    assert lock['version'] == '20.0'
    assert sorted(f['file'] for f in lock['files']) == ['enterprise-attack-20.0.json', 'mobile-attack-20.0.json']
    assert all(f['url'].startswith(fetch.ALLOWED_PREFIX) and len(f['sha256']) == 64 for f in lock['files'])


def test_matching_download_is_kept(tmp_path):
    session = FakeSession(PAYLOAD)
    assert fetch.download(entry(), tmp_path, session) == 'downloaded_and_verified'
    assert (tmp_path / 'mobile-attack-20.0.json').read_bytes() == PAYLOAD
    assert fetch.download(entry(), tmp_path, session) == 'already_verified'
    assert len(session.urls) == 1
    assert not list(tmp_path.glob('*.part'))


def test_mismatched_download_is_discarded(tmp_path):
    with pytest.raises(ValueError, match='sha256_mismatch'):
        fetch.download(entry(), tmp_path, FakeSession(PAYLOAD.replace(b'[]', b'{}')))
    assert list(tmp_path.iterdir()) == []


def test_tampered_existing_file_is_replaced(tmp_path):
    (tmp_path / 'mobile-attack-20.0.json').write_bytes(b'tampered')
    assert fetch.download(entry(), tmp_path, FakeSession(PAYLOAD)) == 'downloaded_and_verified'
    assert fetch.verify(tmp_path / 'mobile-attack-20.0.json', entry())


@pytest.mark.parametrize('change', [
    {'url': 'https://example.com/enterprise-attack-20.0.json'},
    {'file': '../escape.json'},
    {'sha256': 'abc'},
])
def test_lock_rejects_unpinned_locations(tmp_path, change):
    lock = json.loads((ROOT / 'data/attack-lock.json').read_text(encoding='utf-8'))
    lock['files'][0].update(change)
    path = tmp_path / 'lock.json'; path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fetch.load_lock(path)


def test_lock_rejects_extra_files(tmp_path):
    lock = json.loads((ROOT / 'data/attack-lock.json').read_text(encoding='utf-8'))
    lock['files'].append(dict(lock['files'][0], collection='ics'))
    path = tmp_path / 'lock.json'; path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fetch.load_lock(path)
