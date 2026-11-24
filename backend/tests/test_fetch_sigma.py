"""SigmaHQ release fetch: one pinned package, SHA-256 verified, safe extraction, tree hash (design host-engine-v1 §2.2).

Uses in-memory invented zip packages; no network access and no SigmaHQ rule text.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

from app.engines.host.sigma_harness import load_release

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch_sigma', ROOT / 'data/scripts/fetch_sigma.py')
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

RULE_A = b'title: Invented A\nid: 00000000-0000-4000-8000-00000000000a\n'
RULE_B = b'title: Invented B\nid: 00000000-0000-4000-8000-00000000000b\n'


def package(members: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buffer.getvalue()


GOOD = {'rules/windows/a.yml': RULE_A, 'rules/windows/sub/b.yml': RULE_B, 'version.txt': b'r2099-01-01',
        'tools/ignored.py': b'print(1)'}


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        for start in range(0, len(self.body), 1000):
            yield self.body[start:start + 1000]


class FakeSession:
    def __init__(self, body):
        self.body, self.urls = body, []

    def get(self, url, **_):
        self.urls.append(url)
        return contextlib.nullcontext(FakeResponse(self.body))


def lock_for(body: bytes, tmp_path: Path, tree=None) -> dict:
    return {'release': 'r2099-01-01', 'license': 'DRL-1.1', 'destination': '',
            'package': {'file': 'sigma_all_rules.zip', 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                        'url': fetch.ALLOWED_PREFIX + 'r2099-01-01/sigma_all_rules.zip'},
            'extracted': {'directory': 'r2099-01-01', 'rule_files': 2, 'tree_sha256': tree or tree_of(GOOD)}}


def tree_of(members):
    lines = sorted(f'{name}\t{hashlib.sha256(body).hexdigest()}' for name, body in members.items()
                   if name.endswith('.yml'))
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('utf-8')).hexdigest()


def test_committed_lock_pins_one_release_package():
    lock = fetch.load_lock()
    assert lock['release'] == 'r2026-07-01' and lock['license'] == 'DRL-1.1'
    assert lock['package']['file'] == 'sigma_all_rules.zip'
    assert lock['package']['url'] == fetch.ALLOWED_PREFIX + 'r2026-07-01/sigma_all_rules.zip'
    assert len(lock['package']['sha256']) == 64 and lock['package']['size'] > 0
    assert len(lock['extracted']['tree_sha256']) == 64 and lock['extracted']['rule_files'] > 1000
    assert lock['destination'] == 'data/external/sigma/'


def test_rules_directory_is_ignored_by_git():
    assert 'data/external/sigma/' in (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()


def test_matching_package_is_kept_extracted_and_verified(tmp_path):
    body = package(GOOD)
    lock = lock_for(body, tmp_path)
    session = FakeSession(body)
    assert fetch.fetch(lock, tmp_path, session) == 'downloaded_and_verified'
    root = tmp_path / 'r2099-01-01'
    assert (root / 'rules/windows/sub/b.yml').read_bytes() == RULE_B
    assert (root / 'version.txt').is_file() and not (root / 'tools').exists()
    assert fetch.fetch(lock, tmp_path, session) == 'already_verified' and len(session.urls) == 1
    assert not list(tmp_path.rglob('*.part'))


def test_mismatched_package_is_discarded(tmp_path):
    body = package(GOOD)
    lock = lock_for(body, tmp_path)
    with pytest.raises(ValueError, match='sha256_mismatch'):
        fetch.fetch(lock, tmp_path, FakeSession(package({**GOOD, 'rules/x.yml': b'x'})))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('name', ['../evil.yml', '/abs/evil.yml', 'rules/../../evil.yml', 'C:/evil.yml',
                                  'rules\\..\\..\\evil.yml'])
def test_unsafe_member_paths_are_refused(tmp_path, name):
    body = package({**GOOD, name: b'x'})
    with pytest.raises(ValueError, match='unsafe_member'):
        fetch.fetch(lock_for(body, tmp_path), tmp_path, FakeSession(body))
    assert not (tmp_path.parent / 'evil.yml').exists() and not (tmp_path / 'r2099-01-01').exists()


def test_oversized_members_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, 'MAX_MEMBER_BYTES', 10)
    body = package(GOOD)
    with pytest.raises(ValueError, match='member_too_large'):
        fetch.fetch(lock_for(body, tmp_path), tmp_path, FakeSession(body))
    assert not (tmp_path / 'r2099-01-01').exists()


def test_tree_hash_mismatch_removes_the_extraction(tmp_path):
    body = package(GOOD)
    lock = lock_for(body, tmp_path, tree='0' * 64)
    with pytest.raises(ValueError, match='tree_sha256_mismatch'):
        fetch.fetch(lock, tmp_path, FakeSession(body))
    assert not (tmp_path / 'r2099-01-01').exists()


@pytest.mark.parametrize('change', [
    {'url': 'https://example.com/sigma_all_rules.zip'},
    {'file': '../escape.zip'},
    {'sha256': 'abc'},
])
def test_lock_rejects_unpinned_locations(tmp_path, change):
    lock = json.loads((ROOT / 'data/sigma-lock.json').read_text(encoding='utf-8'))
    lock['package'].update(change)
    path = tmp_path / 'lock.json'
    path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fetch.load_lock(path)


def test_release_loader_reads_verified_rule_files(tmp_path):
    body = package(GOOD)
    lock = lock_for(body, tmp_path)
    fetch.fetch(lock, tmp_path, FakeSession(body))
    lock_path = tmp_path / 'lock.json'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    release, files = load_release(lock_path, tmp_path)
    assert release == 'r2099-01-01'
    assert [f.path for f in files] == ['rules/windows/a.yml', 'rules/windows/sub/b.yml']
    assert files[0].text == RULE_A.decode() and files[0].sha256 == hashlib.sha256(RULE_A).hexdigest()
    (tmp_path / 'r2099-01-01/rules/windows/a.yml').write_bytes(RULE_A + b'# edited\n')
    with pytest.raises(ValueError) as exc:
        load_release(lock_path, tmp_path)
    assert str(exc.value) == 'sigma_rules_hash_mismatch'


def test_release_loader_reports_missing_rules(tmp_path):
    lock_path = tmp_path / 'lock.json'
    lock_path.write_text(json.dumps(lock_for(package(GOOD), tmp_path)), encoding='utf-8')
    with pytest.raises(FileNotFoundError) as exc:
        load_release(lock_path, tmp_path)
    assert str(exc.value) == 'sigma_rules_missing'
