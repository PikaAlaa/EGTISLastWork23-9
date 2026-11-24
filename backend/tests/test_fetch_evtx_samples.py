"""EVTX-ATTACK-SAMPLES fetch: pinned commit, per-file SHA-256, safe extraction (design host-engine-v1 §3.2).

Uses in-memory invented archives; no network access and no sample content. Nothing is parsed.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch_evtx_samples', ROOT / 'data/scripts/fetch_evtx_samples.py')
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

COMMIT = '0123456789abcdef0123456789abcdef01234567'
TOP = f'EVTX-ATTACK-SAMPLES-{COMMIT}/'
EVTX_A, EVTX_B = b'ElfFile\0invented-a', b'ElfFile\0invented-b'
GOOD = {TOP + 'Execution/a.evtx': EVTX_A, TOP + 'Lateral Movement/b.evtx': EVTX_B, TOP + 'LICENSE.GPL': b'GPL',
        TOP + 'README.md': b'readme', TOP + 'tools/run.ps1': b'Write-Output 1', TOP + 'evtx_data.csv': b'a,b'}


def archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as handle:
        for name, body in members.items():
            handle.writestr(name, body)
    return buffer.getvalue()


def lock_for(members=GOOD):
    files = [{'path': name[len(TOP):], 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
             for name, body in sorted(members.items()) if name.endswith(('.evtx', 'LICENSE.GPL', 'README.md'))]
    return {'commit': COMMIT, 'destination': '', 'directory': COMMIT[:12],
            'archive': {'url': fetch.ALLOWED_PREFIX + COMMIT, 'top_level': TOP.rstrip('/')}, 'files': files}


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


def test_committed_lock_pins_one_commit_with_per_file_hashes():
    lock = fetch.load_lock()
    assert lock['commit'] == '4ceed2f4706daf601c212a8f91c113dd85349a2c'
    assert lock['archive']['url'] == fetch.ALLOWED_PREFIX + lock['commit']
    assert lock['license'] == 'GPL-3.0' and lock['destination'] == 'data/external/evtx-attack-samples/'
    evtx = [f for f in lock['files'] if f['path'].endswith('.evtx')]
    assert len(evtx) == 278 and all(len(f['sha256']) == 64 and f['size'] > 0 for f in lock['files'])
    assert len({f['path'] for f in lock['files']}) == len(lock['files'])
    assert {f['path'] for f in lock['files'] if not f['path'].endswith('.evtx')} == {'LICENSE.GPL', 'README.md'}


def test_samples_directory_is_ignored_by_git():
    assert 'data/external/evtx-attack-samples/' in (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()


def test_matching_archive_extracts_only_pinned_files(tmp_path):
    body = archive(GOOD)
    session = FakeSession(body)
    assert fetch.fetch(lock_for(), tmp_path, session) == 'downloaded_and_verified'
    root = tmp_path / COMMIT[:12]
    assert (root / 'Execution/a.evtx').read_bytes() == EVTX_A
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()) == [
        'Execution/a.evtx', 'LICENSE.GPL', 'Lateral Movement/b.evtx', 'README.md']
    assert fetch.fetch(lock_for(), tmp_path, session) == 'already_verified' and len(session.urls) == 1
    assert not list(tmp_path.glob('*.zip')) and not list(tmp_path.rglob('*.part'))


def test_any_file_hash_mismatch_discards_the_extraction(tmp_path):
    tampered = dict(GOOD)
    tampered[TOP + 'Execution/a.evtx'] = b'ElfFile\0changed'
    with pytest.raises(ValueError, match='file_sha256_mismatch'):
        fetch.fetch(lock_for(), tmp_path, FakeSession(archive(tampered)))
    assert list(tmp_path.iterdir()) == []


def test_missing_or_extra_pinned_files_fail(tmp_path):
    missing = {k: v for k, v in GOOD.items() if not k.endswith('b.evtx')}
    with pytest.raises(ValueError, match='file_set_mismatch'):
        fetch.fetch(lock_for(), tmp_path, FakeSession(archive(missing)))
    extra = {**GOOD, TOP + 'Other/c.evtx': b'ElfFile\0c'}
    with pytest.raises(ValueError, match='file_set_mismatch'):
        fetch.fetch(lock_for(), tmp_path, FakeSession(archive(extra)))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('name', [TOP + '../evil.evtx', '/abs/evil.evtx', TOP + 'x/../../evil.evtx',
                                  'C:/evil.evtx', 'OTHER-TOP/a.evtx'])
def test_unsafe_or_foreign_member_paths_are_refused(tmp_path, name):
    body = archive({**GOOD, name: b'x'})
    with pytest.raises(ValueError, match='unsafe_member'):
        fetch.fetch(lock_for(), tmp_path, FakeSession(body))
    assert list(tmp_path.iterdir()) == []


def test_oversized_members_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, 'MAX_MEMBER_BYTES', 5)
    with pytest.raises(ValueError, match='member_too_large'):
        fetch.fetch(lock_for(), tmp_path, FakeSession(archive(GOOD)))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('change', [
    {'commit': 'master'},
    {'archive': {'url': 'https://example.com/x.zip', 'top_level': 'x'}},
])
def test_lock_rejects_unpinned_sources(tmp_path, change):
    lock = json.loads((ROOT / 'data/evtx-attack-samples-lock.json').read_text(encoding='utf-8'))
    lock.update(change)
    path = tmp_path / 'lock.json'
    path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fetch.load_lock(path)


def test_lock_rejects_unsafe_file_paths(tmp_path):
    lock = json.loads((ROOT / 'data/evtx-attack-samples-lock.json').read_text(encoding='utf-8'))
    lock['files'][0]['path'] = '../escape.evtx'
    path = tmp_path / 'lock.json'
    path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fetch.load_lock(path)


def test_fetcher_never_parses_or_executes_samples():
    source = (ROOT / 'data/scripts/fetch_evtx_samples.py').read_text(encoding='utf-8')
    for forbidden in ('import evtx', 'from evtx', 'subprocess', 'os.system', 'exec(', 'eval('):
        assert forbidden not in source
