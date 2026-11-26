"""EMBER2024 fetch script: pinned files only, Hugging Face hosts only, resume, verification, safe inspection
(design malware-engine-v1 §3.7, §4.2 download rule, §9 step 7). No network: a fake session serves bytes."""
import hashlib
import importlib.util
import json
import stat
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def fe(monkeypatch):
    spec = importlib.util.spec_from_file_location('etis_fetch_ember2024', ROOT / 'data/scripts/fetch_ember2024.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.time, 'sleep', lambda s: None)
    return module


class Response:
    def __init__(self, status, body=b'', headers=None):
        self.status_code, self.body, self.headers = status, body, headers or {}

    def iter_content(self, size):
        for i in range(0, len(self.body), 7):
            yield self.body[i:i + 7]

    def close(self):
        pass


class Session:
    """Serves `body` after a redirect to `target`; optionally fails once mid-stream."""

    def __init__(self, body, target='https://cas-bridge.xethub.hf.co/x?signed=1', fail_after=None, etag=None):
        self.body, self.target, self.fail_after, self.etag = body, target, fail_after, etag
        self.calls = []

    def get(self, url, headers=None, **kwargs):
        self.calls.append((url, dict(headers or {})))
        if 'huggingface.co/datasets/' in url:
            return Response(302, headers={'Location': self.target, **({'X-Linked-Etag': f'"{self.etag}"'}
                                                                        if self.etag else {})})
        start = int(headers.get('Range', 'bytes=0-')[6:-1]) if headers.get('Range') else 0
        chunk = self.body[start:]
        if self.fail_after is not None:
            limit, self.fail_after = self.fail_after, None
            response = Response(206 if start else 200, chunk[:limit])
            original = response.iter_content

            def broken(size):
                yield from original(size)
                raise ConnectionError('invented interruption')
            response.iter_content = broken
            return response
        return Response(206 if start else 200, chunk)


def _pin(fe, monkeypatch, body, name='Dot_Net_train.zip'):
    monkeypatch.setitem(fe.FILES, name, {'size': len(body), 'card_gb': 0.0,
                                         'sha256': hashlib.sha256(body).hexdigest()})
    monkeypatch.setattr(fe, 'MIN_FREE_BYTES', 0)


def test_only_the_three_approved_train_zips_can_be_requested(fe):
    assert set(fe.FILES) == {'Dot_Net_train.zip', 'Win64_train.zip', 'Win32_train.zip'}
    assert fe.ORDER == ('Dot_Net_train.zip', 'Win64_train.zip', 'Win32_train.zip')
    for name in ('Win32_test.zip', 'challenge.zip', 'APK_train.zip', '../x.zip'):
        with pytest.raises(fe.FetchStop, match='file_not_allowed'):
            fe.resolve_url(name)
    assert fe.resolve_url('Win64_train.zip') == ('https://huggingface.co/datasets/joyce8/EMBER2024/resolve/'
                                                 '3d23efef7c0f0b702c5024400cfff4c3744a3832/Win64_train.zip')


@pytest.mark.parametrize('url,ok', [
    ('https://huggingface.co/datasets/x', True), ('https://cdn-lfs.hf.co/x', True),
    ('https://cas-bridge.xethub.hf.co/x', True), ('https://us.huggingface.co/x', True),
    ('http://huggingface.co/x', False), ('https://huggingface.co.example/x', False),
    ('https://evilhf.co/x', False), ('https://example.com/x', False)])
def test_redirects_are_followed_only_to_hugging_face_hosts(fe, url, ok):
    assert fe.allowed_host(url) is ok


def test_download_verifies_and_renames(fe, monkeypatch, tmp_path):
    body = b'invented zip bytes ' * 50
    _pin(fe, monkeypatch, body)
    result = fe.download('Dot_Net_train.zip', tmp_path, Session(body))
    assert result['status'] == 'downloaded_and_verified'
    assert (tmp_path / 'Dot_Net_train.zip').read_bytes() == body
    assert not (tmp_path / 'Dot_Net_train.zip.part').exists()


def test_interrupted_download_resumes_with_range(fe, monkeypatch, tmp_path):
    body = bytes(range(256)) * 4
    _pin(fe, monkeypatch, body)
    session = Session(body, fail_after=300)
    assert fe.download('Dot_Net_train.zip', tmp_path, session)['status'] == 'downloaded_and_verified'
    ranges = [h.get('Range') for url, h in session.calls if 'huggingface.co/datasets' in url]
    assert ranges[0] is None and ranges[1].startswith('bytes=') and ranges[1] != 'bytes=0-'
    assert (tmp_path / 'Dot_Net_train.zip').read_bytes() == body


def test_existing_part_file_is_resumed(fe, monkeypatch, tmp_path):
    body = b'0123456789' * 100
    _pin(fe, monkeypatch, body)
    (tmp_path / 'Dot_Net_train.zip.part').write_bytes(body[:333])
    session = Session(body)
    fe.download('Dot_Net_train.zip', tmp_path, session)
    assert session.calls[0][1]['Range'] == 'bytes=333-'
    assert (tmp_path / 'Dot_Net_train.zip').read_bytes() == body


def test_redirect_to_another_host_stops(fe, monkeypatch, tmp_path):
    body = b'x' * 100
    _pin(fe, monkeypatch, body)
    with pytest.raises(fe.FetchStop, match='unexpected_redirect_host:example.com'):
        fe.download('Dot_Net_train.zip', tmp_path, Session(body, target='https://example.com/file'))


def test_sha256_mismatch_stops_and_keeps_the_part_file(fe, monkeypatch, tmp_path):
    body = b'y' * 100
    _pin(fe, monkeypatch, body)
    with pytest.raises(fe.FetchStop, match='sha256_mismatch'):
        fe.download('Dot_Net_train.zip', tmp_path, Session(b'z' * 100))
    assert (tmp_path / 'Dot_Net_train.zip.part').exists() and not (tmp_path / 'Dot_Net_train.zip').exists()


def test_linked_etag_mismatch_stops_before_downloading(fe, monkeypatch, tmp_path):
    body = b'y' * 100
    _pin(fe, monkeypatch, body)
    with pytest.raises(fe.FetchStop, match='linked_etag_mismatch'):
        fe.download('Dot_Net_train.zip', tmp_path, Session(body, etag='a' * 64))


def test_low_free_space_stops_before_starting(fe, monkeypatch, tmp_path):
    body = b'y' * 100
    _pin(fe, monkeypatch, body)
    monkeypatch.setattr(fe, 'MIN_FREE_BYTES', 10 ** 18)
    with pytest.raises(fe.FetchStop, match='insufficient_free_space'):
        fe.download('Dot_Net_train.zip', tmp_path, Session(body))
    assert list(tmp_path.iterdir()) == []


def test_inspection_reads_only_the_central_directory_and_flags_risks(fe, tmp_path, monkeypatch):
    path = tmp_path / 'invented.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('2023-09-24_2023-09-30_Win64_train.jsonl', '{"invented": 1}\n' * 10)
        archive.writestr('model.pkl', b'not really a pickle')
        archive.writestr('tool.exe', b'MZ invented')
        archive.writestr('../escape.jsonl', b'{}')
        archive.writestr('C:/drive.jsonl', b'{}')
        link = zipfile.ZipInfo('link.jsonl')
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, 'target')
        archive.writestr('folder/', b'')

    def no_open(*args, **kwargs):
        raise AssertionError('a member was opened')
    monkeypatch.setattr(zipfile.ZipFile, 'open', no_open)
    monkeypatch.setattr(zipfile.ZipFile, 'read', no_open)
    monkeypatch.setattr(zipfile.ZipFile, 'extract', no_open)
    monkeypatch.setattr(zipfile.ZipFile, 'extractall', no_open)
    report = fe.inspect_zip(path)
    assert report['members'] == 7 and report['files'] == 6 and report['directories'] == 1
    assert report['pickle_members'] == ['model.pkl']
    assert report['executable_or_archive_members'] == ['tool.exe']
    assert {m['name'] for m in report['unsafe_path_members']} == {'../escape.jsonl', 'C:/drive.jsonl'}
    assert report['symlink_members'] == ['link.jsonl']
    assert report['extensions']['.jsonl']['count'] == 4
    json.dumps(report)


def test_script_never_uses_thrember_download_or_unpickles():
    source = (ROOT / 'data/scripts/fetch_ember2024.py').read_text(encoding='utf-8')
    for banned in ('import thrember', 'from thrember', 'download_dataset(', 'download_models(', 'pickle.load',
                   'joblib.load', 'np.load', 'extractall', '.extract(', 'hf_hub_download', 'subprocess',
                   '.post(', '.put('):
        assert banned not in source


def test_lock_matches_the_script_pins_when_present(fe):
    lock_path = ROOT / 'data/ember2024-lock.json'
    if not lock_path.exists():
        pytest.skip('lock not written yet')
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    assert lock['revision'] == fe.REVISION and lock['license'] == 'Apache-2.0'
    assert '10.1145/3711896.3737431' in lock['citation']
    for entry in lock['files']:
        pin = fe.FILES[entry['file']]
        assert (entry['size'], entry['sha256']) == (pin['size'], pin['sha256'])
        if entry.get('verified'):
            assert entry['sha256_measured'] == pin['sha256']
