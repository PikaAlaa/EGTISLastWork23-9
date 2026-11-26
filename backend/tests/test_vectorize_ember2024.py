"""EMBER2024 vectorizer: lock and member checks, streaming, resume, counts, memmap layout, one feature
module object, no network (design malware-engine-v1 §9 step 7 phase 2).

Every zip and record here is invented at test time from the harmless PE headers of malware_fixtures.py;
no real EMBER2024 data is read. Socket connections are blocked for every test.
"""
import hashlib
import importlib
import itertools
import json
import re
import socket
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip('thrember')
pl = pytest.importorskip('polars')

from app.engines.malware import features

from malware_fixtures import pe_bytes

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'data' / 'scripts'))
ve = importlib.import_module('vectorize_ember2024')
DIM = features.FEATURE_DIM
WEEKS = ('2023-09-24_2023-09-30', '2023-10-01_2023-10-07')
SEQUENCE = itertools.count()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)


@pytest.fixture(autouse=True)
def small_zips(monkeypatch):
    monkeypatch.setattr(ve, 'WEEKS_PER_ZIP', len(WEEKS))
    monkeypatch.setattr(ve, 'MIN_FREE_DISK', 0)
    monkeypatch.setattr(ve, 'available_memory', lambda: 64 * ve.GIB)


def _raw(kind, label, **changes):
    sample = {'Win32': pe_bytes('pe32'), 'Win64': pe_bytes('pe64', signed=True),
              'Dot_Net': pe_bytes('pe32', dotnet=True)}[kind]
    record = json.loads(json.dumps(features.EXTRACTOR.raw_features(sample)))
    record.update({'md5': 'invented', 'sha1': 'invented', 'tlsh': 'invented', 'first_submission_date': 1695513600,
                   'last_analysis_date': 1695513600, 'detection_ratio': '0/1', 'label': label, 'file_type': kind,
                   'family': None, 'family_confidence': None, 'behavior': [], 'file_property': [], 'packer': [],
                   'exploit': [], 'group': [], 'week_id': 1, 'caps': [], 'ttps': [], 'mbc': []})
    record['sha256'] = hashlib.sha256(f'invented-{kind}-{next(SEQUENCE)}'.encode()).hexdigest()
    record.update(changes)
    if label is ...:
        del record['label']
    return record


def _lines(kind):
    """Week 1: ordinary rows. Week 2: every edge case, none of which may be dropped."""
    first = [_raw(kind, 0), _raw(kind, 1), _raw(kind, 1)]
    broken = _raw(kind, 0)
    del broken['general']
    second = [json.dumps(_raw(kind, None)), json.dumps(_raw(kind, 2)), json.dumps(_raw(kind, 'odd')),
              json.dumps(_raw(kind, ..., novel_field=1)), '{not json', '[1, 2]', '', json.dumps(broken),
              json.dumps(_raw(kind, 0))]
    return ['\n'.join(json.dumps(r) for r in first) + '\n', '\n'.join(second) + '\n']


def _member(kind, week):
    return f'{week}_{kind}_train.jsonl'


def _build(folder, extra_member=None):
    folder.mkdir(parents=True, exist_ok=True)
    lock, inspection = {'files': []}, {}
    for kind, name in ve.TYPES.items():
        path = folder / name
        texts = _lines(kind)
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for week, text in zip(WEEKS, texts):
                archive.writestr(_member(kind, week), text)
            if extra_member and kind == 'Win64':
                archive.writestr(extra_member, b'x')
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
        lock['files'].append({'file': name, 'size': path.stat().st_size, 'verified': True,
                              'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        inspection[name] = {'members': len(infos), 'first_10_members': [i.filename for i in infos][:10],
                            'total_uncompressed_bytes': sum(i.file_size for i in infos)}
    return lock, inspection


@pytest.fixture
def built(tmp_path):
    lock, inspection = _build(tmp_path / 'ember')
    return tmp_path / 'ember', lock, inspection


# ------------------------------------------------------------------ features: one module object

def test_vector_from_raw_equals_the_runtime_vector_of_the_same_bytes():
    for sample in (pe_bytes('pe32'), pe_bytes('pe64', signed=True), pe_bytes('pe32', dotnet=True)):
        raw = json.loads(json.dumps(features.EXTRACTOR.raw_features(sample)))
        out = features.vector_from_raw(raw)
        assert out.dtype == np.float32 and out.shape == (DIM,) == (2568,)
        assert out.tobytes() == features.vector(sample).tobytes()


def test_vectorizer_uses_the_runtime_module_object():
    module = ve.load_features()
    assert module is features is sys.modules['app.engines.malware.features']
    assert type(module.EXTRACTOR) is sys.modules['thrember.features'].PEFeatureExtractor
    assert Path(module.__file__).resolve() == (ROOT / 'backend/app/engines/malware/features.py').resolve()


def test_another_extractor_copy_is_refused(monkeypatch):
    class Copy:
        dim = DIM
    monkeypatch.setattr(features, 'EXTRACTOR', Copy())
    with pytest.raises(ve.VectorizeStop, match='feature_module_mismatch'):
        ve.load_features()


def test_block_network_blocks_connections_in_the_process():
    ve.block_network()
    with pytest.raises(OSError, match='network_blocked_in_vectorizer'):
        socket.create_connection(('127.0.0.1', 9))
    with pytest.raises(OSError, match='network_blocked_in_vectorizer'):
        socket.getaddrinfo('localhost', 80)
    ve._init_worker()
    with socket.socket() as sock, pytest.raises(OSError, match='network_blocked_in_vectorizer'):
        sock.connect(('127.0.0.1', 9))


def test_workers_leave_four_cores_and_eight_gib(monkeypatch):
    monkeypatch.setattr(ve.os, 'cpu_count', lambda: 32)
    monkeypatch.setattr(ve, 'available_memory', lambda: 20 * ve.GIB)
    assert ve.worker_count() == 12
    monkeypatch.setattr(ve, 'available_memory', lambda: 64 * ve.GIB)
    assert ve.worker_count() == 28 and ve.worker_count(6) == 6
    monkeypatch.setattr(ve.os, 'cpu_count', lambda: 4)
    assert ve.worker_count() == 1


# ------------------------------------------------------------------ zips and members

def test_zips_must_match_the_lock(built):
    folder, lock, _ = built
    assert set(ve.verify_zips(folder, lock)) == set(ve.TYPES)
    changed = json.loads(json.dumps(lock))
    changed['files'][0]['sha256'] = '0' * 64
    with pytest.raises(ve.VectorizeStop, match='sha256_mismatch'):
        ve.verify_zips(folder, changed)
    changed = json.loads(json.dumps(lock))
    changed['files'][1]['size'] += 1
    with pytest.raises(ve.VectorizeStop, match='size_mismatch'):
        ve.verify_zips(folder, changed)
    changed = json.loads(json.dumps(lock))
    changed['files'][2]['verified'] = False
    with pytest.raises(ve.VectorizeStop, match='not_in_lock'):
        ve.verify_zips(folder, changed)
    (folder / 'Dot_Net_train.zip').unlink()
    with pytest.raises(ve.VectorizeStop, match='zip_missing'):
        ve.verify_zips(folder, lock)


def test_expected_members_are_accepted(built):
    folder, _, inspection = built
    assert ve.check_members(folder / 'Win32_train.zip', 'Win32', inspection) == [
        _member('Win32', w) for w in WEEKS]


@pytest.mark.parametrize('extra', ['notes.txt', 'model.pkl', '2023-10-08_2023-10-14_Win64_test.jsonl',
                                   '2023-10-08_2023-10-14_Win32_train.jsonl', 'sub/2023-10-08_2023-10-14_Win64_train.jsonl',
                                   '2023-10-08_2023-10-14_Win64_train.jsonl'])
def test_any_unexpected_member_stops_the_run(tmp_path, extra):
    folder = tmp_path / 'ember'
    lock, inspection = _build(folder, extra_member=extra)
    with pytest.raises(ve.VectorizeStop, match='unexpected_member|member_count_mismatch'):
        ve.check_members(folder / 'Win64_train.zip', 'Win64', inspection)
    with pytest.raises(ve.VectorizeStop):
        ve.run(folder, lock, inspection, workers=0)
    assert not (folder / 'vectors' / 'plan.json').exists()


def test_members_must_match_the_inspection_report(built):
    folder, _, inspection = built
    changed = json.loads(json.dumps(inspection))
    changed['Win32_train.zip']['total_uncompressed_bytes'] += 1
    with pytest.raises(ve.VectorizeStop, match='uncompressed_size_mismatch'):
        ve.check_members(folder / 'Win32_train.zip', 'Win32', changed)
    changed = json.loads(json.dumps(inspection))
    changed['Win32_train.zip']['first_10_members'][0] = 'other.jsonl'
    with pytest.raises(ve.VectorizeStop, match='member_names_mismatch'):
        ve.check_members(folder / 'Win32_train.zip', 'Win32', changed)


def test_directory_member_is_refused(tmp_path):
    path = tmp_path / 'Win32_train.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('2023-09-24_2023-09-30_Win32_train.jsonl/', b'')
    with pytest.raises(ve.VectorizeStop, match='unexpected_member'):
        ve.check_members(path, 'Win32', {'Win32_train.zip': {'members': 1, 'first_10_members': [],
                                                              'total_uncompressed_bytes': 0}})


# ------------------------------------------------------------------ full run

def _expected_vector(line):
    return features.vector_from_raw(json.loads(line))


def _check_outputs(folder):
    out = folder / 'vectors'
    for kind in ve.TYPES:
        header = json.loads((out / f'{kind}.f32.json').read_text())
        assert header == {'dtype': 'float32', 'order': 'C', 'shape': [12, DIM], 'meta': f'{kind}_meta.parquet'}
        assert (out / f'{kind}.f32').stat().st_size == 12 * DIM * 4
        vectors = np.memmap(out / f'{kind}.f32', dtype=np.float32, mode='r', shape=(12, DIM))
        meta = pl.read_parquet(out / f'{kind}_meta.parquet')
        assert meta['row'].to_list() == list(range(12))
        assert meta.columns == ['row', 'line', 'sha256', 'label', 'label_raw', 'file_type',
                                'first_submission_date', 'status', 'member']
        lines = [line for text in _lines(kind) for line in text.split('\n')[:-1]]
        for row, (line, status) in enumerate(zip(lines, meta['status'].to_list())):
            if status == 'ok':
                assert vectors[row].tobytes() == _expected_vector(line).tobytes()
            else:
                assert np.isnan(vectors[row]).all()
        assert meta['status'].to_list()[3:] == ['ok', 'ok', 'ok', 'ok', 'json_error', 'not_object', 'empty_line',
                                                 'vectorize_error:KeyError', 'ok']
        assert meta['label'].to_list()[:7] == [0, 1, 1, None, 2, None, None]
        assert meta['label_raw'].to_list()[3:7] == ['null', '2', '"odd"', None]
        assert meta['member'].to_list() == [_member(kind, WEEKS[0])] * 3 + [_member(kind, WEEKS[1])] * 9
        assert meta['file_type'].to_list()[0] == kind and meta['first_submission_date'].to_list()[0] == 1695513600
        del vectors


def test_full_run_counts_layout_and_no_row_data(built):
    folder, lock, inspection = built
    summary = ve.run(folder, lock, inspection, workers=0)
    _check_outputs(folder)
    assert summary['vector_dimension'] == DIM and summary['vector_dtype'] == 'float32'
    assert summary['total_rows'] == 36
    for kind in ve.TYPES:
        counts = summary['types'][kind]
        assert counts['rows'] == 12 and counts['vectors_shape'] == [12, DIM] and counts['weekly_members'] == 2
        assert counts['ok_rows'] == 8
        assert counts['failed_rows'] == {'empty_line': 1, 'json_error': 1, 'not_object': 1,
                                         'vectorize_error:KeyError': 1}
        assert counts['label_values'] == {'0': 3, '1': 2, '2': 1, '"odd"': 1, 'null': 1, 'missing': 1,
                                          'unparsed': 3}
        assert sum(counts['label_values'].values()) == 12
        assert counts['missing_fields'] == {'general': 1, 'label': 1}
        assert counts['extra_fields'] == {'novel_field': 1}
        assert counts['file_type_values'] == {f'"{kind}"': 9, 'unparsed': 3}
        assert counts['weeks'] == {WEEKS[0]: {'rows': 3, 'ok': 3, 'failed': 0, 'labels': {'0': 1, '1': 2}},
                                   WEEKS[1]: {'rows': 9, 'ok': 5, 'failed': 4,
                                              'labels': {'"odd"': 1, '0': 2, '2': 1, 'missing': 1,
                                                         'null': 1, 'unparsed': 3}}}
        assert counts['duplicates'] == {
            'rows_without_sha256': 3, 'distinct_sha256': 9, 'duplicate_rows': 0, 'longest_repeat': 1,
            'repeat_count_distribution': {'1': 9}, 'sha256_in_more_than_one_week': 0,
            'duplicate_pairs_checked': 0, 'duplicate_pairs_with_different_label': 0,
            'duplicate_pairs_with_different_vector': 0,
            'weeks': {WEEKS[0]: {'distinct_sha256': 3, 'duplicate_rows': 0},
                      WEEKS[1]: {'distinct_sha256': 6, 'duplicate_rows': 0}}}
    assert summary['sha256_in_more_than_one_type'] == 0
    text = json.dumps(summary).replace(features.THREMBER_COMMIT, '')
    assert not re.search(r'[0-9a-f]{32,}', text)
    assert 'invented' not in text and 'train.jsonl' not in text


def test_resume_skips_done_members_and_gives_the_same_result(built, monkeypatch):
    folder, lock, inspection = built
    calls = []
    real = ve.vectorize_member

    def counted(task):
        calls.append(task['member'])
        return real(task)
    monkeypatch.setattr(ve, 'vectorize_member', counted)
    states = iter([64 * ve.GIB] * 2 + [0] * 100)
    monkeypatch.setattr(ve, 'available_memory', lambda: next(states))
    with pytest.raises(ve.VectorizeStop, match='low_memory_paused'):
        ve.run(folder, lock, inspection, workers=0)
    assert len(calls) == 2
    assert len(list((folder / 'vectors' / 'parts').glob('*.done.json'))) == 2
    # Rows of members without a done record are rewritten from their first row on the next run.
    monkeypatch.setattr(ve, 'available_memory', lambda: 64 * ve.GIB)
    summary = ve.run(folder, lock, inspection, workers=0)
    assert len(calls) == 6 and len(set(calls)) == 6
    _check_outputs(folder)
    assert summary['total_rows'] == 36


def test_duplicate_counts_compare_labels_and_vectors_with_the_first_row(tmp_path):
    a, b = 'a' * 64, 'b' * 64
    w1, w2 = _member('Win32', WEEKS[0]), _member('Win32', WEEKS[1])
    pl.DataFrame({'row': [0, 1, 2, 3, 4, 5], 'sha256': [a, b, b, a, b, None],
                  'label_raw': ['0', '1', '1', '0', '0', None], 'member': [w1, w1, w1, w2, w2, w2]}
                 ).write_parquet(tmp_path / 'meta.parquet')
    vectors = np.memmap(tmp_path / 'v.f32', dtype=np.float32, mode='w+', shape=(6, 3))
    vectors[:] = [[1, 2, 3], [4, 5, 6], [4, 5, 7], [1, 2, 3], [4, 5, 6], [np.nan] * 3]
    vectors.flush()
    del vectors
    counts = ve.duplicate_counts(tmp_path / 'meta.parquet', tmp_path / 'v.f32', 6, 3)
    assert counts == {'rows_without_sha256': 1, 'distinct_sha256': 2, 'duplicate_rows': 3, 'longest_repeat': 3,
                      'repeat_count_distribution': {'2': 1, '3': 1}, 'sha256_in_more_than_one_week': 2,
                      'duplicate_pairs_checked': 3, 'duplicate_pairs_with_different_label': 1,
                      'duplicate_pairs_with_different_vector': 1,
                      'weeks': {WEEKS[0]: {'distinct_sha256': 2, 'duplicate_rows': 1},
                                WEEKS[1]: {'distinct_sha256': 2, 'duplicate_rows': 0}}}
    assert (tmp_path / 'v.f32').stat().st_size == 6 * 3 * 4  # nothing removed or rewritten


def test_changed_row_count_stops(built):
    folder, lock, inspection = built
    ve.run(folder, lock, inspection, workers=0)
    plan_path = folder / 'vectors' / 'plan.json'
    plan = json.loads(plan_path.read_text())
    member = plan['types']['Win32']['members'][0]
    task = {'kind': 'Win32', 'member': member['member'], 'zip': str(folder / 'Win32_train.zip'), 'offset': 0,
            'rows': member['rows'] - 1, 'vectors': str(folder / 'vectors' / 'Win32.f32'),
            'part': str(folder / 'p.parquet'), 'done': str(folder / 'd.json')}
    with pytest.raises(ve.VectorizeStop, match='row_count_changed'):
        ve.vectorize_member(task)
    plan['zips']['Win32']['sha256'] = '0' * 64
    plan_path.write_text(json.dumps(plan))
    with pytest.raises(ve.VectorizeStop, match='existing_plan_mismatch'):
        ve.run(folder, lock, inspection, workers=0)


def test_low_disk_stops_before_allocating(built, monkeypatch):
    folder, lock, inspection = built
    monkeypatch.setattr(ve, 'MIN_FREE_DISK', 10 ** 18)
    with pytest.raises(ve.VectorizeStop, match='insufficient_free_space'):
        ve.run(folder, lock, inspection, workers=0)
    assert not list((folder / 'vectors').glob('*.f32'))


def test_worker_processes_give_the_same_output(built):
    folder, lock, inspection = built
    summary = ve.run(folder, lock, inspection, workers=2)
    _check_outputs(folder)
    assert summary['total_rows'] == 36


def test_script_never_unpickles_extracts_or_uses_the_network():
    source = (ROOT / 'data/scripts/vectorize_ember2024.py').read_text(encoding='utf-8')
    for banned in ('pickle', 'joblib', 'np.load(', 'allow_pickle', 'extractall', '.extract(', 'requests',
                   'urllib', 'huggingface', 'hf_hub', 'subprocess', 'download', 'import thrember',
                   'from thrember', '.fit(', 'train_model', 'train_test_split'):
        assert banned not in source, banned
