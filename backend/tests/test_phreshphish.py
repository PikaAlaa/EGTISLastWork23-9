"""Safety and operating-point tests; fixtures are generic, not collected messages."""
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
pytest.importorskip('pyarrow')
import pyarrow as pa
import pyarrow.parquet as pq
from data.scripts import download_phreshphish as download
from evaluation.phreshphish_utils import (
    at_threshold, adjusted_precision, brand_match, group_bucket, threshold_at_fpr,
)


def test_ignored_range_rejected_before_body_read():
    class Response:
        status_code = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        @property
        def raw(self): raise AssertionError('Body must not be accessed')
    session = SimpleNamespace(get=lambda *a, **kw: Response())
    with pytest.raises(RuntimeError, match='body NOT read'):
        download.range_get(session, 'https://example.invalid/file', 10, 20, 100)


def test_projection_never_fetches_excluded_column_chunks(monkeypatch, tmp_path):
    columns = {name: ['fixture-a', 'fixture-b'] for name in download.COLUMNS}
    columns['excluded_payload'] = ['DO-NOT-FETCH-' * 100, 'EXCLUDED-' * 100]
    sink = pa.BufferOutputStream()
    pq.write_table(pa.table(columns), sink, row_group_size=1, write_statistics=False)
    payload = sink.getvalue().to_pybytes()
    metadata = pq.read_metadata(pa.BufferReader(payload))
    blocked = []
    for g in range(metadata.num_row_groups):
        column = metadata.row_group(g).column(len(download.COLUMNS))
        start = min(x for x in [column.dictionary_page_offset, column.data_page_offset] if x is not None and x >= 0)
        blocked.append((start, start + column.total_compressed_size))
    fetched = []
    def fetch(session, url, start, end, size):
        assert all(end <= a or start >= b for a, b in blocked)
        fetched.append((start, end))
        return payload[start:end]
    monkeypatch.setattr(download, 'range_get', fetch)
    info = {'rfilename': 'data/train-fixture.parquet', 'size': len(payload),
            'lfs': {'sha256': download.sha(payload)}}
    record = download.project_file(info, output=tmp_path)
    target = tmp_path / 'train-fixture.parquet'
    assert pq.read_table(target).column_names == download.COLUMNS
    assert record['projected_sha256'] == download.sha(target.read_bytes())
    assert record['upstream_whole_file_downloaded'] is False
    # A second, fresh projection verifies pinned range and serialization hashes.
    other = tmp_path / 'repeat'
    repeat = download.project_file(info, expected=record, output=other)
    assert repeat['projected_sha256'] == record['projected_sha256']
    assert len(fetched) > 2


def test_threshold_is_conservative_with_tied_negatives():
    labels = np.array([0] * 1000 + [1, 1])
    scores = np.array([.2] * 995 + [.9] * 5 + [.95, .5])
    t = threshold_at_fpr(labels, scores, .001)
    result = at_threshold(labels, scores, t)
    assert result['fp'] == 0
    assert result['tp'] == 1


def test_abstentions_and_single_class_precision_are_explicit():
    result = at_threshold([0, 0, 1, 1], [.9, np.nan, .9, np.nan], .5)
    assert (result['tp'], result['fp'], result['fn'], result['tn']) == (1, 1, 1, 1)
    assert result['abstentions'] == 2
    single = at_threshold([1], [.9], .5)
    assert single['false_positive_rate'] is None
    assert single['precision_at_phishing_base_rate_1pct'] is None
    assert adjusted_precision(.8, .01, .001) == pytest.approx(.0008 / (.0008 + .00999))


def test_brand_aliases_and_domain_assignment_are_conservative():
    assert brand_match('qnb_al_ahli') == 'QNB Al Ahli'
    assert brand_match('orange') is None
    assert brand_match('QNB') is None
    assert brand_match('Vodafone Egypt') == 'Vodafone Egypt'
    assert group_bucket('example.org') == group_bucket('example.org')
