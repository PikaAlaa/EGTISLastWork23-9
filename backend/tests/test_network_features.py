"""Network flow features net-features-v1 (design network-engine-v1 §1.4, §7.2–7.4). Invented fixtures only."""
import math
from dataclasses import replace

import numpy as np
import pytest

from app.engines.network import features
from app.engines.network.features import (EXCLUDED_FIELDS, FEATURE_NAMES, WINDOW_FEATURES, feature_matrix)
from app.engines.network.parsers import ConnRecord, parse_lines
from network_fixtures import conn_json, conn_tsv

COL = {name: i for i, name in enumerate(FEATURE_NAMES)}


def records(text=None):
    return parse_lines((text or conn_tsv()).splitlines(keepends=True), 'conn').records


def conn(ts, orig='192.168.1.10', resp='198.51.100.20', resp_p=443, state='SF', **extra):
    return ConnRecord(ts=ts, uid=f'C{ts}', orig_h=orig, orig_p=50000, resp_h=resp, resp_p=resp_p, proto='tcp',
                      conn_state=state, **extra)


def window(matrix, row):
    return [matrix[row, COL[name]] for name in WINDOW_FEATURES]


def test_layout_is_fixed_and_versioned():
    assert features.FEATURE_VERSION == 'net-features-v1'
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == 88
    assert FEATURE_NAMES[-len(WINDOW_FEATURES):] == WINDOW_FEATURES


def test_no_excluded_field_is_a_model_column():
    assert not EXCLUDED_FIELDS & set(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert not any(token in name for token in ('addr', 'uid', 'time', 'local', 'tunnel', 'vlan', 'subnet'))
        # The only port-related column is the windowed distinct count, never a port value.
        assert 'port' not in name or name == 'win_orig_distinct_resp_ports'


def test_per_connection_values():
    matrix = feature_matrix(records())
    first = matrix[0]
    assert first[COL['log1p_duration']] == pytest.approx(math.log1p(1.25))
    assert first[COL['log1p_orig_bytes']] == pytest.approx(math.log1p(517))
    assert first[COL['orig_bytes_per_pkt']] == pytest.approx(889 / 9)
    assert first[COL['resp_bytes_per_pkt']] == pytest.approx(4543 / 8)
    assert first[COL['log1p_resp_orig_byte_ratio']] == pytest.approx(math.log1p(4211 / 518))
    assert first[COL['log1p_pkts_per_sec']] == pytest.approx(math.log1p(17 / 1.25))
    assert first[COL['proto_tcp']] == 1 and first[COL['service_ssl']] == 1 and first[COL['state_SF']] == 1
    # history ShADadFf: originator S, A, D, F; responder h, a, d, f
    assert [first[COL[f'history_orig_{c}']] for c in 'sadf'] == [1, 1, 1, 1]
    assert [first[COL[f'history_resp_{c}']] for c in 'hadf'] == [1, 1, 1, 1]
    unset = matrix[2]
    assert unset[COL['duration_missing']] == 1 and unset[COL['bytes_missing']] == 1
    assert unset[COL['service_none']] == 1 and unset[COL['state_S0']] == 1 and unset[COL['log1p_pkts_per_sec']] == 0


def test_tsv_and_json_inputs_give_identical_features():
    assert np.array_equal(feature_matrix(records()), feature_matrix(records(conn_json())))


def test_unknown_categories_use_other_columns():
    row = feature_matrix([replace(conn(1.0), proto='sctp', service='gopher,http', conn_state='XYZ',
                                  history='^Sz')])[0]
    assert row[COL['proto_other']] == 1 and row[COL['service_other']] == 1 and row[COL['service_http']] == 1
    assert row[COL['state_other']] == 1 and row[COL['history_flipped']] == 1 and row[COL['history_orig_s']] == 1


def test_window_uses_only_earlier_rows():
    rows = [conn(0.0, resp='198.51.100.1', resp_p=22, state='S0'),
            conn(10.0, resp='198.51.100.2', resp_p=23, state='REJ'),
            conn(20.0, resp='198.51.100.2', resp_p=80)]
    matrix = feature_matrix(rows)
    assert window(matrix, 0) == [0, 0, 0, 0, 0, 0]
    assert window(matrix, 1) == [1, 1, 1, 1.0, 0, 0]
    assert window(matrix, 2) == [2, 2, 2, 1.0, 1, 1]
    # A later row never changes an earlier row's features.
    extended = feature_matrix(rows + [conn(30.0, resp='198.51.100.9', resp_p=9999, state='S0')])
    assert np.array_equal(extended[:3], matrix)


def test_input_order_does_not_change_features_but_ties_follow_input_order():
    rows = [conn(5.0, resp='198.51.100.3'), conn(1.0, resp='198.51.100.1'), conn(3.0, resp='198.51.100.2')]
    shuffled = feature_matrix(rows)
    ordered = feature_matrix(sorted(rows, key=lambda r: r.ts))
    assert np.array_equal(shuffled[[1, 2, 0]], ordered)
    tie = feature_matrix([conn(1.0, resp='198.51.100.1'), conn(1.0, resp='198.51.100.2')])
    assert window(tie, 0)[0] == 0 and window(tie, 1)[0] == 1


def test_window_is_sixty_seconds_inclusive():
    matrix = feature_matrix([conn(0.0), conn(60.0), conn(119.9), conn(180.5)])
    assert window(matrix, 1)[0] == 1   # exactly 60 s earlier: inside
    assert window(matrix, 2)[0] == 1   # 0.0 is 119.9 s back: outside; 60.0 is inside
    assert window(matrix, 3)[0] == 0   # 119.9 is 60.6 s back: outside


def test_responder_fan_in():
    rows = [conn(1.0, orig=f'203.0.113.{i}', resp='192.168.1.10') for i in range(1, 6)]
    last = feature_matrix(rows)[4]
    assert last[COL['win_resp_conns']] == 4 and last[COL['win_resp_distinct_origs']] == 4
    assert last[COL['win_orig_conns']] == 0


def test_windows_reset_between_calls():
    rows = [conn(0.0), conn(1.0)]
    together = feature_matrix(rows)
    separate = np.vstack([feature_matrix(rows[:1]), feature_matrix(rows[1:])])
    assert window(together, 1)[0] == 1 and window(separate, 1)[0] == 0


def test_features_are_invariant_to_addresses_ports_uids_and_absolute_time():
    base = records()
    renamed = {'192.168.1.10': '10.9.8.7', '198.51.100.20': '192.0.2.200', '198.51.100.21': '192.0.2.201',
               '203.0.113.5': '198.51.100.99'}
    ports = {443: 8443, 53: 5353, 22: 2222, 23: 2323}
    changed = [replace(r, ts=r.ts + 86400 * 365, uid='CChanged' + str(i), orig_h=renamed[r.orig_h],
                       resp_h=renamed[r.resp_h], orig_p=(r.orig_p + 1) % 65536, resp_p=ports[r.resp_p],
                       local_orig=not r.local_orig, local_resp=None)
               for i, r in enumerate(base)]
    assert np.array_equal(feature_matrix(base), feature_matrix(changed))


def test_empty_input_gives_empty_matrix():
    assert feature_matrix([]).shape == (0, len(FEATURE_NAMES))
