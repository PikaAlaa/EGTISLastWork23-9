"""Zeek conn.log / dns.log parsers (design network-engine-v1 §1.1, §7.1). Invented fixtures only."""
import logging

import pytest

from app.engines.network.parsers import ConnRecord, NetworkInputError, parse_file, parse_lines
from network_fixtures import CONN_ROWS, conn_json, conn_tsv, dns_tsv

MARKER = '203.0.113.250'


def lines(text):
    return text.splitlines(keepends=True)


def test_tsv_conn_log_parses_every_field():
    result = parse_lines(lines(conn_tsv()), 'conn')
    assert (result.format, result.data_lines, result.malformed, len(result.records)) == ('tsv', 4, 0, 4)
    first = result.records[0]
    assert first == ConnRecord(ts=1700000000.0, uid='CInvent01', orig_h='192.168.1.10', orig_p=51000,
                               resp_h='198.51.100.20', resp_p=443, proto='tcp', service='ssl', duration=1.25,
                               orig_bytes=517, resp_bytes=4211, conn_state='SF', local_orig=True, local_resp=False,
                               missed_bytes=0, history='ShADadFf', orig_pkts=9, orig_ip_bytes=889, resp_pkts=8,
                               resp_ip_bytes=4543)
    unset = result.records[2]
    assert (unset.service, unset.duration, unset.orig_bytes, unset.resp_bytes) == (None, None, None, None)


def test_json_and_tsv_give_identical_records():
    tsv_records = parse_lines(lines(conn_tsv()), 'conn').records
    json_result = parse_lines(lines(conn_json()), 'conn')
    assert json_result.format == 'json' and json_result.records == tsv_records


def test_dns_log_answers_and_query_normalization():
    records = parse_lines(lines(dns_tsv()), 'dns').records
    assert records[0].query == 'lure.example' and records[0].answers == ('198.51.100.20',)
    assert records[1].query == 'shop.example' and records[1].answers == ('198.51.100.30', '198.51.100.31')
    assert records[2].answers == ()


def test_ipv6_is_compressed():
    row = list(CONN_ROWS[0]); row[2] = '2001:0db8:0000:0000:0000:0000:0000:0001'
    assert parse_lines(lines(conn_tsv([row])), 'conn').records[0].orig_h == '2001:db8::1'


@pytest.mark.parametrize('index,bad', [
    (2, 'not-an-ip'), (3, '70000'), (5, '-5'), (0, 'yesterday'), (12, 'maybe'), (8, 'nan'), (1, '-'),
])
def test_malformed_rows_are_counted_and_skipped(index, bad):
    row = list(CONN_ROWS[0]); row[index] = bad
    result = parse_lines(lines(conn_tsv([row, CONN_ROWS[1]])), 'conn')
    assert result.malformed == 1 and len(result.records) == 1 and result.records[0].uid == 'CInvent02'


def test_wrong_column_count_and_bad_json_are_malformed():
    text = conn_tsv() + 'only\tthree\tcolumns\n'
    assert parse_lines(lines(text), 'conn').malformed == 1
    broken = conn_json() + '{"ts": 1, broken\n[1, 2]\n'
    assert parse_lines(lines(broken), 'conn').malformed == 2


@pytest.mark.parametrize('text,code', [
    ('', 'empty_input'), ('\n\n', 'empty_input'), ('plain text\n', 'unrecognized_format'),
    ('#separator \\x09\n#path\tconn\n1\t2\n', 'missing_fields_header'),
])
def test_unusable_input_raises_reason_codes(text, code):
    with pytest.raises(NetworkInputError, match=code):
        parse_lines(lines(text), 'conn')


def test_wrong_log_type_and_missing_required_fields():
    with pytest.raises(NetworkInputError, match='wrong_log_type'):
        parse_lines(lines(dns_tsv()), 'conn')
    from network_fixtures import tsv
    with pytest.raises(NetworkInputError, match='missing_required_fields'):
        parse_lines(lines(tsv('conn', ['ts', 'uid'], [['1700000000.0', 'CInvent01']])), 'conn')
    with pytest.raises(NetworkInputError, match='unsupported_log_type'):
        parse_lines(lines(conn_tsv()), 'http')


def test_row_limit_fails_closed_including_malformed_lines():
    with pytest.raises(NetworkInputError, match='row_limit_exceeded'):
        parse_lines(lines(conn_tsv()), 'conn', max_rows=3)
    text = conn_tsv(CONN_ROWS[:2]) + 'bad\tline\n'
    with pytest.raises(NetworkInputError, match='row_limit_exceeded'):
        parse_lines(lines(text), 'conn', max_rows=2)
    assert len(parse_lines(lines(conn_tsv()), 'conn', max_rows=4).records) == 4


def test_file_size_limit_checked_before_reading(tmp_path, monkeypatch):
    path = tmp_path / 'conn.log'
    path.write_text(conn_tsv(), encoding='utf-8')
    opened = []
    real_open = type(path).open
    monkeypatch.setattr(type(path), 'open', lambda self, *a, **k: opened.append(1) or real_open(self, *a, **k))
    with pytest.raises(NetworkInputError, match='size_limit_exceeded'):
        parse_file(path, 'conn', max_bytes=100)
    assert opened == []
    assert len(parse_file(path, 'conn').records) == 4


def test_missing_file_and_bad_encoding(tmp_path):
    with pytest.raises(NetworkInputError, match='input_not_found'):
        parse_file(tmp_path / 'absent.log', 'conn')
    path = tmp_path / 'binary.log'
    path.write_bytes(b'#fields\tts\n\xff\xfe\xfa\n')
    with pytest.raises(NetworkInputError, match='invalid_encoding'):
        parse_file(path, 'conn')


def test_errors_and_logs_never_contain_values(tmp_path, caplog):
    row = list(CONN_ROWS[0]); row[3] = MARKER  # an address in a port column: malformed
    path = tmp_path / f'{MARKER}.log'
    path.write_text(conn_tsv([row]), encoding='utf-8')
    with caplog.at_level(logging.DEBUG):
        result = parse_file(path, 'conn')
        with pytest.raises(NetworkInputError) as error:
            parse_file(path, 'conn', max_bytes=10)
    assert result.malformed == 1
    assert MARKER not in str(error.value) and MARKER not in caplog.text
