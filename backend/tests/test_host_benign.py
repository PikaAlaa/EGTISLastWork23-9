"""Owner-PC benign measurement (design host-engine-v1 §4.4, §4.7, §4.8; step 8).

All events are invented. The committed aggregate must never contain event content, names,
paths, file hashes or timestamps; review material is local only.
"""
import importlib.util
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.engines.host.detections import Alert
from app.engines.host.pseudonyms import Pseudonymizer

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('host_benign', ROOT / 'evaluation/host_benign_measure.py')
tool = importlib.util.module_from_spec(spec)
sys.modules['host_benign'] = tool
spec.loader.exec_module(tool)

SEC, SYS = 'Security', 'System'
PS = 'Microsoft-Windows-PowerShell/Operational'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
MARKER = 'invented-marker-5531'
T = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
_ids = iter(range(1, 10 ** 6))


def stamp(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def ev(channel, event_id, moment, **fields):
    return {'Channel': channel, 'Provider': 'Invented', 'EventID': event_id, 'TimeCreated': stamp(moment),
            'EventRecordID': next(_ids), 'Computer': MARKER + '-PC', **fields}


def alert(detection, moment, host='hmac:' + 'a' * 32, account=None, level='medium', record_ids=(1,)):
    return Alert(detection=detection, level=level, techniques=('T1490',), start=stamp(moment), end=stamp(moment),
                 record_ids=tuple(record_ids), host_ref=host, account_ref=account)


# Host-days -----------------------------------------------------------------------------

def span(channel, first, last):
    return [ev(channel, 1, first), ev(channel, 2, last)]


def test_host_days_are_whole_utc_days_inside_every_required_channel():
    records = (span(SEC, T + timedelta(hours=5), T + timedelta(days=4, hours=1))
               + span(SYS, T + timedelta(hours=1), T + timedelta(days=9))
               + span(PS, T - timedelta(days=3), T + timedelta(days=4, hours=2)))
    # Intersection: day 0 05:00 .. day 4 01:00 -> whole days 1, 2, 3.
    assert tool.host_days(records) == [date(2026, 3, 2), date(2026, 3, 3), date(2026, 3, 4)]


def test_a_span_ending_exactly_at_midnight_includes_the_day_before():
    records = [r for c in (SEC, SYS, PS) for r in span(c, T, T + timedelta(days=2))]
    assert tool.host_days(records) == [date(2026, 3, 1), date(2026, 3, 2)]


def test_missing_required_channel_gives_no_host_days():
    records = span(SEC, T, T + timedelta(days=20)) + span(SYS, T, T + timedelta(days=20))
    assert tool.host_days(records) == []


def test_optional_channels_do_not_narrow_the_span():
    records = [r for c in (SEC, SYS, PS) for r in span(c, T, T + timedelta(days=3))]
    records += span(SYSMON, T + timedelta(days=2), T + timedelta(days=2, hours=1))
    assert len(tool.host_days(records)) == 3


# Grouping (§4.7.1) ---------------------------------------------------------------------

def test_alerts_group_into_findings_per_rule_host_account_and_clock_hour():
    alerts = [alert('H12', T + timedelta(minutes=5)), alert('H12', T + timedelta(minutes=59)),
              alert('H12', T + timedelta(minutes=61)),
              alert('H12', T + timedelta(minutes=6), host='hmac:' + 'b' * 32),
              alert('H13', T + timedelta(minutes=7), account='hmac:' + 'c' * 32),
              alert('H13', T + timedelta(minutes=8), account='hmac:' + 'd' * 32),
              alert('sigma:x', T + timedelta(minutes=9)), alert('sigma:x', T + timedelta(minutes=10))]
    findings = tool.group_findings(alerts)
    by_rule = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(len(finding.alerts))
    assert by_rule == {'H12': [2, 1, 1], 'H13': [1, 1], 'sigma:x': [2]}
    assert [f.start for f in findings] == sorted(f.start for f in findings)


# Examples (§4.8.1) ---------------------------------------------------------------------

@pytest.mark.parametrize('count,expected', [
    (0, []), (1, [0]), (10, list(range(10))),
    (11, [0, 1, 2, 3, 4, 6, 7, 8, 9, 10]),
    (100, [0, 11, 22, 33, 44, 55, 66, 77, 88, 99]),
])
def test_examples_are_spread_evenly_and_include_first_and_last(count, expected):
    assert tool.example_indices(count) == expected


# Aggregates ----------------------------------------------------------------------------

def corpus():
    records = []
    for channel in (SEC, SYS, PS):
        records += span(channel, T + timedelta(hours=1), T + timedelta(days=15, hours=3))
    records.append(ev(SEC, 4688, T + timedelta(days=2, hours=4), CommandLine=MARKER + ' vssadmin delete shadows',
                      NewProcessName='C:\\' + MARKER + '\\x.exe'))
    alerts = [alert('H12', T + timedelta(days=2, hours=4), record_ids=(records[-1]['EventRecordID'],)),
              alert('H12', T + timedelta(hours=2), level='high'),           # partial first day
              alert('sigma:x', T + timedelta(days=3, hours=1), level='high'),
              alert('H6', T + timedelta(days=3, hours=2), level='low')]
    return records, alerts


def build():
    records, alerts = corpus()
    days = tool.host_days(records)
    findings = tool.group_findings(alerts)
    pool = {'release': 'r-test', 'candidates': 2, 'excluded': {'logsource': 1}}
    return records, days, findings, tool.aggregates(records, days, findings, files=3, sigma_pool=pool,
                                                     levels={'H12': 'high', 'H6': 'low', 'sigma:x': 'high'})


def test_aggregates_count_findings_on_and_outside_host_days():
    records, days, findings, agg = build()
    assert agg['corpus'] == "one owner PC, one user's habits"
    assert agg['host_days'] == 14 and agg['meets_minimum_14'] is True
    assert agg['rules']['H12'] == {'level': 'high', 'findings': 2, 'on_host_days': 1, 'outside_host_days': 1,
                                   'labels': {'pending': 2}}
    assert agg['rules']['H6']['on_host_days'] == 1
    per_day = agg['per_host_day']
    assert [d['host_day'] for d in per_day] == list(range(1, 15))
    assert sum(d['findings'] for d in per_day) == 3
    assert per_day[1]['findings'] == 1 and per_day[1]['events'] == 1
    assert agg['events_per_channel_event_id'][SEC + ':4688'] == 1
    assert agg['events'] == len(records) and agg['files'] == 3


def test_aggregates_never_contain_content_names_or_timestamps():
    _, _, _, agg = build()
    text = json.dumps(agg)
    assert MARKER not in text and 'vssadmin' not in text and 'hmac:' not in text
    assert not re.search(r'\d{4}-\d{2}-\d{2}', text)
    assert not re.search(r'[0-9a-f]{64}', text)
    assert '\\' not in text and '.evtx' not in text


def test_unknown_channels_are_counted_not_named():
    records, _, _, _ = build()
    records = records + [ev('Invented-' + MARKER, 1, T + timedelta(days=5))]
    days = tool.host_days(records)
    agg = tool.aggregates(records, days, [], files=1, sigma_pool={}, levels={})
    assert agg['other_channel_events'] == 1 and MARKER not in json.dumps(agg)


# Labels (§4.8.3-4) -----------------------------------------------------------------------

def test_label_template_lists_each_rule_with_its_finding_count():
    _, _, findings, _ = build()
    template = tool.label_template(findings)
    assert template['rules']['H12'] == {'findings': 2, 'label': None}
    assert set(template['allowed_labels']) == {'benign_explained', 'unexplained', 'suspected_malicious'}


def test_one_label_per_rule_and_splits_by_alert_number():
    _, _, findings, _ = build()
    labels = {'rules': {
        'H12': {'groups': [{'findings': [1], 'label': 'unexplained'}, {'findings': [2], 'label': 'benign_explained'}]},
        'H6': {'label': 'benign_explained'}, 'sigma:x': {'label': 'suspected_malicious'}}}
    assert tool.apply_labels(findings, labels) == {
        'H12': {'unexplained': 1, 'benign_explained': 1}, 'H6': {'benign_explained': 1},
        'sigma:x': {'suspected_malicious': 1}}


@pytest.mark.parametrize('h12', [
    {'label': 'fine'},
    {'label': None},
    {'groups': [{'findings': [1], 'label': 'unexplained'}]},                       # 2 not covered
    {'groups': [{'findings': [1, 2], 'label': 'unexplained'}, {'findings': [2], 'label': 'unexplained'}]},
    {'groups': [{'findings': [1, 3], 'label': 'unexplained'}]},
])
def test_invalid_labels_are_refused(h12):
    _, _, findings, _ = build()
    labels = {'rules': {'H12': h12, 'H6': {'label': 'benign_explained'}, 'sigma:x': {'label': 'unexplained'}}}
    with pytest.raises(ValueError):
        tool.apply_labels(findings, labels)


def test_every_alerting_rule_needs_a_label():
    _, _, findings, _ = build()
    with pytest.raises(ValueError):
        tool.apply_labels(findings, {'rules': {'H12': {'label': 'unexplained'}}})


# Local review ----------------------------------------------------------------------------

def test_review_is_escaped_and_shows_at_most_ten_examples():
    records = [ev(SEC, 4688, T + timedelta(minutes=70 * i), CommandLine='<b>' + MARKER) for i in range(25)]
    alerts = [alert('H12', T + timedelta(minutes=70 * i), record_ids=(r['EventRecordID'],))
              for i, r in enumerate(records)]
    findings = tool.group_findings(alerts)
    page = tool.review_html(findings, records, days=[], levels={'H12': 'high'}, titles={'H12': 'Shadow copy'})
    assert page.count('class="example"') == 10
    assert '<b>' + MARKER not in page and '&lt;b&gt;' + MARKER in page
    assert 'H12' in page and 'Shadow copy' in page


def test_logs_inside_the_repository_are_refused(tmp_path):
    with pytest.raises(SystemExit):
        tool.check_logs_dir(ROOT / 'data')
    with pytest.raises(SystemExit):
        tool.check_logs_dir(tmp_path / 'missing')


def test_end_to_end_on_invented_evtx_prints_counts_only(tmp_path, monkeypatch, capsys):
    from app.engines.host import sigma_harness
    from host_fixtures import event, write_evtx
    logs = tmp_path / 'logs'
    logs.mkdir()
    day = 86400
    service = dict(ServiceName=MARKER, ImagePath='C:\\' + MARKER + '\\svc.exe', StartType='auto start',
                   AccountName='LocalSystem')
    write_evtx(logs / 'sec.evtx', [event(4624, at=0, TargetUserName=MARKER), event(4624, at=16 * day)])
    write_evtx(logs / 'sys.evtx', [event(7045, channel='System', provider='Service Control Manager', at=t, **service)
                                   for t in (0, 3 * day + 60, 16 * day)])
    write_evtx(logs / 'ps.evtx', [event(4104, channel=PS, provider='Microsoft-Windows-PowerShell', at=t,
                                        ScriptBlockText=MARKER) for t in (0, 16 * day)])
    monkeypatch.setattr(tool, 'OUT', tmp_path / 'out')
    monkeypatch.setattr(tool, 'check_logs_dir', lambda path: path)
    monkeypatch.setattr(sigma_harness, 'load_release', lambda: ('r-test', []))
    monkeypatch.setattr(sigma_harness, 'load_remap', lambda: None)
    monkeypatch.setenv('ETIS_HOST_PSEUDONYM_KEY', '11' * 32)
    assert tool.main(['--logs', str(logs)]) == 0
    printed = capsys.readouterr().out
    assert MARKER not in printed and json.loads(printed)['host_days'] == 15
    agg = json.loads((tmp_path / 'out/aggregates.pending.json').read_text(encoding='utf-8'))
    assert agg['rules']['H6']['findings'] == 3 and agg['rules']['H6']['on_host_days'] == 1
    assert MARKER not in json.dumps(agg) and 'sec.evtx' not in json.dumps(agg)
    assert MARKER in (tmp_path / 'out/review.html').read_text(encoding='utf-8')
    labels = json.loads((tmp_path / 'out/labels.json').read_text(encoding='utf-8'))
    labels['rules']['H6'] = {'groups': [{'findings': [1, 3], 'label': 'benign_explained'},
                                        {'findings': [2], 'label': 'unexplained'}]}
    (tmp_path / 'out/labels.json').write_text(json.dumps(labels), encoding='utf-8')
    assert tool.main(['--apply-labels']) == 0
    labelled = json.loads((tmp_path / 'out/aggregates.labelled.json').read_text(encoding='utf-8'))
    assert labelled['rules']['H6']['labels'] == {'benign_explained': 2, 'unexplained': 1}
