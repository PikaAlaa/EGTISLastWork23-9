"""Coverage report: channels present, time span and detections that could not run (design host-engine-v1 §1.1)."""
import json
from datetime import timedelta

from app.engines.host.coverage import DETECTION_IDS, KNOWN_CHANNELS, coverage_report
from host_fixtures import CHANNEL_SAMPLES, T0

MARKER = 'invented-marker-5521'


def record(event_id, channel='Security', hours=0.0, **fields):
    when = (T0 + timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    base = {'Channel': channel, 'Provider': 'Invented', 'EventID': event_id, 'TimeCreated': when,
            'EventRecordID': 1, 'Computer': 'INVENTED-PC'}
    return {**base, **fields}


def samples():
    out = []
    for index, item in enumerate(CHANNEL_SAMPLES):
        out.append(record(item['event_id'], item['channel'], hours=index / 3600, **item['data']))
    return out


def test_detection_ids_cover_h1_to_h13():
    assert DETECTION_IDS == tuple(f'H{i}' for i in range(1, 14))


def test_empty_import_marks_every_detection_not_visible():
    report = coverage_report([])
    assert report['span'] is None and report['channels'] == {}
    assert {d: v['status'] for d, v in report['detections'].items()} == {d: 'not_visible' for d in DETECTION_IDS}
    assert all(v['reason'] == 'channel_missing' for v in report['detections'].values())


def test_all_channel_samples_make_detections_visible_or_unconfirmed():
    report = coverage_report(samples())
    status = {d: v['status'] for d, v in report['detections'].items()}
    # Event ids present in the samples: 4625, 7045, 4104, 5001, 106, 1149, Sysmon 1, 4688, 4648.
    assert status == {'H1': 'visible', 'H2': 'visible', 'H3': 'unconfirmed', 'H4': 'unconfirmed', 'H5': 'visible',
                      'H6': 'visible', 'H7': 'visible', 'H8': 'unconfirmed', 'H9': 'visible', 'H10': 'visible',
                      'H11': 'visible', 'H12': 'visible', 'H13': 'visible'}
    assert report['detections']['H3']['reason'] == 'no_events_seen'
    assert report['detections']['H13']['limits'] == ['baseline_none']
    assert set(report['channels']) == set(KNOWN_CHANNELS) and report['other_channels'] == 0
    assert report['event_counts']['Security:4625'] == 1


def test_process_creation_and_command_line_visibility():
    only_security = [record(4625)]
    report = coverage_report(only_security)['detections']
    assert report['H11'] == {'status': 'not_visible', 'reason': 'process_creation_not_logged'}
    assert report['H12'] == {'status': 'not_visible', 'reason': 'process_creation_not_logged'}
    no_command_line = [record(4688, NewProcessName='C:\\Windows\\System32\\cmd.exe', CommandLine='')]
    report = coverage_report(no_command_line)['detections']
    assert report['H11']['status'] == 'visible'
    assert report['H12'] == {'status': 'not_visible', 'reason': 'command_line_not_logged'}


def test_h13_baseline_needs_48_hours_of_security_events():
    short = [record(4648, hours=0), record(4625, hours=47.99)]
    long = [record(4648, hours=0), record(4625, hours=48)]
    assert coverage_report(short)['detections']['H13']['limits'] == ['baseline_none']
    assert 'limits' not in coverage_report(long)['detections']['H13']
    # Another channel reaching back further does not create a baseline.
    mixed = [record(7045, 'System', hours=-100), record(4648, hours=0), record(4625, hours=10)]
    assert coverage_report(mixed)['detections']['H13']['limits'] == ['baseline_none']


def test_span_and_channel_spans_are_utc():
    report = coverage_report([record(4625, hours=0), record(7045, 'System', hours=50)])
    assert report['span'] == {'first': '2026-01-05T10:00:00.000000Z', 'last': '2026-01-07T12:00:00.000000Z',
                              'hours': 50.0}
    assert report['channels']['System'] == {'events': 1, 'first': '2026-01-07T12:00:00.000000Z',
                                            'last': '2026-01-07T12:00:00.000000Z'}


def test_report_names_no_unknown_channel_and_no_event_values():
    extra = record(4625, f'{MARKER}-App/Operational', TargetUserName=MARKER, IpAddress='203.0.113.9')
    report = coverage_report(samples() + [extra, record(4625, Computer=MARKER, TargetUserName=MARKER)])
    text = json.dumps(report)
    assert report['other_channels'] == 1
    for value in (MARKER, 'invented-user', 'INVENTED-PC', '203.0.113.9', 'Write-Output', 'svc.exe'):
        assert value not in text
