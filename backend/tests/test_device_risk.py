"""device-risk-v1 score (design core-v2 §3.3-§3.4, step 8). Every finding is invented."""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services import device_risk as dr

NOW = datetime(2026, 11, 28, 12, 0, 0)
WINDOWS = {e: {'days': 30, 'setting': None} for e in ('malware.files', 'network.windows', 'host.windows')}
DOMAIN = {'malware.files': 'malware', 'network.windows': 'network', 'host.windows': 'host'}
_n = iter(range(10_000))


def f(severity='high', confidence='corroborated', age=0, engine='malware.files', kind='known_bad_hash',
      resolution=None, hours=0):
    return dr.RiskInput(finding_id=f'f{next(_n):04d}', engine_name=engine, domain=DOMAIN[engine], kind=kind,
                        severity=severity, confidence=confidence,
                        observed_at=NOW - timedelta(days=age, hours=hours), incident_id=1, resolution=resolution)


def score(*findings, windows=WINDOWS):
    return dr.device_risk(list(findings), NOW, windows=windows)


TABLE = [(s, c, p) for s, row in {
    'critical': (10, 8, 5, 3), 'high': (6, 5, 3, 2), 'medium': (3, 2, 1, 1), 'low': (1, 1, 0, 0), 'info': (0, 0, 0, 0),
}.items() for c, p in zip(('confirmed', 'corroborated', 'single_signal', 'undetermined'), row)]


@pytest.mark.parametrize('severity,confidence,points', TABLE)
def test_every_cell_of_the_points_table(severity, confidence, points):
    result = score(f(severity, confidence))
    assert result['points'] == points == result['counted'][0]['points_before_recency']
    assert result['band'] == dr.band(points)


def test_recency_boundaries_7_8_30_31():
    assert score(f(age=7))['points'] == 5                       # full weight through day 7
    eight = score(f(age=8))
    assert eight['points'] == 3 and eight['counted'][0]['recency'] == 'half'   # ceil(5 / 2)
    assert score(f(age=30))['points'] == 3                      # still inside the window
    out = score(f(age=31))
    assert out['points'] == 0 and out['counted'] == []
    assert out['not_counted'][0]['reason'] == 'outside_window' and out['not_counted'][0]['window_days'] == 30


def test_half_weight_rounds_up():
    assert score(f('high', 'single_signal', age=10))['points'] == 2   # ceil(3 / 2)
    assert score(f('low', 'confirmed', age=10))['points'] == 1        # ceil(1 / 2)


def test_future_dated_finding_counts_as_age_zero():
    assert score(f(age=-2))['counted'][0]['age_days'] == 0


def test_repeat_rule_counts_one_per_engine_and_kind():
    result = score(f(age=2), f(age=3), f('medium', 'corroborated', age=1))
    assert result['points'] == 5 and len(result['counted']) == 1
    assert result['counted'][0]['age_days'] == 2 and result['counted'][0]['repeats_not_counted'] == 2
    assert [r['reason'] for r in result['not_counted']] == ['repeat', 'repeat']
    # A different kind of the same engine is not a repeat.
    assert score(f(age=2), f(kind='yara_match', severity='medium'))['points'] == 5 + 2


def test_cross_engine_plus_three_per_additional_domain_capped_at_six():
    two = score(f(), f(engine='network.windows', kind='beaconing'))
    assert two['cross_engine'] == {'points': 3, 'domains': ['malware', 'network']} and two['points'] == 13
    three = score(f(), f(engine='network.windows', kind='beaconing'), f(engine='host.windows', kind='persistence'))
    assert three['cross_engine']['points'] == 6 and three['points'] == 5 * 3 + 6


def test_cross_engine_not_given_below_three_points_or_older_than_seven_days():
    weak = score(f(), f('medium', 'corroborated', engine='network.windows', kind='beaconing'))   # 2 points
    assert weak['cross_engine']['points'] == 0 and weak['points'] == 7
    old = score(f(), f('high', 'confirmed', age=8, engine='network.windows', kind='beaconing'))   # 3 points, day 8
    assert old['cross_engine']['points'] == 0 and old['points'] == 5 + 3


def test_resolved_benign_and_false_positive_excluded_and_listed():
    result = score(f(resolution='benign'), f(kind='yara_match', resolution='false_positive'),
                   f(engine='network.windows', kind='beaconing', resolution='true_positive'))
    assert result['points'] == 5 and [r['kind'] for r in result['counted']] == ['beaconing']
    assert sorted(r['reason'] for r in result['not_counted']) == ['incident_resolved_benign',
                                                                  'incident_resolved_false_positive']


def test_worked_example_gives_13_high_and_5_when_beaconing_is_benign():
    findings = [f(age=2), f(age=3), f(engine='network.windows', kind='beaconing', age=1)]
    result = score(*findings)
    assert (result['points'], result['band']) == (13, 'high')
    benign = [findings[0], findings[1], f(engine='network.windows', kind='beaconing', age=1, resolution='benign')]
    result = score(*benign)
    assert (result['points'], result['band']) == (5, 'elevated')
    assert 'incident_resolved_benign' in [r['reason'] for r in result['not_counted']]


@pytest.mark.parametrize('points,expected', [(0, 'none'), (1, 'low'), (4, 'low'), (5, 'elevated'), (9, 'elevated'),
                                             (10, 'high'), (40, 'high')])
def test_band_edges(points, expected):
    assert dr.band(points) == expected


def test_n9_info_finding_scores_zero():
    result = score(f('info', 'single_signal', engine='network.windows', kind='rare_destination'))
    assert (result['points'], result['band']) == (0, 'none') and result['counted'][0]['points'] == 0


def test_engine_window_is_min_30_and_its_retention_setting():
    settings = SimpleNamespace(malware_retention_days=45, network_retention_days=14)
    windows = dr.engine_windows({'malware.files', 'network.windows', 'host.windows', 'phishing.analyze'}, settings)
    assert windows == {'host.windows': {'days': 30, 'setting': None},
                       'malware.files': {'days': 30, 'setting': 'ETIS_MALWARE_RETENTION_DAYS'},
                       'network.windows': {'days': 14, 'setting': 'ETIS_NETWORK_RETENTION_DAYS'},
                       'phishing.analyze': {'days': 30, 'setting': None}}
    result = score(f(engine='network.windows', kind='beaconing', age=14),
                   f(engine='network.windows', kind='unusual_port', severity='medium', age=15), windows=windows)
    assert [r['kind'] for r in result['counted']] == ['beaconing']
    assert result['not_counted'][0]['window_days'] == 14 and result['window_days'] == 14
    assert result['windows']['network.windows']['setting'] == 'ETIS_NETWORK_RETENTION_DAYS'


def test_engine_window_reads_the_live_settings_by_default():
    from app.core.settings import settings
    windows = dr.engine_windows({'malware.files', 'network.windows'})
    assert windows['malware.files']['days'] == min(30, settings.malware_retention_days)
    assert windows['network.windows']['days'] == min(30, settings.network_retention_days)


def test_findings_from_a_revoked_device_still_count():
    # No revocation state exists before 010_agent_devices; the score never drops findings for it.
    assert score(f(), f(engine='network.windows', kind='beaconing'))['points'] == 13


def test_empty_device_scores_zero_none():
    result = score()
    assert (result['points'], result['band'], result['counted'], result['version']) == (0, 'none', [], 'device-risk-v1')
