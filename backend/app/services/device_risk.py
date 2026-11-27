"""Cross-engine risk score per device, `device-risk-v1` (design core-v2 §3.3-§3.5).

A fixed, explainable count of what ETIS engines reported on one device recently, weighted by
severity and confidence. Not a verdict, a probability or a prediction; no engine, correlation
step, incident rule or action reads it. The points table, the 7/30-day windows, the +3/+6
cross-engine term and the band edges are design choices accepted for v1 (owner decision
Q10), not fitted to any data. Computed when read, never stored. No ML.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

VERSION = 'device-risk-v1'
MAX_WINDOW_DAYS = 30
FULL_WEIGHT_DAYS = 7
CROSS_ENGINE_POINTS, CROSS_ENGINE_CAP, CROSS_ENGINE_MIN_POINTS = 3, 6, 3
DEVICE_DOMAINS = ('malware', 'host', 'network')
EXCLUDED_RESOLUTIONS = ('false_positive', 'benign')
POINTS = {
    'critical': {'confirmed': 10, 'corroborated': 8, 'single_signal': 5, 'undetermined': 3},
    'high': {'confirmed': 6, 'corroborated': 5, 'single_signal': 3, 'undetermined': 2},
    'medium': {'confirmed': 3, 'corroborated': 2, 'single_signal': 1, 'undetermined': 1},
    'low': {'confirmed': 1, 'corroborated': 1, 'single_signal': 0, 'undetermined': 0},
    'info': {'confirmed': 0, 'corroborated': 0, 'single_signal': 0, 'undetermined': 0},
}
BANDS = ((10, 'high'), (5, 'elevated'), (1, 'low'), (0, 'none'))
# Retention setting behind each engine's window (§3.3). host.windows has none in code yet: 30 days.
RETENTION_SETTINGS = {'malware.files': 'malware_retention_days', 'network.windows': 'network_retention_days',
                      'network.flows': 'network_retention_days', 'host.windows': 'host_retention_days'}
RETENTION_ENV = {'malware_retention_days': 'ETIS_MALWARE_RETENTION_DAYS',
                 'network_retention_days': 'ETIS_NETWORK_RETENTION_DAYS',
                 'host_retention_days': 'ETIS_HOST_RETENTION_DAYS'}


@dataclass(frozen=True)
class RiskInput:
    finding_id: str
    engine_name: str
    domain: str
    kind: str
    severity: str
    confidence: str
    observed_at: datetime          # naive UTC, as stored
    incident_id: int | None = None
    resolution: str | None = None


def base_points(severity: str, confidence: str) -> int:
    return POINTS.get(severity, {}).get(confidence, 0)


def band(points: int) -> str:
    return next(name for edge, name in BANDS if points >= edge)


def engine_windows(engines, settings=None) -> dict[str, dict]:
    """{engine: {days, setting}}: min(30, that engine's retention setting) days."""
    if settings is None:
        from app.core.settings import settings
    out = {}
    for engine in sorted(set(engines)):
        attribute = RETENTION_SETTINGS.get(engine)
        retention = getattr(settings, attribute, None) if attribute else None
        days = MAX_WINDOW_DAYS if retention is None else max(0, min(MAX_WINDOW_DAYS, int(retention)))
        out[engine] = {'days': days, 'setting': RETENTION_ENV.get(attribute) if retention is not None else None}
    return out


def age_days(observed_at: datetime, now: datetime) -> int:
    """Whole days elapsed; a finding dated in the future counts as age 0."""
    return max(0, (now - observed_at).days)


def device_risk(findings: list[RiskInput], now: datetime, *, windows: dict[str, dict] | None = None) -> dict:
    """The §3.4 formula with its explanation: total, band, counted rows and every row not counted."""
    windows = windows if windows is not None else engine_windows({f.engine_name for f in findings})
    counted_candidates, not_counted = [], []
    for f in findings:
        window = windows.get(f.engine_name, {'days': MAX_WINDOW_DAYS})['days']
        age = age_days(f.observed_at, now)
        row = {'finding_id': f.finding_id, 'engine_name': f.engine_name, 'domain': f.domain, 'kind': f.kind,
               'severity': f.severity, 'confidence': f.confidence, 'observed_at': f.observed_at.isoformat(),
               'age_days': age, 'incident_id': f.incident_id}
        if age > window:
            not_counted.append({**row, 'reason': 'outside_window', 'window_days': window})
            continue
        if f.resolution in EXCLUDED_RESOLUTIONS:
            not_counted.append({**row, 'reason': f'incident_resolved_{f.resolution}'})
            continue
        points = base_points(f.severity, f.confidence)
        recent = age <= FULL_WEIGHT_DAYS
        after = points if recent else math.ceil(points / 2)
        counted_candidates.append({**row, 'points_before_recency': points, 'points': after,
                                   'recency': 'full' if recent else 'half'})
    # Step 3: one finding per (engine, kind): most points, then the most recent.
    best: dict[tuple, dict] = {}
    repeats: dict[tuple, int] = {}
    for row in sorted(counted_candidates, key=lambda r: (-r['points'], r['age_days'], r['finding_id'])):
        key = (row['engine_name'], row['kind'])
        if key in best:
            repeats[key] = repeats.get(key, 0) + 1
            not_counted.append({**row, 'reason': 'repeat'})
        else:
            best[key] = row
    counted = sorted(best.values(), key=lambda r: (-r['points'], r['age_days'], r['engine_name'], r['kind']))
    for row in counted:
        row['repeats_not_counted'] = repeats.get((row['engine_name'], row['kind']), 0)
    # Step 4: each additional device domain with a counted finding of >= 3 points in the last 7 days.
    strong = sorted({r['domain'] for r in counted if r['domain'] in DEVICE_DOMAINS
                     and r['points'] >= CROSS_ENGINE_MIN_POINTS and r['age_days'] <= FULL_WEIGHT_DAYS})
    cross = min(CROSS_ENGINE_CAP, CROSS_ENGINE_POINTS * max(0, len(strong) - 1))
    total = sum(r['points'] for r in counted) + cross
    return {
        'version': VERSION, 'points': total, 'band': band(total),
        'counted': counted,
        'cross_engine': {'points': cross, 'domains': strong},
        'not_counted': sorted(not_counted, key=lambda r: (r['reason'], r['engine_name'], r['kind'], r['finding_id'])),
        'windows': windows,
        'window_days': min((w['days'] for w in windows.values()), default=MAX_WINDOW_DAYS),
    }
