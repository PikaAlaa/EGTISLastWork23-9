"""Owner-PC benign measurement for host engine v1 (design host-engine-v1 §4.4, §4.7, §4.8; step 8).

Reads the owner's exported EVTX files (outside the repository) as one import, runs every
native rule and every Sigma candidate of the frozen pool exactly as frozen, groups alerts
into Findings (§4.7.1), and writes, under ignored `evaluation/local-results/host-v1/`:

- `aggregates.pending.json` — the only material that may later be committed: counts per
  rule, per numbered host-day, per channel and EventID. No content, names, paths, file
  hashes or timestamps.
- `review.html` — per-rule summary and up to 10 examples for the owner (local only, §4.8).
- `labels.json` — template the owner fills in, one label per rule (optional split).
- `findings.local.json` — per-rule finding list used to apply labels (local only).

Stdout carries counts only. Nothing is fetched or sent anywhere.

Usage: python evaluation/host_benign_measure.py --logs <folder outside the repository>
       python evaluation/host_benign_measure.py --apply-labels
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/local-results/host-v1'
REQUIRED = ('Security', 'System', 'Microsoft-Windows-PowerShell/Operational')
LABELS = ('benign_explained', 'unexplained', 'suspected_malicious')
CORPUS = "one owner PC, one user's habits"
MIN_HOST_DAYS = 14
MAX_EXAMPLES = 10
MAX_VALUE = 1000
SKIP_SUMMARY_FIELDS = {'TimeCreated', 'EventRecordID'}


def _moment(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


# Host-days (§4.4) ------------------------------------------------------------------------

def host_days(records: list[dict]) -> list[date]:
    """UTC calendar days lying wholly inside the covered span of every required channel."""
    spans = {}
    for record in records:
        channel, when = record.get('Channel'), record.get('TimeCreated')
        if channel in REQUIRED and when:
            moment = _moment(when)
            first, last = spans.get(channel, (moment, moment))
            spans[channel] = (min(first, moment), max(last, moment))
    if len(spans) < len(REQUIRED):
        return []
    start = max(first for first, _ in spans.values())
    end = min(last for _, last in spans.values())
    day = start.date() if start.time() == datetime.min.time() else start.date() + timedelta(days=1)
    days = []
    while datetime.combine(day + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc) <= end:
        days.append(day)
        day += timedelta(days=1)
    return days


# Findings (§4.7.1) -------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    level: str
    host_ref: str | None
    account_ref: str | None
    hour: str
    alerts: list = field(default_factory=list)

    @property
    def start(self) -> str:
        return self.alerts[0].start


def group_findings(alerts) -> list[Finding]:
    """One Finding per rule, host reference, account reference and UTC clock hour of the first event."""
    groups: dict[tuple, Finding] = {}
    for item in sorted(alerts, key=lambda a: (a.start, a.detection)):
        hour = item.start[:13]
        key = (item.detection, item.host_ref, item.account_ref, hour)
        if key not in groups:
            groups[key] = Finding(item.detection, item.level, item.host_ref, item.account_ref, hour)
        groups[key].alerts.append(item)
    return sorted(groups.values(), key=lambda f: (f.start, f.rule))


def by_rule(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Findings per rule, in time order; finding numbers are 1-based positions in these lists."""
    rules: dict[str, list[Finding]] = defaultdict(list)
    for finding in sorted(findings, key=lambda f: (f.start, f.rule)):
        rules[finding.rule].append(finding)
    return dict(sorted(rules.items()))


def example_indices(count: int, limit: int = MAX_EXAMPLES) -> list[int]:
    """All indices when count <= limit, else `limit` spread evenly, first and last included."""
    if count <= limit:
        return list(range(count))
    return [int(i * (count - 1) / (limit - 1) + 0.5) for i in range(limit)]


# Committed aggregates (§4.4) -----------------------------------------------------------------

def aggregates(records: list[dict], days: list[date], findings: list[Finding], files: int,
               sigma_pool: dict, levels: dict, coverage: dict | None = None) -> dict:
    from app.engines.host.coverage import KNOWN_CHANNELS
    number = {day: index for index, day in enumerate(days, start=1)}
    per_channel, per_event, per_day_events = Counter(), Counter(), Counter()
    other = 0
    for record in records:
        channel = record.get('Channel')
        if channel not in KNOWN_CHANNELS:
            other += 1
            continue
        per_channel[channel] += 1
        per_event[f'{channel}:{record.get("EventID")}'] += 1
        when = record.get('TimeCreated')
        if when and _moment(when).date() in number:
            per_day_events[number[_moment(when).date()]] += 1
    per_day_findings = Counter()
    rules = {}
    for rule, items in by_rule(findings).items():
        on = [f for f in items if _moment(f.start).date() in number]
        for finding in on:
            per_day_findings[number[_moment(finding.start).date()]] += 1
        rules[rule] = {'level': levels.get(rule, items[0].level), 'findings': len(items),
                       'on_host_days': len(on), 'outside_host_days': len(items) - len(on),
                       'labels': {'pending': len(items)}}
    result = {
        'corpus': CORPUS,
        'counting_unit': 'grouped Finding per rule, host, account and UTC clock hour (design 4.7.1)',
        'host_days': len(days),
        'meets_minimum_14': len(days) >= MIN_HOST_DAYS,
        'files': files,
        'events': len(records),
        'other_channel_events': other,
        'events_per_channel': dict(sorted(per_channel.items())),
        'events_per_channel_event_id': dict(sorted(per_event.items())),
        'per_host_day': [{'host_day': n, 'events': per_day_events[n], 'findings': per_day_findings[n]}
                         for n in range(1, len(days) + 1)],
        'rules': rules,
        'sigma_pool': sigma_pool,
    }
    if coverage is not None:
        result['coverage'] = coverage['detections']
    return result


# Labels (§4.8) -----------------------------------------------------------------------------

def label_template(findings: list[Finding]) -> dict:
    return {'allowed_labels': list(LABELS),
            'how': 'Give each rule one label, or split it: {"groups": [{"findings": [1, 2], "label": "..."}, ...]} '
                   'using the finding numbers shown in review.html; every finding exactly once.',
            'rules': {rule: {'findings': len(items), 'label': None} for rule, items in by_rule(findings).items()}}


def apply_labels(findings: list[Finding], labels: dict) -> dict[str, dict[str, int]]:
    """Per-rule counts by label; refuses unknown labels, missing rules and incomplete splits."""
    given = labels.get('rules', {})
    result = {}
    for rule, items in by_rule(findings).items():
        entry = given.get(rule)
        if not entry:
            raise ValueError(f'labels_missing_rule:{rule}')
        groups = entry.get('groups') or [{'findings': list(range(1, len(items) + 1)), 'label': entry.get('label')}]
        seen, counts = [], Counter()
        for group in groups:
            if group.get('label') not in LABELS:
                raise ValueError(f'labels_invalid_label:{rule}')
            numbers = group.get('findings') or []
            seen.extend(numbers)
            counts[group['label']] += len(numbers)
        if sorted(seen) != list(range(1, len(items) + 1)):
            raise ValueError(f'labels_split_incomplete:{rule}')
        result[rule] = dict(counts)
    return result


# Local review page (§4.8.1-2) ---------------------------------------------------------------

def _short(value) -> str:
    text = '' if value is None else str(value)
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE] + ' …'


def _records_of(finding: Finding, index: dict) -> list[dict]:
    out = []
    for item in finding.alerts:
        for record_id in item.record_ids:
            for record in index.get(record_id, ()):
                if item.start <= record.get('TimeCreated', '') <= item.end and record not in out:
                    out.append(record)
    return out


def review_html(findings: list[Finding], records: list[dict], days: list[date], levels: dict,
                titles: dict, extra: dict | None = None) -> str:
    esc = html.escape
    index: dict = defaultdict(list)
    for record in records:
        index[record.get('EventRecordID')].append(record)
    dayset = set(days)
    parts = ['<!doctype html><meta charset="utf-8"><title>Host v1 owner review</title>',
             '<style>body{font:14px system-ui,sans-serif;margin:16px;max-width:1100px;color:#111;background:#fff}'
             'table{border-collapse:collapse;margin:6px 0}td,th{border:1px solid #ccc;padding:3px 6px;'
             'vertical-align:top;text-align:left;font-family:ui-monospace,monospace;font-size:12px;'
             'white-space:pre-wrap;word-break:break-all}.rule{border-top:3px solid #333;margin-top:28px}'
             '.example{margin:10px 0 18px}</style>',
             '<h1>Host v1 — owner review (local only, never commit or share)</h1>',
             f'<p>{esc(CORPUS)}. Host-days: {len(days)}. Give one label per rule in <code>labels.json</code> '
             '(benign_explained, unexplained, suspected_malicious), or split a rule by finding number.</p>']
    if extra:
        parts.append(f'<p>{esc(json.dumps(extra))}</p>')
    for rule, items in by_rule(findings).items():
        matched = [r for f in items for r in _records_of(f, index)]
        on = sum(1 for f in items if _moment(f.start).date() in dayset)
        techniques = sorted({t for f in items for a in f.alerts for t in a.techniques})
        parts.append(f'<section class="rule"><h2>{esc(rule)} — {esc(titles.get(rule, ""))}</h2>'
                     f'<p>Level {esc(levels.get(rule, items[0].level))}; techniques {esc(", ".join(techniques))}; '
                     f'findings {len(items)} ({on} on host-days, {len(items) - on} outside); '
                     f'host-days with findings {len({_moment(f.start).date() for f in items} & dayset)}; '
                     f'matched events {len(matched)}.</p>')
        values: dict[str, Counter] = defaultdict(Counter)
        for record in matched:
            for key, value in record.items():
                if key not in SKIP_SUMMARY_FIELDS and value not in (None, '', '-'):
                    values[key][_short(value)[:200]] += 1
        rows = ''.join(
            f'<tr><th>{esc(key)}</th><td>' + '<br>'.join(f'{n}× {esc(v)}' for v, n in counter.most_common(3))
            + '</td></tr>' for key, counter in sorted(values.items()))
        parts.append(f'<details><summary>Most frequent values</summary><table>{rows}</table></details>')
        listing = ''.join(f'<tr><td>{n}</td><td>{esc(f.start)}</td><td>{len(f.alerts)}</td></tr>'
                          for n, f in enumerate(items, start=1))
        parts.append('<details><summary>All findings (number, first event UTC, alerts)</summary>'
                     f'<table>{listing}</table></details>')
        for position in example_indices(len(items)):
            finding = items[position]
            parts.append(f'<div class="example"><h3>Finding {position + 1} — {esc(finding.start)} UTC, '
                         f'{len(finding.alerts)} alert(s)</h3>')
            facts = {k: v for k, v in finding.alerts[0].facts.items() if k != 'sigma'}
            if facts:
                parts.append(f'<p>Facts: {esc(json.dumps(facts))}</p>')
            for record in _records_of(finding, index)[:3]:
                cells = ''.join(f'<tr><th>{esc(str(k))}</th><td>{esc(_short(v))}</td></tr>'
                                for k, v in record.items() if v not in (None, ''))
                parts.append(f'<table>{cells}</table>')
            parts.append('</div>')
        parts.append('</section>')
    return '\n'.join(parts)


# Command line ------------------------------------------------------------------------------

def check_logs_dir(path: Path) -> Path:
    path = Path(path).resolve()
    if not path.is_dir():
        raise SystemExit('logs_dir_not_found')
    if path == ROOT or ROOT in path.parents:
        raise SystemExit('logs_dir_inside_repository')
    return path


def _load_env_key() -> None:
    from app.engines.host.pseudonyms import KEY_ENV
    if os.getenv(KEY_ENV):
        return
    env = ROOT / '.env'
    if env.is_file():
        for line in env.read_text(encoding='utf-8').splitlines():
            name, sep, value = line.partition('=')
            if sep and name.strip() == KEY_ENV:
                os.environ[KEY_ENV] = value.strip()


def _serialise(findings: list[Finding]) -> dict:
    return {rule: [{'number': n, 'start': f.start, 'alerts': len(f.alerts), 'level': f.level}
                   for n, f in enumerate(items, start=1)] for rule, items in by_rule(findings).items()}


def _stored_findings(stored: dict) -> list:
    """Rebuild finding-shaped objects from findings.local.json for label application."""
    out = []
    for rule, items in stored.items():
        for item in items:
            finding = Finding(rule, item['level'], None, None, item['start'][:13])
            finding.alerts = [SimpleNamespace(start=item['start'])]
            out.append(finding)
    return out


def measure(logs: Path) -> dict:
    sys.path.insert(0, str(ROOT / 'backend'))
    _load_env_key()
    from app.engines.host.coverage import coverage_report
    from app.engines.host.detections import NATIVE_RULES, run_native
    from app.engines.host.pseudonyms import Pseudonymizer, load_key
    from app.engines.host.reader import read_files
    from app.engines.host.sigma_harness import build_candidates, evaluate, load_release, load_remap

    files = sorted(p for p in logs.iterdir() if p.is_file() and p.suffix.lower() == '.evtx')
    if not files:
        raise SystemExit('no_evtx_files')
    read = read_files(files)
    records = read.records
    pseudo = Pseudonymizer(load_key())
    release, rule_files = load_release()
    selection = build_candidates(rule_files, load_remap(), release)
    alerts = run_native(records, pseudo) + evaluate(selection.candidates, records, pseudo)
    findings = group_findings(alerts)
    days = host_days(records)
    coverage = coverage_report(records)
    levels = {r.id: r.level for r in NATIVE_RULES} | {'sigma:' + c.rule_id: c.level for c in selection.candidates}
    titles = {r.id: r.title for r in NATIVE_RULES} | {
        'sigma:' + c.rule_id: f'{c.title} (Sigma, {c.author}, {c.path})' for c in selection.candidates}
    pool = {'release': release, 'candidates': len(selection.candidates), 'excluded': dict(selection.excluded)}
    agg = aggregates(records, days, findings, files=len(files), sigma_pool=pool, levels=levels, coverage=coverage)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'aggregates.pending.json').write_text(json.dumps(agg, indent=1) + '\n', encoding='utf-8')
    (OUT / 'findings.local.json').write_text(json.dumps(_serialise(findings), indent=1) + '\n', encoding='utf-8')
    (OUT / 'review.html').write_text(review_html(findings, records, days, levels, titles), encoding='utf-8')
    labels = OUT / 'labels.json'
    if not labels.exists():
        labels.write_text(json.dumps(label_template(findings), indent=1) + '\n', encoding='utf-8')
    return agg


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--logs', type=Path)
    parser.add_argument('--apply-labels', action='store_true')
    args = parser.parse_args(argv)
    if args.apply_labels:
        stored = json.loads((OUT / 'findings.local.json').read_text(encoding='utf-8'))
        labels = json.loads((OUT / 'labels.json').read_text(encoding='utf-8'))
        counts = apply_labels(_stored_findings(stored), labels)
        agg = json.loads((OUT / 'aggregates.pending.json').read_text(encoding='utf-8'))
        for rule, by_label in counts.items():
            agg['rules'][rule]['labels'] = by_label
        (OUT / 'aggregates.labelled.json').write_text(json.dumps(agg, indent=1) + '\n', encoding='utf-8')
        print(json.dumps({'labelled_rules': len(counts)}))
        return 0
    if not args.logs:
        parser.error('--logs is required')
    agg = measure(check_logs_dir(args.logs))
    print(json.dumps({'files': agg['files'], 'events': agg['events'], 'host_days': agg['host_days'],
                      'rules_with_findings': len(agg['rules']),
                      'findings': sum(r['findings'] for r in agg['rules'].values())}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
