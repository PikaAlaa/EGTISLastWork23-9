"""Network-lite detections N1-N9 (design network-windows-v1 §2.1, §6.1).

Runs on the pseudonymised records of one import and returns alerts grouped per (detection,
`device_ref`, destination, fixed UTC hour of the first event). The constants below are the
design's and are never tuned; a change is a dated amendment (§4.10).

Outside data is injected, never fetched:
- `ip_lists(ip) -> tuple[list name, ...]` for N1 (offline lists, step 5);
- `indicator_domain_hashes` for N3 (registered-domain / value hashes of active `domain` and
  `url` indicators after core exclusions, supplied by the engine);
- `url_score(url) -> float` and its frozen threshold for N4 (the existing URL model);
- `popular_rank(registered domain) -> rank | None` from the local Tranco snapshot.
A detection whose input is missing does not run and is listed in `not_run` with a reason
code; it is never reported as "nothing found". N2 is inactive in v1 (§10 decision 1).

Alerts hold values in memory only (hidden from `repr`); the engine turns them into hash-only
indicators and numeric evidence. No name is resolved and nothing is contacted.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from app.core.indicators import sha256_hex
from app.core.url_utils import _suffixes, registered_domain
from app.engines.network_windows.devices import coverage_report
from app.engines.network_windows.readers import ConnRecord, DnsRecord, ReadResult, locality

# §2.1 constants (fixed).
POPULAR_TOP = 100_000
RARE_TOP = 1_000_000
N5_MIN_LENGTH, N5_MIN_ENTROPY, N5_MIN_CONSONANT_RUN, N5_MIN_DIGIT_SHARE = 10, 3.5, 5, 0.30
N5_BURST_DOMAINS, N5_BURST_WINDOW = 10, timedelta(minutes=10)
N6_MIN_EVENTS, N6_MIN_SPAN = 10, timedelta(minutes=30)
N6_MIN_MEDIAN_GAP, N6_MAX_MEDIAN_GAP, N6_MAX_DISPERSION = 10.0, 3600.0, 0.10
N7_USUAL_PORTS = frozenset({20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 3479, 3480,
                            3481, 5223, 5228, 8080, 8443})
BASELINE, MIN_BASELINE_SPAN = timedelta(hours=24), timedelta(hours=48)
N8_WINDOW, N8_MIN_LABELS, N8_MIN_MEDIAN_LENGTH, N8_MIN_MEAN_ENTROPY = timedelta(minutes=10), 50, 25, 3.8
N8_MIN_TXT, N8_LONG_NAME, TXT = 20, 120, 16
# "DNS name does not exist": 9003 DNS_ERROR_RCODE_NAME_ERROR (verified, W2); 9714
# DNS_ERROR_NAME_DOES_NOT_EXIST has the same wording. Which one the client logs is to verify.
NAME_ERROR = frozenset({9003, 9714})
CONSONANTS = frozenset('bcdfghjklmnpqrstvwxyz')
DOCUMENTATION_SUFFIXES = frozenset({'example'})
DETECTIONS = tuple(f'N{i}' for i in range(1, 10))
REASONS = {
    'N1': ('blocklist_ip_connection', 'blocklist_ip_dropped', 'blocklist_ip_dns_answer'),
    'N2': ('blocklist_host_query',),
    'N3': ('indicator_store_domain_match',),
    'N4': ('url_model_domain_high',),
    'N5': ('dga_like_domain', 'dga_nxdomain_burst'),
    'N6': ('periodic_beaconing',),
    'N7': ('unusual_remote_port',),
    'N8': ('dns_long_labels', 'dns_high_entropy_labels', 'dns_txt_burst', 'dns_very_long_name'),
    'N9': ('rare_first_seen_destination',),
}


@dataclass
class Alert:
    detection: str
    device_ref: str | None
    dest_type: str                    # domain | ip
    hour: str                         # fixed UTC hour of the first event, e.g. 2026-01-05T10
    first: str
    last: str
    reasons: set = field(default_factory=set)
    events: int = 0
    details: dict = field(default_factory=dict)      # numbers and fixed codes only
    dest: str = field(default='', repr=False)        # registered domain or remote IP (in memory only)
    ips: set = field(default_factory=set, repr=False)            # remote / answer IPs (non-local)
    process_guids: set = field(default_factory=set, repr=False)  # for the connecting_process join
    sources: set = field(default_factory=set)

    @property
    def dest_hash(self) -> str:
        return sha256_hex(self.dest)


@dataclass
class DetectionResult:
    alerts: list[Alert] = field(default_factory=list)
    not_run: dict[str, str] = field(default_factory=dict)   # detection -> reason code
    baseline: str = 'none'                                   # 24h | none
    counts: Counter = field(default_factory=Counter)         # (detection, reason) -> events


# ----------------------------------------------------------------- helpers

def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def _hour(value: str) -> str:
    return value[:13]


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def longest_consonant_run(text: str) -> int:
    best = run = 0
    for ch in text:
        run = run + 1 if ch in CONSONANTS else 0
        best = max(best, run)
    return best


def dga_like(label: str) -> bool:
    """N5 lexical test on the registered-domain label (left of the public suffix)."""
    if len(label) < N5_MIN_LENGTH or entropy(label) < N5_MIN_ENTROPY:
        return False
    digits = sum(ch.isdigit() for ch in label) / len(label)
    return longest_consonant_run(label) >= N5_MIN_CONSONANT_RUN or digits >= N5_MIN_DIGIT_SHARE


def split_name(name: str) -> tuple[str, str] | None:
    """(registered domain, its label) when the name ends in a known public suffix, else None.

    Names without a known suffix (single labels, `.local`, `.lan`, ...) are local names and
    are skipped. `.example` (RFC 2606, reserved for documentation, never a real name) is
    treated as a suffix so invented test names behave like real ones.
    """
    labels = name.split('.')
    if len(labels) >= 2 and labels[-1] in DOCUMENTATION_SUFFIXES:
        parent = '.'.join(labels[-2:])
        return parent, labels[-2]
    if not _suffixes(name).suffix:
        return None
    parent = registered_domain(name)
    if not parent or '.' not in parent:
        return None
    return parent, parent.split('.')[0]


def query_events(dns: list[DnsRecord]) -> list[DnsRecord]:
    """One event per DNS lookup: DNS Client 3006 (query called) or, if the log has none, 3008,
    else 3020; plus every Sysmon 22 event."""
    client_ids = {r.event_id for r in dns if r.source == 'dns_client'}
    pick = next((e for e in (3006, 3008, 3020) if e in client_ids), None)
    return [r for r in dns if (r.source == 'dns_client' and r.event_id == pick) or r.source == 'sysmon22']


class _Groups:
    def __init__(self):
        self.alerts: dict[tuple, Alert] = {}

    def add(self, detection, device, dest_type, dest, when, reasons, *, ips=(), guids=(), source=None,
            details=None) -> Alert:
        key = (detection, device, dest_type, dest, _hour(when))
        alert = self.alerts.get(key)
        if alert is None:
            alert = self.alerts[key] = Alert(detection, device, dest_type, _hour(when), when, when, dest=dest)
        alert.first, alert.last = min(alert.first, when), max(alert.last, when)
        alert.reasons.update(reasons)
        alert.events += 1
        alert.ips.update(ips)
        alert.process_guids.update(g for g in guids if g)
        if source:
            alert.sources.add(source)
        for name, value in (details or {}).items():
            alert.details[name] = value
        return alert


# ----------------------------------------------------------------- detections

def run_n1(result: ReadResult, groups: _Groups, ip_lists, local_nets) -> None:
    for record in result.connections:
        if record.remote_local:
            continue
        hits = ip_lists(record.remote_ip)
        if hits:
            reason = 'blocklist_ip_dropped' if record.action == 'dropped' else 'blocklist_ip_connection'
            alert = groups.add('N1', record.device_ref, 'ip', record.remote_ip, record.time, [reason],
                               ips=[record.remote_ip], guids=[record.process_guid], source=record.source)
            alert.details['lists'] = sorted(set(alert.details.get('lists', ())) | set(hits))
    for record in result.dns:
        for ip in record.answers:
            if locality(ip, local_nets) == 'local':
                continue
            hits = ip_lists(ip)
            if hits:
                alert = groups.add('N1', record.device_ref, 'ip', ip, record.time, ['blocklist_ip_dns_answer'],
                                   ips=[ip], guids=[record.process_guid], source=record.source)
                alert.details['lists'] = sorted(set(alert.details.get('lists', ())) | set(hits))


def run_n3(queries, groups, hashes: frozenset) -> None:
    for record in queries:
        split = split_name(record.query_name)
        if split and sha256_hex(split[0]) in hashes:
            groups.add('N3', record.device_ref, 'domain', split[0], record.time, ['indicator_store_domain_match'],
                       ips=record.answers, guids=[record.process_guid], source=record.source)


def run_n4(queries, groups, url_score, threshold: float) -> None:
    scores: dict[str, float] = {}
    for record in queries:
        split = split_name(record.query_name)
        if not split:
            continue
        name = record.query_name
        if name not in scores:
            scores[name] = float(url_score(f'https://{name}/'))
        if scores[name] >= threshold:
            alert = groups.add('N4', record.device_ref, 'domain', split[0], record.time, ['url_model_domain_high'],
                               ips=record.answers, guids=[record.process_guid], source=record.source)
            alert.details['score'] = max(alert.details.get('score', 0.0), round(scores[name], 6))
            alert.details['threshold'] = threshold


def run_n5(result: ReadResult, queries, groups, popular) -> None:
    dga: dict[str, dict] = {}
    for record in queries:
        split = split_name(record.query_name)
        if not split or popular(split[0]):
            continue
        parent, label = split
        if parent not in dga:
            dga[parent] = {'match': dga_like(label), 'label': label}
        if dga[parent]['match']:
            label_info = dga[parent]['label']
            groups.add('N5', record.device_ref, 'domain', parent, record.time, ['dga_like_domain'],
                       ips=record.answers, guids=[record.process_guid], source=record.source,
                       details={'label_length': len(label_info), 'label_entropy': round(entropy(label_info), 4),
                                'consonant_run': longest_consonant_run(label_info),
                                'digit_share': round(sum(c.isdigit() for c in label_info) / len(label_info), 4)})
    # Burst: >= 10 distinct DGA-like registered domains answered "name does not exist" for one
    # device within 10 minutes. Every domain in such a window carries the burst reason.
    failures = defaultdict(list)
    for record in result.dns:
        if record.status in NAME_ERROR:
            split = split_name(record.query_name)
            if split and split[0] in dga and dga[split[0]]['match']:
                failures[record.device_ref].append((_time(record.time), split[0], record))
    for device, items in failures.items():
        items.sort(key=lambda item: item[0])
        members: dict[str, tuple] = {}
        window: Counter = Counter()
        start = 0
        for end, (moment, parent, record) in enumerate(items):
            window[parent] += 1
            while moment - items[start][0] > N5_BURST_WINDOW:
                window[items[start][1]] -= 1
                if not window[items[start][1]]:
                    del window[items[start][1]]
                start += 1
            if len(window) >= N5_BURST_DOMAINS:
                for _, member, member_record in items[start:end + 1]:
                    members.setdefault(member, (member_record, len(window)))
                    members[member] = (members[member][0], max(members[member][1], len(window)))
        for parent, (record, size) in members.items():
            groups.add('N5', device, 'domain', parent, record.time, ['dga_like_domain', 'dga_nxdomain_burst'],
                       guids=[record.process_guid], source=record.source, details={'burst_domains': size})


def _periodic(times: list[datetime]) -> dict | None:
    times = sorted(times)
    if len(times) < N6_MIN_EVENTS or times[-1] - times[0] < N6_MIN_SPAN:
        return None
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    median = statistics.median(gaps)
    if not N6_MIN_MEDIAN_GAP <= median <= N6_MAX_MEDIAN_GAP:
        return None
    mad = statistics.median(abs(g - median) for g in gaps)
    dispersion = mad / median
    if dispersion > N6_MAX_DISPERSION + 1e-12:
        return None
    return {'events': len(times), 'median_gap_s': round(median, 3), 'dispersion': round(dispersion, 4),
            'span_s': round((times[-1] - times[0]).total_seconds(), 3)}


def run_n6(result: ReadResult, queries, groups, popular, use_dns: bool) -> None:
    series = defaultdict(list)
    for record in result.connections:
        if record.remote_local or record.direction == 'inbound':
            continue
        split = split_name(record.remote_name) if record.remote_name else None
        if split and popular and popular(split[0]):
            continue
        series[(record.device_ref, 'ip', record.remote_ip, record.remote_port)].append(record)
    if use_dns:
        for record in queries:
            split = split_name(record.query_name)
            if split and not popular(split[0]):
                series[(record.device_ref, 'domain', split[0], None)].append(record)
    for (device, dest_type, dest, port), records in series.items():
        stats = _periodic([_time(r.time) for r in records])
        if stats is None:
            continue
        first = min(records, key=lambda r: r.time)
        ips = [dest] if dest_type == 'ip' else [ip for r in records for ip in r.answers]
        alert = groups.add('N6', device, dest_type, dest, first.time, ['periodic_beaconing'], ips=ips,
                           guids=[r.process_guid for r in records], source=first.source, details=stats)
        alert.last = max(r.time for r in records)
        if port is not None:
            alert.details['port'] = port


def run_n7(result: ReadResult, groups, start: datetime | None, has_baseline: bool) -> None:
    baseline_end = start + BASELINE if start else None
    seen = set()
    candidates = []
    for record in result.connections:
        if (record.remote_local or record.direction != 'outbound' or record.action == 'dropped'
                or record.protocol not in ('tcp', 'udp') or record.remote_port is None):
            continue
        key = (record.device_ref, record.remote_port)
        if has_baseline and _time(record.time) < baseline_end:
            seen.add(key)
            continue
        candidates.append((key, record))
    for key, record in candidates:
        if record.remote_port in N7_USUAL_PORTS or (has_baseline and key in seen):
            continue
        groups.add('N7', record.device_ref, 'ip', record.remote_ip, record.time, ['unusual_remote_port'],
                   ips=[record.remote_ip], guids=[record.process_guid], source=record.source,
                   details={'port': record.remote_port, 'baseline': '24h' if has_baseline else 'none'})


def run_n8(queries, groups, popular, has_query_type: bool) -> None:
    by_domain = defaultdict(list)
    for record in queries:
        split = split_name(record.query_name)
        if split and not popular(split[0]):
            by_domain[(record.device_ref, split[0])].append(record)
    for (device, parent), records in by_domain.items():
        records.sort(key=lambda r: r.time)
        times = [_time(r.time) for r in records]
        signs: dict[str, dict] = {}
        first_time: dict[str, str] = {}
        long_names = [r for r in records if len(r.query_name) >= N8_LONG_NAME]
        if long_names:
            signs['dns_very_long_name'] = {'max_name_length': max(len(r.query_name) for r in long_names)}
            first_time['dns_very_long_name'] = long_names[0].time
        start = 0
        for end in range(len(records)):
            while times[end] - times[start] > N8_WINDOW:
                start += 1
            window = records[start:end + 1]
            labels = {r.query_name.split('.')[0] for r in window if r.query_name != parent}
            if len(labels) >= N8_MIN_LABELS:
                median_length = statistics.median(len(label) for label in labels)
                mean_entropy = statistics.fmean(entropy(label) for label in labels)
                values = {'distinct_labels': len(labels), 'median_label_length': median_length,
                          'mean_label_entropy': round(mean_entropy, 4)}
                if median_length >= N8_MIN_MEDIAN_LENGTH:
                    signs.setdefault('dns_long_labels', values)
                    first_time.setdefault('dns_long_labels', window[0].time)
                if mean_entropy >= N8_MIN_MEAN_ENTROPY:
                    signs.setdefault('dns_high_entropy_labels', values)
                    first_time.setdefault('dns_high_entropy_labels', window[0].time)
            if has_query_type:
                txt = sum(1 for r in window if r.query_type == TXT)
                if txt >= N8_MIN_TXT:
                    signs.setdefault('dns_txt_burst', {'txt_queries': txt})
                    first_time.setdefault('dns_txt_burst', window[0].time)
        if not signs:
            continue
        first = min(first_time.values())
        details = {'signs': len(signs)}
        for values in signs.values():
            details.update(values)
        # Only the registered domain is kept: query names may carry tunnelled data (§6.4).
        alert = groups.add('N8', device, 'domain', parent, first, sorted(signs), source=records[0].source,
                           guids=[r.process_guid for r in records], details=details)
        alert.last = records[-1].time
        alert.events = len(records)


def run_n9(result: ReadResult, queries, groups, popular_rank, start: datetime) -> None:
    baseline_end = start + BASELINE
    answered = {ip for r in result.dns for ip in r.answers}
    first_seen: dict[tuple, tuple] = {}
    for record in queries:
        split = split_name(record.query_name)
        if split:
            key = (record.device_ref, 'domain', split[0])
            if key not in first_seen or record.time < first_seen[key][0]:
                first_seen[key] = (record.time, record)
    for record in result.connections:
        if record.remote_local or record.remote_name or record.remote_ip in answered:
            continue
        key = (record.device_ref, 'ip', record.remote_ip)
        if key not in first_seen or record.time < first_seen[key][0]:
            first_seen[key] = (record.time, record)
    for (device, dest_type, dest), (when, record) in first_seen.items():
        if _time(when) < baseline_end:
            continue
        if dest_type == 'domain':
            rank = popular_rank(dest)
            if rank is not None and rank <= RARE_TOP:
                continue
        ips = record.answers if isinstance(record, DnsRecord) else [record.remote_ip]
        groups.add('N9', device, dest_type, dest, when, ['rare_first_seen_destination'], ips=ips,
                   guids=[record.process_guid], source=record.source, details={'baseline': '24h'})


# ----------------------------------------------------------------- one import

def run(result: ReadResult, *, ip_lists: Callable[[str], Iterable[str]] | None = None,
        indicator_domain_hashes: frozenset | None = None, url_score: Callable[[str], float] | None = None,
        url_threshold: float | None = None, popular_rank: Callable[[str], int | None] | None = None,
        local_nets: tuple = ()) -> DetectionResult:
    coverage = coverage_report(result)
    states = coverage['detections']
    out = DetectionResult(baseline=coverage['baseline'])
    groups = _Groups()
    queries = query_events(result.dns)
    times = [_time(r.time) for r in [*result.dns, *result.connections]]
    start = min(times) if times else None
    has_baseline = bool(times) and max(times) - start >= MIN_BASELINE_SPAN
    popular = (lambda d: (popular_rank(d) or RARE_TOP + 1) <= POPULAR_TOP) if popular_rank else None
    out.not_run['N2'] = 'inactive_in_v1'

    def blocked(detection, missing_input=None):
        if states[detection] == 'not_visible':
            out.not_run[detection] = 'not_visible'
            return True
        if missing_input:
            out.not_run[detection] = missing_input
            return True
        return False

    if not blocked('N1', None if ip_lists else 'blocklists_missing'):
        run_n1(result, groups, lambda ip: tuple(ip_lists(ip) or ()), local_nets)
    if not blocked('N3', None if indicator_domain_hashes is not None else 'indicator_store_unavailable'):
        run_n3(queries, groups, frozenset(indicator_domain_hashes))
    if not blocked('N4', None if url_score and url_threshold is not None else 'url_model_unavailable'):
        run_n4(queries, groups, url_score, float(url_threshold))
    if not blocked('N5', None if popular else 'popular_list_missing'):
        run_n5(result, queries, groups, popular)
    if not blocked('N6'):
        connections_present = any(coverage['sources'][s]['records'] for s in ('firewall', 'sysmon3', 'snapshot'))
        if connections_present or popular:
            run_n6(result, queries, groups, popular, use_dns=not connections_present)
        else:
            out.not_run['N6'] = 'popular_list_missing'
    if not blocked('N7'):
        run_n7(result, groups, start, has_baseline)
    if not blocked('N8', None if popular else 'popular_list_missing'):
        run_n8(queries, groups, popular, has_query_type=any(r.query_type is not None for r in queries))
    if states['N9'] == 'no_baseline':
        out.not_run['N9'] = 'no_baseline'
    elif not blocked('N9', None if popular_rank else 'popular_list_missing'):
        run_n9(result, queries, groups, popular_rank, start)
    out.alerts = sorted(groups.alerts.values(), key=lambda a: (a.first, a.detection, a.dest_type, a.dest_hash))
    for alert in out.alerts:
        for reason in alert.reasons:
            out.counts[(alert.detection, reason)] += 1
    return out


N4_URL_CANDIDATE, N4_THRESHOLD = 'ee0ba9f0077c1fd140aa', 0.9870690448552604
# The constants a shipped-item manifest must repeat exactly for each rule (design §4.7).
RULE_CONSTANTS = {
    'N1': {'match': 'exact_ip', 'local_excluded': True},
    'N3': {'match': 'registered_domain_hash'},
    'N4': {'url_candidate': N4_URL_CANDIDATE, 'threshold': N4_THRESHOLD, 'input': 'https://<query name>/'},
    'N5': {'min_length': N5_MIN_LENGTH, 'min_entropy': N5_MIN_ENTROPY, 'min_consonant_run': N5_MIN_CONSONANT_RUN,
           'min_digit_share': N5_MIN_DIGIT_SHARE, 'burst_domains': N5_BURST_DOMAINS, 'burst_window_s': 600,
           'popular_top': POPULAR_TOP},
    'N6': {'min_events': N6_MIN_EVENTS, 'min_span_s': 1800, 'min_median_gap_s': N6_MIN_MEDIAN_GAP,
           'max_median_gap_s': N6_MAX_MEDIAN_GAP, 'max_dispersion': N6_MAX_DISPERSION, 'popular_top': POPULAR_TOP},
    'N7': {'usual_ports': sorted(N7_USUAL_PORTS), 'baseline_hours': 24, 'min_span_hours': 48},
    'N8': {'window_s': 600, 'min_labels': N8_MIN_LABELS, 'min_median_length': N8_MIN_MEDIAN_LENGTH,
           'min_mean_entropy': N8_MIN_MEAN_ENTROPY, 'min_txt': N8_MIN_TXT, 'long_name': N8_LONG_NAME,
           'popular_top': POPULAR_TOP},
    'N9': {'rare_top': RARE_TOP, 'baseline_hours': 24, 'min_span_hours': 48},
}
SHIPPABLE = tuple(RULE_CONSTANTS)   # N2 is inactive in v1 (§4.2)
