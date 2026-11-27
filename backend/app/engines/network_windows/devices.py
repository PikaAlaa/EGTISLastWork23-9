"""Device and account pseudonyms, and the coverage report, for one network.windows import
(design network-windows-v1 §1.2, §6.5, §7).

`device_ref` is the host engine's `host_ref` (HMAC-SHA-256 with `ETIS_HOST_PSEUDONYM_KEY` and
the host engine's normalisation), so the same PC has the same reference in both engines.
Sources without a computer name (firewall log, snapshots) use the name given by
`--device-name`, defaulting to this PC's own name. `account_ref` (Sysmon `User` only) is the
host engine's account pseudonym. `pseudonymise` drops every computer and user name from the
records right after reading; later steps only see references.

The coverage report holds fixed source names, detection ids, counts and times only. A
detection that could not run is `not_visible`, never "nothing found".
"""
from __future__ import annotations

import os
import platform
from dataclasses import replace
from datetime import datetime

from app.engines.host.pseudonyms import Pseudonymizer
from app.engines.network_windows.readers import ReadResult

SOURCES = ('dns_client', 'sysmon22', 'firewall', 'sysmon3', 'snapshot')
DNS_SOURCES = ('dns_client', 'sysmon22')
CONNECTION_SOURCES = ('firewall', 'sysmon3', 'snapshot')
DETECTION_IDS = tuple(f'N{i}' for i in range(1, 10))
BASELINE_HOURS = 24
MIN_BASELINE_SPAN_HOURS = 48


class DeviceNameError(ValueError):
    """Raised with a fixed reason code when no device name is available."""


def default_device_name() -> str | None:
    """This PC's own name, from the environment or the platform (no lookup of any kind)."""
    return (os.environ.get('COMPUTERNAME') or platform.node() or '').strip() or None


def _account(pseudo: Pseudonymizer, user: str | None) -> str | None:
    if not user:
        return None
    domain, sep, name = user.partition('\\')
    return pseudo.account_ref(name=name, domain=domain) if sep else pseudo.account_ref(name=user)


def pseudonymise(result: ReadResult, pseudo: Pseudonymizer, device_name: str | None = None) -> ReadResult:
    """Replace computer and user names with references, in place; returns `result`.

    Records with their own computer name (EVTX) use it; the others use `device_name`.
    """
    fallback = pseudo.host_ref(device_name) if device_name else None
    needs_fallback = any(r.computer is None for r in [*result.dns, *result.connections])
    if needs_fallback and fallback is None:
        raise DeviceNameError('device_name_missing')
    refs: dict[str, str | None] = {}

    def device(computer):
        if computer is None:
            return fallback
        if computer not in refs:
            refs[computer] = pseudo.host_ref(computer) or fallback
        return refs[computer]

    result.dns = [replace(r, computer=None, device_ref=device(r.computer)) for r in result.dns]
    result.connections = [replace(r, computer=None, user=None, device_ref=device(r.computer),
                                  account_ref=_account(pseudo, r.user)) for r in result.connections]
    return result


def _hours(first: str, last: str) -> float:
    parse = lambda v: datetime.fromisoformat(v.replace('Z', '+00:00'))  # noqa: E731
    return round((parse(last) - parse(first)).total_seconds() / 3600, 6)


def coverage_report(result: ReadResult) -> dict:
    """Which sources are present, their spans, and whether each detection could run (§1.2)."""
    present = {s: 0 for s in SOURCES}
    spans: dict[str, list[str]] = {}
    for record in [*result.dns, *result.connections]:
        source = record.source
        present[source] += 1
        first, last = spans.get(source, (record.time, record.time))
        spans[source] = [min(first, record.time), max(last, record.time)]
    has = {s for s, n in present.items() if n}
    dns = bool(has & set(DNS_SOURCES))
    conns = bool(has & set(CONNECTION_SOURCES))
    answers = any(r.answers for r in result.dns)
    qtype = any(r.query_type is not None for r in result.dns)
    outbound = any(r.direction == 'outbound' and r.action in ('allowed', 'observed') for r in result.connections)
    times = [t for span in spans.values() for t in span]
    import_hours = _hours(min(times), max(times)) if times else 0.0
    baseline = import_hours >= MIN_BASELINE_SPAN_HOURS

    def state(visible: bool, partial: bool = False) -> str:
        return 'not_visible' if not visible else ('partial' if partial else 'visible')

    detections = {
        'N1': state(conns or (dns and answers), partial=not (conns and dns)),
        'N2': 'inactive',   # no v1 list provides hosts (§10 decision 1)
        'N3': state(dns), 'N4': state(dns), 'N5': state(dns),
        'N6': state(conns or dns, partial=not conns),
        'N7': state(conns and outbound) if baseline or not (conns and outbound) else 'no_baseline',
        'N8': state(dns, partial=not qtype),
        'N9': ('no_baseline' if (dns or conns) and not baseline else state(dns or conns, partial=not (dns and conns))),
    }
    return {
        'sources': {s: {'records': present[s], 'first': spans[s][0], 'last': spans[s][1],
                        'hours': _hours(*spans[s])} if s in spans else {'records': 0} for s in SOURCES},
        'import_hours': import_hours,
        'baseline': '24h' if baseline else 'none',
        'detections': detections,
        'not_visible': sorted(d for d, s in detections.items() if s == 'not_visible'),
        'firewall_time_basis': result.firewall_time_basis,
        'events': {f'{s}:{k}': n for (s, k), n in sorted(result.counts.items(), key=str)},
        'skipped': {f'{s}:{k}': n for (s, k), n in sorted(result.skipped.items(), key=str)},
    }
