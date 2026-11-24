"""Coverage report for one host import (design host-engine-v1 §1.1, §7).

States which of the design's channels are present, the time span covered, and for each
detection whether it could run. A detection that could not run is `not_visible`, never
"nothing found". `unconfirmed` means its channel is present but none of its events were
seen: either nothing happened or the audit policy does not log them.

The report holds only fixed channel names, event ids, counts and times. Channels outside
the design's list are counted, not named (their names could reveal installed software).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

SECURITY = 'Security'
SYSTEM = 'System'
POWERSHELL = 'Microsoft-Windows-PowerShell/Operational'
DEFENDER = 'Microsoft-Windows-Windows Defender/Operational'
TASKS = 'Microsoft-Windows-TaskScheduler/Operational'
RDP = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
KNOWN_CHANNELS = (SECURITY, SYSTEM, POWERSHELL, DEFENDER, TASKS, RDP, SYSMON)
REQUIRED_CHANNELS = (SECURITY, SYSTEM, POWERSHELL)

PROCESS_CREATION = {(SECURITY, 4688), (SYSMON, 1)}
# Detection -> the (channel, event id) sources it reads.
SOURCES = {
    'H1': {(SECURITY, 4625)},
    'H2': {(SECURITY, 4625)},
    'H3': {(SECURITY, 4720)},
    'H4': {(SECURITY, 4732)},
    'H5': {(POWERSHELL, 4104), (POWERSHELL, 4103), (SYSMON, 1)},
    'H6': {(SYSTEM, 7045), (SECURITY, 4697)},
    'H7': {(SECURITY, 4698), (TASKS, 106)},
    'H8': {(SECURITY, 1102), (SECURITY, 4719), (SYSTEM, 104)},
    'H9': {(SECURITY, 4624), (RDP, 1149)},
    'H10': {(DEFENDER, 5001), (DEFENDER, 5010), (DEFENDER, 5012), (SYSTEM, 7040), (SYSTEM, 7036), (SYSMON, 13)},
    'H11': PROCESS_CREATION,
    'H12': PROCESS_CREATION,
    'H13': {(SECURITY, 4648)},
}
DETECTION_IDS = tuple(f'H{i}' for i in range(1, 14))
H13_MIN_SPAN_HOURS = 48


def _parse(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, ValueError):
        return None


def _span(times: list[datetime]) -> dict | None:
    if not times:
        return None
    first, last = min(times), max(times)
    fmt = '%Y-%m-%dT%H:%M:%S.%fZ'
    return {'first': first.strftime(fmt), 'last': last.strftime(fmt),
            'hours': round((last - first).total_seconds() / 3600, 6)}


def channel_span_hours(records: list[dict], channel: str) -> float:
    times = [t for t in (_parse(r.get('TimeCreated')) for r in records if r.get('Channel') == channel) if t]
    return (max(times) - min(times)).total_seconds() / 3600 if times else 0.0


def coverage_report(records: list[dict]) -> dict:
    counts: Counter = Counter()
    times: dict[str, list[datetime]] = defaultdict(list)
    other: set = set()
    command_lines = 0
    for record in records:
        channel, event_id = record.get('Channel'), record.get('EventID')
        moment = _parse(record.get('TimeCreated'))
        if channel not in KNOWN_CHANNELS:
            other.add(channel)
            continue
        counts[(channel, event_id)] += 1
        if moment:
            times[channel].append(moment)
        if (channel, event_id) in PROCESS_CREATION and (record.get('CommandLine') or '').strip():
            command_lines += 1
    channels = {}
    for channel in KNOWN_CHANNELS:
        events = sum(n for (c, _), n in counts.items() if c == channel)
        if events:
            span = _span(times[channel]) or {}
            channels[channel] = {'events': events, 'first': span.get('first'), 'last': span.get('last')}
    detections = {}
    for detection in DETECTION_IDS:
        sources = SOURCES[detection]
        if not any(channel in channels for channel, _ in sources):
            detections[detection] = {'status': 'not_visible', 'reason': 'channel_missing'}
        elif detection in ('H11', 'H12') and not any(counts[s] for s in PROCESS_CREATION):
            detections[detection] = {'status': 'not_visible', 'reason': 'process_creation_not_logged'}
        elif detection == 'H12' and not command_lines:
            detections[detection] = {'status': 'not_visible', 'reason': 'command_line_not_logged'}
        elif not any(counts[s] for s in sources):
            detections[detection] = {'status': 'unconfirmed', 'reason': 'no_events_seen'}
        else:
            detections[detection] = {'status': 'visible'}
    if detections['H13']['status'] != 'not_visible' \
            and channel_span_hours(records, SECURITY) < H13_MIN_SPAN_HOURS:
        detections['H13']['limits'] = ['baseline_none']
    all_times = [t for values in times.values() for t in values]
    return {
        'channels': channels,
        'other_channels': len(other),
        'event_counts': {f'{c}:{e}': n for (c, e), n in sorted(counts.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0))},
        'span': _span(all_times),
        'detections': detections,
    }
