"""Native host detections H1-H4 and H6-H13 (design host-engine-v1 §2.1, amendment 1).

Each detection reads normalised records (reader.py) and returns in-memory `Alert`s. Alerts
carry only keyed references (`host_ref`, `account_ref`), fixed-vocabulary facts, event
record ids and, where the design allows, outside addresses and executed-file hashes that
later become hash-only indicators. Constants are fixed by the design and never tuned.
Grouping into Findings, severity escalation and confidence belong to the engine (§6).
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.engines.host.coverage import DEFENDER, RDP, SECURITY, SYSMON, SYSTEM, TASKS
from app.engines.host.pseudonyms import Pseudonymizer, locality

SCM = 'Service Control Manager'
EVENTLOG = 'Microsoft-Windows-Eventlog'


@dataclass(frozen=True)
class NativeRule:
    id: str
    title: str
    level: str
    techniques: tuple[str, ...]
    constants: dict = field(default_factory=dict, compare=False, hash=False)


NATIVE_RULES = (
    NativeRule('H1', 'Failed-logon flood', 'medium', ('T1110.001',), {'failures': 20, 'window_seconds': 600}),
    NativeRule('H2', 'Password spraying', 'high', ('T1110.003',), {'distinct_accounts': 10, 'window_seconds': 600}),
    NativeRule('H3', 'New local account', 'medium', ('T1136.001',)),
    NativeRule('H4', 'Added to local Administrators', 'high', ('T1098.007',), {'group_sid': 'S-1-5-32-544'}),
    NativeRule('H6', 'New service', 'low', ('T1543.003',)),
    NativeRule('H7', 'New scheduled task', 'low', ('T1053.005',)),
    NativeRule('H8', 'Audit log cleared or auditing disabled', 'high', ('T1685.005', 'T1685.001')),
    NativeRule('H9', 'RDP logon from outside', 'medium', ('T1133', 'T1021.001')),
    NativeRule('H10', 'Defender disabled', 'high', ('T1685',)),
    NativeRule('H11', 'Office application starts a shell or script host', 'high', ('T1204.002',)),
    NativeRule('H12', 'Shadow copy deletion', 'high', ('T1490',)),
    NativeRule('H13', "Run-as with another account's credentials from an unusual account", 'medium',
               ('T1134.002', 'T1078'), {'baseline_hours': 24, 'min_span_hours': 48}),
)
RULES = {rule.id: rule for rule in NATIVE_RULES}

OFFICE_PARENTS = ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
SHELL_CHILDREN = {'powershell.exe': 'T1059.001', 'pwsh.exe': 'T1059.001', 'cmd.exe': 'T1059.003',
                  'wscript.exe': 'T1059.005', 'mshta.exe': 'T1218.005'}
WELL_KNOWN_SUBJECTS = {'S-1-5-18', 'S-1-5-19', 'S-1-5-20'}
LOCAL_SERVERS = {'localhost', '127.0.0.1', '::1'}
AUDIT_REMOVED = ('%%8448', '%%8450', 'success removed', 'failure removed')
DEFENDER_POLICY_VALUES = ('\\disableantispyware', '\\disablerealtimemonitoring')
_HASH_LENGTHS = {'sha256': 64, 'sha1': 40, 'md5': 32}
_HEX = re.compile(r'^[0-9a-fA-F]+$')


@dataclass
class Alert:
    detection: str
    level: str
    techniques: tuple[str, ...]
    start: str
    end: str
    record_ids: tuple[int, ...]
    host_ref: str | None
    account_ref: str | None = None
    facts: dict = field(default_factory=dict)
    remote_ips: tuple[str, ...] = ()
    hashes: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return {'detection': self.detection, 'level': self.level, 'techniques': list(self.techniques),
                'start': self.start, 'end': self.end, 'record_ids': list(self.record_ids), 'host_ref': self.host_ref,
                'account_ref': self.account_ref, 'facts': dict(self.facts), 'remote_ips': list(self.remote_ips),
                'hashes': [list(h) for h in self.hashes]}


def _time(record: dict) -> datetime:
    return datetime.fromisoformat(record['TimeCreated'].replace('Z', '+00:00'))


def _get(record: dict, name: str) -> str:
    value = record.get(name)
    return '' if value is None else str(value).strip()


def file_name(path: str) -> str:
    return re.split(r'[\\/]', path.strip().strip('"'))[-1].lower() if path else ''


def best_hash(value) -> tuple[str, str] | None:
    """Sysmon `Hashes` -> (algorithm, lower-case hex) with precedence SHA256 > SHA1 > MD5."""
    if not value:
        return None
    found = {}
    for part in str(value).split(','):
        name, _, digest = part.partition('=')
        name, digest = name.strip().lower(), digest.strip()
        if name in _HASH_LENGTHS and len(digest) == _HASH_LENGTHS[name] and _HEX.match(digest):
            found[name] = digest.lower()
    for name in ('sha256', 'sha1', 'md5'):
        if name in found:
            return name, found[name]
    return None


class _Context:
    def __init__(self, pseudo: Pseudonymizer, local_nets: tuple):
        self.pseudo, self.local_nets = pseudo, local_nets

    def alert(self, rule_id: str, records: list[dict], techniques=None, **kwargs) -> Alert:
        rule = RULES[rule_id]
        return Alert(detection=rule_id, level=rule.level, techniques=tuple(techniques or rule.techniques),
                     start=records[0]['TimeCreated'], end=records[-1]['TimeCreated'],
                     record_ids=tuple(r['EventRecordID'] for r in records),
                     host_ref=self.pseudo.host_ref(records[0].get('Computer')), **kwargs)

    def source(self, address: str) -> tuple[str, tuple[str, ...]]:
        where = locality(address, self.local_nets)
        return where, ((address,) if where == 'outside' else ())


def _is(record: dict, channel: str, *event_ids: int, provider: str | None = None) -> bool:
    return record.get('Channel') == channel and record.get('EventID') in event_ids and (
        provider is None or record.get('Provider') == provider)


def _failed_logon_floods(records, ctx) -> list[Alert]:
    rule, alerts = RULES['H1'], []
    window = timedelta(seconds=rule.constants['window_seconds'])
    by_account = defaultdict(list)
    for record in records:
        if _is(record, SECURITY, 4625):
            ref = ctx.pseudo.account_ref(_get(record, 'TargetUserSid'), _get(record, 'TargetUserName'),
                                         _get(record, 'TargetDomainName'))
            if ref:
                by_account[ref].append(record)
    for ref, events in by_account.items():
        current: deque = deque()
        for record in events:
            current.append(record)
            while _time(record) - _time(current[0]) >= window:  # window [t, t + 600 s)
                current.popleft()
            if len(current) >= rule.constants['failures']:
                alerts.append(ctx.alert('H1', list(current), account_ref=ref))
                current.clear()
    return alerts


def _password_spraying(records, ctx) -> list[Alert]:
    rule, alerts = RULES['H2'], []
    window = timedelta(seconds=rule.constants['window_seconds'])
    by_source = defaultdict(list)
    for record in records:
        if not _is(record, SECURITY, 4625):
            continue
        address = _get(record, 'IpAddress')
        if address and address != '-':
            key = 'ip:' + address
        else:
            workstation = ctx.pseudo.host_ref(_get(record, 'WorkstationName'))
            if not workstation:
                continue
            key, address = 'ws:' + workstation, ''
        account = ctx.pseudo.account_ref(_get(record, 'TargetUserSid'), _get(record, 'TargetUserName'),
                                         _get(record, 'TargetDomainName'))
        if account:
            by_source[key].append((record, account, address))
    for key, events in by_source.items():
        current: deque = deque()
        for item in events:
            current.append(item)
            while _time(item[0]) - _time(current[0][0]) >= window:
                current.popleft()
            if len({account for _, account, _ in current}) >= rule.constants['distinct_accounts']:
                where, remote = ctx.source(item[2])
                alerts.append(ctx.alert('H2', [r for r, _, _ in current], facts={'source_locality': where},
                                        remote_ips=remote))
                current.clear()
    return alerts


def _single_event(record, ctx) -> list[Alert]:
    out = []
    if _is(record, SECURITY, 4720):
        out.append(ctx.alert('H3', [record], account_ref=ctx.pseudo.account_ref(
            _get(record, 'TargetSid'), _get(record, 'TargetUserName'), _get(record, 'TargetDomainName'))))
    if _is(record, SECURITY, 4732) and _get(record, 'TargetSid').upper() == RULES['H4'].constants['group_sid']:
        out.append(ctx.alert('H4', [record], account_ref=ctx.pseudo.account_ref(
            _get(record, 'MemberSid'), _get(record, 'MemberName'))))
    if _is(record, SYSTEM, 7045, provider=SCM) or _is(record, SECURITY, 4697):
        out.append(ctx.alert('H6', [record]))
    if _is(record, SECURITY, 4698) or _is(record, TASKS, 106):
        out.append(ctx.alert('H7', [record]))
    if _is(record, SECURITY, 1102) or _is(record, SYSTEM, 104, provider=EVENTLOG):
        out.append(ctx.alert('H8', [record], techniques=('T1685.005',)))
    if _is(record, SECURITY, 4719) and any(code in _get(record, 'AuditPolicyChanges').lower() for code in AUDIT_REMOVED):
        out.append(ctx.alert('H8', [record], techniques=('T1685.001',)))
    out.extend(_rdp(record, ctx))
    if _defender_disabled(record):
        out.append(ctx.alert('H10', [record]))
    out.extend(_process(record, ctx))
    return out


def _rdp(record, ctx) -> list[Alert]:
    if _is(record, SECURITY, 4624) and _get(record, 'LogonType') == '10':
        address, logon_type = _get(record, 'IpAddress'), '10'
        account = ctx.pseudo.account_ref(_get(record, 'TargetUserSid'), _get(record, 'TargetUserName'),
                                         _get(record, 'TargetDomainName'))
    elif _is(record, RDP, 1149):
        address, logon_type = _get(record, 'Param3'), 'rdp_authentication'
        account = ctx.pseudo.account_ref(name=_get(record, 'Param1'), domain=_get(record, 'Param2'))
    else:
        return []
    where, remote = ctx.source(address)
    if where != 'outside':
        return []
    return [ctx.alert('H9', [record], account_ref=account, facts={'source_locality': where, 'logon_type': logon_type},
                      remote_ips=remote)]


def _service_from_binary(value: str) -> str:
    try:
        return bytes.fromhex(value).decode('utf-16-le', errors='ignore').split('/')[0].strip('\0').lower()
    except ValueError:
        return ''


def _defender_disabled(record) -> bool:
    if _is(record, DEFENDER, 5001, 5010, 5012):
        return True
    if _is(record, SYSTEM, 7040, provider=SCM):
        return _get(record, 'param4').lower() == 'windefend' and _get(record, 'param3').lower() == 'disabled'
    if _is(record, SYSTEM, 7036, provider=SCM):
        return _service_from_binary(_get(record, 'Binary')) == 'windefend' and _get(record, 'param2').lower() == 'stopped'
    if _is(record, SYSMON, 13):
        target = _get(record, 'TargetObject').lower()
        return target.endswith(DEFENDER_POLICY_VALUES) and _get(record, 'Details').lower() == 'dword (0x00000001)'
    return False


def _process(record, ctx) -> list[Alert]:
    if _is(record, SECURITY, 4688):
        image, parent, hashes = _get(record, 'NewProcessName'), _get(record, 'ParentProcessName'), ()
    elif _is(record, SYSMON, 1):
        image, parent = _get(record, 'Image'), _get(record, 'ParentImage')
        found = best_hash(record.get('Hashes'))
        hashes = (found,) if found else ()
    else:
        return []
    child, parent_name = file_name(image), file_name(parent)
    out = []
    if parent_name in OFFICE_PARENTS and child in SHELL_CHILDREN:
        out.append(ctx.alert('H11', [record], techniques=('T1204.002', SHELL_CHILDREN[child]),
                             facts={'parent': parent_name, 'child': child}, hashes=hashes))
    command = ' '.join(_get(record, 'CommandLine').lower().split())
    if command and _shadow_copy_deletion(child, command):
        out.append(ctx.alert('H12', [record], facts={'tool': child}, hashes=hashes))
    return out


def _shadow_copy_deletion(tool: str, command: str) -> bool:
    if tool == 'vssadmin.exe':
        return 'delete shadows' in command
    if tool == 'wmic.exe':
        return 'shadowcopy' in command and 'delete' in command
    if tool == 'wbadmin.exe':
        return any(form in command for form in ('delete catalog', 'delete systemstatebackup', 'delete backup'))
    return False


def _run_as(records, ctx) -> list[Alert]:
    rule = RULES['H13']
    security_times = [_time(r) for r in records if r.get('Channel') == SECURITY]
    if not security_times:
        return []
    start = min(security_times)
    has_baseline = max(security_times) - start >= timedelta(hours=rule.constants['min_span_hours'])
    baseline_end = start + timedelta(hours=rule.constants['baseline_hours'])
    qualifying = []
    for record in records:
        if not _is(record, SECURITY, 4648):
            continue
        subject, subject_sid = _get(record, 'SubjectUserName'), _get(record, 'SubjectUserSid').upper()
        if not subject or subject == '-' or subject.endswith('$') or subject_sid in WELL_KNOWN_SUBJECTS:
            continue
        server = _get(record, 'TargetServerName').lower()
        computer = _get(record, 'Computer').lower().split('.')[0]
        if server not in LOCAL_SERVERS and server.split('.')[0] != computer:
            continue
        subject_key = (_get(record, 'SubjectDomainName').casefold(), subject.casefold())
        target_key = (_get(record, 'TargetDomainName').casefold(), _get(record, 'TargetUserName').casefold())
        if not target_key[1] or target_key[1] == '-' or subject_key == target_key:
            continue
        qualifying.append((record, subject_key, target_key))
    baseline = {(s, t) for r, s, t in qualifying if has_baseline and _time(r) < baseline_end}
    alerts = []
    for record, subject_key, target_key in qualifying:
        if has_baseline and (_time(record) < baseline_end or (subject_key, target_key) in baseline):
            continue
        account = ctx.pseudo.account_ref(name=target_key[1], domain=target_key[0])
        alerts.append(ctx.alert('H13', [record], account_ref=account,
                                facts={'baseline': '24h' if has_baseline else 'none'}))
    return alerts


def run_native(records: list[dict], pseudo: Pseudonymizer, local_nets: tuple = ()) -> list[Alert]:
    """Run every native detection; alerts are ordered by detection, then time."""
    ordered = sorted((r for r in records if r.get('TimeCreated') and r.get('EventID') is not None),
                     key=lambda r: (r['TimeCreated'], r.get('EventRecordID') or 0))
    ctx = _Context(pseudo, local_nets)
    alerts = _failed_logon_floods(ordered, ctx) + _password_spraying(ordered, ctx)
    for record in ordered:
        alerts.extend(_single_event(record, ctx))
    alerts.extend(_run_as(ordered, ctx))
    order = {rule.id: index for index, rule in enumerate(NATIVE_RULES)}
    return sorted(alerts, key=lambda a: (order[a.detection], a.start))
