"""Native host detections H1-H13 at their exact constants (design host-engine-v1 §2.1, §8.3).

All events are invented dictionaries in the reader's normalised form.
"""
import json
from datetime import timedelta

import pytest

from app.engines.host.detections import NATIVE_RULES, best_hash, run_native
from app.engines.host.pseudonyms import Pseudonymizer
from host_fixtures import T0

PSEUDO = Pseudonymizer(bytes(range(32)))
SEC, SYS = 'Security', 'System'
PS = 'Microsoft-Windows-PowerShell/Operational'
DEF = 'Microsoft-Windows-Windows Defender/Operational'
TASKS = 'Microsoft-Windows-TaskScheduler/Operational'
RDP = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
PROVIDERS = {SEC: 'Microsoft-Windows-Security-Auditing', SYS: 'Service Control Manager', SYSMON: 'Microsoft-Windows-Sysmon'}
MARKER = 'invented-marker-9902'
_counter = iter(range(1, 10 ** 6))


def ev(event_id, channel=SEC, seconds=0.0, provider=None, computer='INVENTED-PC', **fields):
    when = (T0 + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return {'Channel': channel, 'Provider': provider or PROVIDERS.get(channel, 'Invented'), 'EventID': event_id,
            'TimeCreated': when, 'EventRecordID': next(_counter), 'Computer': computer,
            **{k: str(v) for k, v in fields.items()}}


def run(records, **kwargs):
    return run_native(records, PSEUDO, **kwargs)


def ids(alerts):
    return [a.detection for a in alerts]


def failed(account='invented-user', seconds=0.0, ip='203.0.113.9', workstation='INVENTED-WS'):
    return ev(4625, seconds=seconds, TargetUserSid='S-1-0-0', TargetUserName=account, TargetDomainName='INVENTED-PC',
              LogonType=3, IpAddress=ip, WorkstationName=workstation)


def test_rule_table_matches_the_design():
    assert [r.id for r in NATIVE_RULES] == ['H1', 'H2', 'H3', 'H4', 'H6', 'H7', 'H8', 'H9', 'H10', 'H11', 'H12',
                                            'H13']
    table = {r.id: r for r in NATIVE_RULES}
    assert table['H1'].constants == {'failures': 20, 'window_seconds': 600}
    assert table['H2'].constants == {'distinct_accounts': 10, 'window_seconds': 600}
    assert table['H13'].constants == {'baseline_hours': 24, 'min_span_hours': 48}
    assert table['H11'].techniques == ('T1204.002',) and table['H12'].techniques == ('T1490',)
    assert table['H13'].techniques == ('T1134.002', 'T1078')
    assert table['H8'].techniques == ('T1685.005', 'T1685.001') and table['H10'].techniques == ('T1685',)
    assert {r.id: r.level for r in NATIVE_RULES} == {
        'H1': 'medium', 'H2': 'high', 'H3': 'medium', 'H4': 'high', 'H6': 'low', 'H7': 'low', 'H8': 'high',
        'H9': 'medium', 'H10': 'high', 'H11': 'high', 'H12': 'high', 'H13': 'medium'}


# --- H1 failed-logon flood: >= 20 failures for one account within [t, t + 600 s) ---

def test_h1_needs_20_failures_for_one_account():
    assert ids(run([failed(seconds=i) for i in range(19)])) == []
    alerts = run([failed(seconds=i) for i in range(20)])
    assert ids(alerts) == ['H1'] and len(alerts[0].record_ids) == 20
    assert alerts[0].techniques == ('T1110.001',) and alerts[0].account_ref.startswith('hmac:')


def test_h1_window_edge_is_600_seconds_exclusive():
    within = [failed(seconds=i * 599 / 19) for i in range(20)]  # first at 0 s, 20th at 599 s
    outside = [failed(seconds=i * 600 / 19) for i in range(20)]  # 20th at exactly 600 s
    assert ids(run(within)) == ['H1'] and ids(run(outside)) == []


def test_h1_counts_per_account_and_restarts_after_an_alert():
    mixed = [failed('invented-a', i) for i in range(10)] + [failed('invented-b', 10 + i) for i in range(10)]
    assert ids(run(mixed)) == []
    assert ids(run([failed(seconds=i) for i in range(39)])) == ['H1']
    assert ids(run([failed(seconds=i) for i in range(40)])) == ['H1', 'H1']


def test_h1_orders_events_by_time_across_files():
    events = [failed(seconds=i) for i in range(20)]
    assert ids(run(list(reversed(events)))) == ['H1']


# --- H2 password spraying: one source, >= 10 distinct accounts within [t, t + 600 s) ---

def test_h2_needs_10_distinct_accounts_from_one_source():
    assert ids(run([failed(f'invented-{i}', i) for i in range(9)])) == []
    alerts = run([failed(f'invented-{i}', i) for i in range(10)])
    assert ids(alerts) == ['H2'] and alerts[0].techniques == ('T1110.003',)
    assert alerts[0].facts['source_locality'] == 'outside' and alerts[0].remote_ips == ('203.0.113.9',)


def test_h2_repeated_accounts_and_split_sources_do_not_count():
    assert ids(run([failed('invented-same', i) for i in range(10)])) == []
    split = [failed(f'invented-{i}', i, ip='203.0.113.9' if i % 2 else '198.51.100.7') for i in range(10)]
    assert ids(run(split)) == []


def test_h2_window_edge_and_workstation_fallback():
    assert ids(run([failed(f'invented-{i}', i * 600 / 9) for i in range(10)])) == []
    assert ids(run([failed(f'invented-{i}', i * 599 / 9) for i in range(10)])) == ['H2']
    by_name = run([failed(f'invented-{i}', i, ip='-') for i in range(10)])
    assert ids(by_name) == ['H2'] and by_name[0].remote_ips == () and by_name[0].facts['source_locality'] == 'unknown'
    local = run([failed(f'invented-{i}', i, ip='192.168.1.50') for i in range(10)])
    assert local[0].facts['source_locality'] == 'local' and local[0].remote_ips == ()


# --- H3 new local account, H4 added to local Administrators ---

def test_h3_and_h4():
    created = ev(4720, TargetSid='S-1-5-21-1-2-3-1009', TargetUserName='invented-new', TargetDomainName='INVENTED-PC')
    admins = ev(4732, seconds=5, MemberSid='S-1-5-21-1-2-3-1009', MemberName='-', TargetSid='S-1-5-32-544',
                TargetUserName='Administrators')
    users = ev(4732, seconds=6, MemberSid='S-1-5-21-1-2-3-1009', MemberName='-', TargetSid='S-1-5-32-545',
               TargetUserName='Users')
    alerts = run([created, admins, users])
    assert ids(alerts) == ['H3', 'H4']
    assert alerts[0].techniques == ('T1136.001',) and alerts[1].techniques == ('T1098.007',)
    assert alerts[0].account_ref == alerts[1].account_ref  # same SID -> same reference


# --- H6 new service, H7 new scheduled task ---

def test_h6_and_h7_sources():
    records = [ev(7045, SYS, ServiceName='InventedSvc', ImagePath='C:\\Invented\\svc.exe'),
               ev(4697, seconds=1, ServiceName='InventedSvc2'),
               ev(4698, seconds=2, TaskName='\\InventedTask'),
               ev(106, TASKS, seconds=3, TaskName='\\InventedTask2'),
               ev(7045, SYS, seconds=4, provider='Invented-Other-Provider')]
    alerts = run(records)
    assert ids(alerts) == ['H6', 'H6', 'H7', 'H7']
    assert {a.techniques for a in alerts} == {('T1543.003',), ('T1053.005',)}


# --- H8 log cleared / auditing disabled ---

@pytest.mark.parametrize('record,technique', [
    (lambda: ev(1102, provider='Microsoft-Windows-Eventlog', SubjectUserName='invented-admin'), 'T1685.005'),
    (lambda: ev(104, SYS, provider='Microsoft-Windows-Eventlog', SubjectUserName='invented-admin'), 'T1685.005'),
    (lambda: ev(4719, AuditPolicyChanges='%%8448'), 'T1685.001'),
    (lambda: ev(4719, AuditPolicyChanges='%%8450'), 'T1685.001'),
    (lambda: ev(4719, AuditPolicyChanges='%%8448, %%8451'), 'T1685.001'),
    (lambda: ev(4719, AuditPolicyChanges='Failure removed'), 'T1685.001'),
])
def test_h8_positives(record, technique):
    alerts = run([record()])
    assert ids(alerts) == ['H8'] and alerts[0].techniques == (technique,)


@pytest.mark.parametrize('record', [
    lambda: ev(4719, AuditPolicyChanges='%%8449'),
    lambda: ev(4719, AuditPolicyChanges='%%8451'),
    lambda: ev(104, SYS, provider='Invented-Other-Provider'),
])
def test_h8_negatives(record):
    assert run([record()]) == []


# --- H9 RDP logon from outside ---

def test_h9_rdp_from_outside_only():
    def logon(ip, logon_type=10):
        return ev(4624, TargetUserSid='S-1-5-21-1-2-3-1001', TargetUserName='invented-user', LogonType=logon_type,
                  IpAddress=ip)
    alerts = run([logon('203.0.113.9')])
    assert ids(alerts) == ['H9'] and alerts[0].techniques == ('T1133', 'T1021.001')
    assert alerts[0].remote_ips == ('203.0.113.9',) and alerts[0].facts['logon_type'] == '10'
    assert run([logon('192.168.1.5'), logon('-'), logon('203.0.113.9', 3)]) == []
    assert ids(run([logon('192.168.1.5')], local_nets=())) == []
    rcm = run([ev(1149, RDP, Param1='invented-user', Param2='INVENTED-PC', Param3='198.51.100.20'),
               ev(1149, RDP, Param1='invented-user', Param2='INVENTED-PC', Param3='10.0.0.4')])
    assert ids(rcm) == ['H9']


def test_h9_local_net_option():
    from app.engines.host.pseudonyms import parse_local_nets
    record = ev(4624, TargetUserName='invented-user', LogonType=10, IpAddress='203.0.113.9')
    assert run([record], local_nets=parse_local_nets(['203.0.113.0/24'])) == []


# --- H10 Defender disabled ---

WINDEFEND_BINARY = 'WinDefend/1'.encode('utf-16-le').hex().upper() + '0000'


@pytest.mark.parametrize('record', [
    lambda: ev(5001, DEF),
    lambda: ev(5010, DEF),
    lambda: ev(5012, DEF),
    lambda: ev(7040, SYS, param1='Microsoft Defender Antivirus Service', param2='auto start', param3='disabled',
               param4='WinDefend'),
    lambda: ev(7036, SYS, param1='Microsoft Defender Antivirus Service', param2='stopped', Binary=WINDEFEND_BINARY),
    lambda: ev(13, SYSMON, TargetObject='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware',
               Details='DWORD (0x00000001)'),
    lambda: ev(13, SYSMON, TargetObject='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time '
               'Protection\\DisableRealtimeMonitoring', Details='DWORD (0x00000001)'),
])
def test_h10_positives(record):
    alerts = run([record()])
    assert ids(alerts) == ['H10'] and alerts[0].techniques == ('T1685',)


@pytest.mark.parametrize('record', [
    lambda: ev(5007, DEF),
    lambda: ev(7040, SYS, param3='auto start', param4='WinDefend'),
    lambda: ev(7040, SYS, param3='disabled', param4='InventedSvc'),
    lambda: ev(7036, SYS, param2='running', Binary=WINDEFEND_BINARY),
    lambda: ev(7036, SYS, param2='stopped', Binary='InventedSvc/1'.encode('utf-16-le').hex()),
    lambda: ev(13, SYSMON, TargetObject='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware',
               Details='DWORD (0x00000000)'),
])
def test_h10_negatives(record):
    assert run([record()]) == []


# --- H11 Office application starts a shell or script host ---

PARENTS = ['WINWORD.EXE', 'excel.exe', 'POWERPNT.EXE', 'OUTLOOK.EXE']
CHILDREN = {'powershell.exe': 'T1059.001', 'pwsh.exe': 'T1059.001', 'cmd.exe': 'T1059.003',
            'wscript.exe': 'T1059.005', 'mshta.exe': 'T1218.005'}


def process(image, parent, command_line='', sysmon=False, **extra):
    if sysmon:
        return ev(1, SYSMON, Image=image, ParentImage=parent, CommandLine=command_line, **extra)
    return ev(4688, NewProcessName=image, ParentProcessName=parent, CommandLine=command_line, **extra)


@pytest.mark.parametrize('parent', PARENTS)
@pytest.mark.parametrize('child', sorted(CHILDREN))
@pytest.mark.parametrize('sysmon', [False, True])
def test_h11_every_listed_parent_and_child(parent, child, sysmon):
    alerts = run([process(f'C:\\Windows\\System32\\{child.upper()}',
                          f'C:\\Program Files\\Microsoft Office\\root\\Office16\\{parent}', sysmon=sysmon)])
    assert ids(alerts) == ['H11']
    assert alerts[0].techniques == ('T1204.002', CHILDREN[child])
    assert alerts[0].facts == {'parent': parent.lower(), 'child': child}


@pytest.mark.parametrize('image,parent', [
    ('C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\explorer.exe'),
    ('C:\\Windows\\System32\\notepad.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'),
    ('C:\\Invented\\notcmd.exe', 'C:\\Office\\WINWORD.EXE'),
    ('C:\\Windows\\System32\\cmd.exe', 'C:\\Invented\\notwinword.exe'),
    ('C:\\Windows\\System32\\cmd.exe', ''),
])
def test_h11_negatives(image, parent):
    assert run([process(image, parent)]) == [] and run([process(image, parent, sysmon=True)]) == []


def test_h11_sysmon_hash_precedence_and_no_hash_from_4688():
    hashes = 'SHA1=' + 'A' * 40 + ',MD5=' + 'B' * 32 + ',SHA256=' + 'C' * 64
    alert = run([process('C:\\Windows\\System32\\cmd.exe', 'C:\\Office\\WINWORD.EXE', sysmon=True, Hashes=hashes)])[0]
    assert alert.hashes == (('sha256', 'c' * 64),)
    alert = run([process('C:\\Windows\\System32\\cmd.exe', 'C:\\Office\\WINWORD.EXE', Hashes=hashes)])[0]
    assert alert.hashes == ()


@pytest.mark.parametrize('value,expected', [
    ('SHA1=' + 'A' * 40 + ',MD5=' + 'B' * 32 + ',SHA256=' + 'C' * 64, ('sha256', 'c' * 64)),
    ('SHA1=' + 'A' * 40 + ',MD5=' + 'B' * 32, ('sha1', 'a' * 40)),
    ('MD5=' + 'B' * 32 + ',IMPHASH=' + 'D' * 32, ('md5', 'b' * 32)),
    ('IMPHASH=' + 'D' * 32, None), ('SHA256=xyz', None), ('', None), (None, None),
])
def test_best_hash_precedence(value, expected):
    assert best_hash(value) == expected


# --- H12 shadow copy deletion ---

@pytest.mark.parametrize('image,command_line', [
    ('C:\\Windows\\System32\\vssadmin.exe', 'vssadmin.exe Delete Shadows /All /Quiet'),
    ('C:\\Windows\\System32\\VSSADMIN.EXE', '"C:\\Windows\\system32\\vssadmin.exe"  delete   shadows /for=c:'),
    ('C:\\Windows\\System32\\wbem\\WMIC.exe', 'wmic shadowcopy delete'),
    ('C:\\Windows\\System32\\wbem\\wmic.exe', 'wmic.exe SHADOWCOPY where "ID=\'{x}\'" DELETE'),
    ('C:\\Windows\\System32\\wbadmin.exe', 'wbadmin delete catalog -quiet'),
    ('C:\\Windows\\System32\\wbadmin.exe', 'wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0'),
    ('C:\\Windows\\System32\\wbadmin.exe', 'wbadmin delete backup -keepVersions:0'),
])
@pytest.mark.parametrize('sysmon', [False, True])
def test_h12_each_tool_delete_form(image, command_line, sysmon):
    alerts = run([process(image, 'C:\\Windows\\System32\\cmd.exe', command_line, sysmon=sysmon)])
    assert ids(alerts) == ['H12'] and alerts[0].techniques == ('T1490',)
    assert alerts[0].facts == {'tool': image.rsplit('\\', 1)[1].lower()}


@pytest.mark.parametrize('image,command_line', [
    ('C:\\Windows\\System32\\vssadmin.exe', 'vssadmin list shadows'),
    ('C:\\Windows\\System32\\vssadmin.exe', ''),
    ('C:\\Windows\\System32\\wbem\\wmic.exe', 'wmic shadowcopy list brief'),
    ('C:\\Windows\\System32\\wbem\\wmic.exe', 'wmic process where name="x" delete'),
    ('C:\\Windows\\System32\\wbadmin.exe', 'wbadmin get versions'),
    ('C:\\Windows\\System32\\cmd.exe', 'cmd /c echo vssadmin delete shadows'),
])
def test_h12_negatives(image, command_line):
    assert run([process(image, 'C:\\Windows\\explorer.exe', command_line)]) == []


# --- H13 run-as with another account's credentials from an unusual account ---

def explicit(seconds, subject='invented-user', target='invented-admin', server='localhost', subject_sid=None,
             computer='INVENTED-PC', target_domain='INVENTED-PC'):
    return ev(4648, seconds=seconds, computer=computer, SubjectUserSid=subject_sid or 'S-1-5-21-1-2-3-1001',
              SubjectUserName=subject, SubjectDomainName='INVENTED-PC', TargetUserName=target,
              TargetDomainName=target_domain, TargetServerName=server, ProcessName='C:\\Windows\\System32\\runas.exe')


def span_end(hours):
    return ev(4625, seconds=hours * 3600, TargetUserName='invented-other', IpAddress='-')


def test_h13_short_import_has_no_baseline_and_alerts_every_qualifying_pair():
    alerts = [a for a in run([explicit(0), span_end(47)]) if a.detection == 'H13']
    assert len(alerts) == 1 and alerts[0].facts == {'baseline': 'none'}
    assert alerts[0].techniques == ('T1134.002', 'T1078')


@pytest.mark.parametrize('server', ['localhost', '127.0.0.1', '::1', 'INVENTED-PC', 'invented-pc.lan.example'])
def test_h13_local_targets(server):
    assert ids([a for a in run([explicit(0, server=server)]) if a.detection == 'H13']) == ['H13']


@pytest.mark.parametrize('kwargs', [
    {'target': 'invented-user'},  # same account
    {'target': 'INVENTED-USER'},  # same account, other case
    {'subject': 'INVENTED-PC$'},  # machine account
    {'subject_sid': 'S-1-5-18', 'subject': 'SYSTEM'},
    {'subject_sid': 'S-1-5-19', 'subject': 'LOCAL SERVICE'},
    {'subject_sid': 'S-1-5-20', 'subject': 'NETWORK SERVICE'},
    {'subject': '-'},
    {'server': 'invented-srv.example'},  # remote target, not run-as
])
def test_h13_negatives(kwargs):
    assert [a for a in run([explicit(0, **kwargs)]) if a.detection == 'H13'] == []


def test_h13_same_name_in_another_domain_is_another_account():
    alerts = run([explicit(0, target='invented-user', target_domain='INVENTED-OTHER')])
    assert ids(alerts) == ['H13']


def test_h13_baseline_is_first_24_hours_when_span_reaches_48_hours():
    records = [explicit(0), explicit(23.99 * 3600, target='invented-admin2'),
               explicit(30 * 3600),                       # pair seen in baseline -> usual
               explicit(31 * 3600, target='invented-admin2'),  # also in baseline
               explicit(24 * 3600, target='invented-new'),  # first seen at exactly 24 h -> after baseline
               span_end(48)]
    alerts = [a for a in run(records) if a.detection == 'H13']
    assert len(alerts) == 1 and alerts[0].facts == {'baseline': '24h'}
    # One second short of 48 h: no baseline, every qualifying event alerts.
    short = [r for r in records if r['EventID'] == 4648] + [span_end(48 - 1 / 3600)]
    assert len([a for a in run(short) if a.detection == 'H13']) == 5


# --- general ---

def test_alerts_carry_no_names_paths_command_lines_or_local_addresses():
    records = [
        *[failed(MARKER, i, ip='192.168.1.77', workstation=MARKER) for i in range(20)],
        ev(4720, TargetSid='S-1-5-21-9-9-9-1', TargetUserName=MARKER, computer=MARKER),
        process(f'C:\\{MARKER}\\cmd.exe', f'C:\\{MARKER}\\WINWORD.EXE', f'cmd /c {MARKER}'),
        process('C:\\Windows\\System32\\vssadmin.exe', 'C:\\x.exe', f'vssadmin delete shadows {MARKER}'),
        explicit(0, subject=MARKER, target=MARKER + '2'),
        ev(7045, SYS, ServiceName=MARKER, ImagePath=f'C:\\{MARKER}.exe'),
    ]
    alerts = run(records)
    assert set(ids(alerts)) >= {'H1', 'H3', 'H11', 'H12', 'H13', 'H6'}
    text = json.dumps([a.as_dict() for a in alerts])
    assert MARKER not in text and '192.168.1.77' not in text and 'INVENTED-PC' not in text


def test_record_ids_and_window_are_kept_for_the_user_to_find_events():
    alerts = run([failed(seconds=i) for i in range(20)])
    assert alerts[0].start == '2026-01-05T10:00:00.000000Z' and alerts[0].end == '2026-01-05T10:00:19.000000Z'
    assert all(isinstance(i, int) for i in alerts[0].record_ids)
    assert alerts[0].host_ref == PSEUDO.host_ref('INVENTED-PC')
