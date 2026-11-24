"""Invented Windows events for host engine tests (design host-engine-v1 §8).

Every name, address and path is invented: accounts `invented-*`, computer `INVENTED-PC`,
addresses from RFC 5737 documentation ranges or a private LAN, domains under `.example`.
No real machine, log or dataset was used.
"""
from datetime import datetime, timedelta, timezone

from evtx_writer import build_evtx

T0 = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
SECURITY = 'Microsoft-Windows-Security-Auditing'


def event(event_id, channel='Security', provider=SECURITY, at=0.0, record_id=1, computer='INVENTED-PC', **data):
    """One invented event as the writer expects; `at` is seconds after T0."""
    return dict(event_id=event_id, channel=channel, provider=provider, time=T0 + timedelta(seconds=at),
                record_id=record_id, computer=computer, data={k: str(v) for k, v in data.items()})


def numbered(events):
    for index, item in enumerate(events, start=1):
        item['record_id'] = index
    return events


def write_evtx(path, events, per_chunk=100):
    path.write_bytes(build_evtx(numbered(events), per_chunk=per_chunk))
    return path


# One invented event per required/optional channel of design §1.1.
CHANNEL_SAMPLES = [
    event(4625, TargetUserName='invented-user', TargetDomainName='INVENTED-PC', LogonType=3,
          IpAddress='203.0.113.9', WorkstationName='INVENTED-WS'),
    event(7045, channel='System', provider='Service Control Manager', at=1, ServiceName='InventedSvc',
          ImagePath='C:\\Invented\\svc.exe', StartType='auto start', AccountName='LocalSystem'),
    event(4104, channel='Microsoft-Windows-PowerShell/Operational', provider='Microsoft-Windows-PowerShell', at=2,
          MessageNumber=1, MessageTotal=1, ScriptBlockText='Write-Output invented', ScriptBlockId='inv-1'),
    event(5001, channel='Microsoft-Windows-Windows Defender/Operational', provider='Microsoft-Windows-Windows Defender',
          at=3),
    event(106, channel='Microsoft-Windows-TaskScheduler/Operational', provider='Microsoft-Windows-TaskScheduler', at=4,
          TaskName='\\InventedTask', UserContext='INVENTED-PC\\invented-user'),
    event(1149, channel='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
          provider='Microsoft-Windows-TerminalServices-RemoteConnectionManager', at=5,
          Param1='invented-user', Param2='INVENTED-PC', Param3='203.0.113.9'),
    event(1, channel='Microsoft-Windows-Sysmon/Operational', provider='Microsoft-Windows-Sysmon', at=6,
          Image='C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
          ParentImage='C:\\Windows\\explorer.exe', CommandLine='"WINWORD.EXE" /n invented.docx',
          Hashes='SHA1=' + '1' * 40 + ',MD5=' + '2' * 32 + ',SHA256=' + '3' * 64, User='INVENTED-PC\\invented-user'),
    event(4688, at=7, NewProcessName='C:\\Windows\\System32\\cmd.exe',
          ParentProcessName='C:\\Windows\\explorer.exe', CommandLine='cmd.exe /c echo invented',
          SubjectUserName='invented-user'),
    event(4648, at=8, SubjectUserName='invented-user', SubjectDomainName='INVENTED-PC',
          TargetUserName='invented-admin', TargetDomainName='INVENTED-PC', TargetServerName='localhost',
          ProcessName='C:\\Windows\\System32\\runas.exe'),
]
