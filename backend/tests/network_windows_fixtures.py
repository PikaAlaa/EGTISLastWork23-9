"""Invented DNS Client, Sysmon and firewall records for network.windows tests (design §8.1).

Every value is invented: computer `INVENTED-PC`, account `invented-*`, domains under
`.example`, addresses from RFC 5737 documentation ranges or a private LAN. No real machine,
log, export or dataset was used. EVTX files are written with the test-only writer.
"""
from host_fixtures import T0, event, write_evtx  # noqa: F401  (re-exported)

DNS_CHANNEL = 'Microsoft-Windows-DNS-Client/Operational'
DNS_PROVIDER = 'Microsoft-Windows-DNS-Client'
SYSMON_CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
SYSMON_PROVIDER = 'Microsoft-Windows-Sysmon'
FIREWALL_HEADER = (
    '#Version: 1.5\n'
    '#Software: Microsoft Windows Firewall\n'
    '#Time Format: Local\n'
    '#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin '
    'icmptype icmpcode info path pid\n'
    '\n'
)


def dns(event_id, at=0.0, computer='INVENTED-PC', **data):
    return event(event_id, channel=DNS_CHANNEL, provider=DNS_PROVIDER, at=at, computer=computer, **data)


def sysmon(event_id, at=0.0, computer='INVENTED-PC', **data):
    return event(event_id, channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER, at=at, computer=computer, **data)


def query_started(name, at=0.0, qtype=1, **extra):
    return dns(3006, at=at, QueryName=name, QueryType=qtype, QueryOptions=0, ServerList='', IsNetworkQuery=0,
               NetworkQueryIndex=0, InterfaceIndex=0, IsAsyncQuery=0, **extra)


def query_completed(name, at=0.0, qtype=1, status=0, results='', **extra):
    return dns(3008, at=at, QueryName=name, QueryType=qtype, QueryOptions=0, QueryStatus=status,
               QueryResults=results, **extra)


def query_response(name, at=0.0, qtype=1, status=0, results='', pid=None, **extra):
    data = dict(QueryName=name, QueryType=qtype, NetworkIndex=0, InterfaceIndex=7, Status=status,
                QueryResults=results, **extra)
    if pid is not None:
        data['ClientPID'] = pid
    return dns(3020, at=at, **data)


def connection(at=0.0, initiated='true', protocol='tcp', src='192.168.1.20', sport=50000, dst='203.0.113.10',
               dport=443, image='C:\\Users\\invented-user\\AppData\\Local\\Invented\\invented-agent.exe',
               user='INVENTED-PC\\invented-user', hostname='c2.invented.example', **extra):
    return sysmon(3, at=at, RuleName='-', UtcTime='2026-01-05 10:00:00.000', ProcessGuid='{inv-guid-1}',
                  ProcessId=4242, Image=image, User=user, Protocol=protocol, Initiated=initiated,
                  SourceIsIpv6='false', SourceIp=src, SourceHostname='-', SourcePort=sport, SourcePortName='-',
                  DestinationIsIpv6='false', DestinationIp=dst, DestinationHostname=hostname,
                  DestinationPort=dport, DestinationPortName='-', **extra)


def sysmon_query(name, at=0.0, status=0, results='', image='C:\\Users\\invented-user\\invented-agent.exe', **extra):
    return sysmon(22, at=at, RuleName='-', UtcTime='2026-01-05 10:00:00.000', ProcessGuid='{inv-guid-1}',
                  ProcessId=4242, QueryName=name, QueryStatus=status, QueryResults=results, Image=image, **extra)


def process_create(guid='{inv-guid-1}', sha256='a' * 64, at=0.0, **extra):
    return sysmon(1, at=at, ProcessGuid=guid, ProcessId=4242,
                  Image='C:\\Users\\invented-user\\invented-agent.exe',
                  Hashes=f'SHA1={"b" * 40},MD5={"c" * 32},SHA256={sha256.upper()},IMPHASH={"d" * 32}', **extra)


def firewall_line(date='2026-01-05', time='10:00:00', action='ALLOW', protocol='TCP', src='192.168.1.20',
                  dst='203.0.113.10', sport='50000', dport='443', path='SEND', pid='4242'):
    return f'{date} {time} {action} {protocol} {src} {dst} {sport} {dport} 0 - - - - - - - {path} {pid}\n'


def write_firewall(path, lines, header=FIREWALL_HEADER, encoding='utf-8'):
    path.write_text(header + ''.join(lines), encoding=encoding, newline='')
    return path
