"""Invented Zeek log fixtures for network engine tests.

Addresses come from documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and a private LAN; names use the reserved `.example` domain. No real
capture, dataset or network was used.
"""
import json

CONN_FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration',
               'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
               'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents']
CONN_TYPES = ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'string', 'interval', 'count', 'count',
              'string', 'bool', 'bool', 'count', 'string', 'count', 'count', 'count', 'count', 'set[string]']

# ts, uid, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state,
# local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes
CONN_ROWS = [
    ['1700000000.000000', 'CInvent01', '192.168.1.10', '51000', '198.51.100.20', '443', 'tcp', 'ssl',
     '1.250000', '517', '4211', 'SF', 'T', 'F', '0', 'ShADadFf', '9', '889', '8', '4543'],
    ['1700000001.500000', 'CInvent02', '192.168.1.10', '51001', '198.51.100.21', '53', 'udp', 'dns',
     '0.020000', '40', '120', 'SF', 'T', 'F', '0', 'Dd', '1', '68', '1', '148'],
    ['1700000002.000000', 'CInvent03', '203.0.113.5', '40000', '192.168.1.10', '22', 'tcp', '-',
     '-', '-', '-', 'S0', 'F', 'T', '0', 'S', '1', '44', '0', '0'],
    ['1700000002.000000', 'CInvent04', '203.0.113.5', '40001', '192.168.1.10', '23', 'tcp', '-',
     '-', '-', '-', 'REJ', 'F', 'T', '0', 'Sr', '1', '44', '1', '40'],
]

DNS_FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'query', 'qtype_name',
              'answers']
DNS_ROWS = [
    ['1700000001.400000', 'CInvent02', '192.168.1.10', '51001', '198.51.100.21', '53', 'udp', 'lure.example', 'A',
     '198.51.100.20'],
    ['1700000001.450000', 'CInvent05', '192.168.1.10', '51002', '198.51.100.21', '53', 'udp', 'Shop.Example.',
     'A', '198.51.100.30,198.51.100.31'],
    ['1700000001.460000', 'CInvent06', '192.168.1.10', '51003', '198.51.100.21', '53', 'udp', 'nothing.example',
     'A', '-'],
]


def tsv(path, fields, rows, types=None, closed=True):
    lines = ['#separator \\x09', '#set_separator\t,', '#empty_field\t(empty)', '#unset_field\t-',
             f'#path\t{path}', '#open\t2026-11-18-10-00-00', '#fields\t' + '\t'.join(fields)]
    if types:
        lines.append('#types\t' + '\t'.join(types))
    for row in rows:
        padded = list(row) + ['-'] * (len(fields) - len(row))
        lines.append('\t'.join(padded))
    if closed:
        lines.append('#close\t2026-11-18-10-05-00')
    return '\n'.join(lines) + '\n'


def conn_tsv(rows=None):
    return tsv('conn', CONN_FIELDS, CONN_ROWS if rows is None else rows, CONN_TYPES)


def dns_tsv(rows=None):
    return tsv('dns', DNS_FIELDS, DNS_ROWS if rows is None else rows)


def conn_json(rows=None):
    out = []
    for row in (CONN_ROWS if rows is None else rows):
        item = {}
        for name, value in zip(CONN_FIELDS, row):
            if value == '-':
                continue  # Zeek's JSON writer omits unset fields
            if name in ('ts', 'duration'):
                item[name] = float(value)
            elif name in ('id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts',
                          'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'):
                item[name] = int(value)
            elif name in ('local_orig', 'local_resp'):
                item[name] = value == 'T'
            else:
                item[name] = value
        out.append(json.dumps(item))
    return '\n'.join(out) + '\n'
