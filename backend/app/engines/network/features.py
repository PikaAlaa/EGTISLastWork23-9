"""Network flow features `net-features-v1` (design network-engine-v1 §1.4).

This is the ONLY implementation of network features. The training pipeline and the
runtime engine must both import it, so the model sees identical features in training and
in use. Vocabularies are fixed here, so the column layout never depends on the data.

Excluded by design (frozen): IP addresses and subnets, source and destination port
numbers, uid, timestamps, local_orig/local_resp, tunnel/VLAN fields. Addresses and ports
are used only *inside* the causal window aggregates, as identities and distinct counts,
never as values. Timestamps only order rows and bound windows.
"""
from __future__ import annotations

import math
from collections import Counter, deque
from typing import Sequence

import numpy as np

from app.engines.network.parsers import ConnRecord

FEATURE_VERSION = 'net-features-v1'
WINDOW_SECONDS = 60.0
PROTOCOLS = ('tcp', 'udp', 'icmp')
SERVICES = ('dns', 'http', 'ssl', 'ssh', 'ftp', 'ftp-data', 'smtp', 'dhcp', 'ntp', 'irc', 'radius', 'snmp', 'smb',
            'krb', 'rdp', 'sip', 'mysql', 'dce_rpc', 'pop3', 'imap', 'socks', 'syslog')
CONN_STATES = ('S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH')
FAILED_STATES = frozenset({'S0', 'REJ', 'RSTO', 'RSTOS0'})
HISTORY_LETTERS = 'shadfrcgtwiq'
COUNTS = ('orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes')
WINDOW_FEATURES = ('win_orig_conns', 'win_orig_distinct_resp_hosts', 'win_orig_distinct_resp_ports',
                   'win_orig_failed_share', 'win_resp_conns', 'win_resp_distinct_origs')
# Raw conn.log fields that must never become model columns (§1.4).
EXCLUDED_FIELDS = frozenset({'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'orig_h', 'orig_p',
                             'resp_h', 'resp_p', 'local_orig', 'local_resp', 'tunnel_parents', 'vlan',
                             'inner_vlan'})


def _names() -> tuple[str, ...]:
    names = ['log1p_duration', 'duration_missing', 'bytes_missing']
    names += [f'log1p_{name}' for name in COUNTS]
    names += ['orig_bytes_per_pkt', 'resp_bytes_per_pkt', 'log1p_resp_orig_byte_ratio', 'log1p_pkts_per_sec']
    names += [f'proto_{p}' for p in PROTOCOLS] + ['proto_other']
    names += [f'service_{s}' for s in SERVICES] + ['service_other', 'service_none']
    names += [f'state_{s}' for s in CONN_STATES] + ['state_other', 'state_missing']
    names += [f'history_orig_{c}' for c in HISTORY_LETTERS] + [f'history_resp_{c}' for c in HISTORY_LETTERS]
    names += ['history_flipped']
    names += list(WINDOW_FEATURES)
    return tuple(names)


FEATURE_NAMES = _names()
_INDEX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def _per_connection(record: ConnRecord, row: np.ndarray) -> None:
    def put(name, value):
        row[_INDEX[name]] = value

    duration = record.duration
    put('log1p_duration', math.log1p(duration) if duration is not None else 0.0)
    put('duration_missing', 1.0 if duration is None else 0.0)
    put('bytes_missing', 1.0 if record.orig_bytes is None or record.resp_bytes is None else 0.0)
    counts = {name: getattr(record, name) or 0 for name in COUNTS}
    for name, value in counts.items():
        put(f'log1p_{name}', math.log1p(value))
    put('orig_bytes_per_pkt', counts['orig_ip_bytes'] / counts['orig_pkts'] if counts['orig_pkts'] else 0.0)
    put('resp_bytes_per_pkt', counts['resp_ip_bytes'] / counts['resp_pkts'] if counts['resp_pkts'] else 0.0)
    put('log1p_resp_orig_byte_ratio', math.log1p(counts['resp_bytes'] / (counts['orig_bytes'] + 1)))
    packets = counts['orig_pkts'] + counts['resp_pkts']
    put('log1p_pkts_per_sec', math.log1p(packets / duration) if duration else 0.0)
    put(f'proto_{record.proto}' if record.proto in PROTOCOLS else 'proto_other', 1.0)
    services = [s for s in (record.service or '').split(',') if s and s != '-']
    if not services:
        put('service_none', 1.0)
    for service in services:
        put(f'service_{service}' if service in SERVICES else 'service_other', 1.0)
    state = record.conn_state
    put('state_missing' if not state else f'state_{state}' if state in CONN_STATES else 'state_other', 1.0)
    for char in record.history or '':
        lower = char.lower()
        if char == '^':
            row[_INDEX['history_flipped']] += 1
        elif lower in HISTORY_LETTERS:
            row[_INDEX[f"history_{'orig' if char.isupper() else 'resp'}_{lower}"]] += 1


class _Window:
    """Causal 60 s window: aggregates for a row use only rows ordered before it."""

    def __init__(self):
        self.events = deque()
        self.orig_count, self.orig_failed = Counter(), Counter()
        self.orig_hosts: dict[str, Counter] = {}
        self.orig_ports: dict[str, Counter] = {}
        self.resp_count = Counter()
        self.resp_origs: dict[str, Counter] = {}

    def _change(self, event, step):
        _, orig, resp, port, failed = event
        self.orig_count[orig] += step
        self.orig_failed[orig] += step * failed
        for table, key, value in ((self.orig_hosts, orig, resp), (self.orig_ports, orig, port),
                                  (self.resp_origs, resp, orig)):
            counter = table.setdefault(key, Counter())
            counter[value] += step
            if counter[value] <= 0:
                del counter[value]
        self.resp_count[resp] += step

    def evict_before(self, cutoff):
        while self.events and self.events[0][0] < cutoff:
            self._change(self.events.popleft(), -1)

    def add(self, event):
        self.events.append(event)
        self._change(event, +1)

    def aggregates(self, orig, resp):
        conns = self.orig_count[orig]
        return (conns, len(self.orig_hosts.get(orig, ())), len(self.orig_ports.get(orig, ())),
                self.orig_failed[orig] / conns if conns else 0.0, self.resp_count[resp],
                len(self.resp_origs.get(resp, ())))


def feature_matrix(records: Sequence[ConnRecord]) -> np.ndarray:
    """Rows align with `records` (input order). Call once per import or per split segment:
    windows never cross a call, which is how import and split boundaries are enforced."""
    matrix = np.zeros((len(records), len(FEATURE_NAMES)), dtype=np.float64)
    window = _Window()
    first_window_column = _INDEX[WINDOW_FEATURES[0]]
    for index in sorted(range(len(records)), key=lambda i: (records[i].ts, i)):
        record = records[index]
        row = matrix[index]
        _per_connection(record, row)
        window.evict_before(record.ts - WINDOW_SECONDS)
        row[first_window_column:first_window_column + len(WINDOW_FEATURES)] = window.aggregates(
            record.orig_h, record.resp_h)
        window.add((record.ts, record.orig_h, record.resp_h, record.resp_p,
                    1 if record.conn_state in FAILED_STATES else 0))
    return matrix
