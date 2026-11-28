"""Invented agent wire payloads for the LAN agent server tests (design windows-agent-lan-v1 §5).

Everything here is invented: endpoint refs are fixed hex strings, hashes are made up, addresses are never
present (indicators are hash-only), and no real hostname, username or path appears. The server key used with
these fixtures is the invented test key set in conftest.py.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

INVENTED_DEVICE = 'hmac:' + '1a' * 16      # invented endpoint device ref
INVENTED_OTHER_DEVICE = 'hmac:' + '2b' * 16
INVENTED_ACCOUNT = 'hmac:' + '3c' * 16
INVENTED_PATH_REF = 'hmac:' + '4d' * 16
INVENTED_HASH = 'e' * 64                    # invented sha256 of a file
INVENTED_IP_HASH = 'f' * 64                 # invented sha256 of a remote IP
T0 = '2026-11-27T10:00:00+00:00'


def _base(engine: str, domain: str, kind: str, details: dict, indicators=None, **extra) -> dict:
    return {
        'id': str(uuid.uuid4()), 'schema_version': 'finding-v1',
        'engine': {'name': engine, 'version': f'{engine}-invented-v1'}, 'domain': domain, 'kind': kind,
        'severity': extra.pop('severity', 'high'), 'confidence': 'single_signal',
        'indicators': indicators if indicators is not None else [],
        'attack': extra.pop('attack', []),
        'evidence': {'reasons': extra.pop('reasons', ['invented_reason']), 'details': details},
        'observed_at': extra.pop('observed_at', T0), 'created_at': T0,
        'source': {'kind': 'import', 'ref': 'agent-local:invented'}, **extra}


def network_finding(device=INVENTED_DEVICE, **extra) -> dict:
    details = {
        'detection': 'N1', 'reason_codes': ['blocklist_ip_connection'], 'events': 3,
        'window': {'first': '2026-11-27T10:00:00.000000Z', 'last': '2026-11-27T10:05:00.000000Z'},
        'values': {'lists': ['feodo_tracker']}, 'combined_with': [], 'device_ref': device,
        'rule_validation': 'unvalidated_on_samples', 'coverage': {'N1': 'visible', 'N8': 'not_visible'},
        'baseline': 'none', 'input_files_sha256': ['a' * 64], 'process_category': 'unknown', 'attack_basis': [],
        'lists': [{'list': 'feodo_tracker', 'title': 'abuse.ch Feodo Tracker IP blocklist',
                   'version': '2026-11-27T12:37:23Z+sha256:7c72fe807208', 'licence': 'CC0 (abuse.ch terms of use §3.4)',
                   'link': 'https://feodotracker.abuse.ch/blocklist/'}],
    }
    details.update(extra.pop('details', {}))
    indicators = extra.pop('indicators', [{'type': 'ip', 'value_hash': INVENTED_IP_HASH, 'value': None,
                                           'role': 'remote_endpoint'}])
    return _base('network.windows', 'network', 'known_bad_destination', details, indicators, **extra)


def malware_finding(device=INVENTED_DEVICE, **extra) -> dict:
    details = {
        'layers': {
            'hash_lists': {'status': 'loaded', 'known_software_match': False,
                           'lists': [{'name': 'invented_list', 'role': 'malicious', 'version': '2026-11-01',
                                      'match': True, 'algorithm': 'sha256'}]},
            'yara': {'status': 'ok', 'dropped_matches': 0, 'rules': [{
                'rule': 'INVENTED_Rule_1', 'source': 'signature-base', 'author': 'Invented Author',
                'licence': 'Detection Rule License 1.1', 'licence_class': 'drl', 'pinned_commit': 'd' * 40,
                'rule_file': 'yara/invented_rules.yar',
                'link': 'https://github.com/Neo23x0/signature-base/blob/' + 'd' * 40 + '/yara/invented_rules.yar#L1',
                'attack_tags': [], 'packer': None}]},
            'model': {'status': 'ok', 'model_id': 'invented-model', 'threshold': 0.9, 'score': 0.95,
                      'above_threshold': True},
        },
        'layers_fired': ['hash_list', 'yara', 'model'], 'model_counts': True, 'known_software_conflict': False,
        'pe_type': 'pe64', 'size_band': '1-10mb', 'extension': '.exe', 'location_class': 'user_downloads',
        'path_ref': INVENTED_PATH_REF, 'path_count': 1, 'signature_present': False, 'signature_verified': False,
        'attack_basis': [], 'device_ref': device,
    }
    details.update(extra.pop('details', {}))
    indicators = extra.pop('indicators', [{'type': 'hash', 'value_hash': INVENTED_HASH, 'value': None,
                                           'role': 'scanned_file', 'hash_algo': 'sha256'}])
    return _base('malware.files', 'malware', 'malicious_file', details, indicators, **extra)


def host_finding(device=INVENTED_DEVICE, **extra) -> dict:
    details = {
        'detection': 'H11', 'level': 'high', 'event_counts': {'Microsoft-Windows-Sysmon/Operational:1': 1},
        'window': {'start': '2026-11-27T10:00:00Z', 'end': '2026-11-27T10:00:00Z'},
        'host_ref': device, 'account_ref': INVENTED_ACCOUNT, 'parent': 'winword.exe', 'child': 'powershell.exe',
        'coverage': {'sysmon1': 'visible'}, 'input_files_sha256': ['b' * 64], 'record_ids': [101, 102],
        'rule_validation': 'unvalidated_on_samples', 'attack_basis': ['office_child_shell'],
    }
    details.update(extra.pop('details', {}))
    indicators = extra.pop('indicators', [{'type': 'hash', 'value_hash': INVENTED_HASH, 'value': None,
                                           'role': 'executed_file', 'hash_algo': 'sha256'}])
    return _base('host.windows', 'host', 'office_spawned_shell', details, indicators, **extra)


def coverage() -> dict:
    return {'engines': {'host.windows': {'sources': {'security': {'status': 'unreadable_or_absent', 'records': 0},
                                                     'sysmon': {'status': 'read', 'records': 40, 'hours': 2.0}},
                                         'detections': {'H1': 'not_visible', 'H11': 'visible'},
                                         'health': ['available']}},
            'queue_status': {'queued_batches': 0, 'queue_overflow_findings_dropped': 0}}


def batch(findings, batch_id=None, **extra) -> dict:
    return {'schema_version': 'agent-batch-v1', 'batch_id': batch_id or str(uuid.uuid4()),
            'sent_at': datetime.now(timezone.utc).isoformat(), 'agent_version': 'agent-v1.0.0',
            'engine_versions': {'network.windows': 'netwin-v1+rules:invented'}, 'coverage': coverage(),
            'findings': list(findings), **extra}


def body(payload) -> bytes:
    return json.dumps(payload).encode('utf-8')
