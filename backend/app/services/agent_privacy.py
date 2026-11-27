"""Server-side privacy gate for agent batches (design windows-agent-lan-v1 §5.2 gates 3-5, §10 step 2).

Runs before anything is stored. A batch is accepted only if every Finding:

- comes from an agent engine with its own domain (`host.windows`, `malware.files`, `network.windows`);
- carries its device on the wire only as an endpoint `hmac:<32 hex>` (`device_ref` or `host_ref`); any `srv:`
  string on the wire is refused (`ref_prefix_invalid`), differing `device_ref`/`host_ref` are refused
  (`device_ref_conflict`);
- binds to the authenticated device: `wrap_ref(incoming, "device")` (core v2, reused, not reimplemented) must
  equal the stored `srv:` `devices.device_ref`, compared with `hmac.compare_digest` (`device_ref_mismatch`);
- has hash-only indicators (`indicator.value is None`, else `plaintext_indicator_forbidden`);
- has `evidence.details` made only of the non-content keys of host-engine-v1 §6.5, malware-engine-v1 §6.6 and
  network-windows-v1 §6.5 (plus `device_ref`), each value in its fixed format (`disallowed_evidence_field`).

Every error is a fixed reason code; no value, ref or key is ever placed in an error or a log.
"""
from __future__ import annotations

import hmac
import math
import re
from typing import Callable

from app.core.device_names import ENDPOINT_REF, WELL_KNOWN_ACCOUNT_REFS, wrap_ref
from app.services.agent_schemas import ENGINE_DOMAINS, AgentRequestError

Check = Callable[[object], bool]

TOKEN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,199}$')
CODE = re.compile(r'^[a-z0-9][a-z0-9_.:-]{0,99}$')
ISO = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
HEX40 = re.compile(r'^[0-9a-f]{40}$')
# Attribution text from pinned rule packs and lists: no control characters, no backslash, no '@', no angle
# brackets, and never starting like a path. Never used for any value that comes from the PC.
TEXT = re.compile(r'^(?![/~.])[^\x00-\x1f\\@<>]{1,200}$')
IMAGE_NAME = re.compile(r'^[a-z0-9][a-z0-9_.-]{0,63}\.(exe|com|bat|cmd|ps1|vbs|js|hta|scr|msc|cpl|wsf)$')
CHANNEL_KEY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _./:-]{0,99}$')
SIGMA_PATH = re.compile(r'^rules[a-z_-]*/(?!.*\.\.)[A-Za-z0-9_./-]{1,200}\.yml$')
YARA_PATH = re.compile(r'^yara/(?!.*\.\.)[A-Za-z0-9_.-]{1,200}\.(yar|yara)$')
DETECTION_HOST = re.compile(r'^(H(1[0-3]|[1-9])|sigma)$')
DETECTION_NETWORK = re.compile(r'^N[1-9]$')
SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')


# ---------------------------------------------------------------- value checks

def regex(pattern: re.Pattern) -> Check:
    return lambda v: isinstance(v, str) and bool(pattern.match(v))


def enum(*values) -> Check:
    return lambda v: isinstance(v, str) and v in values


def integer(low: int = 0, high: int = 10**12) -> Check:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high


def number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def boolean(v) -> bool:
    return isinstance(v, bool)


def optional(check: Check) -> Check:
    return lambda v: v is None or check(v)


def either(*checks: Check) -> Check:
    return lambda v: any(c(v) for c in checks)


def list_of(check: Check, max_len: int = 100) -> Check:
    return lambda v: isinstance(v, list) and len(v) <= max_len and all(check(x) for x in v)


def dict_of(key: Check, value: Check, max_len: int = 200) -> Check:
    return lambda v: isinstance(v, dict) and len(v) <= max_len and all(key(k) and value(x) for k, x in v.items())


def struct(spec: dict[str, Check]) -> Check:
    """A dict whose keys all belong to `spec` and whose values pass their checks."""
    return lambda v: isinstance(v, dict) and all(k in spec and spec[k](x) for k, x in v.items())


def https_prefix(*prefixes: str) -> Check:
    return lambda v: (isinstance(v, str) and len(v) <= 400 and v.startswith(prefixes)
                      and not any(c in v for c in ' \\@<>"\'') and '..' not in v)


token, code, iso, sha256 = regex(TOKEN), regex(CODE), regex(ISO), regex(SHA256)
text = regex(TEXT)
scalar = either(number, boolean, lambda v: v is None, token)
endpoint_ref = regex(ENDPOINT_REF)


def account_ref(v) -> bool:
    return isinstance(v, str) and (v in WELL_KNOWN_ACCOUNT_REFS or bool(ENDPOINT_REF.match(v)))


COMMON = {'device_ref': endpoint_ref, 'attack_basis': list_of(code, 50),
          'input_files_sha256': list_of(sha256, 100), 'rule_validation': enum('samples', 'unvalidated_on_samples')}

HOST_DETAILS = {
    **COMMON,
    'detection': regex(DETECTION_HOST),
    'level': enum(*SEVERITIES),
    'sigma': struct({'id': token, 'title': text, 'author': optional(text), 'level': enum(*SEVERITIES),
                     'path': regex(SIGMA_PATH), 'release': token, 'licence': optional(text),
                     'link': https_prefix('https://github.com/SigmaHQ/sigma/blob/')}),
    'event_counts': dict_of(regex(CHANNEL_KEY), integer(), 100),
    'window': struct({'start': iso, 'end': iso}),
    'host_ref': endpoint_ref,
    'account_ref': account_ref,
    'logon_type': integer(0, 20),
    'source_locality': enum('local', 'outside', 'unknown'),
    'parent': regex(IMAGE_NAME), 'child': regex(IMAGE_NAME), 'tool': regex(IMAGE_NAME),
    'baseline': enum('24h', 'none'),
    'coverage': dict_of(token, either(scalar, list_of(token, 100)), 200),
    'record_ids': list_of(integer(0, 2**63), 20),
}

MALWARE_DETAILS = {
    **COMMON,
    'layers': struct({
        'hash_lists': struct({'status': token, 'known_software_match': boolean, 'lists': list_of(struct({
            'name': token, 'role': token, 'version': token, 'match': boolean,
            'algorithm': optional(enum('sha256', 'sha1', 'md5'))}), 20)}),
        'yara': struct({'status': token, 'dropped_matches': integer(), 'rules': list_of(struct({
            'rule': regex(re.compile(r'^[A-Za-z0-9_]{1,128}$')), 'source': token, 'author': optional(text),
            'licence': optional(text), 'licence_class': optional(token), 'pinned_commit': regex(HEX40),
            'rule_file': regex(YARA_PATH), 'link': https_prefix('https://github.com/Neo23x0/signature-base/blob/'),
            'attack_tags': list_of(token, 20), 'packer': either(boolean, lambda v: v is None, token)}), 50)}),
        'model': dict_of(token, scalar, 20),
    }),
    'layers_fired': list_of(enum('hash_list', 'yara', 'model'), 3),
    'model_counts': boolean,
    'known_software_conflict': boolean,
    'pe_type': token,
    'size_band': token,
    'extension': regex(re.compile(r'^(\.[a-z0-9]{1,7})?$')),
    'location_class': token,
    'path_ref': endpoint_ref,
    'path_count': integer(0, 1_000_000),
    'signature_present': boolean,
    'signature_verified': boolean,
}

NETWORK_DETAILS = {
    **COMMON,
    'detection': regex(DETECTION_NETWORK),
    'reason_codes': list_of(code, 20),
    'events': integer(),
    'window': struct({'first': iso, 'last': iso}),
    'values': dict_of(token, either(scalar, list_of(scalar, 50)), 50),
    'combined_with': list_of(regex(DETECTION_NETWORK), 9),
    'coverage': dict_of(regex(DETECTION_NETWORK), token, 9),
    'baseline': enum('24h', 'none'),
    'process_category': enum('known_process_hash', 'unknown'),
    'lists': list_of(struct({'list': enum('feodo_tracker'), 'title': text, 'version': token, 'licence': text,
                             'link': https_prefix('https://feodotracker.abuse.ch/')}), 5),
}

ALLOWLISTS = {'host.windows': HOST_DETAILS, 'malware.files': MALWARE_DETAILS, 'network.windows': NETWORK_DETAILS}
DEVICE_FIELDS = ('device_ref', 'host_ref')


# ---------------------------------------------------------------- gate

def _reject(status: int, code: str):
    raise AgentRequestError(status, code)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def finding_device_ref(finding) -> str:
    """The one endpoint device ref of a Finding, after the prefix, conflict and format checks."""
    details = finding.evidence.details
    present = [details[f] for f in DEVICE_FIELDS if details.get(f) is not None]
    if any(isinstance(v, str) and v.startswith('srv:') for v in present):
        _reject(422, 'ref_prefix_invalid')
    if len(set(map(str, present))) > 1:
        _reject(422, 'device_ref_conflict')
    if not present:
        _reject(422, 'device_ref_mismatch')
    if not endpoint_ref(present[0]):
        _reject(422, 'disallowed_evidence_field')
    return present[0]


def check_finding(finding) -> str:
    """Wire checks for one Finding; returns its endpoint device ref. Order: prefix, conflict, allowlist,
    indicators. The device binding is checked by `check_batch`."""
    engine = finding.engine.name
    if ENGINE_DOMAINS.get(engine) != finding.domain:
        _reject(400, 'invalid_input')
    if finding.incident_id is not None:
        _reject(400, 'invalid_input')
    details = finding.evidence.details
    if any(s.startswith('srv:') for s in _strings(details)):
        _reject(422, 'ref_prefix_invalid')
    device = finding_device_ref(finding)
    allowed = ALLOWLISTS[engine]
    for key, value in details.items():
        check = allowed.get(key)
        if check is None or not check(value):
            _reject(422, 'disallowed_evidence_field')
    if any(ref.value is not None for ref in finding.indicators):
        _reject(422, 'plaintext_indicator_forbidden')
    return device


def check_batch(findings, stored_device_ref: str, server_key: bytes) -> None:
    """Gate 3-5 for a whole batch; raises AgentRequestError on the first failure, storing nothing.

    `server_key` is the loaded ETIS_SERVER_REF_KEY (the caller fails closed with 503 when it is absent)."""
    devices = [check_finding(f) for f in findings]
    for device in devices:
        wrapped = wrap_ref(device, 'device', server_key)
        if not hmac.compare_digest(wrapped.encode('ascii'), stored_device_ref.encode('ascii')):
            _reject(422, 'device_ref_mismatch')
