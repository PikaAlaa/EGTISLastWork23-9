"""Indicator normalization and hashing (design core-v1 §2.2).

Pure functions over supplied strings. Nothing here resolves, fetches or contacts
an indicator. `value_hash` is SHA-256 of the normalized value; for URLs this is
exactly the existing `blacklist_entries.url_hash` formula, so feed and scan
indicators join without re-hashing the feed. Unkeyed SHA-256 of low-entropy
values (domains, phone numbers) is pseudonymization, not anonymization.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

import idna

from app.core.url_utils import parse_url, registered_domain

INDICATOR_TYPES = ('domain', 'url', 'ip', 'hash', 'phone', 'email')
HASH_LENGTHS = {'md5': 32, 'sha1': 40, 'sha256': 64}
_HEX = re.compile(r'^[0-9a-f]+$')
_PHONE_SEPARATORS = re.compile(r'[\s.()\-]')


@dataclass(frozen=True)
class NormalizedIndicator:
    type: str
    value: str
    value_hash: str
    registered_domain: str | None = None
    registered_domain_hash: str | None = None
    hash_algo: str | None = None
    short_code: bool = False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _with_domain(kind: str, value: str, host: str) -> NormalizedIndicator:
    try:
        ipaddress.ip_address(host)
        parent = None
    except ValueError:
        parent = registered_domain(host)
    return NormalizedIndicator(kind, value, sha256_hex(value), parent,
                               sha256_hex(parent) if parent else None)


def normalize_domain(value: str) -> NormalizedIndicator:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('invalid_domain')
    host = value.strip().rstrip('.')
    try:
        ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        pass
    else:
        raise ValueError('domain_is_ip')
    try:
        host = idna.encode(host, uts46=True).decode('ascii').lower()
    except (idna.IDNAError, UnicodeError):
        raise ValueError('invalid_domain') from None
    if '.' not in host or len(host) > 253:
        raise ValueError('invalid_domain')
    return _with_domain('domain', host, host)


def normalize_url(value: str) -> NormalizedIndicator:
    try:
        parsed = parse_url(value)
    except Exception:
        raise ValueError('invalid_url') from None
    return _with_domain('url', parsed.canonical, parsed.host)


def normalize_ip(value: str) -> NormalizedIndicator:
    try:
        address = ipaddress.ip_address(value.strip().strip('[]'))
    except (ValueError, AttributeError):
        raise ValueError('invalid_ip') from None
    compressed = address.compressed
    return NormalizedIndicator('ip', compressed, sha256_hex(compressed))


def normalize_hash(value: str, hash_algo: str) -> NormalizedIndicator:
    if hash_algo not in HASH_LENGTHS:
        raise ValueError('invalid_hash_algo')
    digest = value.strip().lower() if isinstance(value, str) else ''
    if len(digest) != HASH_LENGTHS[hash_algo] or not _HEX.match(digest):
        raise ValueError('invalid_hash')
    return NormalizedIndicator('hash', digest, sha256_hex(digest), hash_algo=hash_algo)


def normalize_phone(value: str) -> NormalizedIndicator:
    """E.164 for Egyptian national numbers; 3-6 digit short codes kept as digits."""
    if not isinstance(value, str):
        raise ValueError('invalid_phone')
    raw = _PHONE_SEPARATORS.sub('', value.strip())
    if raw.startswith('00'):
        raw = '+' + raw[2:]
    if raw.startswith('+'):
        digits = raw[1:]
        if not digits.isdigit() or not 8 <= len(digits) <= 15:
            raise ValueError('invalid_phone')
        normalized = '+' + digits
    elif not raw.isdigit():
        raise ValueError('invalid_phone')
    elif 3 <= len(raw) <= 6:
        return NormalizedIndicator('phone', raw, sha256_hex(raw), short_code=True)
    elif raw.startswith('0') and 9 <= len(raw) <= 11:
        normalized = '+20' + raw[1:]
    elif raw.startswith('201') and len(raw) == 12:
        normalized = '+' + raw
    else:
        raise ValueError('invalid_phone')
    return NormalizedIndicator('phone', normalized, sha256_hex(normalized))


def normalize_email(value: str) -> NormalizedIndicator:
    if not isinstance(value, str) or value.count('@') != 1:
        raise ValueError('invalid_email')
    local, domain = value.strip().rsplit('@', 1)
    if not local or re.search(r'\s', local):
        raise ValueError('invalid_email')
    try:
        domain = idna.encode(domain.rstrip('.'), uts46=True).decode('ascii').lower()
    except (idna.IDNAError, UnicodeError):
        raise ValueError('invalid_email') from None
    if '.' not in domain:
        raise ValueError('invalid_email')
    address = local.lower() + '@' + domain
    return NormalizedIndicator('email', address, sha256_hex(address))


def normalize(kind: str, value: str, hash_algo: str | None = None) -> NormalizedIndicator:
    if kind == 'hash':
        return normalize_hash(value, hash_algo or '')
    if hash_algo is not None:
        raise ValueError('hash_algo_only_for_hash')
    handlers = {'domain': normalize_domain, 'url': normalize_url, 'ip': normalize_ip,
                'phone': normalize_phone, 'email': normalize_email}
    if kind not in handlers:
        raise ValueError('invalid_indicator_type')
    return handlers[kind](value)
