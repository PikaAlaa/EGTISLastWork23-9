"""De-fanged display of indicator values, rules `defang-v1` (design core-v2 §4.2).

Display only. Storage, hashing, lookups, correlation, STIX patterns and STIX ids keep the
canonical value; this module is used where a person reads a value (the STIX bundle's
human-readable note, and the same table drives the console). Pure string functions:
nothing here resolves, fetches or contacts a value.

The cases in `docs/design/defang-cases.json` are the contract for both this module and
the console implementation.
"""
from __future__ import annotations

import ipaddress
import re

import idna

RULES_VERSION = 'defang-v1'
_SCHEMES = {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp'}
_REFANG_SCHEMES = {v: k for k, v in _SCHEMES.items()}
_SCHEME = re.compile(r'^([A-Za-z][A-Za-z0-9+.-]*)://')
_DEFANGED_SCHEME = re.compile(r'^(hxxps?|fxp)://', re.I)
_UNCHANGED_TYPES = frozenset({'hash', 'phone'})


def refang(value: str) -> str:
    """Undo every `defang-v1` mark: hxxp/hxxps/fxp schemes, `[.]`, `[@]` and `[:]`.

    A superset of the `extract_links` rule in `url_utils.py` (which handles only `hxxp` and
    `[.]`), so de-fanged e-mail addresses and IPv6 addresses refang too.
    """
    if not isinstance(value, str):
        raise ValueError('invalid_value')
    text = _DEFANGED_SCHEME.sub(lambda m: _REFANG_SCHEMES[m.group(1).lower()] + '://', value.strip())
    return text.replace('[.]', '.').replace('[@]', '@').replace('[:]', ':')


def _ascii_host(host: str) -> str:
    """IDN hosts are shown in IDNA ASCII (`xn--…`), never as Unicode."""
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode('ascii')
    except (idna.IDNAError, UnicodeError):
        # Not encodable: show code points escaped rather than lookalike characters.
        return host.encode('ascii', 'backslashreplace').decode('ascii')


def _ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version == 4:
        head, _, last = value.rpartition('.')
        return f'{head}[.]{last}'
    return value.replace(':', '[:]')


def _host(host: str) -> str:
    if host.startswith('[') and host.endswith(']'):
        return '[' + host[1:-1].replace(':', '[:]') + ']'
    return _ascii_host(host).replace('.', '[.]')


def _url(value: str) -> str:
    match = _SCHEME.match(value)
    if match:
        scheme = match.group(1).lower()
        rest = value[match.end():]
        prefix = _SCHEMES.get(scheme, scheme) + '://'
    else:
        prefix, rest = '', value
    cut = min((i for i in (rest.find('/'), rest.find('?'), rest.find('#')) if i >= 0), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    userinfo, at, hostport = authority.rpartition('@')
    if hostport.startswith('['):
        end = hostport.find(']')
        host, port = (hostport[:end + 1], hostport[end + 1:]) if end >= 0 else (hostport, '')
    else:
        host, sep, port = hostport.partition(':')
        port = sep + port
    shown_userinfo = (userinfo.replace('@', '[@]').replace('.', '[.]') + '[@]') if at else ''
    return prefix + shown_userinfo + _host(host) + port + tail


def _email(value: str) -> str:
    local, at, domain = value.rpartition('@')
    if not at:
        return _ascii_host(value).replace('.', '[.]')
    return f'{local}[@]{_ascii_host(domain).replace(".", "[.]")}'


def defang(kind: str, value: str) -> str:
    """De-fanged display form of a canonical (or already de-fanged) value.

    Idempotent: the value is refanged first, so an already de-fanged value comes back the
    same. Hashes, phone numbers and unknown types are returned unchanged.
    """
    if not isinstance(value, str):
        raise ValueError('invalid_value')
    if kind in _UNCHANGED_TYPES:
        return value
    plain = refang(value)
    if kind == 'url':
        return _url(plain)
    if kind == 'domain':
        return _ascii_host(plain).replace('.', '[.]')
    if kind == 'ip':
        shown = _ip(plain.strip('[]'))
        return shown if shown is not None else plain.replace('.', '[.]').replace(':', '[:]')
    if kind == 'email':
        return _email(plain)
    return value
