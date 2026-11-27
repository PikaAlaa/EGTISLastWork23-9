"""Frozen protocol, resource and pairing parameters for the local browser extension v1.

Design: docs/design/browser-extension-v1.md (§1, §2.1–2.4, §4, §10).
All Chrome/Edge Manifest V3 runtime behaviors (match-pattern port granularity,
activeTab lifetime on navigation, incognito enforcement, extension Origin header
presence on loopback fetch, and chrome.storage.local isolation) remain marked
"to verify" against official Chrome/Edge documentation before browser packaging.

This module defines pure validators and frozen constants only; it performs no
database writes, network calls or logging.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.core.exceptions import InvalidScanInputError
from app.core.url_utils import MAX_URL_LENGTH, parse_url
from app.engines.phishing_findings import REASON_CODES as PHISHING_REASON_CODES, url_candidate_id
from app.engines.risk_scoring import POLICY_VERSION

# Protocol schema versions (§2.2).
PAIR_SCHEMA_VERSION = 'extension-pair-v1'
CHECK_SCHEMA_VERSION = 'extension-check-v1'

# Fixed local loopback endpoint (§0, §2.2). No DNS hostname, no fallback port.
ALLOWED_BACKEND_HOST = '127.0.0.1:8000'
ALLOWED_BACKEND_ORIGIN = f'http://{ALLOWED_BACKEND_HOST}'
PAIR_PATH = '/extension/v1/pair'
CHECK_PATH = '/extension/v1/check'

# Chromium unpacked/packed extension ID and Origin format: 32 base16 characters in [a-p]
# (owner decision §9 #2; runtime behavior across Chrome/Edge marked to verify, §10).
EXTENSION_ID_RE = re.compile(r'^[a-p]{32}$')
EXTENSION_ORIGIN_RE = re.compile(r'^chrome-extension://[a-p]{32}$')
IDENTIFIER_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')

# Frozen pre-implementation resource and security budgets (§2.2, §2.3, §4).
MAX_BODY_BYTES = 4096
MAX_CHECK_URL_LENGTH = MAX_URL_LENGTH  # 2048
REQUEST_TIMEOUT_MS = 5000
MAX_CONCURRENT_CHECKS = 2
RATE_LIMIT_PER_MINUTE = 30

# Frozen pairing secret and token parameters (§2.3).
PAIR_SECRET_BYTES = 32
PAIR_SECRET_TTL_SECONDS = 300
PAIR_MAX_FAILED_ATTEMPTS = 5
EXTENSION_TOKEN_BYTES = 32

# Unchanged frozen URL policy and model identifiers (§0, §4).
EXPECTED_POLICY_VERSION = POLICY_VERSION  # 'decision-v2'
EXPECTED_URL_MODEL_CANDIDATE = 'ee0ba9f0077c1fd140aa'
EXPECTED_URL_MODEL_THRESHOLD = 0.9870690448552604

# Fixed error codes (§2.2).
ERROR_PAIRING_REQUIRED = 'pairing_required'
ERROR_PAIRING_INVALID = 'pairing_invalid'
ERROR_INPUT_INVALID = 'input_invalid'
ERROR_LIMIT_EXCEEDED = 'limit_exceeded'
ERROR_SERVICE_UNAVAILABLE = 'service_unavailable'
ERROR_PROTOCOL_MISMATCH = 'protocol_mismatch'

ERROR_CODES = frozenset({
    ERROR_PAIRING_REQUIRED,
    ERROR_PAIRING_INVALID,
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_SERVICE_UNAVAILABLE,
    ERROR_PROTOCOL_MISMATCH,
})

VERDICTS = ('LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE')

# Allowlisted reason and unavailable-component codes that may cross the extension boundary (§2.2).
UNAVAILABLE_COMPONENT_CODES = frozenset({
    'database_unavailable',
    'blacklist_empty',
    'blacklist_missing_source',
    'blacklist_stale',
    'url_model_unavailable',
    'links_truncated',
    'invalid_url',
})

ALLOWED_REASON_CODES = frozenset(
    PHISHING_REASON_CODES
    | UNAVAILABLE_COMPONENT_CODES
    | {'no_warning_signs'}
)

# Schemes that must be refused immediately without decoding payloads (§1, §8).
FORBIDDEN_SCHEME_PREFIXES = (
    'data:',
    'blob:',
    'file:',
    'javascript:',
    'vbscript:',
    'about:',
    'chrome:',
    'chrome-extension:',
    'edge:',
    'devtools:',
    'view-source:',
    'ftp:',
    'ws:',
    'wss:',
)

# Manifest V3 permissions policy (§2.1).
ALLOWED_MANIFEST_PERMISSIONS = frozenset({'activeTab', 'scripting', 'storage'})
ALLOWED_MANIFEST_HOST_PERMISSIONS = ('http://127.0.0.1/*',)
FORBIDDEN_MANIFEST_PERMISSIONS = frozenset({
    'history',
    'tabs',
    'webRequest',
    'webRequestBlocking',
    'declarativeNetRequest',
    'webNavigation',
    'cookies',
    'notifications',
    'clipboardRead',
    'clipboardWrite',
    'downloads',
    'nativeMessaging',
    'debugger',
    'proxy',
    'browsingData',
    '<all_urls>',
    'http://*/*',
    'https://*/*',
    '*://*/*',
})
FORBIDDEN_MANIFEST_KEYS = frozenset({
    'content_scripts',
    'externally_connectable',
    'web_accessible_resources',
    'oauth2',
    'chrome_url_overrides',
})


class ExtensionInputError(ValueError):
    """Raised with a fixed error code; never carries submitted URL or body text."""

    def __init__(self, code: str = ERROR_INPUT_INVALID):
        if code not in ERROR_CODES:
            code = ERROR_INPUT_INVALID
        super().__init__(code)
        self.code = code


def validate_host_header(host: str | None) -> str:
    """Require literal 127.0.0.1:8000 Host header (§2.2, §2.3)."""
    if not isinstance(host, str) or host != ALLOWED_BACKEND_HOST:
        raise ExtensionInputError(ERROR_PAIRING_INVALID)
    return host


def validate_extension_id(extension_id: str | None) -> str:
    """Validate an unpacked/packed extension ID pasted from chrome://extensions: exactly 32 letters a-p (§9 #2)."""
    if not isinstance(extension_id, str) or not EXTENSION_ID_RE.fullmatch(extension_id):
        raise ExtensionInputError(ERROR_PAIRING_INVALID)
    return extension_id


def validate_extension_origin(origin: str | None) -> str:
    """Validate exact Chromium extension Origin syntax before comparing with approved origin (§2.3)."""
    if not isinstance(origin, str) or not EXTENSION_ORIGIN_RE.fullmatch(origin):
        raise ExtensionInputError(ERROR_PAIRING_INVALID)
    return origin


def normalize_approved_extension_origin(ext_id_or_origin: str | None) -> str:
    """Accept either a bare 32-char [a-p] extension ID or chrome-extension://<32 a-p> and return the canonical Origin."""
    if not isinstance(ext_id_or_origin, str):
        raise ExtensionInputError(ERROR_PAIRING_INVALID)
    if EXTENSION_ID_RE.fullmatch(ext_id_or_origin):
        return f'chrome-extension://{ext_id_or_origin}'
    return validate_extension_origin(ext_id_or_origin)


def validate_identifier(value: str | None) -> str:
    """Validate request_ref nonce or extension_instance_id format (§2.2)."""
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    return value


def validate_extension_url(raw_url: str | None) -> str:
    """Validate a top-level HTTP(S) URL for a stateless check (§1).

    Refuses non-HTTP(S) schemes (including data/blob/file/chrome/edge) without
    decoding payloads, refuses embedded credentials (userinfo), refuses URLs
    that still carry a `#` fragment (fragments must be stripped locally by the
    extension before transmission, §1), and enforces MAX_CHECK_URL_LENGTH.
    Returns the validated URL string with its path and query preserved.
    """
    if not isinstance(raw_url, str):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    if len(raw_url) > MAX_CHECK_URL_LENGTH:
        raise ExtensionInputError(ERROR_LIMIT_EXCEEDED)
    if not raw_url or raw_url != raw_url.strip() or any(ch in raw_url for ch in ('\r', '\n', '\t', '\x00')):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    lowered = raw_url.lower()
    if lowered.startswith(FORBIDDEN_SCHEME_PREFIXES):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    if not (lowered.startswith('http://') or lowered.startswith('https://')):
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    if '#' in raw_url:
        # §1: fragments must be removed locally before sending to loopback.
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    try:
        split = urlsplit(raw_url)
    except ValueError:
        raise ExtensionInputError(ERROR_INPUT_INVALID) from None
    if split.scheme not in ('http', 'https') or not split.netloc:
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    if split.username is not None or split.password is not None or '@' in split.netloc:
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    try:
        parsed = parse_url(raw_url)
    except InvalidScanInputError:
        raise ExtensionInputError(ERROR_INPUT_INVALID) from None
    if parsed.userinfo:
        raise ExtensionInputError(ERROR_INPUT_INVALID)
    return raw_url


def current_url_model_candidate() -> str:
    return url_candidate_id()
