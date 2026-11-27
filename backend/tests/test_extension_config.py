"""Step 1 tests: Manifest V3 permissions/CSP, transport boundaries and frozen parameters.

Design: docs/design/browser-extension-v1.md (§1, §2.1–2.3, §4, §9 step 1).
All URLs in this file are INVENTED on reserved RFC 2606 domains (example.com).
"""
from __future__ import annotations

import json
from pathlib import Path
import socket

import pytest

from app.services.extension_config import (
    ALLOWED_BACKEND_HOST,
    ALLOWED_BACKEND_ORIGIN,
    ALLOWED_MANIFEST_HOST_PERMISSIONS,
    ALLOWED_MANIFEST_PERMISSIONS,
    ALLOWED_REASON_CODES,
    CHECK_PATH,
    CHECK_SCHEMA_VERSION,
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PAIRING_INVALID,
    EXPECTED_POLICY_VERSION,
    EXPECTED_URL_MODEL_CANDIDATE,
    EXPECTED_URL_MODEL_THRESHOLD,
    EXTENSION_TOKEN_BYTES,
    FORBIDDEN_MANIFEST_KEYS,
    FORBIDDEN_MANIFEST_PERMISSIONS,
    MAX_BODY_BYTES,
    MAX_CHECK_URL_LENGTH,
    PAIR_MAX_FAILED_ATTEMPTS,
    PAIR_PATH,
    PAIR_SCHEMA_VERSION,
    PAIR_SECRET_BYTES,
    PAIR_SECRET_TTL_SECONDS,
    ExtensionInputError,
    current_url_model_candidate,
    validate_extension_origin,
    validate_extension_url,
    validate_host_header,
    validate_identifier,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / 'browser-extension' / 'manifest.json'


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('extension config test attempted network access')

    for attr in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, attr, forbidden)


def test_manifest_v3_minimal_permissions_and_csp():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding='utf-8'))
    assert manifest['manifest_version'] == 3
    assert manifest['incognito'] == 'not_allowed'
    permissions = set(manifest['permissions'])
    assert permissions == set(ALLOWED_MANIFEST_PERMISSIONS)
    assert not (permissions & FORBIDDEN_MANIFEST_PERMISSIONS)
    host_permissions = tuple(manifest['host_permissions'])
    assert host_permissions == ALLOWED_MANIFEST_HOST_PERMISSIONS
    assert not (set(host_permissions) & FORBIDDEN_MANIFEST_PERMISSIONS)
    assert not (set(manifest) & FORBIDDEN_MANIFEST_KEYS)

    csp = manifest['content_security_policy']['extension_pages']
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert 'unsafe-eval' not in csp
    assert 'unsafe-inline' not in csp
    assert 'http://' not in csp and 'https://' not in csp


def test_frozen_parameters_and_unchanged_policy_identifiers():
    assert PAIR_SCHEMA_VERSION == 'extension-pair-v1'
    assert CHECK_SCHEMA_VERSION == 'extension-check-v1'
    assert ALLOWED_BACKEND_HOST == '127.0.0.1:8000'
    assert ALLOWED_BACKEND_ORIGIN == 'http://127.0.0.1:8000'
    assert PAIR_PATH == '/extension/v1/pair'
    assert CHECK_PATH == '/extension/v1/check'
    assert MAX_BODY_BYTES == 4096
    assert MAX_CHECK_URL_LENGTH == 2048
    assert PAIR_SECRET_BYTES == 32
    assert PAIR_SECRET_TTL_SECONDS == 300
    assert PAIR_MAX_FAILED_ATTEMPTS == 5
    assert EXTENSION_TOKEN_BYTES == 32
    assert EXPECTED_POLICY_VERSION == 'decision-v2'
    assert current_url_model_candidate() == EXPECTED_URL_MODEL_CANDIDATE
    assert EXPECTED_URL_MODEL_THRESHOLD == 0.9870690448552604
    assert 'blacklist_exact' in ALLOWED_REASON_CODES
    assert 'no_warning_signs' in ALLOWED_REASON_CODES


@pytest.mark.parametrize('valid_url', [
    'https://example.com/invented-check',
    'http://example.com/path?query=invented&lang=ar',
    'https://sub.example.com:8443/a/b?c=1',
])
def test_validate_extension_url_accepts_clean_http_https_urls(valid_url):
    assert validate_extension_url(valid_url) == valid_url


@pytest.mark.parametrize('bad_url,expected_code', [
    ('', ERROR_INPUT_INVALID),
    ('   ', ERROR_INPUT_INVALID),
    (' https://example.com/invented', ERROR_INPUT_INVALID),
    ('https://example.com/invented#fragment', ERROR_INPUT_INVALID),
    ('https://example.com/invented#', ERROR_INPUT_INVALID),
    ('https://user:pass@example.com/invented', ERROR_INPUT_INVALID),
    ('https://user@example.com/invented', ERROR_INPUT_INVALID),
    ('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', ERROR_INPUT_INVALID),
    ('blob:https://example.com/550e8400-e29b-41d4-a716-446655440000', ERROR_INPUT_INVALID),
    ('file:///C:/Users/Private/secret.txt', ERROR_INPUT_INVALID),
    ('javascript:alert(1)', ERROR_INPUT_INVALID),
    ('chrome://extensions/', ERROR_INPUT_INVALID),
    ('edge://settings/', ERROR_INPUT_INVALID),
    ('about:blank', ERROR_INPUT_INVALID),
    ('ftp://example.com/file', ERROR_INPUT_INVALID),
    ('example.com/bare-without-scheme', ERROR_INPUT_INVALID),
    ('https://example.com/bad\nheader', ERROR_INPUT_INVALID),
    ('https://example.com/' + ('a' * 2040), ERROR_LIMIT_EXCEEDED),
])
def test_validate_extension_url_rejects_unsupported_schemes_credentials_fragments_and_limits(bad_url, expected_code):
    with pytest.raises(ExtensionInputError) as exc_info:
        validate_extension_url(bad_url)
    assert exc_info.value.code == expected_code
    if bad_url:
        assert bad_url not in str(exc_info.value)


def test_validate_host_origin_and_identifiers():
    assert validate_host_header('127.0.0.1:8000') == '127.0.0.1:8000'
    for bad_host in (None, '', '127.0.0.1', 'localhost:8000', '127.0.0.1:5173', '[::1]:8000', 'example.com:8000'):
        with pytest.raises(ExtensionInputError) as exc_info:
            validate_host_header(bad_host)
        assert exc_info.value.code == ERROR_PAIRING_INVALID

    valid_origin = 'chrome-extension://' + ('a' * 32)
    assert validate_extension_origin(valid_origin) == valid_origin
    for bad_origin in (
        None,
        '',
        'null',
        'http://127.0.0.1:5173',
        'https://example.com',
        'chrome-extension://short',
        'chrome-extension://' + ('q' * 32),  # 'q' is outside Chromium [a-p] alphabet
        'chrome-extension://' + ('A' * 32),  # uppercase rejected
        valid_origin + '/',
    ):
        with pytest.raises(ExtensionInputError) as exc_info:
            validate_extension_origin(bad_origin)
        assert exc_info.value.code == ERROR_PAIRING_INVALID

    assert validate_identifier('invented_nonce_0001') == 'invented_nonce_0001'
    for bad_id in (None, '', 'short', 'x' * 65, 'bad space in id!!', 'https://example.com'):
        with pytest.raises(ExtensionInputError) as exc_info:
            validate_identifier(bad_id)
        assert exc_info.value.code == ERROR_INPUT_INVALID
