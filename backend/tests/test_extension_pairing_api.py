"""Step 3 tests: Local pairing, one-use secret exchange, revocation, Host/Origin/token scope and privacy.

Design: docs/design/browser-extension-v1.md (§2.2, §2.3, §2.4, §6, §7, §8, §9 step 3).
All URLs in this file are INVENTED on reserved RFC 2606 domains.
"""
from __future__ import annotations

import hashlib
import json
import socket

import pytest
from sqlalchemy import text as sql_text

from app.services.extension_config import (
    ALLOWED_BACKEND_HOST,
    CHECK_SCHEMA_VERSION,
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PAIRING_INVALID,
    ERROR_PAIRING_REQUIRED,
    ERROR_PROTOCOL_MISMATCH,
    ERROR_SERVICE_UNAVAILABLE,
    MAX_BODY_BYTES,
    PAIR_MAX_FAILED_ATTEMPTS,
    PAIR_SCHEMA_VERSION,
    PAIR_SECRET_TTL_SECONDS,
    RATE_LIMIT_PER_MINUTE,
    ExtensionInputError,
)
from app.services.extension_pairing import ExtensionPairingStore, pairing_store

APPROVED_ORIGIN = 'chrome-extension://' + ('a' * 32)
OTHER_EXTENSION_ORIGIN = 'chrome-extension://' + ('b' * 32)
INSTANCE_ID = 'ext_instance_invented_0001'
NONCE = 'req_nonce_invented_0001'
LOCAL_HEADERS = {
    'Host': ALLOWED_BACKEND_HOST,
    'Origin': APPROVED_ORIGIN,
}


def _db_snapshot(db) -> list[tuple[str, list[tuple]]]:
    snapshot = []
    for table in sorted(db.bind.dialect.get_table_names(db.connection())):
        rows = [tuple(row) for row in db.execute(sql_text(f'SELECT * FROM "{table}"'))]
        snapshot.append((table, rows))
    return snapshot


@pytest.fixture(autouse=True)
def reset_pairing_and_block_network(monkeypatch):
    pairing_store.reset_for_restart()

    def forbidden(*args, **kwargs):
        pytest.fail('extension pairing API test attempted outbound network socket access')

    for attr in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, attr, forbidden)
    yield
    pairing_store.reset_for_restart()


def _pair_client(client) -> tuple[str, str]:
    """Helper to issue a one-use pairing secret and exchange it for a bearer token."""
    approve = client.post(
        '/extension/v1/pairing-secret',
        headers={'Host': ALLOWED_BACKEND_HOST},
        json={'extension_origin': APPROVED_ORIGIN},
    )
    assert approve.status_code == 200
    assert approve.headers.get('cache-control') == 'no-store'
    secret = approve.json()['pairing_secret']

    pair = client.post(
        '/extension/v1/pair',
        headers=LOCAL_HEADERS,
        json={
            'schema_version': PAIR_SCHEMA_VERSION,
            'pairing_secret': secret,
            'extension_instance_id': INSTANCE_ID,
        },
    )
    assert pair.status_code == 200
    assert pair.headers.get('cache-control') == 'no-store'
    data = pair.json()
    return data['extension_token'], data['server_instance_id']


def test_full_pairing_one_use_secret_check_revocation_and_restart_lifecycle(client, db, caplog):
    before_db = _db_snapshot(db)
    caplog.clear()

    # 1. Check before pairing fails with 401 pairing_required.
    unpaired = client.post(
        '/extension/v1/check',
        headers=LOCAL_HEADERS,
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/invented', 'request_ref': NONCE},
    )
    assert unpaired.status_code == 401
    assert unpaired.json()['detail'] == ERROR_PAIRING_REQUIRED
    assert unpaired.headers.get('cache-control') == 'no-store'

    # 2. Issue one-use secret and pair.
    approve = client.post(
        '/extension/v1/pairing-secret',
        headers={'Host': ALLOWED_BACKEND_HOST},
        json={'extension_origin': APPROVED_ORIGIN},
    )
    secret = approve.json()['pairing_secret']
    pair = client.post(
        '/extension/v1/pair',
        headers=LOCAL_HEADERS,
        json={
            'schema_version': PAIR_SCHEMA_VERSION,
            'pairing_secret': secret,
            'extension_instance_id': INSTANCE_ID,
        },
    )
    assert pair.status_code == 200
    token = pair.json()['extension_token']
    server_id = pair.json()['server_instance_id']

    # 3. One-use secret cannot be reused.
    reuse = client.post(
        '/extension/v1/pair',
        headers=LOCAL_HEADERS,
        json={
            'schema_version': PAIR_SCHEMA_VERSION,
            'pairing_secret': secret,
            'extension_instance_id': INSTANCE_ID,
        },
    )
    assert reuse.status_code == 401
    assert reuse.json()['detail'] == ERROR_PAIRING_REQUIRED

    # 4. Authenticated check succeeds without persisting or logging anything.
    secret_url = 'https://private-marker.example.com/SecretPath?token=SecretQueryValue'
    check = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}'},
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': secret_url, 'request_ref': NONCE},
    )
    assert check.status_code == 200
    assert check.headers.get('cache-control') == 'no-store'
    body = check.json()
    assert body['schema_version'] == CHECK_SCHEMA_VERSION
    assert body['request_ref'] == NONCE
    assert body['server_instance_id'] == server_id
    assert body['verdict'] in ('LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE')

    # Verify zero URL, hash, or token storage in DB, status endpoint, or logs.
    assert _db_snapshot(db) == before_db
    status = client.get('/extension/v1/status', headers={'Host': ALLOWED_BACKEND_HOST}).json()
    assert status == {
        'paired': True,
        'revoked': False,
        'approved_origin': APPROVED_ORIGIN,
        'server_instance_id': server_id,
    }
    combined_surface = json.dumps(body) + json.dumps(status) + caplog.text
    for marker in ('private-marker.example.com', 'SecretPath', 'SecretQueryValue', secret_url, token, secret):
        assert marker not in combined_surface
        assert hashlib.sha256(marker.encode('utf-8')).hexdigest() not in combined_surface

    # 5. Revoke pairing: token immediately stops working.
    rev = client.post('/extension/v1/revoke', headers={'Host': ALLOWED_BACKEND_HOST})
    assert rev.status_code == 200
    assert rev.json()['status'] == 'revoked'

    after_revoke = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}'},
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/invented', 'request_ref': NONCE},
    )
    assert after_revoke.status_code == 401
    assert after_revoke.json()['detail'] == ERROR_PAIRING_INVALID

    # 6. Server restart rotates server_instance_id and retains zero history.
    pairing_store.reset_for_restart()
    restarted_status = client.get('/extension/v1/status', headers={'Host': ALLOWED_BACKEND_HOST}).json()
    assert restarted_status['paired'] is False
    assert restarted_status['revoked'] is False
    assert restarted_status['approved_origin'] is None
    assert restarted_status['server_instance_id'] != server_id


def test_exact_host_and_origin_enforcement_and_no_cors_wildcard_or_bypass(client):
    token, _ = _pair_client(client)

    # Wrong Host headers must be rejected with 403.
    for bad_host in ('localhost:8000', '127.0.0.1', '127.0.0.1:5173', 'evil.example.com:8000'):
        res = client.post(
            '/extension/v1/check',
            headers={'Host': bad_host, 'Origin': APPROVED_ORIGIN, 'Authorization': f'Bearer {token}'},
            json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/', 'request_ref': NONCE},
        )
        assert res.status_code == 403
        assert res.json()['detail'] == ERROR_PAIRING_INVALID

    # Missing Origin, null Origin, webpage Origin, or a different chrome-extension:// Origin must be rejected.
    for bad_origin in (None, 'null', 'http://127.0.0.1:5173', 'https://example.com', OTHER_EXTENSION_ORIGIN):
        headers = {'Host': ALLOWED_BACKEND_HOST, 'Authorization': f'Bearer {token}'}
        if bad_origin is not None:
            headers['Origin'] = bad_origin
        res = client.post(
            '/extension/v1/check',
            headers=headers,
            json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/', 'request_ref': NONCE},
        )
        assert res.status_code in (401, 403)
        assert res.json()['detail'] == ERROR_PAIRING_INVALID
        assert res.headers.get('access-control-allow-origin') is None


def test_token_scope_isolation_and_query_or_method_rejection(client, monkeypatch):
    from dataclasses import replace
    from app.core import security
    token, _ = _pair_client(client)

    # 1. X-API-Key is rejected on /extension/v1/check even alongside a valid extension token.
    res_api_key = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}', 'X-API-Key': 'general-secret-key'},
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/', 'request_ref': NONCE},
    )
    assert res_api_key.status_code == 401
    assert res_api_key.json()['detail'] == ERROR_PAIRING_INVALID

    # 2. Extension bearer token cannot authenticate general API routes when ETIS_API_KEY is configured.
    monkeypatch.setattr(security, 'settings', replace(security.settings, api_key='configured-general-api-key'))
    res_analyze = client.post(
        '/analyze',
        headers={'Authorization': f'Bearer {token}'},
        json={'url': 'https://example.com/'},
    )
    assert res_analyze.status_code == 401

    res_operator = client.post(
        '/extension/v1/revoke',
        headers={'Host': ALLOWED_BACKEND_HOST, 'Authorization': f'Bearer {token}'},
    )
    assert res_operator.status_code == 401

    # 3. Query parameters on /extension/v1/check or /pair are rejected with 400 input_invalid.
    res_query = client.post(
        '/extension/v1/check?url=https://example.com/',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}'},
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': 'https://example.com/', 'request_ref': NONCE},
    )
    assert res_query.status_code == 400
    assert res_query.json()['detail'] == ERROR_INPUT_INVALID

    # 4. GET on /extension/v1/check is not allowed (405).
    res_get = client.get('/extension/v1/check', headers=LOCAL_HEADERS)
    assert res_get.status_code == 405


def test_pairing_secret_ttl_failed_attempt_lockout_and_rate_limits():
    store = ExtensionPairingStore()
    issued = store.issue_pairing_secret(
        json.dumps({'extension_origin': APPROVED_ORIGIN}).encode('utf-8'),
        now=100.0,
    )
    secret = issued['pairing_secret']

    # 1. Wrong attempts increment failed_attempts and lock out at PAIR_MAX_FAILED_ATTEMPTS.
    wrong_body = json.dumps({
        'schema_version': PAIR_SCHEMA_VERSION,
        'pairing_secret': 'wrong_secret_value_0000000000',
        'extension_instance_id': INSTANCE_ID,
    }).encode('utf-8')
    for _ in range(PAIR_MAX_FAILED_ATTEMPTS):
        with pytest.raises(ExtensionInputError) as exc_info:
            store.exchange_pairing_secret(APPROVED_ORIGIN, wrong_body, now=101.0)
        assert exc_info.value.code == ERROR_PAIRING_INVALID

    # Even the right secret now fails because the pending secret was invalidated after max attempts.
    right_body = json.dumps({
        'schema_version': PAIR_SCHEMA_VERSION,
        'pairing_secret': secret,
        'extension_instance_id': INSTANCE_ID,
    }).encode('utf-8')
    with pytest.raises(ExtensionInputError) as exc_info:
        store.exchange_pairing_secret(APPROVED_ORIGIN, right_body, now=102.0)
    assert exc_info.value.code == ERROR_PAIRING_REQUIRED

    # 2. Expired secret fails with pairing_invalid.
    issued2 = store.issue_pairing_secret(
        json.dumps({'extension_origin': APPROVED_ORIGIN}).encode('utf-8'),
        now=200.0,
    )
    expired_body = json.dumps({
        'schema_version': PAIR_SCHEMA_VERSION,
        'pairing_secret': issued2['pairing_secret'],
        'extension_instance_id': INSTANCE_ID,
    }).encode('utf-8')
    with pytest.raises(ExtensionInputError) as exc_info:
        store.exchange_pairing_secret(
            APPROVED_ORIGIN,
            expired_body,
            now=200.0 + PAIR_SECRET_TTL_SECONDS + 1.0,
        )
    assert exc_info.value.code == ERROR_PAIRING_INVALID

    # 3. Rate and concurrency limits enforced on authorized_check.
    issued3 = store.issue_pairing_secret(
        json.dumps({'extension_origin': APPROVED_ORIGIN}).encode('utf-8'),
        now=1000.0,
    )
    pair_res = store.exchange_pairing_secret(
        APPROVED_ORIGIN,
        json.dumps({
            'schema_version': PAIR_SCHEMA_VERSION,
            'pairing_secret': issued3['pairing_secret'],
            'extension_instance_id': INSTANCE_ID,
        }).encode('utf-8'),
        now=1001.0,
    )
    auth_header = f'Bearer {pair_res.extension_token}'

    # Concurrency limit (MAX_CONCURRENT_CHECKS = 2).
    with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1002.0):
        with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1002.0):
            with pytest.raises(ExtensionInputError) as exc_info:
                with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1002.0):
                    pass
            assert exc_info.value.code == ERROR_LIMIT_EXCEEDED

    # Per-minute rate limit (RATE_LIMIT_PER_MINUTE = 30).
    for _ in range(RATE_LIMIT_PER_MINUTE - 2):
        with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1003.0):
            pass
    with pytest.raises(ExtensionInputError) as exc_info:
        with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1003.0):
            pass
    assert exc_info.value.code == ERROR_LIMIT_EXCEEDED

    # Next minute window resets the counter.
    with store.authorized_check(APPROVED_ORIGIN, auth_header, now=1065.0):
        pass


def test_check_endpoint_suppresses_errors_and_rejects_bad_inputs_without_echo(client, caplog):
    token, _ = _pair_client(client)
    caplog.clear()

    # Protocol mismatch
    res_proto = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}'},
        json={'schema_version': 'wrong-version', 'url': 'https://example.com/', 'request_ref': NONCE},
    )
    assert res_proto.status_code == 400
    assert res_proto.json() == {'error': ERROR_PROTOCOL_MISMATCH, 'detail': ERROR_PROTOCOL_MISMATCH}

    # Oversized body
    res_big = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        content=b'x' * (MAX_BODY_BYTES + 10),
    )
    assert res_big.status_code == 413
    assert res_big.json() == {'error': ERROR_LIMIT_EXCEEDED, 'detail': ERROR_LIMIT_EXCEEDED}

    # Forbidden data: URL with marker payload
    secret_payload = 'SecretEmbeddedPayloadMarker999'
    res_data = client.post(
        '/extension/v1/check',
        headers={**LOCAL_HEADERS, 'Authorization': f'Bearer {token}'},
        json={'schema_version': CHECK_SCHEMA_VERSION, 'url': f'data:text/html,{secret_payload}', 'request_ref': NONCE},
    )
    assert res_data.status_code == 400
    assert res_data.json() == {'error': ERROR_INPUT_INVALID, 'detail': ERROR_INPUT_INVALID}
    assert secret_payload not in res_data.text
    assert secret_payload not in caplog.text
    assert caplog.records == []


def test_pairing_accepts_32_letter_a_to_p_extension_id_and_rejects_other_ids(client):
    ext_id = 'a' * 32
    approve = client.post(
        '/extension/v1/pairing-secret',
        headers={'Host': ALLOWED_BACKEND_HOST},
        json={'extension_id': ext_id},
    )
    assert approve.status_code == 200
    assert approve.json()['extension_origin'] == f'chrome-extension://{ext_id}'

    for invalid_id in ('short', 'q' * 32, 'A' * 32, 'a' * 31 + '1', 'a' * 33):
        bad = client.post(
            '/extension/v1/pairing-secret',
            headers={'Host': ALLOWED_BACKEND_HOST},
            json={'extension_id': invalid_id},
        )
        assert bad.status_code == 401
        assert bad.json()['detail'] == ERROR_PAIRING_INVALID


def test_uvicorn_access_log_filter_drops_all_extension_v1_lines():
    import logging
    from app.routers.extension import install_extension_log_filter

    install_extension_log_filter()
    access_logger = logging.getLogger('uvicorn.access')

    captured: list[str] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record.getMessage())

    handler = _ListHandler()
    old_level = access_logger.level
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(handler)
    try:
        access_logger.info('%s - "%s %s HTTP/%s" %d', '127.0.0.1:51000', 'POST', '/extension/v1/check', '1.1', 200)
        access_logger.info('%s - "%s %s HTTP/%s" %d', '127.0.0.1:51000', 'POST', '/extension/v1/pair', '1.1', 200)
        access_logger.info('%s - "%s %s HTTP/%s" %d', '127.0.0.1:51000', 'POST', '/extension/v1/pairing-secret', '1.1', 200)
        access_logger.info('%s - "%s %s HTTP/%s" %d', '127.0.0.1:51000', 'GET', '/health/live', '1.1', 200)
    finally:
        access_logger.removeHandler(handler)
        access_logger.setLevel(old_level)

    assert len(captured) == 1
    assert '/health/live' in captured[0]
    assert all('/extension/v1' not in line for line in captured)
