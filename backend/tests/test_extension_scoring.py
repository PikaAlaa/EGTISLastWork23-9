"""Step 2 tests: Stateless URL scoring adapter, verdict parity and zero-persistence gate.

Design: docs/design/browser-extension-v1.md (§2, §2.2, §4, §6, §7, §9 step 2).
All URLs in this file are INVENTED on reserved RFC 2606 domains.
"""
from __future__ import annotations

import hashlib
import json
import socket

import pytest
from sqlalchemy import text as sql_text

from app.core.url_utils import parse_url
from app.engines import risk_scoring
from app.services.extension_config import (
    CHECK_SCHEMA_VERSION,
    ERROR_INPUT_INVALID,
    ERROR_LIMIT_EXCEEDED,
    ERROR_PROTOCOL_MISMATCH,
    ERROR_SERVICE_UNAVAILABLE,
    EXPECTED_POLICY_VERSION,
    EXPECTED_URL_MODEL_CANDIDATE,
    MAX_BODY_BYTES,
    ExtensionInputError,
)
from app.services.extension_scoring import (
    ExtensionCheckRequest,
    evaluate_extension_url,
    parse_check_request,
)

SERVER_ID = 'srv_instance_invented_0001'
NONCE = 'req_nonce_invented_0001'


def _db_snapshot(db) -> list[tuple[str, list[tuple]]]:
    snapshot = []
    for table in sorted(db.bind.dialect.get_table_names(db.connection())):
        rows = [tuple(row) for row in db.execute(sql_text(f'SELECT * FROM "{table}"'))]
        snapshot.append((table, rows))
    return snapshot


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('stateless extension scoring attempted network access')

    for attr in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, attr, forbidden)


@pytest.mark.parametrize('invented_url', [
    'https://example.com/invented-clean',
    'https://example.com:8443/invented-nonstandard-port?check=1',
    'https://known-phish.example/login',
    'https://docs.google.com/document/d/phish',
])
def test_stateless_adapter_matches_pure_decision_v2_verdict_and_persists_nothing(db, caplog, invented_url):
    before_db = _db_snapshot(db)
    caplog.clear()

    pure = risk_scoring.calculate_final_risk_score(text=None, url=invented_url, db=db)
    raw = json.dumps({
        'schema_version': CHECK_SCHEMA_VERSION,
        'url': invented_url,
        'request_ref': NONCE,
    }).encode('utf-8')
    req = parse_check_request(raw)
    res = evaluate_extension_url(db, req, server_instance_id=SERVER_ID)

    assert res.schema_version == CHECK_SCHEMA_VERSION
    assert res.request_ref == NONCE
    assert res.server_instance_id == SERVER_ID
    assert res.verdict == pure['verdict']
    assert res.decisive_reason == pure['decisive_reason']
    assert res.supporting_signals == pure['supporting_signals']
    assert res.policy_version == EXPECTED_POLICY_VERSION
    assert res.url_model_version == EXPECTED_URL_MODEL_CANDIDATE
    assert _db_snapshot(db) == before_db
    assert caplog.records == []


def test_privacy_no_url_host_query_or_hash_in_response_db_or_logs(db, caplog):
    marker_host = 'secret-host-marker.example.com'
    marker_path = 'PrivatePathMarker99'
    marker_query = 'SecretQueryToken88'
    invented_url = f'https://{marker_host}/{marker_path}?q={marker_query}'
    canonical_url = parse_url(invented_url).canonical

    before_db = _db_snapshot(db)
    caplog.clear()

    req = parse_check_request(json.dumps({
        'schema_version': CHECK_SCHEMA_VERSION,
        'url': invented_url,
        'request_ref': NONCE,
    }).encode('utf-8'))
    res = evaluate_extension_url(db, req, server_instance_id=SERVER_ID)

    after_db = _db_snapshot(db)
    assert after_db == before_db
    assert caplog.text == ''

    payload_text = res.model_dump_json()
    forbidden = (
        invented_url,
        canonical_url,
        marker_host,
        marker_path,
        marker_query,
    )
    for token in forbidden:
        for variant in (token, token.lower(), token.upper()):
            digest = hashlib.sha256(variant.encode('utf-8')).hexdigest()
            assert variant not in payload_text
            assert digest not in payload_text


def test_component_degradation_and_all_components_unavailable(db, monkeypatch):
    # 1. URL model unavailable alone: blacklist still runs, flag is reported in unavailable_components.
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _u: None)
    req = ExtensionCheckRequest(
        schema_version=CHECK_SCHEMA_VERSION,
        url='https://example.com/invented-check',
        request_ref=NONCE,
    )
    res = evaluate_extension_url(db, req, server_instance_id=SERVER_ID)
    assert 'url_model_unavailable' in res.unavailable_components
    assert res.url_model_version is None

    # 2. Blacklist unavailable alone (db=None) while URL model works: returns INCOMPLETE, never LOW.
    monkeypatch.undo()
    res_no_db = evaluate_extension_url(None, req, server_instance_id=SERVER_ID)
    assert res_no_db.verdict == 'INCOMPLETE'
    assert 'database_unavailable' in res_no_db.unavailable_components
    assert res_no_db.verdict != 'LOW'

    # 3. Both blacklist and URL model unavailable: raises service_unavailable.
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _u: None)
    with pytest.raises(ExtensionInputError) as exc_info:
        evaluate_extension_url(None, req, server_instance_id=SERVER_ID)
    assert exc_info.value.code == ERROR_SERVICE_UNAVAILABLE


@pytest.mark.parametrize('raw_body,expected_code', [
    (b'', ERROR_INPUT_INVALID),
    (b'not-json', ERROR_INPUT_INVALID),
    (b'[]', ERROR_INPUT_INVALID),
    (b'{"schema_version":"extension-check-v1","schema_version":"extension-check-v1","url":"https://example.com/","request_ref":"req_nonce_invented_0001"}', ERROR_INPUT_INVALID),
    (b'{"schema_version":"wrong-v0","url":"https://example.com/","request_ref":"req_nonce_invented_0001"}', ERROR_PROTOCOL_MISMATCH),
    (b'{"schema_version":"extension-check-v1","url":"https://example.com/","request_ref":"req_nonce_invented_0001","extra":"forbidden"}', ERROR_INPUT_INVALID),
    (b'{"schema_version":"extension-check-v1","url":"https://example.com/#frag","request_ref":"req_nonce_invented_0001"}', ERROR_INPUT_INVALID),
    (b'{"schema_version":"extension-check-v1","url":"data:text/html,secret","request_ref":"req_nonce_invented_0001"}', ERROR_INPUT_INVALID),
    (b'{"schema_version":"extension-check-v1","url":"https://example.com/","request_ref":"short"}', ERROR_INPUT_INVALID),
    (b'x' * (MAX_BODY_BYTES + 1), ERROR_LIMIT_EXCEEDED),
])
def test_parse_check_request_rejects_malformed_or_oversized_payloads(raw_body, expected_code):
    with pytest.raises(ExtensionInputError) as exc_info:
        parse_check_request(raw_body)
    assert exc_info.value.code == expected_code
