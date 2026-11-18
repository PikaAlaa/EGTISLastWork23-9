"""Verdict parity gate (design core-v1 §5.1, §9.1).

Every existing review case, everyday/controlled/robustness probe, reviewer follow-up
probe and URL-shape probe is posted to /analyze with ETIS_FINDINGS_ENABLED off and
on. The responses must be identical except timing_ms. These inputs are the existing
invented/exposed development cases; no new evaluation claim is made.
"""
import importlib.util
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from app.engines import risk_scoring
from app.engines.phishing_findings import severity_and_confidence
from app.models import (FindingAttack, FindingIndicator, FindingRecord, Incident, Indicator, IndicatorSighting,
                        ScanRequest, ScanResult)
from app.routers import analyze
from app.services.findings import seed_correlation_stoplist
from app.services.registry import populate_registry

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('review_cases', ROOT / 'evaluation/review-evidence/cases.py')
cases = importlib.util.module_from_spec(spec); spec.loader.exec_module(cases)
sys.path.insert(0, str(ROOT))
from evaluation.probe_query_shortcut import HOSTS, VARIANTS  # noqa: E402


def fill(value):
    return (value.replace('{BLACKLISTED_URL_UPPER}', 'https://KNOWN-PHISH.EXAMPLE/login')
            .replace('{BLACKLISTED_URL}', 'https://known-phish.example/login'))


def corpus():
    bodies = [(f'api:{c[0]}', {k: fill(v) for k, v in c[2].items()}) for c in cases.API_CASES]
    bodies += [(f'everyday:{i + 1}', {'text': text}) for i, text in enumerate(cases.EVERYDAY_SMS)]
    for name, first, second in cases.CONTROLLED_PAIRS:
        bodies += [(f'pair:{name}:a', {'text': first}), (f'pair:{name}:b', {'text': second})]
    bodies += [(f'robust:{c[0]}', {'text': fill(c[2])}) for c in cases.ROBUSTNESS]
    rows = json.loads((ROOT / 'evaluation/followup-probes.json').read_text(encoding='utf-8'))
    bodies += [(f'followup:{row["name"]}', row['body']) for row in rows]
    bodies += [(f'urlshape:{host}:{variant}', {'url': 'https://' + host + suffix})
               for host in HOSTS for variant, suffix in VARIANTS.items()]
    return bodies


CORPUS = corpus()


def set_flag(monkeypatch, enabled):
    monkeypatch.setattr(analyze, 'settings', replace(analyze.settings, findings_enabled=enabled))


def comparable(response):
    body = response.json()
    if isinstance(body, dict):
        body.pop('timing_ms', None)
    return response.status_code, body


@pytest.fixture
def realistic(db):
    populate_registry(db)
    seed_correlation_stoplist(db)
    return db


def run_gate(client, monkeypatch, db, bodies, verdicts=None):
    mismatches = []
    verdicts = {} if verdicts is None else verdicts
    for name, body in bodies:
        set_flag(monkeypatch, False)
        before = db.query(FindingRecord).count()
        off = comparable(client.post('/analyze', json=body))
        assert db.query(FindingRecord).count() == before, f'{name}: findings written while disabled'
        set_flag(monkeypatch, True)
        on_response = client.post('/analyze', json=body)
        on = comparable(on_response)
        if off != on:
            mismatches.append(name)
            continue
        if on_response.status_code == 200:
            payload = on_response.json()
            verdicts[payload['verdict']] = verdicts.get(payload['verdict'], 0) + 1
            expected = 1 if severity_and_confidence(payload) else 0
            assert db.query(FindingRecord).count() - before == expected, name
    return mismatches


def test_verdict_parity_gate_real_models(client, monkeypatch, realistic):
    assert len(CORPUS) >= 150
    verdicts = {}
    assert run_gate(client, monkeypatch, realistic, CORPUS, verdicts) == []
    assert {'HIGH', 'MEDIUM', 'LOW'} <= set(verdicts), verdicts  # the gate is not vacuous
    assert realistic.query(FindingRecord).count() == sum(v for k, v in verdicts.items() if k in ('HIGH', 'MEDIUM')) + \
        realistic.query(FindingRecord).filter(FindingRecord.confidence == 'undetermined').count()


def test_verdict_parity_gate_fixture_text_model(client, monkeypatch, realistic):
    # Same orchestration fixture as test_endpoints.py, so the always-high text path is covered too.
    monkeypatch.setattr(risk_scoring, 'score_text',
                        lambda _: dict(probability=.99, score=99, model='fixture', version='test', windows=1))
    api = [b for b in CORPUS if b[0].startswith(('api:', 'robust:', 'followup:'))]
    assert run_gate(client, monkeypatch, realistic, api) == []


def test_findings_are_on_by_default():
    from app.core.settings import Settings
    assert Settings().findings_enabled is True


def test_enabled_scan_records_hash_only_findings(client, monkeypatch, realistic):
    set_flag(monkeypatch, True)
    marker = 'private-marker-ab12'
    body = {'url': f'https://cibeg.com:443@{marker}.example/login', 'text': cases.PHISH_TEXT + ' ' + marker}
    response = client.post('/analyze', json=body)
    assert response.status_code == 200 and response.json()['saved'] and response.json()['verdict'] == 'HIGH'
    record = realistic.query(FindingRecord).one()
    scan = realistic.query(ScanRequest).one()
    assert record.scan_request_id == scan.id and record.source_ref == f'scan_requests:{scan.id}'
    assert record.severity == 'high' and realistic.query(FindingAttack).count() >= 2
    assert realistic.query(FindingIndicator).filter_by(finding_id=record.id).count() >= 2
    assert realistic.query(Incident).count() == 1
    stored = json.dumps([
        [(r.evidence, r.engine_version, r.source_ref) for r in realistic.query(FindingRecord)],
        [(i.value, i.registered_domain) for i in realistic.query(Indicator)],
        [(s.ref, s.source_name) for s in realistic.query(IndicatorSighting)],
    ])
    assert marker not in stored and 'cibeg.com:443@' not in stored


def test_low_scan_records_no_finding(client, monkeypatch, realistic):
    set_flag(monkeypatch, True)
    response = client.post('/analyze', json={'text': cases.EVERYDAY_SMS[4]})
    assert response.status_code == 200 and response.json()['verdict'] == 'LOW' and response.json()['saved']
    assert realistic.query(FindingRecord).count() == 0


def test_finding_failure_rolls_back_scan_but_keeps_verdict(client, monkeypatch, realistic, caplog):
    set_flag(monkeypatch, False)
    expected = comparable(client.post('/analyze', json={'url': 'https://known-phish.example/login'}))
    scans_before = realistic.query(ScanRequest).count()
    set_flag(monkeypatch, True)

    def broken(*_args, **_kwargs):
        raise RuntimeError('private-marker-cd34')
    monkeypatch.setattr(analyze, 'record_findings', broken)
    with caplog.at_level(logging.WARNING):
        response = client.post('/analyze', json={'url': 'https://known-phish.example/login'})
    body = response.json()
    assert response.status_code == 200 and body['saved'] is False and body['save_error'] == 'scan_not_saved'
    status, got = comparable(response)
    assert status == expected[0]
    assert {k: v for k, v in got.items() if k not in ('saved', 'save_error')} == \
        {k: v for k, v in expected[1].items() if k not in ('saved', 'save_error')}
    assert realistic.query(ScanRequest).count() == scans_before
    assert realistic.query(ScanResult).count() == scans_before
    assert realistic.query(FindingRecord).count() == 0
    assert 'private-marker' not in caplog.text and 'scan_persistence_failed' in caplog.text
