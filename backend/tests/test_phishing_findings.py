"""Phishing finding emitter and attack-map-v1 (design core-v1 §4.4, §5.2, §9.3).

Inputs are invented; the review messages come from evaluation/review-evidence/cases.py
(invented, not real Egyptian SMS). Placeholder numbers and .example domains only.
"""
import copy
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.detection_signals import has_secret_request
from app.core.indicators import normalize
from app.core.url_utils import parse_url, url_hash
from app.engines.phishing_findings import attack_map_v1, phishing_findings, url_candidate_id
from app.engines.risk_scoring import calculate_final_risk_score
from app.services.attack import parse_techniques
from app.services.registry import populate_registry

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('review_cases', ROOT / 'evaluation/review-evidence/cases.py')
cases = importlib.util.module_from_spec(spec); spec.loader.exec_module(cases)
FIXTURE = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-subset.json').read_text(encoding='utf-8'))
NOW = datetime(2026, 11, 18, 10, tzinfo=timezone.utc)


def link(url='https://lure.example/x', technique=None, decisive=False, score=0.0, brand=None):
    parsed = parse_url(url)
    return {'url': parsed.canonical, 'host': parsed.host, 'brand': {'technique': technique, 'decisive': decisive,
            'score': score, 'matched_brand': brand}, 'url_model_probability': 0.5, 'url_model_threshold': 0.98}


def result(verdict, signals, decisive=None, links=()):
    return {'verdict': verdict, 'final_score': 90.0, 'decisive_reason': decisive or (signals[0] if signals else 'no_warning_signs'),
            'supporting_signals': sorted(signals), 'checked_links': list(links), 'links_truncated': False,
            'text_finding': {'version': 'textver'}, 'analysis_complete': verdict != 'INCOMPLETE',
            'checks_unavailable': ['blacklist_stale'] if verdict == 'INCOMPLETE' else [],
            'policy_version': 'decision-v2', 'timing_ms': 1.0}


def emit(res, text=None, url=None):
    return phishing_findings(res, SimpleNamespace(text=text, url=url), 7, now=NOW)


def techniques(finding):
    return {(a.technique_id, a.matrix, a.basis) for a in finding.attack}


@pytest.mark.parametrize('verdict,signals,decisive,expected', [
    ('HIGH', ['blacklist_exact'], None, ('high', 'confirmed')),
    ('HIGH', ['blacklist_exact', 'text_high_corroborated'], 'text_high_corroborated', ('high', 'confirmed')),
    ('HIGH', ['text_high_corroborated'], None, ('high', 'corroborated')),
    ('HIGH', ['url_model_corroborated'], None, ('high', 'corroborated')),
    ('MEDIUM', ['url_model'], None, ('medium', 'single_signal')),
    ('MEDIUM', ['text_model_high_uncorroborated'], None, ('medium', 'single_signal')),
    ('INCOMPLETE', ['text_keywords'], 'blacklist_stale', ('medium', 'undetermined')),
    ('INCOMPLETE', [], 'blacklist_stale', None),
    ('LOW', [], None, None),
])
def test_severity_and_confidence_table(verdict, signals, decisive, expected):
    found = emit(result(verdict, signals, decisive, [link()]), url='https://lure.example/x')
    if expected is None:
        assert found == []
    else:
        assert (found[0].severity, found[0].confidence) == expected
        assert found[0].evidence.details['verdict'] == verdict
        assert found[0].evidence.reasons[0] == (decisive or signals[0])


def test_kind_and_engine_identity():
    sms, = emit(result('MEDIUM', ['text_keywords']), text='invented text')
    url, = emit(result('MEDIUM', ['url_model'], links=[link()]), url='https://lure.example/x')
    assert (sms.kind, url.kind) == ('sms_phishing', 'url_phishing')
    assert sms.engine.name == 'phishing.analyze'
    assert sms.engine.version == f'decision-v2+url:{url_candidate_id()}+text:textver'
    assert url_candidate_id() == 'ee0ba9f0077c1fd140aa'
    assert sms.source.ref == 'scan_requests:7' and sms.observed_at == NOW


def test_text_only_maps_to_mobile_phishing_and_enterprise_parent():
    f, = emit(result('MEDIUM', ['text_keywords']), text='invented text')
    assert techniques(f) == {('T1660', 'mobile', 'sms_text_present'), ('T1566', 'enterprise', 'phishing_message')}


def test_url_only_never_maps_to_t1660():
    f, = emit(result('HIGH', ['blacklist_exact'], links=[link()]), url='https://lure.example/x')
    assert techniques(f) == {('T1566', 'enterprise', 'phishing_message'),
                             ('T1204.001', 'enterprise', 'link_action_requested')}


def test_link_without_url_side_reason_is_not_t1204():
    f, = emit(result('HIGH', ['text_high_corroborated'], links=[link()]), text='invented text https://lure.example/x')
    assert not any(a.technique_id == 'T1204.001' for a in f.attack)


def test_secret_request_maps_to_phishing_for_information():
    assert has_secret_request(cases.PHISH_TEXT)
    with_link, = emit(result('HIGH', ['text_high_corroborated', 'url_patterns'], links=[link()]), text=cases.PHISH_TEXT)
    without_link, = emit(result('HIGH', ['text_high_corroborated']), text=cases.PHISH_TEXT)
    assert {('T1598', 'enterprise', 'secret_request'), ('T1598.003', 'enterprise', 'secret_request')} <= techniques(with_link)
    assert ('T1598', 'enterprise', 'secret_request') in techniques(without_link)
    assert not any(a.technique_id == 'T1598.003' for a in without_link.attack)


@pytest.mark.parametrize('technique,lookalike', [('brand_label_reuse', True), ('homoglyph_confusable', True),
                                                 ('domain_embedding', True), ('userinfo_brand', False)])
def test_brand_decisive_maps_to_impersonation(technique, lookalike):
    f, = emit(result('HIGH', [technique], links=[link(technique=technique, decisive=True, score=95, brand='Invented Bank')]),
              url='https://lure.example/x')
    found = techniques(f)
    assert ('T1684.001', 'enterprise', 'brand_decisive') in found
    assert (('T1583.001', 'enterprise', 'lookalike_domain_inferred') in found) is lookalike
    assert f.evidence.details['matched_brands'] == ['Invented Bank']
    roles = {i.role for i in f.indicators if i.type == 'domain'}
    assert roles == ({'lookalike_domain'} if lookalike else {'link_host'})


def test_brand_claim_from_mobile_sender():
    f, = emit(result('MEDIUM', ['brand_claim_from_mobile_number']), text='invented text')
    assert ('T1684.001', 'enterprise', 'brand_claim_sender') in techniques(f)


def test_mapping_never_uses_voice_or_revoked_ids_and_all_ids_exist_in_v20():
    catalogue = {(r['technique_id'], r['matrix']) for matrix in ('enterprise', 'mobile')
                 for r in parse_techniques(FIXTURE['objects'][matrix], matrix, '20.0')}
    every_signal = ['blacklist_exact', 'url_model', 'brand_label_reuse', 'homoglyph_confusable',
                    'brand_claim_from_mobile_number', 'text_high_corroborated']
    refs = attack_map_v1(result('HIGH', every_signal, links=[link()]), cases.PHISH_TEXT)
    emitted = {(r['technique_id'], r['matrix']) for r in refs}
    assert emitted <= catalogue
    assert not {t for t, _ in emitted} & {'T1566.004', 'T1656', 'T1566.002', 'T1566.003'}
    assert {r['attack_version'] for r in refs} == {'20.0'}


def test_indicators_are_hash_only_and_join_with_blacklist_hashes():
    raw = 'HTTPS://Lure.Example:443/pay?x=1'
    text = 'invented: call 010 0000 0000 or write to Someone@Lure.Example then open http://192.0.2.9/a'
    links = [link(raw), link('http://192.0.2.9/a')]
    f, = emit(result('MEDIUM', ['url_patterns'], links=links), text=text, url=raw)
    by = {(i.type, i.role): i for i in f.indicators}
    assert all(i.value is None for i in f.indicators)
    assert by[('url', 'delivery_link')].value_hash in {url_hash(raw), url_hash('http://192.0.2.9/a')}
    assert {i.value_hash for i in f.indicators if i.type == 'url'} == {url_hash(raw), url_hash('http://192.0.2.9/a')}
    assert by[('domain', 'link_host')].value_hash == normalize('domain', 'lure.example').value_hash
    assert by[('ip', 'link_host')].value_hash == normalize('ip', '192.0.2.9').value_hash
    assert by[('phone', 'contact_phone')].value_hash == normalize('phone', '+201000000000').value_hash
    assert by[('email', 'contact_email')].value_hash == normalize('email', 'someone@lure.example').value_hash


def test_emitter_is_pure_and_deterministic():
    res = result('HIGH', ['blacklist_exact'], links=[link()])
    snapshot = copy.deepcopy(res)
    first, = emit(res, url='https://lure.example/x')
    second, = emit(res, url='https://lure.example/x')
    assert res == snapshot
    assert first.model_dump(exclude={'id'}) == second.model_dump(exclude={'id'})


def test_real_pipeline_finding_contains_no_submitted_content(db):
    populate_registry(db)
    marker_url = 'https://cibeg.com:443@private-marker-zq.example/login?token=private-marker-qq'
    text = cases.PHISH_TEXT + ' private-marker-tx 01000000000'
    res = calculate_final_risk_score(text=text, url=marker_url, db=db)
    f, = phishing_findings(res, SimpleNamespace(text=text, url=marker_url), 1, now=NOW)
    dumped = f.model_dump_json()
    for marker in ('private-marker', 'cibeg.com:443@', '01000000000', '+201000000000'):
        assert marker not in dumped
    assert res['verdict'] == 'HIGH' and f.severity == 'high'
    assert ('T1684.001', 'enterprise', 'brand_decisive') in techniques(f)
