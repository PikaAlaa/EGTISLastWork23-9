"""Recommended actions, catalogue `recommended-actions-v1` (design core-v2 §2, FR-14).

Step 5 selectors: schema, coverage. All texts are guidance written by the team, not messages.
"""
import copy
import json

import pytest

from app.engines import email_headers, payment_rules, phishing_findings, provider_claims
from app.engines.malware import engine as malware_engine
from app.engines.network_windows import detections
from app.services import recommended_actions as ra

RAW = json.loads(ra.CATALOGUE_PATH.read_text(encoding='utf-8'))


def mutated(change):
    raw = copy.deepcopy(RAW)
    change(raw)
    return raw


def refused(raw) -> str:
    with pytest.raises(ra.CatalogueError) as info:
        ra.parse_catalogue(raw)
    return str(info.value)


# ---------------------------------------------------------------- schema

def test_schema_shipped_catalogue_loads():
    catalogue = ra.load_catalogue()
    assert catalogue.version == 'recommended-actions-v1'
    assert len(catalogue.entries) >= 60 and catalogue.fallback.en


def test_schema_every_text_has_both_languages():
    catalogue = ra.load_catalogue()
    texts = [*catalogue.entries.values(), *catalogue.kind_defaults.values(), catalogue.fallback]
    for text in texts:
        assert text.en.strip() and text.ar.strip()
        assert any('؀' <= ch <= 'ۿ' for ch in text.ar)


def test_schema_entries_stay_draft_until_a_named_reviewer():
    catalogue = ra.load_catalogue()
    for text in [*catalogue.entries.values(), *catalogue.kind_defaults.values(), catalogue.fallback]:
        if text.status == 'draft':
            assert text.reviewed_by is None and text.reviewed_on is None
        else:
            assert text.reviewed_by and text.reviewed_on


@pytest.mark.parametrize('where', ['entry', 'top', 'kind', 'fallback'])
def test_schema_extra_field_rejected(where):
    def change(raw):
        target = {'entry': raw['entries']['blacklist_exact'], 'top': raw,
                  'kind': raw['kind_defaults']['sms_phishing'], 'fallback': raw['fallback']}[where]
        target['command'] = 'netsh advfirewall set allprofiles state on'
    assert refused(mutated(change)) in ('catalogue_extra_field', 'catalogue_top_level_invalid')


def test_schema_missing_field_and_rank_rejected():
    assert refused(mutated(lambda r: r['entries']['blacklist_exact'].pop('ar'))) == 'catalogue_missing_field'
    assert refused(mutated(lambda r: r['entries']['blacklist_exact'].update(rank=0))) == 'catalogue_rank_invalid'
    assert refused(mutated(lambda r: r['entries']['blacklist_exact'].update(rank=True))) == 'catalogue_rank_invalid'
    assert refused(mutated(lambda r: r['kind_defaults']['sms_phishing'].update(rank=3))) == 'catalogue_extra_field'


@pytest.mark.parametrize('field,text,code', [
    ('en', 'Call your bank on 19623 now.', 'action_text_contains_number'),
    ('en', 'Call +20 100 000 0000 for help.', 'action_text_contains_number'),
    ('ar', 'اتصل بالرقم ١٩٦٢٣ فورًا.', 'action_text_contains_number'),
    ('en', 'Open https://bank.example to check.', 'action_text_contains_link'),
    ('en', 'Visit www.bank.example to check.', 'action_text_contains_link'),
    ('en', 'Check bank.example yourself.', 'action_text_contains_link'),
    ('en', 'Check hxxps://bank[.]example yourself.', 'action_text_contains_link'),
    ('ar', 'افتح bank.example للتحقق.', 'action_text_contains_link'),
    ('en', 'Write to help@bank.example now.', 'action_text_contains_link'),
    ('en', 'Write to support at help@bank now.', 'action_text_contains_placeholder'),
    ('en', 'Call {brand} on its number.', 'action_text_contains_placeholder'),
    ('en', 'Contact %s through the app.', 'action_text_contains_placeholder'),
    ('en', 'اتصل بالبنك', 'action_text_wrong_language'),
    ('ar', 'Call the bank.', 'action_text_wrong_language'),
    ('en', '', 'action_text_invalid'),
    ('en', 'x' * 401, 'action_text_invalid'),
])
def test_schema_text_rules_reject_contacts_links_and_placeholders(field, text, code):
    raw = mutated(lambda r: r['entries']['blacklist_exact'].update({field: text}))
    assert refused(raw).startswith(code)


def test_schema_review_fields_follow_status():
    entry = lambda **kw: mutated(lambda r: r['entries']['blacklist_exact'].update(kw))  # noqa: E731
    assert refused(entry(reviewed_by='Arabic reviewer')) == 'catalogue_draft_has_review'
    assert refused(entry(status='reviewed')) == 'catalogue_reviewer_invalid'
    assert refused(entry(status='reviewed', reviewed_by='Arabic reviewer')) == 'catalogue_review_date_invalid'
    assert refused(entry(status='reviewed', reviewed_by='Reviewer 2', reviewed_on='2026-11-28')) \
        == 'catalogue_reviewer_invalid'
    ok = ra.parse_catalogue(entry(status='reviewed', reviewed_by='Arabic-speaking team member',
                                  reviewed_on='2026-11-28'))
    assert ok.entries['blacklist_exact'].status == 'reviewed'
    assert refused(entry(status='approved')) == 'catalogue_status_invalid'
    assert refused(entry(audience='everyone')) == 'catalogue_audience_invalid'


def test_schema_version_codes_and_no_action_checked():
    assert refused(mutated(lambda r: r.update(version='recommended-actions-v0'))) == 'catalogue_version_invalid'
    assert refused(mutated(lambda r: r['no_action'].update(blacklist_exact='x'))) \
        == 'catalogue_code_in_entries_and_no_action'
    assert refused(mutated(lambda r: r['entries'].update({'Bad Code': r['entries']['blacklist_exact']}))) \
        == 'catalogue_code_invalid:entries'
    assert refused(mutated(lambda r: r['no_action'].update(some_code=''))) == 'catalogue_no_action_reason_invalid'


def test_schema_catalogue_has_no_executable_field():
    allowed = ra.ENTRY_KEYS
    for entry in RAW['entries'].values():
        assert set(entry) == allowed
    assert set(RAW) == ra.TOP_KEYS


# ---------------------------------------------------------------- coverage

def test_coverage_every_engine_code_has_an_entry_or_no_action():
    assert ra.uncovered(ra.load_catalogue()) == {}


def test_coverage_network_windows_uses_detections_reasons_directly():
    codes = {code for group in detections.REASONS.values() for code in group}
    assert len(codes) == 15 and set(detections.REASONS) == {f'N{i}' for i in range(1, 10)}
    assert ra.engine_reason_codes()['network.windows'] == codes
    assert codes <= set(ra.load_catalogue().entries)


def test_coverage_declarations_match_module_constants():
    assert malware_engine.REASON_CODES == {malware_engine.REASON_HASH_MALICIOUS, malware_engine.REASON_HASH_KNOWN,
                                           malware_engine.REASON_YARA, malware_engine.REASON_MODEL,
                                           malware_engine.REASON_MODEL_ADVISORY, malware_engine.REASON_CONFLICT}
    assert payment_rules.REASON_CODES == {r for _, r in payment_rules.RULES.values()} | {
        'payment_context_ambiguous', 'payment_verification_bypass'}
    assert phishing_findings.BRAND_DECISIVE <= phishing_findings.REASON_CODES
    assert 'no_warning_signs' not in phishing_findings.REASON_CODES
    for module in (email_headers, provider_claims, phishing_findings):
        assert all(ra._CODE.match(code) for code in module.REASON_CODES)


def test_coverage_catalogue_has_no_unknown_codes():
    declared = set().union(*ra.engine_reason_codes().values())
    catalogue = ra.load_catalogue()
    assert set(catalogue.entries) | set(catalogue.no_action) <= declared


@pytest.fixture
def realistic(db):
    from app.services.findings import seed_correlation_stoplist
    from app.services.registry import populate_registry
    populate_registry(db)
    seed_correlation_stoplist(db)
    return db


def _replay_reasons(client, db, bodies):
    from app.models import FindingRecord
    for _, body in bodies:
        client.post('/analyze', json=body)
    return {reason for record in db.query(FindingRecord) for reason in record.evidence.get('reasons', [])}


def test_coverage_phishing_replay_reasons_are_declared(client, realistic):
    from test_findings_parity import CORPUS
    reasons = _replay_reasons(client, realistic, CORPUS)
    assert reasons, 'the replay emitted no finding'
    assert reasons <= phishing_findings.REASON_CODES, sorted(reasons - phishing_findings.REASON_CODES)


def test_coverage_phishing_replay_with_high_text_path(client, realistic, monkeypatch):
    from app.engines import risk_scoring
    from test_findings_parity import CORPUS
    monkeypatch.setattr(risk_scoring, 'score_text',
                        lambda _: dict(probability=.99, score=99, model='fixture', version='test', windows=1))
    api = [b for b in CORPUS if b[0].startswith(('api:', 'robust:', 'followup:'))]
    reasons = _replay_reasons(client, realistic, api)
    assert 'text_high_corroborated' in reasons or 'text_model_high_uncorroborated' in reasons
    assert reasons <= phishing_findings.REASON_CODES, sorted(reasons - phishing_findings.REASON_CODES)


# ---------------------------------------------------------------- selection (step 6)

from dataclasses import replace as _replace  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from app.core.findings import Finding  # noqa: E402
from app.models import FindingRecord  # noqa: E402


def reviewed_catalogue(drafts=()):
    """The shipped texts, marked reviewed for these tests (except the codes in `drafts`)."""
    def review(text):
        text.update(status='reviewed', reviewed_by='Arabic-speaking team member', reviewed_on='2026-11-28')
    raw = copy.deepcopy(RAW)
    for code, entry in raw['entries'].items():
        if code not in drafts:
            review(entry)
    for entry in raw['kind_defaults'].values():
        review(entry)
    review(raw['fallback'])
    return ra.parse_catalogue(raw)


CAT = reviewed_catalogue()


def pick(engine, kind, reasons, **kw):
    return ra.recommended_actions({'engine_name': engine, 'kind': kind, 'evidence': {'reasons': reasons}},
                                  catalogue=kw.pop('catalogue', CAT), show_drafts=kw.pop('show_drafts', False))


def codes(actions):
    return [a['reason_code'] for a in actions]


def test_selection_phishing_decisive_reason_first():
    # blacklist_exact ranks above brand_label_reuse, but the decisive reason leads for phishing.analyze.
    actions = pick('phishing.analyze', 'url_phishing', ['brand_label_reuse', 'blacklist_exact', 'url_patterns'])
    assert codes(actions) == ['brand_label_reuse', 'blacklist_exact', 'url_patterns']


def test_selection_rank_orders_alphabetical_network_reasons():
    # network.windows sorts evidence.reasons alphabetically; rank decides the primary action.
    actions = pick('network.windows', 'known_bad_destination', ['blocklist_ip_connection', 'blocklist_ip_dns_answer'])
    assert codes(actions) == ['blocklist_ip_connection', 'blocklist_ip_dns_answer']
    actions = pick('network.windows', 'known_bad_destination', ['blocklist_ip_dns_answer', 'blocklist_ip_dropped'])
    assert codes(actions) == ['blocklist_ip_dropped', 'blocklist_ip_dns_answer']


def test_selection_non_phishing_ignores_decisive_position():
    actions = pick('malware.files', 'known_bad_hash', ['model_above_threshold', 'hash_list_malicious'])
    assert codes(actions) == ['hash_list_malicious', 'model_above_threshold']


def test_selection_at_most_three_and_deduplicated():
    actions = pick('network.windows', 'dns_tunnelling_signs',
                   ['dns_high_entropy_labels', 'dns_long_labels', 'dns_txt_burst', 'dns_very_long_name'])
    assert len(actions) == 1 and actions[0]['reason_code'] == 'dns_high_entropy_labels'
    many = pick('phishing.analyze', 'sms_phishing', ['text_high_corroborated', 'blacklist_domain', 'url_patterns',
                                                     'url_model', 'text_keywords', 'brand_resemblance'])
    assert len(many) == 3 and codes(many)[0] == 'text_high_corroborated'
    assert len({(a['en'], a['ar']) for a in many}) == 3


def test_selection_no_action_and_unknown_codes_skipped():
    actions = pick('malware.files', 'yara_match', ['hash_list_known_software', 'yara_rule_match', 'invented_code'])
    assert codes(actions) == ['yara_rule_match']


def test_selection_kind_default_then_fallback():
    actions = pick('phishing.analyze', 'sms_phishing', ['invented_code'])
    assert actions[0]['source'] == 'kind_default' and actions[0]['reason_code'] is None
    actions = pick('host.windows', 'invented_kind', [])
    assert actions[0]['source'] == 'fallback' and actions[0]['en'] == CAT.fallback.en


def test_selection_every_engine_code_and_kind_gets_an_action():
    """FR-14: once texts are reviewed, no Finding is left without an action."""
    for engine, reason_codes in ra.engine_reason_codes().items():
        for code in reason_codes:
            assert pick(engine, 'any_kind', [code]), (engine, code)
    assert pick('host.windows', 'any_kind', [])


def test_selection_drafts_hidden_unless_flag():
    shipped = ra.load_catalogue()
    assert all(t.status == 'draft' for t in shipped.entries.values())
    assert pick('phishing.analyze', 'url_phishing', ['blacklist_exact'], catalogue=shipped) == []
    shown = pick('phishing.analyze', 'url_phishing', ['blacklist_exact'], catalogue=shipped, show_drafts=True)
    assert codes(shown) == ['blacklist_exact'] and shown[0]['status'] == 'draft'


def test_selection_draft_entry_replaced_by_next_reviewed_match():
    partial = reviewed_catalogue(drafts={'blacklist_exact'})
    actions = pick('phishing.analyze', 'url_phishing', ['blacklist_exact', 'url_patterns'], catalogue=partial)
    assert codes(actions) == ['url_patterns'] and all(a['status'] == 'reviewed' for a in actions)


def test_selection_default_setting_is_off(monkeypatch):
    from app.core.settings import Settings
    monkeypatch.delenv('ETIS_SHOW_DRAFT_ACTIONS', raising=False)
    assert Settings().show_draft_actions is False


def test_selection_accepts_finding_record_and_finding_model():
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    model = Finding(engine={'name': 'network.windows', 'version': 'v'}, domain='network', kind='beaconing',
                    severity='high', confidence='corroborated', evidence={'reasons': ['periodic_beaconing']},
                    observed_at=now, created_at=now, source={'kind': 'import', 'ref': 'test:1'})
    record = FindingRecord(engine_name='malware.files', kind='known_bad_hash',
                           evidence={'reasons': ['hash_list_malicious'], 'details': {}})
    assert codes(ra.recommended_actions(model, catalogue=CAT, show_drafts=False)) == ['periodic_beaconing']
    assert codes(ra.recommended_actions(record, catalogue=CAT, show_drafts=False)) == ['hash_list_malicious']


def test_selection_result_shape_carries_version_and_both_languages():
    action = pick('phishing.analyze', 'url_phishing', ['blacklist_exact'])[0]
    assert set(action) == {'reason_code', 'source', 'audience', 'status', 'en', 'ar', 'catalogue_version'}
    assert action['catalogue_version'] == 'recommended-actions-v1' and action['ar'] and action['en']


def test_selection_endpoint_is_read_only(client):
    from app.main import app
    schema = app.openapi()['paths']
    paths = {path: set(ops) for path, ops in schema.items() if path.startswith('/recommended-actions')}
    assert paths == {'/recommended-actions': {'get'}}
    for method in ('post', 'put', 'patch', 'delete'):
        assert getattr(client, method)('/recommended-actions').status_code == 405


def test_selection_endpoint_hides_drafts_and_requires_key(client, monkeypatch):
    body = client.get('/recommended-actions').json()
    assert body['version'] == 'recommended-actions-v1' and body['entries'] == {} and body['fallback'] is None
    assert body['reviewed_texts'] == 0 and body['total_texts'] > 60
    monkeypatch.setattr(ra, 'load_catalogue', lambda *a, **k: CAT)
    body = client.get('/recommended-actions').json()
    assert body['entries']['blacklist_exact']['status'] == 'reviewed' and body['fallback']
    from app.core import security
    monkeypatch.setattr(security, 'settings', _replace(security.settings, api_key='server-only-test-key'))
    assert client.get('/recommended-actions').status_code == 401
