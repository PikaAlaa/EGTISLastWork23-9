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
