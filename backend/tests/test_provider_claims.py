"""INVENTED-only messages/providers/URLs. No real Egyptian performance evidence."""
from copy import deepcopy
from datetime import timedelta
import socket

import pytest

from app.core.indicators import normalize_url
from app.engines import provider_claims as rules
from app.engines.provider_claims import ProviderClaimEngine, Proof, match_domain, severity_confidence
from app.engines.registry import Observation
from provider_fixtures import (INVENTED_PHONE, INVENTED_URL, NOW, invented_registry, write_invented_registry)


@pytest.fixture(autouse=True)
def blocked_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('provider test attempted network access')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def invented_observation(text=None, **data):
    """Everything passed through this helper, including message/URL/sender, is INVENTED."""
    return Observation('provider_message', 'scan_requests:1', NOW,
                       {'text': text if text is not None else f'This is Invented Example Bank; click {INVENTED_URL}',
                        'channel': 'sms', **data})


def engine(tmp_path, mutate=None):
    payload = invented_registry()
    if mutate:
        mutate(payload)
    return ProviderClaimEngine(write_invented_registry(tmp_path, payload))


@pytest.mark.parametrize('claim', [
    'This is Invented Example Bank', 'We are Invented Example Bank',
    'نحن بنك المثال المخترع', 'نحن بَنْك المِثال المخترع', 'احنا بنكنا المخترع',
    'e7na bank el methal el mo5tara3', 'Invented Example Bank:',
])
def test_four_language_claims(tmp_path, claim):
    results = engine(tmp_path).analyze(invented_observation(f'{claim}; click {INVENTED_URL}'))
    assert len(results) == 1
    finding, = results
    assert (finding.kind, finding.severity, finding.confidence) == ('provider_proof_mismatch', 'medium', 'single_signal')
    assert finding.evidence.reasons == ['provider_domain_outside_set']


@pytest.mark.parametrize('text', [
    f'I mentioned Invented Example Bank; click {INVENTED_URL}',
    f'From Invented Example Banker; click {INVENTED_URL}',
    f'Beware: This is Invented Example Bank; warning click {INVENTED_URL}',
    f'> This is Invented Example Bank; click {INVENTED_URL}',
    f'"This is Invented Example Bank; click {INVENTED_URL}"',
    f'“This is Invented Example Bank; click {INVENTED_URL}”',
    f'This is Invented Example Bank; do not click {INVENTED_URL}',
    'This is Invented Example Bank; thank you',
    f'This is Invented Example Bank; {INVENTED_URL}',
])
def test_mentions_quotes_negation_and_no_action_do_not_alert(tmp_path, text):
    assert engine(tmp_path).analyze(invented_observation(text)) == []


def test_claim_from_sender_id_or_sender_display(tmp_path):
    instance = engine(tmp_path)
    for context in ({'sender_id': 'INVENTEDBANK'}, {'sender_display': 'Invented Example Bank'},
                    {'sender_id': '54321'}):
        assert instance.analyze(invented_observation(f'click {INVENTED_URL}', **context))
    assert instance.analyze(invented_observation(f'click {INVENTED_URL}', sender_id='INVENTEDBANK', channel='email')) == []


@pytest.mark.parametrize('scope,url,expected', [
    ('exact_host', 'https://BANK.example.eg/', 'match'),
    ('exact_host', 'https://bank.example.eg./', 'match'),
    ('exact_host', 'https://service.bank.example.eg/', 'outside_documented_set'),
    ('subdomains', 'https://service.bank.example.eg/', 'match'),
    ('subdomains', 'https://notbank.example.eg/', 'outside_documented_set'),
    ('subdomains', 'https://bank.example.eg.other.example.eg/', 'outside_documented_set'),
    ('registrable_domain', 'https://other.example.eg/', 'match'),
    ('exact_host', 'https://bank.example.eg@other.example.eg/', 'invalid'),
    ('exact_host', 'data:invented', 'invalid'),
    ('exact_host', 'http://127.0.0.1/', 'invalid'),
    ('exact_host', 'https://bank.example.eg:bad/', 'invalid'),
])
def test_domain_scopes_are_offline_and_label_bounded(tmp_path, scope, url, expected):
    provider = engine(tmp_path).snapshot.registry.entries[0]
    provider = provider.model_copy(update={'domains': (provider.domains[0].model_copy(update={'match_scope': scope}),)})
    assert match_domain(url, provider, 'sms', suffix_available=True) == expected


def test_idna_and_punycode_are_literal_not_confusable(tmp_path):
    from app.core.url_utils import parse_url
    payload = invented_registry()
    unicode_host = 'مثال.example.eg'  # INVENTED Unicode name; never resolved
    ascii_host = parse_url(unicode_host).host
    payload['entries'][0]['domains'][0]['host'] = ascii_host
    instance = ProviderClaimEngine(write_invented_registry(tmp_path, payload))
    provider = instance.snapshot.registry.entries[0]
    assert match_domain('https://' + unicode_host, provider, 'sms', suffix_available=True) == 'match'
    assert match_domain('https://' + ascii_host, provider, 'sms', suffix_available=True) == 'match'
    assert rules.confusable_match('invented-lookalike.example.eg', provider) == 'not_checked'
    assert not any('provider_lookalike_host' in f.evidence.reasons for f in instance.analyze(invented_observation()))


def test_suffix_unavailable_is_incomplete_not_mismatch(tmp_path, monkeypatch):
    instance = engine(tmp_path, lambda p: p['entries'][0]['domains'][0].update(match_scope='registrable_domain'))
    monkeypatch.setattr(rules, 'suffix_snapshot_available', lambda: False)
    finding, = instance.analyze(invented_observation())
    assert (finding.severity, finding.confidence, finding.attack, finding.indicators) == ('info', 'undetermined', [], [])
    assert finding.evidence.reasons == ['provider_suffix_unavailable']
    # Literal identity remains usable even if a suffix check is not available.
    assert instance.analyze(invented_observation(url='https://bank.example.eg/', text='This is Invented Example Bank; click here')) == []


def test_partial_unknown_stale_ambiguity_and_unavailable_table_rows(tmp_path, monkeypatch):
    instance = engine(tmp_path, lambda p: p['entries'][0]['coverage'].update(domains='documented_partial'))
    finding, = instance.analyze(invented_observation())
    assert (finding.severity, finding.confidence, finding.attack) == ('low', 'undetermined', [])
    instance = engine(tmp_path, lambda p: p['entries'][0]['coverage'].update(domains='unknown'))
    assert instance.analyze(invented_observation()) == []
    instance = engine(tmp_path, lambda p: p['entries'][0].update(review_due_at='2026-11-26'))
    finding, = instance.analyze(invented_observation())
    assert finding.evidence.reasons == ['provider_registry_stale']
    assert (finding.kind, finding.severity, finding.confidence, finding.attack) == ('provider_check_incomplete', 'info', 'undetermined', [])
    instance = engine(tmp_path)
    duplicate = instance.snapshot.registry.entries[0].model_copy(update={'provider_id': 'invented_second'})
    instance.snapshot = instance.snapshot.__class__(instance.snapshot.registry.model_copy(update={
        'entries': (*instance.snapshot.registry.entries, duplicate)}), instance.snapshot.pin)
    finding, = instance.analyze(invented_observation())
    assert finding.evidence.reasons == ['provider_claim_ambiguous'] and finding.severity == 'info'
    def unavailable():
        raise rules.RegistryUnavailable('provider_registry_unavailable')
    monkeypatch.setattr(rules, 'load_bundled_registry', unavailable)
    finding, = ProviderClaimEngine().analyze(invented_observation())
    assert finding.evidence.reasons == ['provider_registry_unavailable']
    assert finding.severity == 'info' and finding.confidence == 'undetermined'


def test_independent_domain_and_sender_or_callback_are_high(tmp_path):
    instance = engine(tmp_path)
    for context in ({'sender_id': 'INVENTEDOTHER'}, {'sender_id': INVENTED_PHONE}):
        results = instance.analyze(invented_observation(**context))
        assert len(results) == 2 and {f.severity for f in results} == {'high'}
        assert {f.confidence for f in results} == {'corroborated'}
    results = instance.analyze(invented_observation(f'This is Invented Example Bank; click {INVENTED_URL}; call {INVENTED_PHONE}'))
    assert {f.evidence.reasons[0] for f in results} == {'provider_domain_outside_set', 'provider_callback_outside_set'}
    assert {f.severity for f in results} == {'high'}


def test_contact_only_never_corroborates_or_maps_sms_from_sender_alone(tmp_path):
    instance = engine(tmp_path)
    results = instance.analyze(invented_observation(f'This is Invented Example Bank; call {INVENTED_PHONE}', sender_id='INVENTEDOTHER'))
    assert {f.severity for f in results} == {'medium'}
    assert {f.confidence for f in results} == {'single_signal'}
    assert {a.technique_id for f in results for a in f.attack} == {'T1684.001'}
    result, = instance.analyze(invented_observation('This is Invented Example Bank; send otp', sender_id='INVENTEDOTHER'))
    assert {a.technique_id for a in result.attack} == {'T1684.001', 'T1660'}


def test_hotline_cannot_authenticate_outbound_sender_or_an_unrelated_link(tmp_path):
    instance = engine(tmp_path)
    results = instance.analyze(invented_observation(sender_id='65432'))
    assert len(results) == 2  # hotline does not match outbound SMS short-code scope
    assert {f.severity for f in results} == {'high'}
    results = instance.analyze(invented_observation(f'This is Invented Example Bank; click {INVENTED_URL}; call 65432'))
    assert len(results) == 1 and results[0].severity == 'medium'


def test_partial_contact_cannot_escalate_complete_domain(tmp_path):
    instance = engine(tmp_path, lambda p: p['entries'][0]['coverage'].update(sender_ids='documented_partial'))
    results = instance.analyze(invented_observation(sender_id='INVENTEDOTHER'))
    assert {(f.severity, f.confidence) for f in results} == {('medium', 'single_signal'), ('low', 'undetermined')}


def test_deduplication_preserves_full_url_identity_and_no_double_counting(tmp_path):
    instance = engine(tmp_path)
    url = 'https://different.example.eg/PrivatePath?Token=InventedValue'  # INVENTED
    results = instance.analyze(invented_observation(f'This is Invented Example Bank; click {url} {url}', url=url))
    assert len(results) == 1 and results[0].severity == 'medium'
    ref = rules._indicator('url', url, 'delivery_link')
    assert ref.value_hash == normalize_url(url).value_hash
    assert ref.value is None


def test_attack_is_behavior_based_and_never_verdict_based(tmp_path):
    instance = engine(tmp_path)
    for channel in ('sms', 'email', 'unknown'):
        findings = instance.analyze(invented_observation(channel=channel, verdict='HIGH'))
        attack = {(a.technique_id, a.matrix, a.attack_version, a.basis) for f in findings for a in f.attack}
        assert ('T1684.001', 'enterprise', '20.0', 'provider_claim_proof_conflict') in attack
        assert ('T1660', 'mobile', '20.0', 'sms_deceptive_action') in attack if channel == 'sms' else len(attack) == 1
        assert not any(a[0] == 'T1656' for a in attack)
    assert instance.analyze(invented_observation('Nothing actionable, invented text', verdict='HIGH')) == []


def test_health_and_input_failures_are_engine_local(tmp_path):
    instance = engine(tmp_path)
    assert instance.health({'today': NOW.date()}) == {'available': True, 'reason': None}
    assert not instance.health({'today': NOW.date() + timedelta(days=40)})['available']
    assert ProviderClaimEngine().health({}) == {'available': False, 'reason': 'provider_registry_empty'}
    with pytest.raises(ValueError, match='unsupported_observation'):
        instance.analyze(Observation('wrong', 'scan_requests:1', NOW))
    with pytest.raises(ValueError, match='retention_to_verify'):
        instance.analyze(Observation('provider_message', 'import:invented', NOW))
    with pytest.raises(ValueError, match='provider_input_invalid'):
        instance.analyze(invented_observation(text='x' * 5001))


def test_all_severity_confidence_rows_directly():
    complete = Proof('provider_domain_outside_set', 'outside_documented_set', 'documented_complete', 'domain')
    partial = Proof('provider_domain_outside_set', 'outside_documented_set', 'documented_partial', 'domain')
    contact = Proof('provider_sender_outside_set', 'outside_documented_set', 'documented_complete', 'contact')
    assert severity_confidence(partial, (partial, contact)) == ('low', 'undetermined')
    assert severity_confidence(complete, (complete,)) == ('medium', 'single_signal')
    assert severity_confidence(complete, (complete, contact)) == ('high', 'corroborated')


def test_missing_fields_are_unknown_and_never_mismatches(tmp_path):
    instance = engine(tmp_path, lambda p: p['entries'][0]['coverage'].update(
        domains='unknown', sender_ids='unknown', sms_short_codes='unknown', hotlines='unknown'))
    assert instance.analyze(invented_observation(sender_id='INVENTEDOTHER')) == []


def test_raw_urls_cannot_supply_action_or_negation_words(tmp_path):
    instance = engine(tmp_path)
    assert instance.analyze(invented_observation(
        'This is Invented Example Bank; https://different.example.eg/click')) == []
    result, = instance.analyze(invented_observation(
        'This is Invented Example Bank; click https://warning.example.eg/Warning?example=Private'))
    assert result.severity == 'medium'


def test_multiple_distinct_proofs_group_by_hash_even_when_public_pivots_withheld(tmp_path):
    instance = engine(tmp_path)
    results = instance.analyze(invented_observation(
        'This is Invented Example Bank; click https://different.example.eg/one https://different.example.eg/two'))
    assert len(results) == 2
    assert all(not f.indicators for f in results)  # same official registrable parent excluded
    assert all(f.severity == 'medium' for f in results)  # two links are still one family


def test_bundled_suffix_snapshot_is_the_one_used_by_existing_offline_parser():
    assert rules.suffix_snapshot_available()
    from app.core import url_utils
    assert url_utils._suffixes.suffix_list_urls == ()
    assert not url_utils._suffixes.include_psl_private_domains
