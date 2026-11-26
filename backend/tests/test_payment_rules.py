"""INVENTED BEC and payment-change fixtures, minimal pairs and false-alarm gates.

Every message, header, provider, domain (example.eg / example.com) and opaque
payment placeholder in this file is INVENTED (`invented=True`). Nothing here is
real Egyptian SMS/email data or estimates real population accuracy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from app.engines.email_headers import ReceiverProfile
from app.engines.payment_rules import EMAIL, MANIFEST, PROVIDER, RULES, DestinationGrammar, apply_payment_rules
from app.models import AttackTechnique, FindingAttack, FindingIndicator, FindingRecord, Incident, Indicator
from app.services.attack import parse_techniques
from app.services.eml_reader import ImportErrorCode
from app.services.findings import record_findings
from app.services.mail_import import DISABLED, Review, import_eml, review_sms
from provider_fixtures import INVENTED_PHONE, INVENTED_URL, write_invented_registry

ROOT = Path(__file__).resolve().parents[2]
ENGINE = 'phishing.payment_rules'
# Synthetic test-only grammar (bec-payment-rules-v1 §3); never claims real bank/app validation.
SYNTHETIC_GRAMMAR = DestinationGrammar(
    name='invented_synthetic_test_only',
    pattern=r'INVENTED-(?:ACCT|IBAN|WALLET)-[0-9]{4}',
)
PROFILE = ReceiverProfile(
    profile_id='invented_receiver',
    authserv_id='receiver.example.eg',
    prefix=('received-spf', 'authentication-results'),
    source='https://example.eg/invented-receiver-spec',
    read_date='2026-11-26',
    verifier='invented_reviewer',
)


@pytest.fixture(autouse=True)
def blocked_sockets(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('payment rules test attempted network access')

    for attr in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, attr, forbidden)


@dataclass(frozen=True)
class InventedFixture:
    fixture_id: str
    family: str
    language: str
    channel: str
    kind: str  # 'positive' | 'minimal_negative' | 'benign_control' | 'ambiguous_control'
    text: str
    expected_rules: tuple[str, ...]
    expected_severities: dict[str, str]
    expected_confidences: dict[str, str]
    trust_state: str = 'none'
    use_grammar: bool = True
    subject: str = 'invented-subject'
    author: str = 'Tester <sender@example.eg>'
    headers: str = ''
    attested: bool = False
    use_profile: bool = False
    use_registry: bool = False
    registry_coverage: str = 'documented_complete'
    registry_stale: bool = False
    sender_id: str | None = None
    sender_display: str | None = None
    expected_attack: tuple[str, ...] = ()
    expected_bypass_on: tuple[str, ...] = ()
    invented: bool = True


# Four-language positive and minimal-negative pairs covering B1-B5 predicates across email & SMS.
LANGUAGE_B1_B5_FIXTURES: tuple[InventedFixture, ...] = (
    # B1 across en, ar, ar_EG, franco (email and sms)
    InventedFixture(
        'b1_en_pos', 'fam_b1_en', 'en', 'email', 'positive',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
    ),
    InventedFixture(
        'b1_en_neg_no_change', 'fam_b1_en', 'en', 'email', 'minimal_negative',
        'Send payment, iban: INVENTED-IBAN-0001.',
        (), {}, {},
    ),
    InventedFixture(
        'b1_ar_pos', 'fam_b1_ar', 'ar', 'email', 'positive',
        'حوّل دفعة، غيّر الحساب، ايبان: INVENTED-IBAN-0002.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
    ),
    InventedFixture(
        'b1_ar_neg_no_dest', 'fam_b1_ar', 'ar', 'email', 'minimal_negative',
        'حوّل دفعة، غيّر الحساب.',
        (), {}, {},
    ),
    InventedFixture(
        'b1_areg_pos', 'fam_b1_areg', 'ar_EG', 'sms', 'positive',
        'ابعت فلوس، الحساب اتغير، حساب: INVENTED-ACCT-0003.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
    ),
    InventedFixture(
        'b1_areg_neg_no_payment', 'fam_b1_areg', 'ar_EG', 'sms', 'minimal_negative',
        'ابعت تقرير، الحساب اتغير، حساب: INVENTED-ACCT-0003.',
        (), {}, {},
    ),
    InventedFixture(
        'b1_franco_pos', 'fam_b1_franco', 'franco', 'sms', 'positive',
        'eb3at floos, el 7esab etghayar, 7esab: INVENTED-ACCT-0004.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
    ),
    InventedFixture(
        'b1_franco_neg_no_request', 'fam_b1_franco', 'franco', 'sms', 'minimal_negative',
        'floos, el 7esab etghayar, 7esab: INVENTED-ACCT-0004.',
        (), {}, {},
    ),
    # B2 across en, ar, ar_EG, franco
    InventedFixture(
        'b2_en_pos', 'fam_b2_en', 'en', 'email', 'positive',
        'Send payment, pay now.',
        ('B2',), {'B2': 'low'}, {'B2': 'single_signal'},
    ),
    InventedFixture(
        'b2_en_neg_no_urgency', 'fam_b2_en', 'en', 'email', 'minimal_negative',
        'Send payment for the monthly schedule.',
        (), {}, {},
    ),
    InventedFixture(
        'b2_ar_pos', 'fam_b2_ar', 'ar', 'email', 'positive',
        'حوّل دفعة، الدفع فوراً.',
        ('B2',), {'B2': 'low'}, {'B2': 'single_signal'},
    ),
    InventedFixture(
        'b2_areg_pos', 'fam_b2_areg', 'ar_EG', 'sms', 'positive',
        'ابعت فلوس، ادفع دلوقتي.',
        ('B2',), {'B2': 'low'}, {'B2': 'single_signal'},
    ),
    InventedFixture(
        'b2_franco_pos', 'fam_b2_franco', 'franco', 'sms', 'positive',
        'eb3at floos, edfa3 delwa2ty.',
        ('B2',), {'B2': 'low'}, {'B2': 'single_signal'},
    ),
    # B3 across en, ar, ar_EG, franco
    InventedFixture(
        'b3_en_pos', 'fam_b3_en', 'en', 'email', 'positive',
        'Send payment to new recipient, instapay: INVENTED-WALLET-0001.',
        ('B3',), {'B3': 'low'}, {'B3': 'single_signal'},
    ),
    InventedFixture(
        'b3_en_neg_unknown_newness', 'fam_b3_en', 'en', 'email', 'minimal_negative',
        'Send payment, instapay: INVENTED-WALLET-0001.',
        (), {}, {},
    ),
    InventedFixture(
        'b3_ar_pos', 'fam_b3_ar', 'ar', 'email', 'positive',
        'حوّل دفعة إلى مستفيد جديد، محفظة: INVENTED-WALLET-0002.',
        ('B3',), {'B3': 'low'}, {'B3': 'single_signal'},
    ),
    InventedFixture(
        'b3_areg_pos', 'fam_b3_areg', 'ar_EG', 'sms', 'positive',
        'ابعت فلوس لحد جديد، انستاباي: INVENTED-WALLET-0003.',
        ('B3',), {'B3': 'low'}, {'B3': 'single_signal'},
    ),
    InventedFixture(
        'b3_franco_pos', 'fam_b3_franco', 'franco', 'sms', 'positive',
        'eb3at floos le 7ad gedeed, ma7faza: INVENTED-WALLET-0004.',
        ('B3',), {'B3': 'low'}, {'B3': 'single_signal'},
    ),
    # B4 across en, ar, ar_EG, franco
    InventedFixture(
        'b4_en_pos', 'fam_b4_en', 'en', 'email', 'positive',
        'Buy gift card and send the redemption code.',
        ('B4',), {'B4': 'low'}, {'B4': 'single_signal'},
    ),
    InventedFixture(
        'b4_en_neg_no_urgency_or_code', 'fam_b4_en', 'en', 'email', 'minimal_negative',
        'Buy gift card for the office event.',
        (), {}, {},
    ),
    InventedFixture(
        'b4_ar_pos', 'fam_b4_ar', 'ar', 'email', 'positive',
        'اشتر بطاقة هدايا، ارسل رمز الاسترداد.',
        ('B4',), {'B4': 'low'}, {'B4': 'single_signal'},
    ),
    InventedFixture(
        'b4_areg_pos', 'fam_b4_areg', 'ar_EG', 'sms', 'positive',
        'اشتري كارت هدية، ابعت الكود.',
        ('B4',), {'B4': 'low'}, {'B4': 'single_signal'},
    ),
    InventedFixture(
        'b4_franco_pos', 'fam_b4_franco', 'franco', 'sms', 'positive',
        'eshtery kart hedeya w eb3at el code.',
        ('B4',), {'B4': 'low'}, {'B4': 'single_signal'},
    ),
    # B5 + bypass modifier across en, ar, ar_EG, franco
    InventedFixture(
        'b5_en_pos', 'fam_b5_en', 'en', 'email', 'positive',
        'I am the CEO, send payment, pay now, do not call to verify.',
        ('B2', 'B5'), {'B2': 'low', 'B5': 'low'}, {'B2': 'single_signal', 'B5': 'single_signal'},
        expected_bypass_on=('B2', 'B5'),
    ),
    InventedFixture(
        'b5_en_neg_authority_only', 'fam_b5_en', 'en', 'email', 'minimal_negative',
        'I am the CEO, please review the quarterly agenda.',
        (), {}, {},
    ),
    InventedFixture(
        'b5_ar_pos', 'fam_b5_ar', 'ar', 'email', 'positive',
        'أنا المدير التنفيذي، حوّل دفعة، الدفع فوراً، لا تتصل للتأكد.',
        ('B2', 'B5'), {'B2': 'low', 'B5': 'low'}, {'B2': 'single_signal', 'B5': 'single_signal'},
        expected_bypass_on=('B2', 'B5'),
    ),
    InventedFixture(
        'b5_areg_pos', 'fam_b5_areg', 'ar_EG', 'sms', 'positive',
        'أنا مديرك، ابعت فلوس، ادفع دلوقتي، ماتتصلش تتأكد.',
        ('B2', 'B5'), {'B2': 'low', 'B5': 'low'}, {'B2': 'single_signal', 'B5': 'single_signal'},
        expected_bypass_on=('B2', 'B5'),
    ),
    InventedFixture(
        'b5_franco_pos', 'fam_b5_franco', 'franco', 'sms', 'positive',
        'ana modeerak, eb3at floos, edfa3 delwa2ty, matetesselsh tet2aked.',
        ('B2', 'B5'), {'B2': 'low', 'B5': 'low'}, {'B2': 'single_signal', 'B5': 'single_signal'},
        expected_bypass_on=('B2', 'B5'),
    ),
)

# B6 and B7 source-conflict and corroborated-diversion fixtures across all 4 languages and both channels.
B6_B7_FIXTURES: tuple[InventedFixture, ...] = (
    # Email B6 via attested auth failure only (H without R -> no T1684.001, even with B5!)
    InventedFixture(
        'b6_email_auth_fail_with_b5_no_identity_conflict', 'fam_b6_email_h', 'en', 'email', 'positive',
        'I am your manager, send payment, pay now.',
        ('B2', 'B5', 'B6'),
        {'B2': 'low', 'B5': 'low', 'B6': 'medium'},
        {'B2': 'single_signal', 'B5': 'single_signal', 'B6': 'corroborated'},
        trust_state='user_attested_provider_report',
        headers='Received-SPF: fail envelope-from=x@example.eg\nAuthentication-Results: receiver.example.eg; dmarc=fail\n',
        attested=True, use_profile=True,
        expected_attack=(),
    ),
    # Email B6 via display claim conflict + DMARC-only fail (shared From-domain mismatch = ONE family, never B7!)
    InventedFixture(
        'b6_email_shared_from_domain_not_b7', 'fam_b6_email_shared', 'en', 'email', 'positive',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1', 'B6'),
        {'B1': 'low', 'B6': 'medium'},
        {'B1': 'single_signal', 'B6': 'corroborated'},
        trust_state='user_attested_provider_report_non_independent',
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: fail envelope-from=x@other.example.eg\nAuthentication-Results: receiver.example.eg; dmarc=fail\n',
        attested=True, use_profile=True, use_registry=True,
        expected_attack=('T1684.001',),
    ),
    # Email B7 across en, ar, ar_EG, franco (B1/B3 + R + independent DKIM failure H)
    InventedFixture(
        'b7_email_en', 'fam_b7_email_en', 'en', 'email', 'positive',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1', 'B6', 'B7'),
        {'B1': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B1': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='user_attested_independent_dkim_fail',
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
        expected_attack=('T1684.001',),
    ),
    InventedFixture(
        'b7_email_ar', 'fam_b7_email_ar', 'ar', 'email', 'positive',
        'حوّل دفعة، غيّر الحساب، ايبان: INVENTED-IBAN-0002.',
        ('B1', 'B6', 'B7'),
        {'B1': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B1': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='user_attested_independent_dkim_fail',
        author='بنك المثال المخترع <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
        expected_attack=('T1684.001',),
    ),
    InventedFixture(
        'b7_email_areg', 'fam_b7_email_areg', 'ar_EG', 'email', 'positive',
        'ابعت فلوس لحد جديد، انستاباي: INVENTED-WALLET-0003.',
        ('B3', 'B6', 'B7'),
        {'B3': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B3': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='user_attested_independent_dkim_fail',
        author='بنكنا المخترع <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
        expected_attack=('T1684.001',),
    ),
    InventedFixture(
        'b7_email_franco', 'fam_b7_email_franco', 'franco', 'email', 'positive',
        'eb3at floos le 7ad gedeed, ma7faza: INVENTED-WALLET-0004.',
        ('B3', 'B6', 'B7'),
        {'B3': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B3': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='user_attested_independent_dkim_fail',
        author='bank el methal el mo5tara3 <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
        expected_attack=('T1684.001',),
    ),
    # SMS B6 (contact-only mismatch, no link/secret -> T1684.001 only, NO T1660!)
    InventedFixture(
        'b6_sms_contact_only_no_t1660', 'fam_b6_sms_contact', 'en', 'sms', 'positive',
        f'This is Invented Example Bank; call {INVENTED_PHONE}; send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1', 'B6'),
        {'B1': 'low', 'B6': 'medium'},
        {'B1': 'single_signal', 'B6': 'corroborated'},
        trust_state='documented_complete_single_family',
        use_registry=True, sender_id='INVENTEDBANK',
        expected_attack=('T1684.001',),
    ),
    # SMS B7 across en, ar, ar_EG, franco (B1/B3 + independent domain AND contact mismatch families)
    InventedFixture(
        'b7_sms_en', 'fam_b7_sms_en', 'en', 'sms', 'positive',
        f'This is Invented Example Bank; click {INVENTED_URL}; send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1', 'B6', 'B7'),
        {'B1': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B1': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='documented_complete_dual_family',
        use_registry=True, sender_id='INVENTEDOTHER',
        expected_attack=('T1684.001', 'T1660'),
    ),
    InventedFixture(
        'b7_sms_ar', 'fam_b7_sms_ar', 'ar', 'sms', 'positive',
        f'نحن بنك المثال المخترع؛ اضغط {INVENTED_URL}؛ حوّل دفعة، غيّر الحساب، ايبان: INVENTED-IBAN-0002.',
        ('B1', 'B6', 'B7'),
        {'B1': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B1': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='documented_complete_dual_family',
        use_registry=True, sender_id='INVENTEDOTHER',
        expected_attack=('T1684.001', 'T1660'),
    ),
    InventedFixture(
        'b7_sms_areg', 'fam_b7_sms_areg', 'ar_EG', 'sms', 'positive',
        f'احنا بنكنا المخترع؛ دوس {INVENTED_URL}؛ ابعت فلوس لحد جديد، انستاباي: INVENTED-WALLET-0003.',
        ('B3', 'B6', 'B7'),
        {'B3': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B3': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='documented_complete_dual_family',
        use_registry=True, sender_id='INVENTEDOTHER',
        expected_attack=('T1684.001', 'T1660'),
    ),
    InventedFixture(
        'b7_sms_franco', 'fam_b7_sms_franco', 'franco', 'sms', 'positive',
        f'e7na bank el methal el mo5tara3; edghat {INVENTED_URL}; eb3at floos le 7ad gedeed, ma7faza: INVENTED-WALLET-0004.',
        ('B3', 'B6', 'B7'),
        {'B3': 'low', 'B6': 'medium', 'B7': 'high'},
        {'B3': 'single_signal', 'B6': 'corroborated', 'B7': 'corroborated'},
        trust_state='documented_complete_dual_family',
        use_registry=True, sender_id='INVENTEDOTHER',
        expected_attack=('T1684.001', 'T1660'),
    ),
)

# Invented benign and ambiguous controls (§4 & §8): ZERO medium/high findings allowed on any control.
BENIGN_AND_AMBIGUOUS_CONTROLS: tuple[InventedFixture, ...] = (
    # 1. Unknown newness (no explicit change/new-recipient cue)
    InventedFixture(
        'ctrl_unknown_newness', 'ctrl_newness', 'en', 'email', 'benign_control',
        'Send payment to account: INVENTED-ACCT-0001.',
        (), {}, {},
    ),
    # 2. Bare numbers / invoice IDs / order numbers / prices
    InventedFixture(
        'ctrl_bare_invoice_id', 'ctrl_invoice', 'en', 'email', 'benign_control',
        'Send payment for invoice: 900123 and order: 445566.',
        (), {}, {},
    ),
    # 3. Negated requests across languages
    InventedFixture(
        'ctrl_negated_en', 'ctrl_negated', 'en', 'email', 'benign_control',
        'Do not send payment or replace the account, iban: INVENTED-IBAN-0001.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_negated_ar', 'ctrl_negated', 'ar', 'email', 'benign_control',
        'لا تحول دفعة ولا تغير الحساب، ايبان: INVENTED-IBAN-0002.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_negated_areg', 'ctrl_negated', 'ar_EG', 'sms', 'benign_control',
        'ماتبعتش فلوس دلوقتي، الحساب اتغير، حساب: INVENTED-ACCT-0003.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_negated_franco', 'ctrl_negated', 'franco', 'sms', 'benign_control',
        'mateb3atsh floos delwa2ty, el 7esab etghayar, 7esab: INVENTED-ACCT-0004.',
        (), {}, {},
    ),
    # 4. Forwarded awareness examples and training warnings
    InventedFixture(
        'ctrl_awareness_en', 'ctrl_awareness', 'en', 'email', 'benign_control',
        'Fraud awareness training example: send payment, pay now, replace the account, iban: INVENTED-IBAN-0001.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_awareness_ar', 'ctrl_awareness', 'ar', 'sms', 'benign_control',
        'تحذير مثال: حوّل دفعة، الدفع فوراً، غيّر الحساب، ايبان: INVENTED-IBAN-0002.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_forwarded_block', 'ctrl_forwarded', 'en', 'email', 'benign_control',
        'Please see below.\n--- Forwarded message ---\nSend payment, pay now, iban: INVENTED-IBAN-0001.',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_quoted_line', 'ctrl_quoted', 'en', 'email', 'benign_control',
        '> I am the CEO, send payment, pay now.\n"Buy gift card and send the redemption code."',
        (), {}, {},
    ),
    # 5. Executive-title signatures vs active claims
    InventedFixture(
        'ctrl_ceo_signature', 'ctrl_signature', 'en', 'email', 'benign_control',
        'Please review the attached schedule.\n--\nI am the CEO\nSend payment, pay now',
        (), {}, {},
    ),
    InventedFixture(
        'ctrl_title_mention_only', 'ctrl_signature', 'en', 'email', 'benign_control',
        'The CEO and manager approved the quarterly report.',
        (), {}, {},
    ),
    # 6. Normal invoices
    InventedFixture(
        'ctrl_normal_invoice', 'ctrl_invoice', 'en', 'email', 'benign_control',
        'Monthly statement ready. Amount due 500 EGP.',
        (), {}, {},
    ),
    # 7. Gift-card shopping / past tense
    InventedFixture(
        'ctrl_gift_card_shopping', 'ctrl_gift', 'en', 'sms', 'benign_control',
        'Already sent gift card for the birthday party.',
        (), {}, {},
    ),
    # 8. Legitimate urgent payment (low informational review burden only; zero medium/high)
    InventedFixture(
        'ctrl_legit_urgent_payment', 'ctrl_legit_urgent', 'en', 'email', 'benign_control',
        'Send payment, pay now.',
        ('B2',), {'B2': 'low'}, {'B2': 'single_signal'},
        headers='Received-SPF: pass envelope-from=sender@example.eg\nAuthentication-Results: receiver.example.eg; dkim=pass; spf=pass; dmarc=pass\n',
        attested=True, use_profile=True,
    ),
    # 9. Legitimate announced account change with matching official provider domain (low only; zero medium/high)
    InventedFixture(
        'ctrl_legit_account_change', 'ctrl_legit_change', 'en', 'email', 'benign_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
        author='Invented Example Bank <sender@bank.example.eg>',
        headers='Received-SPF: pass envelope-from=sender@bank.example.eg\nAuthentication-Results: receiver.example.eg; dkim=pass; spf=pass; dmarc=pass\n',
        attested=True, use_profile=True, use_registry=True,
    ),
    # 10. Approved wallet-recipient change with matching SMS provider (low only; zero medium/high)
    InventedFixture(
        'ctrl_approved_wallet_change', 'ctrl_legit_wallet', 'en', 'sms', 'benign_control',
        'This is Invented Example Bank; click https://bank.example.eg/ok; send payment to new recipient, instapay: INVENTED-WALLET-0001.',
        ('B3',), {'B3': 'low'}, {'B3': 'single_signal'},
        use_registry=True, sender_id='INVENTEDBANK',
    ),
    # 11. Unverified grammar on account change with contradicting source (capped at low/undetermined; cannot trigger B6/B7!)
    InventedFixture(
        'ctrl_unverified_grammar_no_escalation', 'ctrl_grammar_cap', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'undetermined'},
        use_grammar=False,
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
    ),
    # 12. Forged/untrusted headers without provider identity claim (cannot trigger B6/B7!)
    InventedFixture(
        'ctrl_untrusted_headers_no_escalation', 'ctrl_untrusted_hdr', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
        headers='Received-SPF: fail envelope-from=x@example.eg\nAuthentication-Results: receiver.example.eg; dkim=fail; dmarc=fail\n',
        attested=False, use_profile=True,
    ),
    # 13. Partial registry coverage on provider mismatch (cannot trigger B6/B7!)
    InventedFixture(
        'ctrl_partial_registry_no_escalation', 'ctrl_partial_reg', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
        author='Invented Example Bank <sender@other.example.eg>',
        use_registry=True, registry_coverage='documented_partial',
    ),
    # 14. Stale registry coverage on provider mismatch (cannot trigger B6/B7!)
    InventedFixture(
        'ctrl_stale_registry_no_escalation', 'ctrl_stale_reg', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        ('B1',), {'B1': 'low'}, {'B1': 'single_signal'},
        author='Invented Example Bank <sender@other.example.eg>',
        use_registry=True, registry_stale=True,
    ),
    # 15. Ambiguous inline quote on request clause (prevents B6/B7 escalationeven with full source conflict)
    InventedFixture(
        'ctrl_ambiguous_inline_quote', 'ctrl_ambiguous_quote', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001. Note: "send" confirmation.',
        ('B1',), {'B1': 'low'}, {'B1': 'undetermined'},
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
    ),
    # 16. Forwarded subject header sets payment_context_ambiguous and prevents active payment rule firing
    InventedFixture(
        'ctrl_forwarded_subject_ambiguous', 'ctrl_fwd_subject', 'en', 'email', 'ambiguous_control',
        'Send payment, replace the account, iban: INVENTED-IBAN-0001.',
        (), {}, {},
        subject='Fwd: Urgent invoice',
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
    ),
)


def _build_snapshot(tmp_path: Path, case: InventedFixture):
    if not case.use_registry:
        return None
    from provider_fixtures import invented_registry
    case_dir = tmp_path / f'reg_{case.fixture_id}'
    case_dir.mkdir(exist_ok=True)
    payload = invented_registry()
    payload['entries'][0]['domains'][0]['channel'] = 'any'
    if case.registry_coverage != 'documented_complete':
        payload['entries'][0]['coverage']['domains'] = case.registry_coverage
    if case.registry_stale:
        payload['entries'][0]['review_due_at'] = '2026-11-26'
    return write_invented_registry(case_dir, payload)


def _format_author(author: str) -> str:
    from email.header import Header
    if '<' in author and not author.isascii():
        display, rest = author.split('<', 1)
        encoded = Header(display.strip(), 'utf-8').encode()
        return f'{encoded} <{rest}'
    return author


def evaluate_fixture(tmp_path: Path, case: InventedFixture) -> Review:
    assert case.invented is True
    grammar = SYNTHETIC_GRAMMAR if case.use_grammar else None
    snapshot = _build_snapshot(tmp_path, case)
    if case.channel == 'sms':
        return review_sms(
            case.text,
            sender_id=case.sender_id,
            sender_display=case.sender_display,
            snapshot=snapshot,
            grammar=grammar,
        )
    case_dir = tmp_path / f'eml_{case.fixture_id}'
    case_dir.mkdir(exist_ok=True)
    eml_path = case_dir / 'invented.eml'
    raw = (
        f'{case.headers}From: {_format_author(case.author)}\n'
        f'Subject: {case.subject}\n'
        f'Content-Type: text/plain; charset="utf-8"\n'
        f'Content-Transfer-Encoding: 8bit\n\n'
        f'{case.text}\n'
    )
    eml_path.write_bytes(raw.encode('utf-8'))
    return import_eml(
        eml_path,
        profile=PROFILE if case.use_profile else None,
        attested=case.attested,
        snapshot=snapshot,
        grammar=grammar,
        scorer=lambda _u: {'probability': 0.0, 'threshold': 0.99, 'version': 'invented-stub'},
    )


@pytest.mark.parametrize('case', LANGUAGE_B1_B5_FIXTURES + B6_B7_FIXTURES, ids=lambda c: c.fixture_id)
def test_fixed_rules_b1_to_b7_across_languages_and_channels(tmp_path, case):
    review = evaluate_fixture(tmp_path, case)
    payment_findings = [f for f in review.findings if f.engine.name == ENGINE and f.kind != 'payment_check_incomplete']
    by_rule = {f.evidence.details['rule_id']: f for f in payment_findings}
    assert tuple(sorted(by_rule)) == tuple(sorted(case.expected_rules))
    for rule_id, finding in by_rule.items():
        expected_kind, expected_reason = RULES[rule_id]
        assert finding.kind == expected_kind
        assert finding.evidence.reasons[0] == expected_reason
        assert finding.severity == case.expected_severities[rule_id]
        assert finding.confidence == case.expected_confidences[rule_id]
        assert finding.severity != 'critical' and finding.confidence != 'confirmed'
        assert finding.evidence.details['manifest_sha256'] == MANIFEST
        assert finding.evidence.details['phrase_ids']
        assert not finding.indicators
        has_bypass = 'payment_verification_bypass' in finding.evidence.reasons
        assert has_bypass == (rule_id in case.expected_bypass_on)
    emitted_attack = {a.technique_id for f in payment_findings for a in f.attack}
    assert emitted_attack == set(case.expected_attack)
    assert 'T1657' not in emitted_attack
    assert 'T1656' not in emitted_attack
    assert 'T1566.004' not in emitted_attack


def test_false_alarm_gates_on_invented_benign_and_ambiguous_controls(tmp_path):
    """§4 gates:
    - Zero medium/high Findings on all invented benign or ambiguous controls (per rule and union).
    - Low Findings are tracked explicitly as review burden.
    - Zero high Findings from content alone, untrusted headers, unknown recipient history,
      partial/stale source coverage, or one duplicated From-domain source-conflict family.
    """
    union_medium_high = 0
    per_rule_medium_high = {rule: 0 for rule in RULES}
    low_review_burden = 0
    ambiguous_info_count = 0

    for case in BENIGN_AND_AMBIGUOUS_CONTROLS:
        review = evaluate_fixture(tmp_path, case)
        payment_findings = [f for f in review.findings if f.engine.name == ENGINE]
        active = [f for f in payment_findings if f.kind != 'payment_check_incomplete']
        incomplete = [f for f in payment_findings if f.kind == 'payment_check_incomplete']
        if incomplete:
            ambiguous_info_count += 1
            assert all(
                f.severity == 'info'
                and f.confidence == 'undetermined'
                and f.evidence.reasons == ['payment_context_ambiguous']
                and not f.attack
                for f in incomplete
            )
        by_rule = {f.evidence.details['rule_id']: f for f in active}
        assert tuple(sorted(by_rule)) == tuple(sorted(case.expected_rules)), case.fixture_id
        if any(f.severity in ('medium', 'high', 'critical') for f in active):
            union_medium_high += 1
        for rule_id, finding in by_rule.items():
            assert finding.severity == case.expected_severities[rule_id]
            assert finding.confidence == case.expected_confidences[rule_id]
            if finding.severity in ('medium', 'high', 'critical'):
                per_rule_medium_high[rule_id] += 1
            if finding.severity == 'low':
                low_review_burden += 1

    assert union_medium_high == 0
    assert all(count == 0 for count in per_rule_medium_high.values())
    assert low_review_burden == 8  # explicitly tracked review burden on legitimate/capped low observations
    assert ambiguous_info_count == 2


def test_url_model_signal_never_satisfies_b6_or_b7(tmp_path):
    eml = tmp_path / 'model_signal.eml'
    eml.write_bytes(
        b'From: Tester <sender@example.eg>\n'
        b'Subject: Payment\n\n'
        b'Send payment, replace the account, iban: INVENTED-IBAN-0001. https://example.eg/link\n'
    )
    review = import_eml(
        eml,
        grammar=SYNTHETIC_GRAMMAR,
        scorer=lambda _u: {'probability': 0.999, 'threshold': 0.5, 'version': 'invented-model'},
    )
    assert any(f.kind == 'email_link_model_observation' for f in review.findings)
    payment_rules = {f.evidence.details['rule_id']: f for f in review.findings if f.engine.name == ENGINE}
    assert set(payment_rules) == {'B1'}
    assert payment_rules['B1'].severity == 'low'


def test_destination_values_are_never_confusable_or_case_folded_and_url_punctuation_stays_inert():
    # Uppercase grammar must not match a lowercased destination value, proving raw tokens are not folded.
    upper_review = Review()
    apply_payment_rules(
        upper_review,
        ['Send payment via https://example.eg/a.b;c?pay=now to sender.pay@example.eg, replace the account, IBAN: INVENTED-IBAN-0001'],
        'email',
        versions={},
        grammar=SYNTHETIC_GRAMMAR,
    )
    f_upper, = upper_review.findings
    assert f_upper.confidence == 'single_signal'
    assert f_upper.evidence.details['grammar'] == 'usable'

    lower_review = Review()
    apply_payment_rules(
        lower_review,
        ['Send payment, replace the account, IBAN: invented-iban-0001'],
        'email',
        versions={},
        grammar=SYNTHETIC_GRAMMAR,
    )
    f_lower, = lower_review.findings
    assert f_lower.confidence == 'undetermined'
    assert f_lower.evidence.details['grammar'] == 'destination_label_present'

    # Words inside URLs or email addresses must never trigger payment rules.
    inert_review = Review()
    apply_payment_rules(
        inert_review,
        ['Check https://example.eg/send.payment;pay_now=1 or contact send.payment@example.eg'],
        'email',
        versions={},
        grammar=SYNTHETIC_GRAMMAR,
    )
    assert inert_review.findings == []


def test_cross_message_and_mismatched_version_dependencies_are_rejected(tmp_path):
    from app.core.findings import SourceRef
    review = Review()
    # Add a fake provider conflict with a different source ref and another with a mismatched engine version.
    wrong_ref = review.add(
        PROVIDER, 'provider-v1+expected', 'provider_proof_mismatch', 'provider_domain_outside_set',
        'medium', 'single_signal',
        details={'coverage': 'documented_complete', 'proof_state': 'outside_documented_set', 'evidence_family': 'domain'},
    )
    review.findings[-1] = wrong_ref.model_copy(update={'source': SourceRef(kind='import', ref='other-message-ref')})
    review.add(
        PROVIDER, 'provider-v1+stale-version', 'provider_proof_mismatch', 'provider_domain_outside_set',
        'medium', 'single_signal',
        details={'coverage': 'documented_complete', 'proof_state': 'outside_documented_set', 'evidence_family': 'domain'},
    )
    apply_payment_rules(
        review,
        ['Send payment, replace the account, iban: INVENTED-IBAN-0001'],
        'sms',
        versions={PROVIDER: 'provider-v1+expected'},
        grammar=SYNTHETIC_GRAMMAR,
    )
    payment_rules = {f.evidence.details['rule_id'] for f in review.findings if f.engine.name == ENGINE}
    assert payment_rules == {'B1'}


def test_repeated_cues_produce_one_finding_per_rule_and_preserve_dependencies(tmp_path):
    case = next(c for c in B6_B7_FIXTURES if c.fixture_id == 'b7_email_en')
    duplicated = InventedFixture(
        **{
            **case.__dict__,
            'fixture_id': 'b7_email_en_dup',
            'text': (
                'Send payment, replace the account, iban: INVENTED-IBAN-0001. '
                'Transfer money, change the account, iban: INVENTED-IBAN-0002.'
            ),
        }
    )
    review = evaluate_fixture(tmp_path, duplicated)
    payment_findings = [f for f in review.findings if f.engine.name == ENGINE]
    rule_ids = [f.evidence.details['rule_id'] for f in payment_findings]
    assert rule_ids == ['B1', 'B6', 'B7']
    dep_ids = {f.id for f in review.findings if f.engine.name == EMAIL and f.severity != 'info'}
    assert set(payment_findings[-1].evidence.details['dependency_ids']) == dep_ids
    assert payment_findings[-1].evidence.details['supporting_rules'] == ['B1']


def test_no_payment_recipients_or_hashes_stored_anywhere_and_attack_validates(tmp_path, db, caplog):
    fixture = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-subset.json').read_text(encoding='utf-8'))
    for matrix in ('enterprise', 'mobile'):
        db.add_all(AttackTechnique(**r) for r in parse_techniques(fixture['objects'][matrix], matrix, '20.0'))
    db.flush()

    secret_iban = 'INVENTED-IBAN-9876'
    secret_wallet = 'INVENTED-WALLET-5432'
    secret_account = 'INVENTED-ACCT-1122'
    secret_code = 'INVENTED-GIFT-CODE-7788'
    secret_beneficiary = 'InventedBeneficiaryMarker'
    secret_amount = '987654EGP'

    email_case = InventedFixture(
        'privacy_email', 'fam_privacy', 'en', 'email', 'positive',
        f'I am the CEO, send payment {secret_amount} to {secret_beneficiary}, replace the account, '
        f'iban: {secret_iban}, bank account: {secret_account}, do not call to verify. '
        f'Buy gift card and send the redemption code {secret_code}.',
        ('B1', 'B4', 'B5', 'B6', 'B7'), {}, {},
        author='Invented Example Bank <sender@other.example.eg>',
        headers='Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail; spf=fail\n',
        attested=True, use_profile=True, use_registry=True,
    )
    sms_case = InventedFixture(
        'privacy_sms', 'fam_privacy', 'en', 'sms', 'positive',
        f'This is Invented Example Bank; click {INVENTED_URL}; '
        f'send payment to new recipient, instapay: {secret_wallet}.',
        ('B3', 'B6', 'B7'), {}, {},
        use_registry=True, sender_id='INVENTEDOTHER',
    )

    email_review = evaluate_fixture(tmp_path, email_case)
    sms_review = evaluate_fixture(tmp_path, sms_case)

    payment_findings = [
        f for f in (*email_review.findings, *sms_review.findings)
        if f.engine.name == ENGINE
    ]
    records = record_findings(db, payment_findings)
    db.commit()

    assert len(records) == 8
    # Content-only and payment-rule Findings carry no payment indicators and open no recipient-pivoted incidents.
    assert db.query(Indicator).count() == 0
    assert db.query(FindingIndicator).count() == 0
    assert db.query(Incident).count() == 0

    attacks = {(a.technique_id, a.matrix, a.basis) for a in db.query(FindingAttack)}
    assert attacks == {
        ('T1684.001', 'enterprise', 'payment_claim_identity_conflict'),
        ('T1660', 'mobile', 'sms_deceptive_action'),
    }
    assert 'T1657' not in {a[0] for a in attacks}

    stored = []
    from sqlalchemy import text as sql_text
    for table in db.bind.dialect.get_table_names(db.connection()):
        stored.extend(tuple(row) for row in db.execute(sql_text(f'SELECT * FROM "{table}"')))
    serialized = (
        json.dumps(email_review.public())
        + json.dumps(sms_review.public())
        + json.dumps(stored, default=str)
        + caplog.text
    )

    forbidden_values = (
        secret_iban,
        secret_wallet,
        secret_account,
        secret_code,
        secret_beneficiary,
        secret_amount,
        INVENTED_PHONE,
    )
    for raw_val in forbidden_values:
        for candidate in (raw_val, raw_val.lower(), raw_val.upper()):
            digest = hashlib.sha256(candidate.encode('utf-8')).hexdigest()
            assert candidate not in serialized
            assert digest not in serialized


def test_cli_sms_stdin_and_limit_guard():
    text = 'Send payment, pay now.'
    review = review_sms(text)
    payload = review.public()
    assert payload['persistence'] == DISABLED
    assert [f['evidence']['reasons'][0] for f in payload['findings']] == ['payment_urgent_request']
    with pytest.raises(ImportErrorCode, match='^sms_import_limit_exceeded$'):
        review_sms('x' * 5001)
