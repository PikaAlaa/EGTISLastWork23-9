"""Finite, offline BEC rules. Only codes and types survive clause evaluation."""
from dataclasses import dataclass
import re

from app.core.findings import AttackRef
from app.core.provider_registry import digest_json
from app.engines.provider_claims import claim_view

PHRASES = {
    'request': ('send', 'transfer', 'pay', 'buy', 'purchase', 'حوّل', 'ارسل', 'ادفع', 'اشتر', 'ابعت', 'اشتري', 'eb3at', 'edfa3', 'eshtery'),
    'payment': ('payment', 'money', 'pay', 'دفعة', 'الدفع', 'ادفع', 'فلوس', 'floos', 'edfa3'),
    'change': ('replace the account', 'change the account', 'use the new account', 'غيّر الحساب', 'الحساب اتغير', 'el 7esab etghayar'),
    'urgent': ('urgent', 'pay now', 'immediately', 'الدفع فوراً', 'فوراً', 'ادفع دلوقتي', 'دلوقتي', 'edfa3 delwa2ty', 'delwa2ty'),
    'new': ('new recipient', 'مستفيد جديد', 'لحد جديد', 'le 7ad gedeed'),
    'wallet': ('wallet', 'instapay', 'محفظة', 'انستاباي', 'ma7faza'),
    'gift': ('gift card', 'gift cards', 'بطاقة هدايا', 'كارت هدية', 'kart hedeya'),
    'code': ('send the redemption code', 'ارسل رمز الاسترداد', 'ابعت الكود', 'eb3at el code'),
    'authority': ('i am your manager', 'i am the ceo', 'your manager asks you to', 'انا المدير التنفيذي', 'انا مديرك', 'ana modeerak'),
    'bypass': ('do not call to verify', 'لا تتصل للتأكد', 'ماتتصلش تتأكد', 'matetesselsh tet2aked'),
    'exclude': ('do not', "don't", 'never', 'beware', 'training example', 'fraud awareness', 'for example',
                'was asked to', 'already sent', 'لا ترسل', 'لا تحول', 'لا تدفع', 'تحذير', 'مثال', 'ماتبعتش', 'mateb3atsh'),
}
LABELS = {'bank_account': ('bank account', 'account', 'حساب', '7esab'), 'iban': ('iban', 'ايبان'),
          'wallet': PHRASES['wallet']}
RULES = {
    'B1': ('payment_change_request', 'payment_destination_change'),
    'B2': ('payment_pressure_request', 'payment_urgent_request'),
    'B3': ('payment_change_request', 'payment_new_transfer_recipient'),
    'B4': ('payment_pressure_request', 'payment_gift_card_request'),
    'B5': ('payment_authority_request', 'payment_authority_claim'),
    'B6': ('payment_source_conflict', 'payment_request_source_conflict'),
    'B7': ('payment_diversion_suspected', 'payment_diversion_corroborated'),
}
MANIFEST = digest_json([PHRASES, LABELS, RULES, 'payment-clauses-v1'])
PROVIDER = 'phishing.provider_claim'
EMAIL = 'phishing.email_headers'


def _pattern(words):
    return re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(claim_view(w)) for w in words) + r')(?!\w)')


WORDS = {name: _pattern(words) for name, words in PHRASES.items()}
DESTINATIONS = {kind: re.compile(_pattern(words).pattern + r'$')
                for kind, words in LABELS.items()}


@dataclass(frozen=True)
class DestinationGrammar:
    """An explicitly reviewed grammar supplied by the local caller. Production has none."""
    name: str
    pattern: str

    @property
    def version(self):
        return digest_json([self.name, self.pattern])


def _clauses(lines):
    for line in lines:
        # Remove delivery/address tokens before splitting. Their punctuation and
        # contents cannot become independent words. Never retain or hash these values.
        prose = re.sub(r'https?://\S+|(?<!\w)[\w.+-]+@[\w.-]+', ' ', line, flags=re.I)
        yield from re.split(r'[.;؛؟\n]', prose)


def _content(raw_clause, grammar):
    clause = claim_view(raw_clause)
    bypass = WORDS['bypass'].search(clause) is not None
    clause = WORDS['bypass'].sub(' ', clause)
    if WORDS['exclude'].search(clause) or any(c in raw_clause for c in '"“”«»'):
        return {}, False
    cues = {k for k, pat in WORDS.items() if pat.search(clause)}
    if 'request' not in cues:
        return {}, False
    result = {}
    if 'payment' in cues:
        for match in re.finditer(r'[:=]\s*([^\s;,؛:=]+)', raw_clause):
            prefix = claim_view(raw_clause[:match.start()])
            # Account/destination values are never normalized with a confusable fold.
            verified = bool(grammar and re.fullmatch(grammar.pattern, match[1]))
            for kind, pattern in DESTINATIONS.items():
                if not pattern.search(prefix):
                    continue
                if kind in ('bank_account', 'iban') and 'change' in cues:
                    if 'B1' not in result or verified:
                        result['B1'] = (kind, verified, ('change', 'payment', 'request'))
                if kind == 'wallet' and ('new' in cues or 'change' in cues):
                    if 'B3' not in result or verified:
                        phrases = tuple(sorted({'payment', 'request', 'wallet'} | ({'new', 'change'} & cues)))
                        result['B3'] = (kind, verified, phrases)
        if 'urgent' in cues:
            result['B2'] = ('none', True, ('payment', 'request', 'urgent'))
    if 'gift' in cues and {'urgent', 'code'} & cues:
        phrases = tuple(sorted({'gift', 'request'} | ({'urgent', 'code'} & cues)))
        result['B4'] = ('gift_card', True, phrases)
    if result and 'authority' in cues:
        phrases = tuple(sorted({'authority', *(p for _, _, ps in result.values() for p in ps)}))
        result['B5'] = ('none', any(valid for _, valid, _ in result.values()), phrases)
    return result, bypass


def apply_payment_rules(review, lines, channel, *, versions, grammar=None):
    """Use only findings from this import and the exact dependency versions supplied by its caller."""
    candidates = {}
    bypass_rules = set()
    ambiguous = 'payment_context_ambiguous' in review.coverage
    for raw_clause in _clauses(lines):
        clause = claim_view(raw_clause)
        if WORDS['request'].search(clause) and any(c in raw_clause for c in '"“”«»'):
            ambiguous = True
            continue
        matches, bypass = _content(raw_clause, grammar)
        for rule, state in matches.items():
            if rule not in candidates or state[1]:
                candidates[rule] = state
        if bypass:
            bypass_rules.update(matches)
    if ambiguous:
        review.coverage.add('payment_context_ambiguous')
    deps = [f for f in review.findings if f.source.ref == review.ref and f.source.kind == 'import'
            and f.engine.version == versions.get(f.engine.name)]
    def matches(f, engine, reason):
        return f.engine.name == engine and reason in f.evidence.reasons
    identities = [f for f in deps if f.severity in ('medium', 'high')
                  and f.evidence.details.get('coverage') == 'documented_complete'
                  and (matches(f, EMAIL, 'email_provider_display_claim_conflict') or
                       (f.engine.name == PROVIDER and f.kind == 'provider_proof_mismatch'
                        and f.evidence.details.get('proof_state') == 'outside_documented_set'))]
    reports = [f for f in deps if channel == 'email' and matches(f, EMAIL, 'email_provider_auth_failure_reported')
               and f.evidence.details.get('trust') == 'user_attested_provider_report']
    families = {f.evidence.details.get('evidence_family') for f in identities}
    independent = (bool(identities) and any(f.evidence.details.get('independent') for f in reports)
                   if channel == 'email' else {'contact', 'domain'} <= families)
    eligible = {rule for rule, (_, verified, _) in candidates.items() if verified and not ambiguous}
    eligible_phrases = tuple(sorted({p for r in eligible for p in candidates[r][2]}))
    if eligible and (identities or reports) and not ambiguous:
        candidates['B6'] = ('none', True, eligible_phrases)
        if eligible & {'B1', 'B3'} and independent:
            candidates['B7'] = ('none', True, eligible_phrases)
    grammar_version = grammar.version if grammar else 'to_verify'
    version = 'payment-v1+' + digest_json([MANIFEST, versions, grammar_version])
    if ambiguous:
        review.add('phishing.payment_rules', version, 'payment_check_incomplete', 'payment_context_ambiguous',
                   'info', 'undetermined')
    for rule, (kind, verified, phrases) in sorted(candidates.items()):
        finding_kind, reason = RULES[rule]
        combined = rule in ('B6', 'B7')
        phrase_ids = sorted({*phrases, *(('bypass',) if rule in bypass_rules else ())})
        details = {'rule_id': rule, 'phrase_ids': phrase_ids, 'destination_type': kind,
                   'explicit_change': rule in ('B1', 'B3', 'B7'),
                   'grammar': 'usable' if verified else 'destination_label_present',
                   'manifest_sha256': MANIFEST, 'grammar_version': grammar_version}
        attack = []
        if combined:
            details['supporting_rules'] = sorted(eligible)
            details['dependency_ids'] = [f.id for f in identities + reports]
            if identities:
                attack.append(AttackRef(technique_id='T1684.001', matrix='enterprise', attack_version='20.0',
                                        basis='payment_claim_identity_conflict'))
            if channel == 'sms' and any(a.basis == 'sms_deceptive_action' and a.technique_id == 'T1660'
                                        for f in identities for a in f.attack):
                attack.append(AttackRef(technique_id='T1660', matrix='mobile', attack_version='20.0',
                                        basis='sms_deceptive_action'))
        f = review.add('phishing.payment_rules', version, finding_kind, reason,
                       'high' if rule == 'B7' else 'medium' if combined else 'low',
                       'corroborated' if combined else 'single_signal' if (verified and not ambiguous) else 'undetermined',
                       details=details, attack=attack)
        if rule in bypass_rules:
            f.evidence.reasons.append('payment_verification_bypass')
    return review
