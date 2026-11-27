"""Offline statements in an export. No production receiving profiles have been reviewed.

To verify: provider insertion/stripping boundaries and method grammars (RFCs
8601, 7208, 6376, 7489 and updates), ARC semantics (8617), delegation scope.
The small parser accepts a strict subset and treats other syntax as unavailable.
"""
from dataclasses import dataclass
import re

from app.core.provider_registry import digest_json


@dataclass(frozen=True)
class ReceiverProfile:
    """Trusted configuration from code, never from a submitted message."""
    profile_id: str
    authserv_id: str
    prefix: tuple[str, ...]  # exact sequence of leading field names ending at Authentication-Results
    source: str
    read_date: str
    verifier: str
    # Exact From/destination host pair and role, from the same reviewed publication.
    delegations: tuple[tuple[str, str, str], ...] = ()

    @property
    def version(self):
        return digest_json(vars(self))


PROFILES: dict[str, ReceiverProfile] = {}
RESULTS = {
    'spf': {'pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'},
    'dkim': {'pass', 'fail', 'neutral', 'none', 'temperror', 'permerror'},
    'dmarc': {'pass', 'fail', 'none', 'temperror', 'permerror'},
}
METHOD = re.compile(r'([a-z][a-z0-9_-]*)=([a-z]+)((?:\s+[\w.-]+=[\w.@+-]+)*)', re.I)
# Every code `phishing.email_headers` Findings (built in app/services/mail_import.py) can carry in
# evidence.reasons, including the email_check_incomplete coverage codes (design core-v2 §2.2).
REASON_CODES = frozenset({
    'email_provider_auth_failure_reported', 'email_reply_to_domain_differs', 'email_return_path_domain_differs',
    'email_provider_display_claim_conflict', 'email_link_model_signal',
    'email_auth_not_visible', 'email_auth_report_conflict', 'email_auth_report_untrusted',
    'email_from_not_visible', 'email_identity_ambiguous', 'email_url_model_unavailable',
    'provider_registry_unavailable', 'provider_claim_ambiguous', 'provider_registry_stale',
    'provider_suffix_unavailable', 'payment_context_ambiguous'})


@dataclass(frozen=True)
class Report:
    trust: str
    methods: tuple[tuple[str, str], ...]
    reason: str | None
    arc: str
    independent: bool = False


def _arc_state(headers):
    sets = []
    for key in ('ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results'):
        values = headers.get_all(key, [])
        instances = [re.search(r'(?:^|;)\s*i=(\d+)\s*;', str(v), re.I) for v in values]
        if any(item is None for item in instances):
            return 'reported_arc_incomplete'
        ids = [int(item[1]) for item in instances]
        if len(set(ids)) != len(ids) or ids != sorted(ids, reverse=True):
            return 'reported_arc_conflict'
        sets.append(ids)
    if not any(sets):
        return 'absent'
    if not all(sets):
        return 'reported_arc_incomplete'
    if sets[0] != sets[1] or sets[0] != sets[2] or sorted(sets[0]) != list(range(1, len(sets[0]) + 1)):
        return 'reported_arc_conflict'
    return 'reported_arc_present'


def authentication(headers, profile=None, attested=False):
    arc = _arc_state(headers)
    fields = [(k.lower(), str(v).strip()) for k, v in headers.items()]
    reports = [(i, v.split(';')) for i, (k, v) in enumerate(fields) if k == 'authentication-results']
    candidates = [(i, pieces) for i, pieces in reports if profile and pieces[0].strip().lower() == profile.authserv_id]
    unavailable = 'untrusted_header_report'
    if not reports:
        return Report(unavailable, (), 'email_auth_not_visible', arc)
    if len(candidates) > 1:
        return Report(unavailable, (), 'email_auth_report_conflict', arc)
    pos, pieces = candidates[0] if candidates else reports[0]
    methods, envelope, unsupported = [], None, False
    for raw in pieces[1:]:
        match = METHOD.fullmatch(raw.strip())
        if not match or match[1].lower() not in RESULTS:
            unsupported = True
            continue
        method, result = match[1].lower(), match[2].lower()
        methods.append((method, result if result in RESULTS[method] else 'unknown'))
        if method == 'spf':
            prop = re.search(r'\bsmtp\.mailfrom=([\w.@+-]+)', match[3], re.I)
            envelope = prop[1].lower() if prop else None
    methods = tuple(methods)
    if not (attested and candidates and tuple(k for k, _ in fields[:pos+1]) == profile.prefix):
        return Report(unavailable, methods, 'email_auth_report_untrusted', arc)
    if len(methods) != len(dict(methods)):
        return Report(unavailable, methods, 'email_auth_report_conflict', arc)
    states = dict(methods)
    # Only Received-SPF in the reviewed prefix may be used; compare equal envelope identities.
    for key, raw in fields[:pos]:
        if key == 'received-spf' and envelope:
            other = re.search(r'(?:^|[;\s])envelope-from=([\w.@+-]+)', raw, re.I)
            if other and other[1].lower() == envelope and raw.split()[0].lower() != states['spf']:
                return Report(unavailable, methods, 'email_auth_report_conflict', arc)
    if unsupported or not methods or 'unknown' in states.values():
        return Report(unavailable, methods, 'email_auth_not_visible', arc)
    fallback = [v for k, v in methods if k in ('spf', 'dkim')]
    fail = states.get('dmarc') == 'fail' or (fallback and all(v == 'fail' for v in fallback)
                                            and 'pass' not in states.values())
    # Only an explicitly separate DKIM failure supplies independent identity evidence.
    return Report('user_attested_provider_report', methods, 'email_provider_auth_failure_reported' if fail else None,
                  arc, bool(fail and states.get('dkim') == 'fail'))
