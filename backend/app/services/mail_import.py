"""Local CLI: from backend run python -m app.services.mail_import path/to/message.eml."""
import argparse
from dataclasses import dataclass, field
from email.headerregistry import Address
import json
from pathlib import Path
import re
from uuid import uuid4

from app.core.findings import AttackRef, Evidence, Finding, IndicatorRef, utc_now
from app.core.indicators import normalize_domain, normalize_url
from app.core.provider_registry import RegistryUnavailable, load_bundled_registry
from app.engines.email_headers import PROFILES, authentication
from app.engines.provider_claims import (ProviderClaimEngine, claim_view, claimed_providers,
                                         match_domain, suffix_snapshot_available)
from app.engines.payment_rules import EMAIL, PROVIDER, _clauses, _content, apply_payment_rules
from app.engines.registry import Observation
from app.core.url_utils import MAX_TEXT_LENGTH
from app.engines.url_model import score_url
from app.services.eml_reader import ImportErrorCode, read_eml

DISABLED = 'import_persistence_disabled_retention_unresolved'


@dataclass
class Review:
    ref: str = field(default_factory=lambda: str(uuid4()))
    findings: list[Finding] = field(default_factory=list)
    coverage: set[str] = field(default_factory=set)
    reported: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)

    def add(self, engine, version, kind, reason, severity, confidence, *, details=None, attack=(), indicators=()):
        now = utc_now()
        finding = Finding(engine={'name': engine, 'version': version}, domain='phishing', kind=kind,
                          severity=severity, confidence=confidence, evidence=Evidence(reasons=[reason], details=details or {}),
                          attack=list(attack), indicators=list(indicators), observed_at=now, created_at=now,
                          source={'kind': 'import', 'ref': self.ref})
        self.findings.append(finding)
        return finding

    def public(self):
        return {'persistence': DISABLED, 'coverage': sorted(self.coverage), 'reported': self.reported,
                'findings': [f.model_dump(mode='json') for f in self.findings]}


def mailbox(headers, field, coverage):
    values = headers.get_all(field, [])
    if not values or (field == 'Return-Path' and str(values[0]).strip() == '<>' and len(values) == 1):
        return None
    try:
        if len(values) != 1 or getattr(values[0], 'defects', ()):
            raise ValueError
        if field == 'Return-Path':
            path = re.fullmatch(r'<([^<>]+)>', str(values[0]).strip())
            if not path:
                raise ValueError
            addresses = [Address(addr_spec=path[1])]
        else:
            addresses = values[0].addresses
        if len(addresses) != 1 or not addresses[0].username:
            raise ValueError
        return addresses[0].display_name, normalize_domain(addresses[0].domain)
    except (ValueError, IndexError, AttributeError):
        coverage.add('email_identity_ambiguous')
        return None


def review_parts(parts, *, profile=None, attested=False, snapshot=None, scorer=score_url):
    review = Review()
    review.coverage.update(parts.coverage)
    headers = parts.headers
    report = authentication(headers, profile, attested)
    review.reported = {'trust': report.trust, 'methods': report.methods, 'arc': report.arc}
    try:
        snapshot = snapshot or load_bundled_registry()
    except RegistryUnavailable:
        review.coverage.add('provider_registry_unavailable')
    version = 'email-v1+' + (profile.version if profile else 'no-profile') + '+' + (
        snapshot.pin.registry_sha256 if snapshot else 'no-registry')
    review.versions[EMAIL] = version

    def add(kind, reason, severity, confidence, **kwargs):
        return review.add('phishing.email_headers', version, kind, reason, severity, confidence, **kwargs)

    if report.reason == 'email_provider_auth_failure_reported':
        add('email_auth_reported_failure', report.reason, 'low', 'single_signal',
            details={'trust': report.trust, 'independent': report.independent})
    elif report.reason:
        review.coverage.add(report.reason)
    author = mailbox(headers, 'From', review.coverage)
    if not author:
        review.coverage.add('email_from_not_visible')
    suffix_ok = suffix_snapshot_available()
    for field, reason in [('Reply-To', 'email_reply_to_domain_differs'), ('Return-Path', 'email_return_path_domain_differs')]:
        other = mailbox(headers, field, review.coverage)
        if not author or not other or author[1].value == other[1].value:
            continue
        if profile and (author[1].value, other[1].value, field) in profile.delegations:
            continue
        add('email_identity_difference', reason, 'low', 'single_signal',
            details={'same_registered_domain': author[1].registered_domain_hash == other[1].registered_domain_hash
                     if suffix_ok else None})
    claims = claimed_providers(snapshot, (), None, author[0], 'email') if snapshot and author else ()
    if len(claims) > 1:
        review.coverage.add('provider_claim_ambiguous')
    if len(claims) == 1:
        p = claims[0]
        state = match_domain(author[1].value, p, 'email', suffix_available=suffix_ok)
        if p.is_stale(utc_now().date()):
            review.coverage.add('provider_registry_stale')
        elif state == 'not_checked':
            review.coverage.add('provider_suffix_unavailable')
        elif state == 'outside_documented_set':
            complete = p.coverage.domains == 'documented_complete'
            # Action must occur in authored prose, independently of the display name.
            authored = list(authored_lines(parts.text))
            action = any(re.match(
                r'^\s*(?:please\s+)?(?:click|open|visit|call|send|transfer|pay|buy|purchase|'
                r'اضغط|افتح|ادخل|اتصل|ارسل|اشتر|اشتري|ابعت|حول|ادفع|eb3at|edfa3|eshtery)\b',
                claim_view(clause), re.I) or bool(_content(clause, None)[0]) for clause in _clauses(authored))
            if action:
                high = complete and report.independent
                attack = [AttackRef(technique_id='T1684.001', matrix='enterprise', attack_version='20.0',
                                    basis='email_provider_identity_conflict')] if complete else []
                add('email_provider_impersonation', 'email_provider_display_claim_conflict',
                    'high' if high else 'medium' if complete else 'low',
                    'corroborated' if high else 'single_signal' if complete else 'undetermined',
                    details={'coverage': p.coverage.domains, 'provider_id': p.provider_id}, attack=attack)
    for raw in parts.targets.values():
        try:
            score = scorer(raw)
        except Exception:
            score = None
        if score is None:
            review.coverage.add('email_url_model_unavailable')
        elif score['probability'] >= score['threshold']:
            target = normalize_url(raw)
            add('email_link_model_observation', 'email_link_model_signal', 'low', 'single_signal',
                details={'model_version': score['version'], 'policy_eligibility': 'not_checked'},
                indicators=[IndicatorRef(type='url', role='delivery_link', value_hash=target.value_hash,
                                         registered_domain_hash=target.registered_domain_hash)])
    for code in sorted(review.coverage):
        add('email_check_incomplete', code, 'info', 'undetermined')
    return review


def authored_lines(parts):
    for part in parts:
        for line in part.splitlines():
            stripped = line.strip()
            if stripped == '--' or re.match(r'^(?:-+\s*(?:original|forwarded) message|begin forwarded message|on .+ wrote:)', stripped, re.I):
                break
            if not stripped or stripped.startswith(('>', '|')):
                continue
            if stripped.startswith(('"', '“', '«')) and not (
                    stripped.count('"') % 2 or stripped.count('“') != stripped.count('”')
                    or stripped.count('«') != stripped.count('»')):
                continue
            yield stripped


def import_eml(path, *, grammar=None, **options):
    parts = read_eml(Path(path))
    try:
        review = review_parts(parts, **options)
        versions = dict(review.versions)
        subject = str(parts.headers.get('Subject', ''))
        lines = list(authored_lines([subject, *parts.text]))
        if re.match(r'^\s*(?:fw|fwd):', subject, re.I):
            review.coverage.add('payment_context_ambiguous')
            lines = []
        return apply_payment_rules(review, lines, 'email', versions=versions, grammar=grammar)
    except (ValueError, LookupError, RecursionError, IndexError) as exc:
        raise ImportErrorCode('email_malformed_mime') from None


def review_sms(text, *, sender_id=None, sender_display=None, snapshot=None, grammar=None):
    if len(text) > MAX_TEXT_LENGTH:
        raise ImportErrorCode('sms_import_limit_exceeded')
    engine = ProviderClaimEngine(snapshot)
    review = Review()
    lines = list(authored_lines([text]))
    observation = Observation('sms_preview', review.ref, utc_now(),
                              {'text': '\n'.join(lines), 'channel': 'sms',
                               'sender_id': sender_id, 'sender_display': sender_display})
    # Transfer only rule metadata. Contact values can also be payment destinations.
    for finding in engine.preview_sms(observation):
        review.findings.append(finding.model_copy(update={'indicators': []}))
    return apply_payment_rules(review, lines, 'sms', versions={PROVIDER: engine.version}, grammar=grammar)


def main():
    parser = argparse.ArgumentParser(description='Review a selected local EML in memory.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('path', nargs='?')
    source.add_argument('--sms-stdin', action='store_true', help='Read a selected SMS from standard input.')
    parser.add_argument('--profile', choices=tuple(PROFILES))
    parser.add_argument('--attest-unmodified-export', action='store_true')
    args = parser.parse_args()
    try:
        if args.sms_stdin:
            import sys
            review = review_sms(sys.stdin.read(MAX_TEXT_LENGTH + 1))
        else:
            review = import_eml(args.path, profile=PROFILES.get(args.profile), attested=args.attest_unmodified_export)
    except ImportErrorCode as exc:
        parser.exit(2, str(exc) + '\n')
    print(json.dumps(review.public()))


if __name__ == '__main__':
    main()
