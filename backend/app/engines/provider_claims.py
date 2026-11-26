"""Additive, offline provider claim/proof engine (provider-registry-v1 §§2,5,6).

Severity: partial outside-set low; complete fresh actionable mismatch medium;
independent complete fresh domain plus contact mismatch high; incomplete info.
Confidence: partial/unavailable undetermined; one family single_signal; independent
domain/contact families corroborated. Never confirmed/critical. Nothing here reads
models, thresholds, verdicts, or writes a database.

Open questions/to verify: Unicode UTS #39 acquisition/licence/pin (stub only),
curator approval of language coverage/delegation, and import retention ownership.
No import persistence is enabled. No linguistic or real-Egyptian accuracy claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
import hashlib
import ipaddress
import re
from typing import TYPE_CHECKING, Literal

from app.core.exceptions import InvalidScanInputError
from app.core.findings import AttackRef, Evidence, Finding, IndicatorRef
from app.core.indicators import normalize_domain, normalize_phone, normalize_url
from app.core.provider_registry import (MATCHING_TABLE, LoadedRegistry, Provider, RegistryUnavailable,
                                        digest_json, load_bundled_registry)
from app.core.url_utils import MAX_LINKS, MAX_TEXT_LENGTH, MAX_URL_LENGTH, extract_links, parse_url, registered_domain

if TYPE_CHECKING:
    from app.engines.registry import Observation

# Installed tldextract's bundled snapshot; no download, cache, or dependency change.
# The existing url_utils configuration disables suffix_list_urls/private suffixes.
OFFLINE_SUFFIX_SHA256 = 'b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38'
TO_VERIFY = ('Unicode UTS #39 confusable data/licence/pin; import retention owner; '
             'reviewed shared-contact delegation and language coverage')
State = Literal['match', 'outside_documented_set', 'unknown', 'invalid', 'stale', 'not_checked']


def confusable_match(_host: str, _provider: Provider) -> Literal['not_checked']:
    """To verify: local Unicode data, licence and release pin. Never infer a look-alike."""
    return 'not_checked'


def suffix_snapshot_available() -> bool:
    try:
        raw = files('tldextract').joinpath('.tld_set_snapshot').read_bytes()
        return hashlib.sha256(raw).hexdigest() == OFFLINE_SUFFIX_SHA256
    except (OSError, ModuleNotFoundError):
        return False


def claim_view(value: str) -> str:
    """A claim-only view. Never use these folds to identify proof/recipient strings."""
    value = re.sub(r'[\u0610-\u061a\u064b-\u065f\u0670\u06d6-\u06ed\u0640]', '', value)
    return ' '.join(value.translate(str.maketrans(MATCHING_TABLE['arabic_folds'])).casefold().split())


def _contains(text: str, phrase: str) -> bool:
    return bool(re.search(r'(?<!\w)' + re.escape(claim_view(phrase)) + r'(?!\w)', claim_view(text)))


def _has(text: str, group: str) -> bool:
    # Link paths/queries are proof strings, never language evidence or negation.
    links, _invalid = extract_links(text)
    for link in links:
        text = text.replace(link, ' ')
    return any(_contains(text, word) for word in MATCHING_TABLE[group])


def active_clauses(text: str) -> tuple[str, ...]:
    # Conservative quote/awareness handling; ambiguous quoting yields no active claim.
    active = []
    for line in text.splitlines():
        if line.lstrip().startswith(('>', '|')):
            continue
        if line.count('"') % 2 or line.count('“') != line.count('”'):
            continue
        line = re.sub(r'"[^"]*"|“[^”]*”|«[^»]*»', ' ', line)
        # Delimiters inside URL paths/queries are part of the inert identity.
        spans = [m.span() for m in re.finditer(
            r'(?i)(?:https?://|hxxps?://|www\.)\S+|(?<![\w@])(?:[\w-]+\.)+[\w-]+(?:[/?]\S*)?', line)]
        boundaries = [m for m in re.finditer(r'[;؛!?؟]|\.\s+', line)
                      if not any(start <= m.start() < end for start, end in spans)]
        offset = 0
        clauses = []
        for boundary in boundaries:
            clauses.append(line[offset:boundary.start()])
            offset = boundary.end()
        clauses.append(line[offset:])
        for clause in clauses:
            view = claim_view(clause)
            if view and not _has(view, 'excluded_contexts'):
                active.append(clause.strip())
    return tuple(active)


def claimed_providers(registry: LoadedRegistry, clauses: tuple[str, ...], sender_id: str | None,
                      sender_display: str | None, channel: str) -> tuple[Provider, ...]:
    claims = []
    for provider in registry.registry.entries:
        identities = [provider.display_name] + [a.value for a in provider.aliases if a.claim_context == 'identity']
        display_aliases = identities + [a.value for a in provider.aliases if a.claim_context == 'sender_only']
        asserted = any(claim_view(sender_display or '') == claim_view(alias) for alias in display_aliases)
        if channel == 'sms' and sender_id:
            asserted |= any(sender_id == entry.value for entry in provider.sender_ids)
            asserted |= any(sender_id == entry.value and entry.purpose == 'outbound_sender'
                            for entry in provider.sms_short_codes)
        for clause in clauses:
            clause = claim_view(clause)
            for alias in identities:
                name = claim_view(alias)
                if clause.startswith(name + ':'):
                    asserted = True
                for prefix in MATCHING_TABLE['identity_prefixes']:
                    phrase = claim_view(prefix) + ' ' + name
                    if re.match(re.escape(phrase) + r'(?!\w)', clause):
                        asserted = True
            asserted |= any(_contains(clause, a.value) for a in provider.aliases
                            if a.claim_context == 'self_identification')
        if asserted:
            claims.append(provider)
    return tuple(claims)


def match_domain(value: str, provider: Provider, channel: str, *, suffix_available: bool) -> State:
    try:
        parsed = parse_url(value)
        if parsed.userinfo:
            return 'invalid'
        try:
            ipaddress.ip_address(parsed.host)
        except ValueError:
            pass
        else:
            return 'invalid'
    except InvalidScanInputError:
        return 'invalid'
    domains = [d for d in provider.domains if d.channel in ('any', 'web', channel)]
    if not domains:
        return 'unknown'
    needs_suffix = False
    for domain in domains:
        if parsed.host == domain.host:
            return 'match'
        if domain.match_scope == 'subdomains' and parsed.host.endswith('.' + domain.host):
            return 'match'
        if domain.match_scope == 'registrable_domain':
            if not suffix_available:
                needs_suffix = True
            elif registered_domain(parsed.host) == registered_domain(domain.host):
                return 'match'
    if needs_suffix:
        return 'not_checked'
    return 'unknown' if provider.coverage.domains == 'unknown' else 'outside_documented_set'


@dataclass(frozen=True)
class Proof:
    reason: str
    state: State
    coverage: str
    family: Literal['domain', 'contact']
    indicators: tuple[IndicatorRef, ...] = ()
    # Ephemeral grouping only, including when a public contact's refs are withheld.
    proof_hash: str = ''


def _indicator(kind: str, value: str, role: str) -> IndicatorRef:
    normalized = {'url': normalize_url, 'domain': normalize_domain, 'phone': normalize_phone}[kind](value)
    return IndicatorRef(type=kind, value_hash=normalized.value_hash, value=None, role=role,
                        registered_domain_hash=normalized.registered_domain_hash)


def _public_contacts(registry: LoadedRegistry):
    """Conservatively withhold public/shared contacts, including stale entries.

    No core stoplist/brand mutation is needed: an entry official for another
    provider must not become a cross-brand incident pivot from this engine.
    """
    domains, phones = set(), set()
    for provider in registry.registry.entries:
        for domain in provider.domains:
            domains.update((domain.host, registered_domain(domain.host)))
        for contact in (*provider.sms_short_codes, *provider.hotlines):
            phones.add(normalize_phone(contact.value).value_hash)
    return domains, phones


def _safe_indicators(registry: LoadedRegistry, refs: tuple[IndicatorRef, ...], host: str | None = None):
    domains, phones = _public_contacts(registry)
    if host and ({host, registered_domain(host)} & domains):
        return ()
    return tuple(ref for ref in refs if not (ref.type == 'phone' and ref.value_hash in phones))


def _contact_proof(registry: LoadedRegistry, provider: Provider, value: str, role: str,
                   channel: str) -> Proof:
    reason = 'provider_sender_outside_set' if role == 'sender' else 'provider_callback_outside_set'
    if role == 'sender' and not re.fullmatch(r'[+0-9 ()-]+', value):
        if channel != 'sms' or not provider.sender_ids or provider.coverage.sender_ids == 'unknown':
            return Proof(reason, 'unknown', 'unknown', 'contact')
        state = 'match' if any(value == s.value for s in provider.sender_ids) else 'outside_documented_set'
        return Proof(reason, state, provider.coverage.sender_ids, 'contact',
                     proof_hash=hashlib.sha256(value.encode()).hexdigest())
    try:
        normalized = normalize_phone(value)
    except ValueError:
        return Proof(reason, 'invalid', 'unknown', 'contact')
    field = 'sms_short_codes' if normalized.short_code and role == 'sender' else 'hotlines'
    contacts = [c for c in getattr(provider, field)
                if c.purpose == ('outbound_sender' if role == 'sender' else 'callback')
                and c.channel in ('any', channel, 'phone' if role == 'callback' else channel)]
    coverage = getattr(provider.coverage, field)
    if not contacts or coverage == 'unknown':
        return Proof(reason, 'unknown', 'unknown', 'contact')
    state = 'match' if any(normalized.value == c.value for c in contacts) else 'outside_documented_set'
    refs = (_indicator('phone', value, role),) if state == 'outside_documented_set' else ()
    return Proof(reason, state, coverage, 'contact', _safe_indicators(registry, refs), normalized.value_hash)


def severity_confidence(proof: Proof, mismatches: tuple[Proof, ...]) -> tuple[str, str]:
    """Fixed §6 table; partial evidence never supplies independent corroboration."""
    if proof.coverage != 'documented_complete':
        return 'low', 'undetermined'
    families = {p.family for p in mismatches if p.coverage == 'documented_complete'}
    if families == {'domain', 'contact'}:
        return 'high', 'corroborated'
    return 'medium', 'single_signal'


class ProviderClaimEngine:
    name = 'phishing.provider_claim'
    domain = 'phishing'

    def __init__(self, snapshot: LoadedRegistry | None = None):
        self.snapshot = snapshot

    @property
    def version(self) -> str:
        # Full digests live in evidence; the composite identity stays within finding-v1's limit.
        from app.core.provider_release import BUNDLED_PIN
        pin = self.snapshot.pin if self.snapshot is not None else BUNDLED_PIN
        manifest = {'registry': pin.registry_sha256, 'schema': pin.schema_sha256,
                    'matching': pin.matching_sha256, 'normalization': pin.normalization_version,
                    'suffix': OFFLINE_SUFFIX_SHA256, 'rules': 'provider-v1'}
        return 'provider-v1+manifest:' + digest_json(manifest)

    def _load(self):
        return self.snapshot if self.snapshot is not None else load_bundled_registry()

    def health(self, context) -> dict:
        try:
            loaded = self._load()
        except RegistryUnavailable:
            return {'available': False, 'reason': 'provider_registry_unavailable'}
        today = context.get('today', datetime.now(timezone.utc).date())
        if not loaded.registry.entries:
            return {'available': False, 'reason': 'provider_registry_empty'}
        if all(p.is_stale(today) for p in loaded.registry.entries):
            return {'available': False, 'reason': 'provider_registry_stale'}
        return {'available': True, 'reason': None}

    def analyze(self, observation: Observation) -> list[Finding]:
        if observation.kind != 'provider_message':
            raise ValueError('unsupported_observation')
        # Persisted source refs must never contain a path, message, URL or phone.
        if not re.fullmatch(r'scan_requests:[1-9][0-9]*', observation.source_ref):
            raise ValueError('provider_import_retention_to_verify')
        return self._evaluate(observation, 'scan')

    def preview_sms(self, observation: Observation) -> list[Finding]:
        """Transient dependency for one local SMS import. No scan/database writer."""
        from uuid import UUID
        try:
            valid_ref = isinstance(observation.source_ref, str) and str(UUID(observation.source_ref)) == observation.source_ref
        except ValueError:
            valid_ref = False
        if observation.kind != 'sms_preview' or observation.data.get('channel') != 'sms' or not valid_ref:
            raise ValueError('provider_preview_invalid')
        return self._evaluate(observation, 'import')

    def _evaluate(self, observation: Observation, source_kind: str) -> list[Finding]:
        if observation.observed_at.tzinfo is None:
            raise ValueError('provider_observation_time_invalid')
        text = observation.data.get('text') or ''
        url = observation.data.get('url')
        sender = observation.data.get('sender_id')
        display = observation.data.get('sender_display')
        channel = observation.data.get('channel', 'unknown')
        if (not isinstance(text, str) or len(text) > MAX_TEXT_LENGTH
                or channel not in ('sms', 'email', 'unknown')
                or any(value is not None and (not isinstance(value, str) or len(value) > limit)
                       for value, limit in ((url, MAX_URL_LENGTH), (sender, 80), (display, 200)))):
            raise ValueError('provider_input_invalid')
        loaded = None

        def finding(reason, *, provider=None, proof=None, mismatches=(), attack=()):
            details = {'normalization_version': 'provider-normalization-v1', 'lookalike': 'not_checked',
                       'lookalike_note': 'to_verify_unicode_data_and_pin',
                       'suffix_sha256': OFFLINE_SUFFIX_SHA256, 'matching_sha256': digest_json(MATCHING_TABLE)}
            if loaded:
                details['registry_sha256'] = loaded.pin.registry_sha256
                details['schema_sha256'] = loaded.pin.schema_sha256
            if provider:
                details['provider_id'] = provider.provider_id
            if proof:
                details.update(coverage=proof.coverage, proof_state=proof.state, evidence_family=proof.family)
            severity, confidence = severity_confidence(proof, mismatches) if proof else ('info', 'undetermined')
            return Finding(engine={'name': self.name, 'version': self.version}, domain=self.domain,
                           kind='provider_proof_mismatch' if proof else 'provider_check_incomplete',
                           severity=severity, confidence=confidence,
                           indicators=list(proof.indicators) if proof else [], attack=list(attack),
                           evidence=Evidence(reasons=[reason], details=details),
                           observed_at=observation.observed_at, created_at=observation.observed_at,
                           source={'kind': source_kind, 'ref': observation.source_ref})

        try:
            loaded = self._load()
        except RegistryUnavailable:
            return [finding('provider_registry_unavailable')]
        clauses = active_clauses(text)
        claims = claimed_providers(loaded, clauses, sender, display, channel)
        if len(claims) > 1:
            return [finding('provider_claim_ambiguous')]
        if not claims:
            return []
        provider, = claims
        if provider.is_stale(observation.observed_at.astimezone(timezone.utc).date()):
            return [finding('provider_registry_stale', provider=provider)]
        action_clauses = tuple(c for c in clauses if _has(c, 'actions') or _has(c, 'secrets'))
        if not action_clauses:
            return []
        suffix_ok = suffix_snapshot_available()
        proofs, links = [], []
        for clause in action_clauses:
            extracted, _invalid = extract_links(clause)
            links.extend(extracted)
        if url and any(_has(c, 'actions') for c in action_clauses):
            links.append(url)
        diagnostics = []
        for link in dict.fromkeys(links):
            if sum(p.family == 'domain' for p in proofs) >= MAX_LINKS:
                break
            state = match_domain(link, provider, channel, suffix_available=suffix_ok)
            if state == 'not_checked':
                diagnostics.append('provider_suffix_unavailable')
            refs = ()
            if state == 'outside_documented_set':
                parsed = parse_url(link)
                refs = _safe_indicators(loaded, (_indicator('url', link, 'delivery_link'),
                                                _indicator('domain', parsed.host, 'delivery_host')), parsed.host)
            proofs.append(Proof('provider_domain_outside_set', state, provider.coverage.domains, 'domain', refs,
                                normalize_url(link).value_hash if state == 'outside_documented_set' else ''))
        if sender:
            proofs.append(_contact_proof(loaded, provider, sender, 'sender', channel))
        for clause in action_clauses:
            if _has(clause, 'callbacks'):
                # Strip URLs before extracting callback digits (never treat a URL port as a phone).
                without_links = re.sub(r'https?://\S+', ' ', clause)
                for phone in re.findall(r'(?<!\w)\+?\d[\d ()-]{1,20}\d(?!\w)', without_links):
                    proofs.append(_contact_proof(loaded, provider, phone.strip(), 'callback', channel))
        mismatches = tuple(p for p in proofs if p.state == 'outside_documented_set')
        findings, seen = [], set()
        mismatched_link = any(p.family == 'domain' for p in mismatches)
        for proof in mismatches:
            key = (proof.reason, proof.proof_hash)
            if key in seen:
                continue
            seen.add(key)
            # Partial coverage cannot assert deceptive identity for ATT&CK purposes.
            attack = []
            if proof.coverage == 'documented_complete':
                attack.append(AttackRef(technique_id='T1684.001', matrix='enterprise', attack_version='20.0',
                                        basis='provider_claim_proof_conflict'))
                if channel == 'sms' and (mismatched_link or any(_has(c, 'secrets') for c in action_clauses)):
                    attack.append(AttackRef(technique_id='T1660', matrix='mobile', attack_version='20.0',
                                            basis='sms_deceptive_action'))
            findings.append(finding(proof.reason, provider=provider, proof=proof, mismatches=mismatches, attack=attack))
        findings.extend(finding(code, provider=provider) for code in dict.fromkeys(diagnostics))
        return findings
