"""Offline provider-registry-v1 schema and exact-byte release verification.

No public contacts ship here. Open questions/to verify: who curates completeness
and review dates; official numbering/delegation semantics; future PSL upgrades.
Per-field coverage is conservative: a missing field is unknown, never complete.
The release manifest is code, separate from the empty JSON it pins.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.indicators import normalize_phone
from app.core.exceptions import InvalidScanInputError
from app.core.url_utils import parse_url

Code = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_]{0,79}$')]
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Channel = Literal['sms', 'email', 'web', 'phone', 'any']
CoverageState = Literal['documented_partial', 'documented_complete', 'unknown']
NORMALIZATION_VERSION = 'provider-normalization-v1'
# Finite design choices, not a claim of linguistic coverage. Every fixture is invented.
MATCHING_TABLE = {
    'identity_prefixes': ['this is', 'we are', 'from', 'نحن', 'من', 'احنا', 'انا', 'e7na', 'ana'],
    'actions': ['click', 'open', 'visit', 'follow', 'call', 'اضغط', 'افتح', 'ادخل', 'اتصل',
                'دوس', 'خش', 'كلم', 'edghat', 'efta7', 'ed5ol', 'dos', 'kallem'],
    'callbacks': ['call', 'اتصل', 'كلم', 'kallem'],
    'secrets': ['send otp', 'send password', 'ارسل الكود', 'ابعت الكود', 'eb3at el code'],
    'excluded_contexts': ['do not', "don't", 'beware', 'warning', 'example', 'quoted',
                          'لا تضغط', 'لا تتصل', 'تحذير', 'احذر', 'ماتضغطش', 'matdossh'],
    'arabic_folds': {'أ': 'ا', 'إ': 'ا', 'آ': 'ا', 'ى': 'ي'},
    'confusables': 'not_checked:to_verify_Unicode_UTS39_data_and_pin',
}


def digest_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':')).encode()).hexdigest()


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, hide_input_in_errors=True)


class Source(Strict):
    id: Code
    url: str
    read_at: date
    verifier: Code
    reviewer: Code
    field_paths: tuple[str, ...]
    note_digest: Digest

    @model_validator(mode='after')
    def valid_source(self):
        parsed = parse_url(self.url)
        if parsed.bare or parsed.userinfo or self.reviewer == self.verifier or not self.field_paths:
            raise ValueError('invalid_provider_source')
        return self


class Alias(Strict):
    value: str = Field(min_length=1, max_length=200)
    language: Literal['ar', 'ar_EG', 'franco', 'en']
    # self_identification is a complete, reviewed assertion phrase, not a bare brand word.
    claim_context: Literal['identity', 'self_identification', 'sender_only'] = 'identity'
    source_ref: Code


class Domain(Strict):
    host: str
    match_scope: Literal['exact_host', 'subdomains', 'registrable_domain']
    channel: Channel
    purpose: Code
    source_ref: Code

    @field_validator('host')
    @classmethod
    def canonical_host(cls, value):
        parsed = parse_url(value)
        if parsed.host != value or parsed.userinfo or parsed.path != '/' or parsed.query or parsed.port:
            raise ValueError('provider_domain_not_canonical')
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        raise ValueError('provider_domain_is_ip')


class SenderID(Strict):
    value: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$')
    channel: Literal['sms']
    comparison: Literal['literal']
    source_ref: Code


class Contact(Strict):
    value: str
    channel: Channel
    purpose: Literal['outbound_sender', 'callback']
    source_ref: Code

    @field_validator('value')
    @classmethod
    def normalized_phone(cls, value):
        if normalize_phone(value).value != value:
            raise ValueError('provider_phone_not_canonical')
        return value


class Coverage(Strict):
    domains: CoverageState = 'unknown'
    sender_ids: CoverageState = 'unknown'
    sms_short_codes: CoverageState = 'unknown'
    hotlines: CoverageState = 'unknown'


class Provider(Strict):
    provider_id: Code
    category: Literal['bank', 'mobile_operator', 'payment_app', 'government', 'courier']
    display_name: str = Field(min_length=1, max_length=200)
    invented: bool
    aliases: tuple[Alias, ...] = ()
    domains: tuple[Domain, ...] = ()
    sender_ids: tuple[SenderID, ...] = ()
    sms_short_codes: tuple[Contact, ...] = ()
    hotlines: tuple[Contact, ...] = ()
    sources: tuple[Source, ...]
    coverage: Coverage
    verified_at: date
    review_due_at: date
    status: Literal['active', 'stale', 'withdrawn', 'example_only']
    source_disputed: bool = False

    def is_stale(self, today: date) -> bool:
        return self.status in ('stale', 'withdrawn') or self.source_disputed or self.review_due_at <= today

    @model_validator(mode='after')
    def provenance(self):
        sources = {s.id: s for s in self.sources}
        if len(sources) != len(self.sources) or not sources:
            raise ValueError('provider_source_duplicate_or_missing')
        if self.verified_at >= self.review_due_at or any(s.read_at > self.verified_at for s in self.sources):
            raise ValueError('provider_dates_invalid')
        if self.invented != (self.status == 'example_only'):
            raise ValueError('provider_example_status_invalid')
        supported = set().union(*(set(s.field_paths) for s in self.sources))
        if 'display_name' not in supported:
            raise ValueError('provider_display_source_missing')
        for field in ('aliases', 'domains', 'sender_ids', 'sms_short_codes', 'hotlines'):
            seen = set()
            for index, item in enumerate(getattr(self, field)):
                source = sources.get(item.source_ref)
                if source is None or f'{field}.{index}' not in source.field_paths:
                    raise ValueError('provider_field_source_missing')
                identity = item.host if field == 'domains' else item.value
                if identity in seen:
                    raise ValueError('provider_field_duplicate')
                seen.add(identity)
                if field == 'sms_short_codes' and not normalize_phone(item.value).short_code:
                    raise ValueError('provider_short_code_invalid')
            if field != 'aliases' and getattr(self.coverage, field) != 'unknown':
                if not getattr(self, field) or f'coverage.{field}' not in supported:
                    raise ValueError('provider_coverage_source_missing')
        return self


class ProviderRegistry(Strict):
    schema_version: Literal['provider-registry-v1']
    registry_version: str = Field(pattern=r'^[a-z0-9][a-z0-9_.-]{0,79}$')
    released_at: date
    example_only: bool
    entries: tuple[Provider, ...]

    @model_validator(mode='after')
    def unique_entries(self):
        if len({p.provider_id for p in self.entries}) != len(self.entries):
            raise ValueError('provider_id_duplicate')
        contacts = set()
        for entry in self.entries:
            if entry.invented != self.example_only or entry.verified_at > self.released_at:
                raise ValueError('provider_release_invalid')
            # Shared-contact delegation has no approved schema yet: reject rather than guess.
            for field in ('domains', 'sender_ids', 'sms_short_codes', 'hotlines'):
                for item in getattr(entry, field):
                    key = (('phone' if field in ('sms_short_codes', 'hotlines') else field),
                           item.host if field == 'domains' else item.value)
                    if key in contacts:
                        raise ValueError('provider_contact_ownership_conflict')
                    contacts.add(key)
        return self


@dataclass(frozen=True)
class ReleasePin:
    registry_version: str
    registry_sha256: str
    schema_sha256: str
    matching_sha256: str
    normalization_version: str = NORMALIZATION_VERSION


@dataclass(frozen=True)
class LoadedRegistry:
    registry: ProviderRegistry
    pin: ReleasePin


class RegistryUnavailable(ValueError):
    """Fixed error code only: never leak source JSON or file paths."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


def load_registry(path: Path, pin: ReleasePin, *, allow_invented: bool = False,
                  today: date | None = None) -> LoadedRegistry:
    """Read once, hash those exact bytes, validate and return an immutable snapshot.

    Production always rejects examples. allow_invented exists solely for labelled
    tests/demos. No caching, fetching, activation writes or automatic refresh.
    """
    try:
        with path.open('rb') as handle:
            raw = handle.read((1 << 20) + 1)  # local parser resource cap, not a measured claim
        if len(raw) > (1 << 20) or hashlib.sha256(raw).hexdigest() != pin.registry_sha256:
            raise ValueError('provider_registry_digest_invalid')
        if (pin.schema_sha256 != digest_json(ProviderRegistry.model_json_schema())
                or pin.matching_sha256 != digest_json(MATCHING_TABLE)
                or pin.normalization_version != NORMALIZATION_VERSION):
            raise ValueError('provider_registry_release_invalid')
        decoded = json.loads(raw, object_pairs_hook=_unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))
        registry = ProviderRegistry.model_validate_json(json.dumps(decoded))
        if registry.registry_version != pin.registry_version or (registry.example_only and not allow_invented):
            raise ValueError('provider_registry_release_invalid')
        if registry.released_at > (today or datetime.now(timezone.utc).date()):
            raise ValueError('provider_registry_future_release')
        return LoadedRegistry(registry, pin)
    except (OSError, ValueError, TypeError, RecursionError, InvalidScanInputError):
        raise RegistryUnavailable('provider_registry_unavailable') from None


def load_bundled_registry() -> LoadedRegistry:
    from app.core.provider_release import BUNDLED_PIN
    return load_registry(Path(__file__).resolve().parents[1] / 'resources' / 'provider-registry-v1.json', BUNDLED_PIN)
