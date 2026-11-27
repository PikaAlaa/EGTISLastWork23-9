"""Recommended action per Finding, catalogue `recommended-actions-v1` (design core-v2 §2, FR-14).

Fixed, reviewed text keyed by reason code, in Arabic and English. Text only: nothing here
runs, schedules or offers an action, and the catalogue has no field a process could execute.
The strict loader refuses any entry that carries a link, an e-mail address, a number or a
placeholder, so an action can never point the reader to a contact point ETIS did not verify.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

CATALOGUE_PATH = Path(__file__).resolve().parents[1] / 'resources' / 'recommended-actions-v1.json'
VERSION = 'recommended-actions-v1'
AUDIENCES = ('user', 'analyst')
STATUSES = ('draft', 'reviewed')
TOP_KEYS = frozenset({'version', 'design', 'entries', 'no_action', 'kind_defaults', 'fallback'})
TEXT_KEYS = frozenset({'audience', 'status', 'reviewed_by', 'reviewed_on', 'en', 'ar'})
ENTRY_KEYS = TEXT_KEYS | {'rank'}
MAX_TEXT = 400
_CODE = re.compile(r'^[a-z0-9][a-z0-9_.:-]{0,99}$')
_URL = re.compile(r'(?i)(?:[a-z][a-z0-9+.-]*://|www\.|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}\b)')
_DIGIT = re.compile(r'[0-9٠-٩۰-۹]')
_PLACEHOLDER = re.compile(r'[{}<>%@\[\]]')
_ARABIC = re.compile(r'[؀-ۿ]')


class CatalogueError(ValueError):
    """Raised with a fixed reason code naming what is wrong; never with catalogue text."""


@dataclass(frozen=True)
class ActionText:
    audience: str
    status: str
    reviewed_by: str | None
    reviewed_on: str | None
    en: str
    ar: str
    rank: int | None = None


@dataclass(frozen=True)
class Catalogue:
    version: str
    entries: dict[str, ActionText]
    no_action: dict[str, str]
    kind_defaults: dict[str, ActionText]
    fallback: ActionText


def _check_text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise CatalogueError(f'action_text_invalid:{field}')
    if _URL.search(value):
        raise CatalogueError(f'action_text_contains_link:{field}')
    if _DIGIT.search(value):
        raise CatalogueError(f'action_text_contains_number:{field}')
    if _PLACEHOLDER.search(value):
        raise CatalogueError(f'action_text_contains_placeholder:{field}')
    has_arabic = bool(_ARABIC.search(value))
    if (field == 'ar') != has_arabic:
        raise CatalogueError(f'action_text_wrong_language:{field}')
    return value


def _text(raw, *, ranked: bool) -> ActionText:
    if not isinstance(raw, dict):
        raise CatalogueError('catalogue_entry_not_object')
    expected = ENTRY_KEYS if ranked else TEXT_KEYS
    if set(raw) != expected:
        raise CatalogueError('catalogue_extra_field' if set(raw) - expected else 'catalogue_missing_field')
    if raw['audience'] not in AUDIENCES:
        raise CatalogueError('catalogue_audience_invalid')
    if raw['status'] not in STATUSES:
        raise CatalogueError('catalogue_status_invalid')
    if raw['status'] == 'draft':
        if raw['reviewed_by'] is not None or raw['reviewed_on'] is not None:
            raise CatalogueError('catalogue_draft_has_review')
    else:
        reviewer = raw['reviewed_by']
        if not isinstance(reviewer, str) or not 1 <= len(reviewer) <= 64 or _DIGIT.search(reviewer) \
                or _PLACEHOLDER.search(reviewer):
            raise CatalogueError('catalogue_reviewer_invalid')
        try:
            date.fromisoformat(raw['reviewed_on'])
        except (TypeError, ValueError):
            raise CatalogueError('catalogue_review_date_invalid') from None
    rank = None
    if ranked:
        rank = raw['rank']
        if not isinstance(rank, int) or isinstance(rank, bool) or not 1 <= rank <= 999:
            raise CatalogueError('catalogue_rank_invalid')
    return ActionText(audience=raw['audience'], status=raw['status'], reviewed_by=raw['reviewed_by'],
                      reviewed_on=raw['reviewed_on'], en=_check_text(raw['en'], 'en'),
                      ar=_check_text(raw['ar'], 'ar'), rank=rank)


def parse_catalogue(raw) -> Catalogue:
    if not isinstance(raw, dict) or set(raw) != TOP_KEYS:
        raise CatalogueError('catalogue_top_level_invalid')
    if raw['version'] != VERSION:
        raise CatalogueError('catalogue_version_invalid')
    for section in ('entries', 'no_action', 'kind_defaults'):
        if not isinstance(raw[section], dict):
            raise CatalogueError(f'catalogue_section_invalid:{section}')
        for code in raw[section]:
            if not isinstance(code, str) or not _CODE.match(code):
                raise CatalogueError(f'catalogue_code_invalid:{section}')
    entries = {code: _text(entry, ranked=True) for code, entry in raw['entries'].items()}
    overlap = set(entries) & set(raw['no_action'])
    if overlap:
        raise CatalogueError('catalogue_code_in_entries_and_no_action')
    for reason in raw['no_action'].values():
        if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_TEXT:
            raise CatalogueError('catalogue_no_action_reason_invalid')
    kinds = {kind: _text(entry, ranked=False) for kind, entry in raw['kind_defaults'].items()}
    return Catalogue(version=raw['version'], entries=entries, no_action=dict(raw['no_action']),
                     kind_defaults=kinds, fallback=_text(raw['fallback'], ranked=False))


@lru_cache(maxsize=4)
def load_catalogue(path: str | Path = CATALOGUE_PATH) -> Catalogue:
    try:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise CatalogueError('catalogue_unreadable') from None
    return parse_catalogue(raw)


def engine_reason_codes() -> dict[str, frozenset[str]]:
    """Reason codes each Finding-emitting engine can put in `evidence.reasons` (§2.2).

    `host.windows` joins when it emits Findings; its entries are written in that step.
    """
    from app.engines import email_headers, payment_rules, phishing_findings, provider_claims
    from app.engines.malware import engine as malware_engine
    from app.engines.network_windows import detections
    return {
        'phishing.analyze': phishing_findings.REASON_CODES,
        'phishing.provider_claim': provider_claims.REASON_CODES,
        'phishing.email_headers': email_headers.REASON_CODES,
        'phishing.payment_rules': payment_rules.REASON_CODES,
        'malware.files': malware_engine.REASON_CODES,
        'network.windows': frozenset(code for codes in detections.REASONS.values() for code in codes),
    }


def uncovered(catalogue: Catalogue) -> dict[str, list[str]]:
    """Codes of each engine with neither an entry nor a `no_action` reason ({} when complete)."""
    covered = set(catalogue.entries) | set(catalogue.no_action)
    missing = {engine: sorted(codes - covered) for engine, codes in engine_reason_codes().items()}
    return {engine: codes for engine, codes in missing.items() if codes}
