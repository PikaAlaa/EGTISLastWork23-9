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


MAX_ACTIONS = 3
DECISIVE_FIRST_ENGINES = frozenset({'phishing.analyze'})


def _finding_parts(finding) -> tuple[str, str, list[str]]:
    """(engine name, kind, reasons) from a `Finding`, a `FindingRecord` or a plain dict."""
    if isinstance(finding, dict):
        evidence = finding.get('evidence') or {}
        engine = finding.get('engine_name') or (finding.get('engine') or {}).get('name', '')
        return engine, finding.get('kind', ''), list(evidence.get('reasons') or [])
    engine = getattr(finding, 'engine', None)
    if engine is not None and hasattr(engine, 'name'):
        return engine.name, finding.kind, list(finding.evidence.reasons)
    evidence = getattr(finding, 'evidence', None) or {}
    return getattr(finding, 'engine_name', ''), getattr(finding, 'kind', ''), list(evidence.get('reasons') or [])


def _shown(text: ActionText | None, show_drafts: bool) -> bool:
    return text is not None and (text.status == 'reviewed' or show_drafts)


def _action(text: ActionText, catalogue: Catalogue, *, source: str, reason_code: str | None) -> dict:
    return {'reason_code': reason_code, 'source': source, 'audience': text.audience, 'status': text.status,
            'en': text.en, 'ar': text.ar, 'catalogue_version': catalogue.version}


def recommended_actions(finding, *, catalogue: Catalogue | None = None, show_drafts: bool | None = None) -> list[dict]:
    """The actions to show for one Finding (§2.3): a primary action, then up to two more.

    Reasons are ordered by catalogue `rank` (lower is more urgent), ties keeping their
    `evidence.reasons` order; for `phishing.analyze` the decisive reason (`reasons[0]`) comes
    first. Without any shown reason entry the kind default applies, then the fallback. Draft
    texts are hidden unless `show_drafts` (`ETIS_SHOW_DRAFT_ACTIONS`) is set, so the result is
    empty while every text is still draft. Computed when read; never stored, never executed.
    """
    if catalogue is None:
        catalogue = load_catalogue()
    if show_drafts is None:
        from app.core.settings import settings
        show_drafts = settings.show_draft_actions
    engine, kind, reasons = _finding_parts(finding)
    reasons = list(dict.fromkeys(r for r in reasons if isinstance(r, str)))
    usable = [(i, r) for i, r in enumerate(reasons) if _shown(catalogue.entries.get(r), show_drafts)]
    usable.sort(key=lambda item: (catalogue.entries[item[1]].rank, item[0]))
    ordered = [r for _, r in usable]
    if engine in DECISIVE_FIRST_ENGINES and reasons and reasons[0] in ordered:
        ordered.remove(reasons[0])
        ordered.insert(0, reasons[0])
    actions, seen = [], set()
    for code in ordered:
        text = catalogue.entries[code]
        if (text.en, text.ar) in seen:
            continue
        seen.add((text.en, text.ar))
        actions.append(_action(text, catalogue, source='reason', reason_code=code))
        if len(actions) == MAX_ACTIONS:
            break
    if actions:
        return actions
    default = catalogue.kind_defaults.get(kind)
    if _shown(default, show_drafts):
        return [_action(default, catalogue, source='kind_default', reason_code=None)]
    if _shown(catalogue.fallback, show_drafts):
        return [_action(catalogue.fallback, catalogue, source='fallback', reason_code=None)]
    return []


def displayable_catalogue(catalogue: Catalogue | None = None, *, show_drafts: bool | None = None) -> dict:
    """The catalogue as the console may show it: reviewed texts, plus drafts only when enabled."""
    if catalogue is None:
        catalogue = load_catalogue()
    if show_drafts is None:
        from app.core.settings import settings
        show_drafts = settings.show_draft_actions

    def view(text: ActionText) -> dict:
        return {'audience': text.audience, 'status': text.status, 'en': text.en, 'ar': text.ar}
    entries = {code: {**view(t), 'rank': t.rank} for code, t in sorted(catalogue.entries.items())
               if _shown(t, show_drafts)}
    kinds = {kind: view(t) for kind, t in sorted(catalogue.kind_defaults.items()) if _shown(t, show_drafts)}
    total = len(catalogue.entries) + len(catalogue.kind_defaults) + 1
    reviewed = sum(t.status == 'reviewed' for t in
                   [*catalogue.entries.values(), *catalogue.kind_defaults.values(), catalogue.fallback])
    return {'version': catalogue.version, 'show_drafts': show_drafts, 'entries': entries, 'kind_defaults': kinds,
            'fallback': view(catalogue.fallback) if _shown(catalogue.fallback, show_drafts) else None,
            'reviewed_texts': reviewed, 'total_texts': total}


def uncovered(catalogue: Catalogue) -> dict[str, list[str]]:
    """Codes of each engine with neither an entry nor a `no_action` reason ({} when complete)."""
    covered = set(catalogue.entries) | set(catalogue.no_action)
    missing = {engine: sorted(codes - covered) for engine, codes in engine_reason_codes().items()}
    return {engine: codes for engine, codes in missing.items() if codes}
