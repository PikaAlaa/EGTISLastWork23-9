"""Independent corroboration signals for the text-model decision rule.

These functions only inspect supplied strings and already-computed URL evidence.
They never open, fetch, or resolve a URL.
"""
from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from app.core.url_utils import extract_links

KEYWORD_FILE = Path(__file__).resolve().parents[3] / "data" / "secret_request_keywords.json"


@lru_cache(maxsize=1)
def _keywords():
    return json.loads(KEYWORD_FILE.read_text(encoding="utf-8"))


def _fold(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def has_secret_request(text: str) -> bool:
    """Return true only when a request verb occurs near a credential or secret term."""
    if not isinstance(text, str) or not text.strip():
        return False
    folded = _fold(text)
    data = _keywords()
    secrets = {term for group in data["secret_terms"].values() for term in group}
    requests = {term for group in data["request_terms"].values() for term in group}
    negations = data["negation_terms"]
    secret_spans = [(m.start(), m.end()) for term in sorted(secrets, key=len, reverse=True)
                    for m in re.finditer(re.escape(_fold(term)), folded)]
    request_spans = [(m.start(), m.end()) for term in sorted(requests, key=len, reverse=True)
                     for m in re.finditer(re.escape(_fold(term)), folded)]
    for a, b in secret_spans:
        for c, d in request_spans:
            left, right = min(a, c), max(b, d)
            if right - left > 100:
                continue
            context = folded[max(0, left - 45):min(len(folded), right + 15)]
            if any(_fold(negation) in context for negation in negations):
                continue
            return True
    return False


def has_url_side_evidence(link_findings: list[dict] | tuple[dict, ...]) -> bool:
    """Require a URL plus a concrete reputation, brand, pattern, or URL-model signal."""
    for finding in link_findings:
        reputation = finding.get("blacklist") or {}
        brand = finding.get("brand") or {}
        patterns = finding.get("patterns") or []
        if reputation.get("match_type") in {"exact", "domain"}:
            return True
        if brand.get("decisive") or float(brand.get("score") or 0) > 0:
            return True
        if any((flag[0] if isinstance(flag, (list, tuple)) else flag)
               in {"userinfo_in_url", "punycode_domain", "confusable_letters", "homoglyph_confusable"}
               for flag in patterns):
            return True
        if finding.get("url_model_above_threshold"):
            return True
    return False


def _has_phrase_pair(text: str, left_terms: list[str], right_terms: list[str], max_gap: int = 100) -> bool:
    folded = _fold(text)
    left_spans = [(m.start(), m.end()) for term in left_terms for m in re.finditer(re.escape(_fold(term)), folded)]
    right_spans = [(m.start(), m.end()) for term in right_terms for m in re.finditer(re.escape(_fold(term)), folded)]
    return any(max(b, d) - min(a, c) <= max_gap for a, b in left_spans for c, d in right_spans)


def _contains_egyptian_phone(text: str) -> bool:
    # Mobile numbers only: local 01x form or international +20 1x form.
    return bool(re.search(r"(?<!\w)(?:0|\+?20[ .()-]*)1[0125](?:[ .()-]?\d){8}(?!\d)", text))


def _contains_short_link(text: str) -> bool:
    data = _keywords()
    for link in extract_links(text)[0]:
        try:
            host = (urlsplit(link if "://" in link else "http://" + link).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if any(host == item or host.endswith("." + item) for item in data["short_link_hosts"]):
            return True
    return False


def has_phone_or_short_link_with_urgent_action(text: str) -> bool:
    """Return true when an Egyptian mobile/shortener and urgent action co-occur."""
    if not isinstance(text, str) or not text.strip():
        return False
    data = _keywords()
    urgent = [term for group in data["urgent_terms"].values() for term in group]
    actions = [term for group in data["action_terms"].values() for term in group]
    if not (_contains_egyptian_phone(text) or _contains_short_link(text)):
        return False
    return _has_phrase_pair(text, urgent, actions, max_gap=140)
