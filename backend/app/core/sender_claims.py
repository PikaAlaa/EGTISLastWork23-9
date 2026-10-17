"""Transient sender-display evidence. No phone number is requested or retained."""
import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from app.core.egyptian_brands import BRAND_CATEGORIES, EGYPTIAN_BRAND_DOMAINS
from app.core.text_utils import normalize_arabic_text

KEYWORDS = Path(__file__).resolve().parents[3] / 'data/sender_claim_keywords.json'
ELIGIBLE_CATEGORIES = {'bank', 'wallet', 'telecom', 'payments', 'finance'}


def fold(value):
    return ' '.join(normalize_arabic_text(unicodedata.normalize('NFKC', value)).casefold().split())


def phrase(value):
    return r'(?<!\w)' + re.escape(fold(value)) + r'(?!\w)'


@lru_cache(maxsize=1)
def vocabulary():
    return json.loads(KEYWORDS.read_text(encoding='utf-8'))


def has_financial_or_telecom_brand_claim(text):
    """Recognize named sender claims, branded prefixes/signatures and bank claims.

    This is an exposed heuristic, not sender authentication. A casual mid-sentence
    mention is insufficient. Vocabulary is restricted to eligible registry brands;
    delivery/shopping/government names do not trigger the sender rule.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    value = fold(text)
    words = vocabulary()
    if any(re.search(phrase(term), value) for term in words['generic_claims']):
        return True
    registered = {name for name, _ in EGYPTIAN_BRAND_DOMAINS}
    for name in registered:
        if BRAND_CATEGORIES.get(name) not in ELIGIBLE_CATEGORIES:
            continue
        for alias in [name, *words['aliases'].get(name, [])]:
            for match in re.finditer(phrase(alias), value):
                prefix, suffix = value[:match.start()], value[match.end():]
                # Brand at the start, or a sender signature after a dash/colon.
                if not prefix.strip() or (prefix.rstrip().endswith(('-', '—', ':')) and not suffix.strip(' .!،')):
                    return True
                # Require a claim cue immediately before the brand (up to three
                # intervening words), not any unrelated occurrence of 'from'.
                if any(re.search(phrase(term) + r'\s+(?:\w+\s+){0,3}$', prefix[-70:])
                       for term in words['claim_prefixes']):
                    return True
    return False
