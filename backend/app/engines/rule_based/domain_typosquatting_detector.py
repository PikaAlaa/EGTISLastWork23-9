"""Brand rules using the real host: userinfo disguise, whole-domain embedding,
Unicode confusables, token aliases and supporting edit-distance resemblance.
Official hosts bypass only brand resemblance; URL and text checks still run.
"""

import re
import json
from pathlib import Path

from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from app.core.exceptions import InvalidScanInputError


MIN_DOMAIN_LENGTH_FOR_LEVENSHTEIN = 9
MIN_LABEL_LENGTH_FOR_REUSE_CHECK = 4
LEVENSHTEIN_SIMILARITY_THRESHOLD = 0.75
HOMOGLYPH_SCORE = 92.0  # just below domain_embedding's 95 -- both are highly
                         # deceptive, deliberate impersonation techniques,
                         # but domain embedding additionally still contains
                         # the brand's real string verbatim, which is a
                         # marginally stronger signal than a visual-only match

# Brand-label reuse (technique 4) requires one of these nearby, not just bare
# substring containment -- otherwise legitimate infrastructure domains that
# happen to contain a brand's label (e.g. "amazonaws.com", "nooncdn.com") or
# domains containing an accidental common-word match (e.g. "digital" from
# "digital.gov.eg") get flagged incorrectly.
SUSPICIOUS_MODIFIER_PATTERN = re.compile(
    r"secure|verify|login|update|confirm|account|support|service|"
    r"activate|alert|billing|payment|wallet|refund|unlock"
)

# Curated set of visually-confusable Unicode characters mapped to the Latin
# letter they're commonly substituted for in real phishing/homoglyph
# attacks. Covers the Cyrillic and Greek lookalikes most frequently seen in
# the wild -- not exhaustive by design (see module docstring).
CONFUSABLE_CHAR_MAP = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s", "һ": "h", "ј": "j", "ԁ": "d",
    "ѡ": "w", "ѵ": "v",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v", "κ": "k",
    "ι": "i",
}
_extended=json.loads((Path(__file__).parents[2]/'core/confusables_ascii.json').read_text(encoding='utf-8'))
CONFUSABLE_CHAR_MAP.update(_extended['mapping'])
CONFUSABLE_CHARS = set(CONFUSABLE_CHAR_MAP.keys())


def normalize_domain(url_or_domain: str) -> str:
    from app.core.url_utils import parse_url
    host = parse_url(url_or_domain).host
    return host[4:] if host.startswith('www.') else host


def _decode_punycode_labels(domain: str) -> str:
    """
    Decode any 'xn--' punycode-encoded labels in a domain back to their
    real Unicode form, leaving non-punycode labels unchanged. Falls back
    to the original domain unchanged if a label fails to decode (malformed
    punycode should not crash the engine -- it just won't be checked for
    homoglyphs; url_pattern_analyzer's punycode_domain flag still catches
    it as a raw structural signal either way).
    """
    labels = domain.split(".")
    decoded_labels = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                decoded_labels.append(label)
        else:
            decoded_labels.append(label)
    return ".".join(decoded_labels)


def _skeletonize(domain: str) -> str:
    """Map each confusable Unicode character to its Latin lookalike."""
    return "".join(CONFUSABLE_CHAR_MAP.get(char, char) for char in domain)


def _contains_confusable_chars(domain: str) -> bool:
    return any(char in CONFUSABLE_CHARS for char in domain)


def calculate_levenshtein_distance(a: str, b: str) -> int:
    """Standard dynamic-programming edit distance. No external dependency."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insertion = current_row[j - 1] + 1
            deletion = previous_row[j] + 1
            substitution = previous_row[j - 1] + (0 if char_a == char_b else 1)
            current_row.append(min(insertion, deletion, substitution))
        previous_row = current_row

    return previous_row[-1]


def _brand_label(domain: str) -> str:
    """The core label of a domain, e.g. 'cibeg' from 'cibeg.com'."""
    return domain.split(".")[0]



ALIASES = {
    'cibeg.com': {'cib', 'cibeg'}, 'nbe.com.eg': {'nbe', 'ahly'},
    'banquemisr.com': {'banquemisr', 'bm'}, 'qnbalahli.com': {'qnb', 'qnbalahli'},
    'qnb.com.eg': {'qnb'}, 'vodafone.com.eg': {'vodafone'},
    'instapay.eg': {'instapay'}, 'fawry.com': {'fawry'},
}
ACTION_TOKENS = {'login', 'verify', 'secure', 'update', 'account', 'confirm', 'wallet', 'unlock', 'payment'}

def official_host(host, domain):
    return host == domain or host.endswith('.' + domain)

def calculate_domain_typosquatting_score(url_or_domain: str, registry=None) -> dict:
    from urllib.parse import unquote
    from app.core.url_utils import parse_url
    parsed = parse_url(url_or_domain)
    candidate = parsed.host
    brands = registry or EGYPTIAN_BRAND_DOMAINS
    result = dict(score=0.0, matched_brand=None, matched_brand_domain=None,
                  technique=None, normalized_domain=candidate, decisive=False)
    userinfo = unquote(parsed.userinfo).lower()
    user_tokens = set(re.split(r'[^a-z0-9]+', userinfo))
    # An official destination must not hide impersonation of a different brand before @.
    for brand, domain in brands:
        aliases = ALIASES.get(domain, {_brand_label(domain)})
        disguised = user_tokens & aliases or re.search(r'(?<![a-z0-9-])'+re.escape(domain)+r'(?![a-z0-9-])',userinfo)
        if parsed.userinfo and disguised and not official_host(candidate,domain):
            return dict(result,score=95.0,matched_brand=brand,matched_brand_domain=domain,technique='userinfo_brand',decisive=True)
    # An official host cannot impersonate another registry entry through an overlapping name.
    for brand, domain in brands:
        if official_host(candidate, domain):
            return dict(result, matched_brand=brand, matched_brand_domain=domain, technique='exact_match')
    tokens = set(re.split(r'[.-]', candidate))
    actions = set(re.findall(r'[a-z]+', unquote(parsed.path).lower())) & ACTION_TOKENS
    actions |= tokens & ACTION_TOKENS
    skeleton = _skeletonize(parsed.unicode_host)
    for brand, domain in brands:
        aliases = ALIASES.get(domain, {_brand_label(domain)})
        technique, score, decisive = None, 0.0, False
        embedded = ('.' + domain + '.') in ('.' + candidate + '.')
        if parsed.userinfo and (user_tokens & aliases or re.search(r'(?<![a-z0-9-])' + re.escape(domain) + r'(?![a-z0-9-])', userinfo)):
            technique, score, decisive = 'userinfo_brand', 95.0, True
        elif skeleton != candidate and official_host(skeleton, domain):
            technique, score, decisive = 'homoglyph_confusable', 95.0, True
        elif embedded:
            technique, score, decisive = 'domain_embedding', 95.0, True
        elif tokens & aliases and actions:
            technique, score, decisive = 'brand_label_reuse', 95.0, True
        elif tokens & aliases:
            technique, score = 'brand_alias', 40.0
        elif len(domain) >= MIN_DOMAIN_LENGTH_FOR_LEVENSHTEIN:
            similarity = 1 - calculate_levenshtein_distance(candidate, domain) / max(len(candidate), len(domain))
            if similarity >= LEVENSHTEIN_SIMILARITY_THRESHOLD:
                technique, score = 'levenshtein', 60.0
        if score > result['score']:
            result = dict(result, score=score, matched_brand=brand, matched_brand_domain=domain,
                          technique=technique, decisive=decisive)
    return result
