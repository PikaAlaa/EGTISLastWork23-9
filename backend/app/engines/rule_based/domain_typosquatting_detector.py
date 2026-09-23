from __future__ import annotations

import re
from urllib.parse import urlparse

from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS, VERIFIED_DOMAINS


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").casefold().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def levenshtein_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_left != char_right)))
        previous = current
    return previous[-1]


def _brand_token(domain: str) -> str:
    return re.sub(r"[^a-z0-9]", "", domain.split(".")[0].casefold())


def detect_domain_typosquatting(url: str | None) -> dict:
    if not url:
        return {"applicable": False, "score": None, "domain": None, "matched_brand": None, "reason": "No URL supplied"}
    domain = normalize_domain(url)
    if not domain:
        return {"applicable": True, "score": 35.0, "domain": domain, "matched_brand": None, "reason": "URL has no valid hostname"}
    for verified in VERIFIED_DOMAINS:
        if domain == verified or domain.endswith(f".{verified}"):
            return {"applicable": True, "score": 0.0, "domain": domain, "matched_brand": verified, "allowlisted": True, "reason": "Verified institution domain"}

    best = None
    host_labels = [part for label in domain.split(".") for part in label.split("-") if part]
    for brand, verified in EGYPTIAN_BRAND_DOMAINS:
        token = _brand_token(verified)
        first_label = _brand_token(domain)
        distance = levenshtein_distance(first_label, token)
        embedded = len(token) >= 4 and token in host_labels
        if embedded:
            score, reason = 95.0, "Official brand label embedded in an unverified domain"
        elif distance == 1 and max(len(first_label), len(token)) >= 4:
            score, reason = 88.0, "One-edit lookalike of a verified institution domain"
        elif distance == 2 and max(len(first_label), len(token)) >= 6:
            score, reason = 68.0, "Close lookalike of a verified institution domain"
        else:
            continue
        candidate = (score, brand, verified, distance, reason)
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best:
        score, brand, verified, distance, reason = best
        return {"applicable": True, "score": score, "domain": domain, "matched_brand": brand, "official_domain": verified, "edit_distance": distance, "allowlisted": False, "reason": reason}
    return {"applicable": True, "score": 0.0, "domain": domain, "matched_brand": None, "allowlisted": False, "reason": "No Egyptian-brand lookalike detected"}
