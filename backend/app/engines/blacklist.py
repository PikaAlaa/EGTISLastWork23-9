from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import BlacklistEntry
from .rule_based.domain_typosquatting_detector import normalize_domain
from .rule_based.url_utils import canonicalize_url

SHARED_HOSTING_SUFFIXES = {
    "blogspot.com", "github.io", "myfreesites.net", "netlify.app", "onrender.com",
    "pages.dev", "vercel.app", "weebly.com", "wixsite.com", "wixstudio.com",
}


def calculate_blacklist_score(db: Session, url: str | None) -> dict:
    if not url:
        return {"applicable": False, "score": None, "match_type": None, "reason": "No URL supplied"}
    canonical_url = canonicalize_url(url)
    url_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
    exact = db.scalar(select(BlacklistEntry).where(BlacklistEntry.url_hash == url_hash))
    if exact:
        return {"applicable": True, "score": 98.0, "match_type": "exact", "entry_id": exact.id, "source": exact.source, "reason": "Exact URL appears in a phishing feed"}
    domain = normalize_domain(url)
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in SHARED_HOSTING_SUFFIXES):
        return {"applicable": True, "score": 0.0, "match_type": None, "reason": "No domain-wide match applied to shared hosting"}
    domain_match = db.scalar(select(BlacklistEntry).where(BlacklistEntry.domain == domain).limit(1)) if domain else None
    if domain_match:
        return {"applicable": True, "score": 75.0, "match_type": "domain", "entry_id": domain_match.id, "source": domain_match.source, "reason": "Domain appears in a phishing feed"}
    return {"applicable": True, "score": 0.0, "match_type": None, "reason": "URL is not present in the local blacklist"}
