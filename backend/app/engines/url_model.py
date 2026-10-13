"""Local lexical URL model; treats URL text as data and never makes network calls."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import hashlib

import joblib
import tldextract
from app.core.url_utils import parse_url
from app.engines.url_features import url_features

ARTIFACT = Path(__file__).resolve().parents[3] / "ml" / "models" / "url_host_v3.joblib"
PSL = Path(__file__).resolve().parents[3] / "evaluation" / "reports" / "2026-10-v3" / "public_suffix_list.dat"


@lru_cache(maxsize=1)
def _load():
    if not ARTIFACT.is_file():
        return None
    artifact = joblib.load(ARTIFACT)
    artifact["artifact_sha256"] = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    return artifact


@lru_cache(maxsize=1)
def _extractor():
    if not PSL.is_file():
        return None
    return tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(PSL.resolve().as_uri(),),
                                 fallback_to_snapshot=False, include_psl_private_domains=True)


def score_url(value: str) -> dict | None:
    """Score the canonical host string. Return None before the model is packaged."""
    artifact = _load()
    if artifact is None:
        return None
    parsed = parse_url(value)
    extractor = _extractor()
    if 'classifier' in artifact:
        if extractor is None:
            return None
        features = artifact['vectorizer'].transform([url_features(parsed.host, extractor)])
        probability = float(artifact['classifier'].predict_proba(features)[0, 1])
    else:
        probability = float(artifact["pipeline"].predict_proba([parsed.host])[0, 1])
    if extractor:
        ext = extractor(parsed.host)
        registered = (ext.top_domain_under_public_suffix or parsed.host).lower()
    else:
        registered = parsed.host
    return {"probability": probability,
            "threshold": float(artifact["thresholds"]["medium"]),
            "registered_domain": registered,
            "version": artifact["artifact_sha256"][:16]}
