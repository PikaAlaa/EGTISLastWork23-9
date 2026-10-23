"""Local lexical URL model; treats URL text as data and never makes network calls."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import hashlib

import joblib
import tldextract
from app.core.url_utils import parse_url
from app.engines.url_features import url_features, phresh_features, shortcut_features

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
    """Score inert URL characters with the packaged artifact's frozen schema."""
    artifact = _load()
    if artifact is None:
        return None
    parsed = parse_url(value)
    extractor = _extractor()
    schema = artifact.get('deployment_schema')
    if schema:
        representation = schema['representation']
        if representation not in {'host_only', 'full_url', 'shortcut_only'}:
            raise ValueError('Unsupported deployed URL representation')
        input_mode = schema.get('input_mode', 'original')
        if input_mode == 'host_path' and representation == 'full_url':
            # Model input only. The scanner retains the complete original URL
            # for blacklist identity, brand/pattern checks and displayed evidence.
            value = value.split('#', 1)[0].split('?', 1)[0]
        elif input_mode != 'original':
            raise ValueError('Unsupported deployed URL input mode')
        feature = value if representation == 'full_url' else parsed.host
        if 'pipeline' in artifact:
            probability = float(artifact['pipeline'].predict_proba([feature])[0, 1])
        else:
            if artifact['vectorizer'].__class__.__name__ == 'DictVectorizer':
                if extractor is None:
                    return None
                if representation == 'shortcut_only':
                    feature = shortcut_features(value)
                elif schema['phresh_schema']:
                    feature = phresh_features(value, parsed.host, extractor, representation == 'full_url')
                else:
                    feature = url_features(feature, extractor)
            features = artifact['vectorizer'].transform([feature])
            probability = float(artifact['classifier'].predict_proba(features)[0, 1])
    elif 'classifier' in artifact:
        if extractor is None:
            return None
        if artifact.get('research_feature_version') == 'phresh-1':
            # The promoted calibrated SVM consumes canonical host characters,
            # not the earlier LightGBM feature dictionary. Fail closed on an
            # incompatible research artifact instead of silently mis-scoring it.
            if artifact.get('representation') != 'host_only' or artifact.get('model') != 'char_calibrated_svm':
                raise ValueError('Unsupported deployed URL feature schema')
            features = artifact['vectorizer'].transform([parsed.host])
        else:
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
