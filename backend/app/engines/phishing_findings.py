"""Phishing finding emitter and ATT&CK mapping `attack-map-v1` (design core-v1 §4.4, §5).

`phishing_findings` is a pure function of the finished /analyze result and the
submitted input. It runs after the verdict exists, never calls an engine, model
or threshold, and never changes the result. Severity is a relabelling of the
existing verdict; there are no new cut-offs. Indicators are hash-only; evidence
holds reason codes, versions and indicator strengths, never submitted content.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from app.core.detection_signals import EGYPTIAN_MOBILE_PATTERN, has_secret_request
from app.core.findings import Finding, utc_now
from app.core.indicators import normalize_domain, normalize_email, normalize_ip, normalize_phone, sha256_hex
from app.core.url_utils import registered_domain

ENGINE_NAME = 'phishing.analyze'
ATTACK_MAP_VERSION = 'attack-map-v1'
ATTACK_VERSION = '20.0'
URL_DEPLOYMENT = Path(__file__).resolve().parents[3] / 'ml' / 'models' / 'url_host_deployment.json'
BRAND_DECISIVE = frozenset({'userinfo_brand', 'homoglyph_confusable', 'domain_embedding', 'brand_label_reuse'})
LOOKALIKE = frozenset({'homoglyph_confusable', 'domain_embedding', 'brand_label_reuse'})
URL_SIDE_REASONS = BRAND_DECISIVE | {'blacklist_exact', 'blacklist_domain', 'brand_resemblance', 'url_patterns',
                                     'url_model', 'url_model_corroborated'}
EMAIL_PATTERN = re.compile(r'(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}(?![\w-])')


@lru_cache(maxsize=1)
def url_candidate_id() -> str:
    try:
        return json.loads(URL_DEPLOYMENT.read_text(encoding='utf-8'))['candidate_id']
    except (OSError, ValueError, KeyError):
        return 'unknown'


def severity_and_confidence(result: dict) -> tuple[str, str] | None:
    """§5.2: None means no finding is emitted (LOW, or INCOMPLETE without any signal)."""
    verdict, signals = result['verdict'], set(result.get('supporting_signals') or [])
    if verdict == 'HIGH':
        return 'high', 'confirmed' if 'blacklist_exact' in signals else 'corroborated'
    if verdict == 'MEDIUM':
        return 'medium', 'single_signal'
    if verdict == 'INCOMPLETE' and signals:
        return 'medium', 'undetermined'
    return None


def attack_map_v1(result: dict, text: str) -> list[dict]:
    """§4.4: technique references keyed by existing reason codes. Never influences the verdict."""
    signals = set(result.get('supporting_signals') or [])
    links = result.get('checked_links') or []
    refs = []

    def add(technique, matrix, basis):
        refs.append({'technique_id': technique, 'matrix': matrix, 'attack_version': ATTACK_VERSION, 'basis': basis})
    if text:
        add('T1660', 'mobile', 'sms_text_present')  # Mobile Phishing; Enterprise has no SMS sub-technique
    add('T1566', 'enterprise', 'phishing_message')
    if links and signals & URL_SIDE_REASONS:
        add('T1204.001', 'enterprise', 'link_action_requested')
    if has_secret_request(text):  # same pure function the decision policy uses
        add('T1598', 'enterprise', 'secret_request')
        if links:
            add('T1598.003', 'enterprise', 'secret_request')
    if signals & BRAND_DECISIVE:
        add('T1684.001', 'enterprise', 'brand_decisive')  # T1656 is revoked in v20.0
    elif 'brand_claim_from_mobile_number' in signals:
        add('T1684.001', 'enterprise', 'brand_claim_sender')
    if signals & LOOKALIKE:
        add('T1583.001', 'enterprise', 'lookalike_domain_inferred')
    return refs


def _host_ref(host: str, role: str) -> dict | None:
    try:
        ip = normalize_ip(host)
        return {'type': 'ip', 'value_hash': ip.value_hash, 'value': None, 'role': role}
    except ValueError:
        pass
    try:
        domain = normalize_domain(host)
    except ValueError:
        return None
    return {'type': 'domain', 'value_hash': domain.value_hash, 'value': None, 'role': role,
            'registered_domain_hash': domain.registered_domain_hash}


def indicator_refs(result: dict, text: str) -> list[dict]:
    refs, seen = [], set()

    def add(ref):
        if ref and (ref['type'], ref['value_hash'], ref['role']) not in seen:
            seen.add((ref['type'], ref['value_hash'], ref['role']))
            refs.append(ref)
    for link in result.get('checked_links') or []:
        host = link.get('host') or ''
        try:
            normalize_ip(host)
            parent = None
        except ValueError:
            parent = registered_domain(host) if host else None
        # link['url'] is parse_url(...).canonical, so this equals blacklist_entries.url_hash.
        add({'type': 'url', 'value_hash': sha256_hex(link['url']), 'value': None, 'role': 'delivery_link',
             'registered_domain_hash': sha256_hex(parent) if parent else None})
        technique = (link.get('brand') or {}).get('technique')
        add(_host_ref(host, 'lookalike_domain' if technique in LOOKALIKE else 'link_host'))
    for match in EGYPTIAN_MOBILE_PATTERN.finditer(text):
        try:
            add({'type': 'phone', 'value_hash': normalize_phone(match.group()).value_hash, 'value': None,
                 'role': 'contact_phone'})
        except ValueError:
            continue
    for match in EMAIL_PATTERN.finditer(text):
        try:
            add({'type': 'email', 'value_hash': normalize_email(match.group()).value_hash, 'value': None,
                 'role': 'contact_email'})
        except ValueError:
            continue
    return refs


def _details(result: dict) -> dict:
    text_finding = result.get('text_finding') or {}
    links = result.get('checked_links') or []
    brands = sorted({(l.get('brand') or {}).get('matched_brand') for l in links
                     if (l.get('brand') or {}).get('matched_brand')
                     and ((l.get('brand') or {}).get('decisive') or float((l.get('brand') or {}).get('score') or 0) > 0)})
    return {
        'verdict': result['verdict'],
        'policy_version': result['policy_version'],
        'attack_map': ATTACK_MAP_VERSION,
        'indicator_strength': result['final_score'],
        'text_model_version': text_finding.get('version'),
        'url_model_candidate': url_candidate_id(),
        'url_model': [{'probability': l.get('url_model_probability'), 'threshold': l.get('url_model_threshold')}
                      for l in links],
        'checks_unavailable': list(result.get('checks_unavailable') or []),
        'links_truncated': bool(result.get('links_truncated')),
        'matched_brands': brands,
    }


def phishing_findings(result: dict, payload, scan_request_id: int, now: datetime | None = None) -> list[Finding]:
    graded = severity_and_confidence(result)
    if graded is None:
        return []
    severity, confidence = graded
    text = (getattr(payload, 'text', None) or '').strip()
    now = now or utc_now()
    text_version = (result.get('text_finding') or {}).get('version') or 'none'
    reasons = list(dict.fromkeys([result['decisive_reason'], *(result.get('supporting_signals') or [])]))
    return [Finding.model_validate({
        'engine': {'name': ENGINE_NAME,
                   'version': f"{result['policy_version']}+url:{url_candidate_id()}+text:{text_version}"},
        'domain': 'phishing',
        'kind': 'sms_phishing' if text else 'url_phishing',
        'severity': severity,
        'confidence': confidence,
        'indicators': indicator_refs(result, text),
        'attack': attack_map_v1(result, text),
        'evidence': {'reasons': reasons, 'details': _details(result)},
        'observed_at': now,
        'created_at': now,
        'source': {'kind': 'scan', 'ref': f'scan_requests:{scan_request_id}'},
    })]
