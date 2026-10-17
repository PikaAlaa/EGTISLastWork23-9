"""Decision policy v2: collect all evidence; decisive HIGH, incomplete, supporting, LOW.

Scores are indicator strengths, never calibrated probabilities or additive points.
"""
import time
from app.core.exceptions import InvalidScanInputError
from app.core.url_utils import parse_url, extract_links, MAX_LINKS, MAX_TEXT_LENGTH
from app.core.settings import settings
from app.engines.rule_based.domain_typosquatting_detector import calculate_domain_typosquatting_score
from app.engines.rule_based.url_pattern_analyzer import calculate_url_pattern_score
from app.engines.rule_based.arabic_keyword_detector import calculate_arabic_keyword_phishing_score
from app.engines.rule_based.english_keyword_detector import calculate_english_keyword_phishing_score
from app.engines.threat_intel.blacklist_lookup import calculate_blacklist_reputation_score, blacklist_health, SHARED_HOSTING_DOMAINS
from app.engines.text_model import score_text
from app.models.brand import EgyptianBrand, BrandDomain
from app.core.brand_contacts import official_contact
from app.core.detection_signals import has_secret_request, has_url_side_evidence, has_phone_or_short_link_with_urgent_action
from app.engines.url_model import score_url
from app.core.sender_claims import has_financial_or_telecom_brand_claim

POLICY_VERSION = 'decision-v2'

def calculate_final_risk_score(text=None, url=None, db=None, sender_type=None):
    start = time.perf_counter()
    text = text.strip() if isinstance(text, str) else ''
    url = url.strip() if isinstance(url, str) else ''
    if not text and not url:
        raise InvalidScanInputError('input_required')
    if len(text) > MAX_TEXT_LENGTH:
        raise InvalidScanInputError('text_too_long')
    if url:
        parse_url(url)
    extracted, invalid = extract_links(text)
    candidates = ([url] if url else []) + extracted
    # Preserve bare status for pattern checks, deduplicate by canonical identity.
    unique = {}
    for value in candidates:
        parsed = parse_url(value)
        # Canonical reputation identity omits userinfo; the evidence identity must retain it.
        unique.setdefault((parsed.canonical, parsed.userinfo), value)
    truncated = len(unique) > MAX_LINKS
    unavailable = list(invalid)
    if truncated:
        unavailable.append('links_truncated')
    registry = None
    health = {'available': False, 'reason': 'database_unavailable'}
    if unique and db is not None:
        try:
            health = blacklist_health(db)
            rows = db.query(EgyptianBrand.brand_name, BrandDomain.domain).join(BrandDomain).all()
            registry = rows or None
        except Exception:
            db.rollback()
    decisive, supporting, strengths = [], [], []
    if sender_type == 'mobile_number' and has_financial_or_telecom_brand_claim(text):
        # Supporting only: never corroborates text HIGH or authenticates a sender.
        supporting.append('brand_claim_from_mobile_number')
    links = []
    url_model_high = False
    for (canonical, _userinfo), value in list(unique.items())[:MAX_LINKS]:
        parsed = parse_url(value)
        brand = calculate_domain_typosquatting_score(value, registry=registry)
        brand['official_contact']=official_contact(brand.get('matched_brand'))
        pattern = calculate_url_pattern_score(value)
        reputation = {'score': 0, 'match_type': None, 'matched_entry': None}
        available = health['available']
        if not available:
            unavailable.append(health['reason'])
        if db is not None:
            try:
                reputation = calculate_blacklist_reputation_score(value, db)
            except Exception:
                db.rollback()
                available = False
                unavailable.append('database_unavailable')
        if reputation['match_type'] == 'exact':
            decisive.append('blacklist_exact')
        elif reputation['match_type'] == 'domain':
            supporting.append('blacklist_domain')
        if brand['decisive']:
            decisive.append(brand['technique'])
        elif brand['score']:
            supporting.append('brand_resemblance')
        if pattern['flags']:
            supporting.append('url_patterns')
        model_result = None
        try:
            model_result = score_url(value)
        except Exception:
            # The URL model is an optional supporting engine; its absence must not
            # weaken exact blacklist, brand, or other existing rule evidence.
            model_result = None
        model_probability = model_result.get('probability') if model_result else None
        model_threshold = model_result.get('threshold') if model_result else None
        model_above_raw = bool(model_probability is not None and model_threshold is not None
                               and model_probability >= model_threshold)
        # Host-only features cannot distinguish a benign hosted document from a
        # malicious path on the same provider. Retain the existing generic policy
        # for shared hosts; exact URL matches and secret requests still apply.
        # Verified official domains are likewise handled by the existing registry,
        # uniformly across all brands, with no bank-name exception.
        official_host = brand.get('technique') == 'exact_match'
        shared_host = any(parsed.host == shared or parsed.host.endswith('.' + shared)
                          for shared in SHARED_HOSTING_DOMAINS)
        model_above = model_above_raw and not official_host and not shared_host
        url_model_high = url_model_high or model_above_raw
        if model_above:
            supporting.append('url_model')
        strengths.extend([brand['score'], pattern['score'], reputation['score']])
        links.append({'url': canonical, 'host': parsed.host, 'bare': parsed.bare,
                      'brand': brand, 'patterns': pattern['flags'], 'blacklist': reputation,
                      'url_model_probability': model_probability,
                      'url_model_threshold': model_threshold,
                      'url_model_above_threshold': model_above,
                      'url_model_raw_above_threshold': model_above_raw,
                      'verified_official_host': official_host,
                      'shared_hosting_domain': shared_host,
                      'analysis_complete': available})
    text_finding = None
    text_high = False
    secret_request = has_secret_request(text)
    urgent_contact = has_phone_or_short_link_with_urgent_action(text)
    if text:
        # Existing keyword rules remain supporting evidence, not probability estimates.
        keyword = max(calculate_arabic_keyword_phishing_score(text)['score'], calculate_english_keyword_phishing_score(text)['score'])
        try:
            text_finding = score_text(text)
            probability = text_finding['probability']
            high = text_finding.get('high_threshold', settings.text_high_threshold)
            low = text_finding.get('low_threshold', settings.text_low_threshold)
            strengths.append(text_finding['score'])
            if probability >= high:
                text_high = True
            elif probability > low:
                supporting.append('text_medium')
            # One keyword cannot turn a low-probability routine SMS into an alert.
            if keyword >= 60:
                supporting.append('text_keywords')
        except Exception:
            unavailable.append('text_model_unavailable')
    # A URL model alert alone is MEDIUM. A model alert plus brand impersonation
    # or a request for secrets is HIGH; exact blacklist and existing decisive
    # URL rules retain priority. The text model cannot independently produce HIGH.
    if url_model_high and (secret_request or any((item.get('brand') or {}).get('decisive') for item in links)):
        decisive.append('url_model_corroborated')
    corroborated_text = bool(links and has_url_side_evidence(links)) or secret_request or urgent_contact
    if text_high and corroborated_text:
        decisive.append('text_high_corroborated')
    elif text_high:
        supporting.append('text_model_high_uncorroborated')
    unavailable = sorted(set(unavailable))
    if decisive:
        verdict, reason, score = 'HIGH', decisive[0], max(90.0, max(strengths, default=0))
    elif unavailable:
        verdict, reason, score = 'INCOMPLETE', unavailable[0], max(strengths, default=0)
    elif supporting:
        verdict, reason, score = 'MEDIUM', supporting[0], max(20.0, min(79.0, max(strengths, default=0)))
    else:
        verdict, reason, score = 'LOW', 'no_warning_signs', max(strengths, default=0)
    return {'verdict': verdict, 'final_score': round(score, 2), 'decisive_reason': reason,
            'supporting_signals': sorted(set(supporting + decisive)), 'checked_links': links,
            'links_truncated': truncated, 'text_finding': text_finding,
            'analysis_complete': not unavailable, 'checks_unavailable': unavailable,
            'policy_version': POLICY_VERSION, 'timing_ms': round((time.perf_counter()-start)*1000, 2)}
