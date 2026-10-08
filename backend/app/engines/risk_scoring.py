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
from app.engines.threat_intel.blacklist_lookup import calculate_blacklist_reputation_score, blacklist_health
from app.engines.text_model import score_text
from app.models.brand import EgyptianBrand, BrandDomain
from app.core.brand_contacts import official_contact

POLICY_VERSION = 'decision-v2'

def calculate_final_risk_score(text=None, url=None, db=None):
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
    links = []
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
        strengths.extend([brand['score'], pattern['score'], reputation['score']])
        links.append({'url': canonical, 'host': parsed.host, 'bare': parsed.bare,
                      'brand': brand, 'patterns': pattern['flags'], 'blacklist': reputation,
                      'analysis_complete': available})
    text_finding = None
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
                decisive.append('text_high')
            elif probability > low:
                supporting.append('text_medium')
            # One keyword cannot turn a low-probability routine SMS into an alert.
            if keyword >= 60:
                supporting.append('text_keywords')
        except Exception:
            unavailable.append('text_model_unavailable')
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
