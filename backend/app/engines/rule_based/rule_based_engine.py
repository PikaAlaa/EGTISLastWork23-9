"""Compatibility helper: strongest rule indicator, with all engine findings retained.
Scores are heuristic strengths; decision-v2 chooses the verdict.
"""

from app.core.exceptions import InvalidScanInputError
from app.engines.rule_based.arabic_keyword_detector import calculate_arabic_keyword_phishing_score
from app.engines.rule_based.english_keyword_detector import calculate_english_keyword_phishing_score
from app.engines.rule_based.domain_typosquatting_detector import calculate_domain_typosquatting_score
from app.engines.rule_based.url_pattern_analyzer import calculate_url_pattern_score


def calculate_rule_based_score(text: str | None = None, url: str | None = None) -> dict:
    """
    Run all applicable rule-based sub-engines and combine their scores.

    At least one of `text` or `url` must be provided (non-empty).

    Returns a dict:
        {
            "score": float,   # 0-100, strongest applicable indicator
            "engine_results": {
                "arabic_keyword":       {...} | None,  # None if not applicable (no text)
                "english_keyword":      {...} | None,  # None if not applicable (no text)
                "domain_typosquatting": {...} | None,  # None if not applicable (no url)
                "url_pattern":          {...} | None,  # None if not applicable (no url)
            },
        }

    Raises InvalidScanInputError if neither text nor url is provided.
    """
    text_provided = isinstance(text, str) and text.strip() != ""
    url_provided = isinstance(url, str) and url.strip() != ""

    if not text_provided and not url_provided:
        raise InvalidScanInputError("At least one of 'text' or 'url' must be provided.")

    engine_results = {
        "arabic_keyword": None,
        "english_keyword": None,
        "domain_typosquatting": None,
        "url_pattern": None,
    }
    applicable_scores = []

    if text_provided:
        keyword_result = calculate_arabic_keyword_phishing_score(text)
        engine_results["arabic_keyword"] = keyword_result
        applicable_scores.append(keyword_result["score"])

        english_keyword_result = calculate_english_keyword_phishing_score(text)
        engine_results["english_keyword"] = english_keyword_result
        applicable_scores.append(english_keyword_result["score"])

    if url_provided:
        typosquat_result = calculate_domain_typosquatting_score(url)
        engine_results["domain_typosquatting"] = typosquat_result
        applicable_scores.append(typosquat_result["score"])

        url_pattern_result = calculate_url_pattern_score(url)
        engine_results["url_pattern"] = url_pattern_result
        applicable_scores.append(url_pattern_result["score"])

    combined_score = round(max(applicable_scores, default=0), 2)

    return {
        "score": combined_score,
        "engine_results": engine_results,
    }
