from __future__ import annotations

from math import prod

from .arabic_keyword_detector import detect_arabic_keywords
from .domain_typosquatting_detector import detect_domain_typosquatting
from .url_pattern_analyzer import analyze_url_patterns


def calculate_rule_based_score(text: str | None = None, url: str | None = None) -> dict:
    details = {
        "arabic_keywords": detect_arabic_keywords(text),
        "domain_typosquatting": detect_domain_typosquatting(url),
        "url_patterns": analyze_url_patterns(url),
    }
    scores = [item["score"] for item in details.values() if item["applicable"] and item["score"] is not None]
    if not scores:
        return {"applicable": False, "score": None, "sub_engines": details, "reason": "No rule-based input supplied"}
    score = round(100 * (1 - prod(1 - value / 100 for value in scores)), 2)
    strongest = max((item for item in details.values() if item["applicable"]), key=lambda item: item["score"] or 0)
    return {"applicable": True, "score": score, "sub_engines": details, "reason": strongest["reason"]}
