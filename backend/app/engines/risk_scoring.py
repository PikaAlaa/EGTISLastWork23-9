from __future__ import annotations

from app.core.config import settings

DEFAULT_WEIGHTS = {"rule_based": 0.30, "blacklist": 0.40, "ml": 0.30}


def calculate_final_risk_score(engine_results: dict[str, dict], weights: dict[str, float] | None = None) -> dict:
    weights = weights or DEFAULT_WEIGHTS
    rule_details = engine_results.get("rule_based", {}).get("sub_engines", {})
    keywords = rule_details.get("arabic_keywords", {})
    domain = rule_details.get("domain_typosquatting", {})
    blacklist_score = engine_results.get("blacklist", {}).get("score") or 0
    if (
        keywords.get("suppressed_terms")
        and not keywords.get("matched_terms")
        and (domain.get("score") or 0) == 0
        and blacklist_score < 75
        and engine_results.get("ml", {}).get("score") is not None
    ):
        engine_results["ml"] = {
            **engine_results["ml"],
            "score": min(15.0, engine_results["ml"]["score"]),
            "context_adjusted": True,
            "reason": "Text-model score capped because credential terms occur only in a safety warning",
        }
    applicable = {name: result for name, result in engine_results.items() if result.get("applicable") and result.get("score") is not None}
    if not applicable:
        return {"final_score": 0.0, "verdict": "LOW", "reason": "No detection engine could evaluate the input", "engines_applied": [], "weighted_contributions": {}}
    active_weight = sum(weights[name] for name in applicable)
    raw_contributions = {
        name: result["score"] * weights[name] / active_weight
        for name, result in applicable.items()
    }
    contributions = {name: round(value, 2) for name, value in raw_contributions.items()}
    final_score = round(min(100.0, sum(raw_contributions.values())), 2)
    verdict = "HIGH" if final_score >= settings.high_threshold else "MEDIUM" if final_score >= settings.medium_threshold else "LOW"
    strongest_name, strongest = max(applicable.items(), key=lambda item: item[1]["score"])
    if verdict == "LOW":
        reason = "No strong phishing signal detected"
    else:
        reason = strongest.get("reason") or f"Strongest signal: {strongest_name}"
    return {"final_score": final_score, "verdict": verdict, "reason": reason, "engines_applied": list(applicable), "weighted_contributions": contributions}
