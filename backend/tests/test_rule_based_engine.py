from app.engines.risk_scoring import calculate_final_risk_score
from app.engines.rule_based.rule_based_engine import calculate_rule_based_score


def test_rule_engine_handles_no_input():
    assert calculate_rule_based_score()["applicable"] is False


def test_rule_engine_uses_noisy_or():
    result = calculate_rule_based_score(
        text="عاجل: أدخل رمز التحقق",
        url="http://cibeg.com.verify-account-now.net/account/verify",
    )
    assert result["score"] >= 95
    assert len(result["sub_engines"]) == 3


def test_final_score_redistributes_missing_engine_weight():
    result = calculate_final_risk_score({
        "rule_based": {"applicable": True, "score": 60, "reason": "rules"},
        "blacklist": {"applicable": True, "score": 80, "reason": "blacklist"},
        "ml": {"applicable": False, "score": None},
    })
    assert result["final_score"] == 71.43
    assert result["verdict"] == "HIGH"
    assert set(result["weighted_contributions"]) == {"rule_based", "blacklist"}


def test_safety_warning_caps_ml_false_positive():
    rule = calculate_rule_based_score(text="تحذير أمني: لا تشارك رمز التحقق أو كلمة المرور")
    engines = {
        "rule_based": rule,
        "blacklist": {"applicable": False, "score": None},
        "ml": {"applicable": True, "score": 55.0, "reason": "model"},
    }
    result = calculate_final_risk_score(engines)
    assert result["verdict"] == "LOW"
    assert engines["ml"]["context_adjusted"] is True
