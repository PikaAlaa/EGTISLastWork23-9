from app.engines.rule_based.arabic_keyword_detector import detect_arabic_keywords


def test_detects_high_risk_arabic_terms():
    result = detect_arabic_keywords("أدخل رمز التحقق وكلمة المرور فورا")
    assert result["applicable"] is True
    assert result["score"] >= 80
    assert {item["tier"] for item in result["matched_terms"]} >= {"high"}


def test_clean_message_scores_zero():
    result = detect_arabic_keywords("تم تأكيد موعد فرعك يوم الأحد")
    assert result["score"] == 0


def test_security_warning_does_not_trigger_credential_alarm():
    result = detect_arabic_keywords("تحذير أمني: لا تشارك رمز التحقق أو كلمة المرور مع أي شخص")
    assert result["score"] == 0
    assert len(result["suppressed_terms"]) == 2


def test_safety_words_do_not_hide_a_direct_request():
    result = detect_arabic_keywords("لا تشارك الرمز مع أحد، أرسل لنا رمز التحقق الآن")
    assert result["score"] > 0


def test_no_text_is_not_applicable():
    assert detect_arabic_keywords(None)["applicable"] is False
