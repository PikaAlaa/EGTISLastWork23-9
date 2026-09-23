from app.engines.rule_based.domain_typosquatting_detector import detect_domain_typosquatting, normalize_domain


def test_normalizes_url_hostname():
    assert normalize_domain("HTTPS://WWW.CIBEG.COM/login") == "cibeg.com"


def test_verified_domain_is_allowlisted():
    result = detect_domain_typosquatting("https://secure.cibeg.com/login")
    assert result["score"] == 0
    assert result["allowlisted"] is True


def test_brand_inside_attacker_domain_is_high_risk():
    result = detect_domain_typosquatting("https://cibeg.com.verify-account-now.net")
    assert result["score"] >= 90
    assert result["allowlisted"] is False


def test_one_edit_lookalike_is_detected():
    result = detect_domain_typosquatting("https://c1beg.com")
    assert result["score"] >= 80


def test_brand_letters_inside_unrelated_word_are_not_flagged():
    assert detect_domain_typosquatting("https://notcibeg.com")["score"] == 0


def test_hyphenated_brand_impersonation_is_detected():
    assert detect_domain_typosquatting("https://cibeg-secure.net")["score"] >= 90
