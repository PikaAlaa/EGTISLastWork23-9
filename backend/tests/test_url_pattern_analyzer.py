from app.engines.rule_based.url_pattern_analyzer import analyze_url_patterns


def test_suspicious_url_accumulates_explainable_flags():
    result = analyze_url_patterns("http://192.0.2.4/account/verify?otp=1")
    names = {item["name"] for item in result["flags"]}
    assert {"ip_host", "no_https", "credential_path"} <= names
    assert result["score"] >= 70


def test_clean_https_url_has_no_flags():
    result = analyze_url_patterns("https://example.com/about")
    assert result["score"] == 0
    assert result["flags"] == []
