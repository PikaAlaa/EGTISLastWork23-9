"""Unit fixtures only; these strings are not dataset records or examples of real messages."""
from app.core.detection_signals import (
    has_phone_or_short_link_with_urgent_action,
    has_secret_request,
    has_url_side_evidence,
)


def test_secret_request_keywords_cover_english_arabic_and_egyptian_dialect():
    assert has_secret_request("Please send your one-time code to restore access")
    assert has_secret_request("ابعت كود التحقق لتأكيد الدخول")
    assert has_secret_request("eb3at el code now")


def test_secret_notice_that_warns_against_sharing_is_not_a_request():
    assert not has_secret_request("Your verification code is 1234. Do not share it")
    assert not has_secret_request("لا تشارك رمز التحقق مع أي شخص")


def test_urgent_contact_signal_requires_phone_or_short_link_and_action():
    assert has_phone_or_short_link_with_urgent_action("Call 01012345678 immediately")
    assert has_phone_or_short_link_with_urgent_action("Call +20 10 12345678 immediately")
    assert has_phone_or_short_link_with_urgent_action("Click https://bit.ly/abc today")
    assert not has_phone_or_short_link_with_urgent_action("Call 01012345678 when convenient")
    assert not has_phone_or_short_link_with_urgent_action("Click this today")


def test_url_signal_checks_reputation_brand_pattern_or_model():
    assert has_url_side_evidence([{"blacklist": {"match_type": "exact"}}])
    assert has_url_side_evidence([{"brand": {"score": 40}}])
    assert has_url_side_evidence([{"patterns": [("userinfo_in_url", 20, None)]}])
    assert has_url_side_evidence([{"url_model_above_threshold": True}])
    assert not has_url_side_evidence([{"blacklist": {}, "brand": {"score": 0}, "patterns": []}])
