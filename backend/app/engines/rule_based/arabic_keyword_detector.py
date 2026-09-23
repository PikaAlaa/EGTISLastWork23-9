from __future__ import annotations

import re
from math import prod

TERM_TIERS = {
    "high": (
        "كلمة المرور", "الرقم السري", "رمز التحقق", "كود التحقق", "otp",
        "بيانات البطاقة", "حسابك سيتم تعليقه", "حسابك معرض للإغلاق",
    ),
    "medium": (
        "تأكيد بياناتك", "تحديث بياناتك", "اضغط هنا", "سجل الدخول",
        "تجنب الإيقاف", "نشاط غير معتاد", "محاولة دخول", "استرداد المبلغ",
    ),
    "low": (
        "فورا", "عاجل", "خلال 24 ساعة", "جائزة", "مكافأة", "تم حظر",
        "urgent", "verify", "suspended", "locked",
    ),
}
WEIGHTS = {"high": 65.0, "medium": 35.0, "low": 16.0}
SAFETY_PHRASES = (
    "لا تشارك", "لن نطلب", "لا نطلب", "لا ترسل", "احذر", "تحذير امني",
    "اي طلب", "حافظ على سرية", "do not share", "never ask",
)
DIRECT_REQUESTS = (
    "ادخل", "يرجي ادخال", "ارسل", "زودنا", "قدم", "اكتب", "اضغط هنا",
    "enter", "send", "submit", "verify now",
)


def _normalize(text: str) -> str:
    text = text.casefold()
    text = re.sub(r"[إأآٱ]", "ا", text)
    text = re.sub(r"ى", "ي", text)
    text = re.sub(r"ؤ", "و", text)
    text = re.sub(r"ئ", "ي", text)
    text = re.sub(r"[ًٌٍَُِّْـ]", "", text)
    return " ".join(text.split())


def detect_arabic_keywords(text: str | None) -> dict:
    if not text:
        return {"applicable": False, "score": None, "matched_terms": [], "reason": "No text supplied"}
    normalized = _normalize(text)
    safety_context = any(_normalize(phrase) in normalized for phrase in SAFETY_PHRASES)
    direct_request = any(_normalize(phrase) in normalized for phrase in DIRECT_REQUESTS)
    matches = []
    suppressed = []
    weights = []
    for tier, terms in TERM_TIERS.items():
        for term in terms:
            if _normalize(term) in normalized:
                match = {"term": term, "tier": tier, "weight": WEIGHTS[tier]}
                if safety_context and not direct_request and tier in {"high", "medium"}:
                    suppressed.append(match)
                else:
                    matches.append(match)
                    weights.append(WEIGHTS[tier])
    score = round(100 * (1 - prod(1 - weight / 100 for weight in weights)), 2) if weights else 0.0
    if matches:
        reason = "Matched suspicious credential/urgency language"
    elif suppressed:
        reason = "Credential terms occur in a safety-warning context"
    else:
        reason = "No suspicious keyword pattern found"
    return {"applicable": True, "score": score, "matched_terms": matches, "suppressed_terms": suppressed, "reason": reason}
