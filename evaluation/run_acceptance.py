"""Run the final local acceptance set and write a traceable report."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

REPORT = ROOT / "acceptance_test_report.json"
CASES = [
    {
        "name": "known_blacklisted_url",
        "payload": {"url": "https://allegrolokalnie.pl-5878761824523.lol/oferta/l/-130425072"},
        "expected": "HIGH",
    },
    {
        "name": "verified_egyptian_bank",
        "payload": {"url": "https://www.cibeg.com"},
        "expected": "LOW",
    },
    {
        "name": "arabic_credential_phishing",
        "payload": {"text": "عاجل: أدخل كلمة المرور ورمز التحقق لتجنب إيقاف حسابك"},
        "expected": "HIGH",
    },
    {
        "name": "mixed_language_phishing",
        "payload": {"text": "Urgent: حسابك suspended. Verify كلمة المرور و OTP الآن"},
        "expected": "HIGH",
    },
    {
        "name": "legitimate_arabic_notice",
        "payload": {"text": "تم تأكيد موعد زيارتك للفرع يوم الأحد الساعة العاشرة صباحا"},
        "expected": "LOW",
    },
    {
        "name": "legitimate_security_warning",
        "payload": {"text": "تحذير أمني: لا تشارك رمز التحقق أو كلمة المرور مع أي شخص"},
        "expected": "LOW",
    },
    {
        "name": "verified_domain_with_phishing_text",
        "payload": {"url": "https://www.cibeg.com", "text": "عاجل أدخل كلمة المرور ورمز التحقق فورا"},
        "expected": "HIGH",
    },
    {
        "name": "unrelated_domain_containing_brand_letters",
        "payload": {"url": "https://notcibeg.com"},
        "expected": "LOW",
    },
]


def main() -> int:
    results = []
    with TestClient(app) as client:
        for case in CASES:
            started = time.perf_counter()
            response = client.post("/analyze", json=case["payload"])
            latency_ms = (time.perf_counter() - started) * 1000
            body = response.json()
            actual = body.get("verdict")
            results.append({
                "name": case["name"],
                "expected": case["expected"],
                "actual": actual,
                "score": body.get("final_score"),
                "status_code": response.status_code,
                "latency_ms": round(latency_ms, 2),
                "passed": response.status_code == 200 and actual == case["expected"],
            })
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": "local SQLite, canonically seeded blacklist, validation-selected TF-IDF model",
        "passed": all(item["passed"] for item in results),
        "cases": results,
        "average_latency_ms": round(sum(item["latency_ms"] for item in results) / len(results), 2),
        "limitations": [
            "Not a hosted-environment benchmark",
            "Commercial-tool comparison requires an authorized external API key",
            "BiLSTM was evaluated separately and not selected because validation F1 was lower",
        ],
    }
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
