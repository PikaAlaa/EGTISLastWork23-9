"""Calibrate a binary phishing decision threshold on the validation split."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from sklearn.metrics import precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "backend"))

from app.engines.ml import calculate_ml_score  # noqa: E402
from app.engines.risk_scoring import calculate_final_risk_score  # noqa: E402
from app.engines.rule_based import calculate_rule_based_score  # noqa: E402
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain  # noqa: E402
from app.engines.rule_based.url_utils import canonicalize_url  # noqa: E402
from app.engines.blacklist import SHARED_HOSTING_SUFFIXES  # noqa: E402

DATASET = ROOT / "data" / "processed" / "dataset.csv"
REPORT = ROOT / "evaluation" / "reports" / "threshold_calibration.json"


def main() -> None:
    with DATASET.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    train_bad_urls = {
        canonicalize_url(row["text"]) for row in rows
        if row["split"] == "train" and row["content_type"] == "url" and row["label"] == "phishing"
    }
    train_bad_domains = {normalize_domain(url) for url in train_bad_urls}
    scores, labels = [], []
    for row in rows:
        if row["split"] != "val":
            continue
        url = row["text"] if row["content_type"] == "url" else None
        text = row["text"] if row["content_type"] in {"text", "email"} else None
        if not url:
            blacklist = {"applicable": False, "score": None, "reason": "No URL supplied"}
        elif canonicalize_url(url) in train_bad_urls:
            blacklist = {"applicable": True, "score": 98.0, "match_type": "exact", "reason": "Train-split exact match"}
        elif normalize_domain(url) in train_bad_domains and not any(
            normalize_domain(url) == suffix or normalize_domain(url).endswith(f".{suffix}")
            for suffix in SHARED_HOSTING_SUFFIXES
        ):
            blacklist = {"applicable": True, "score": 75.0, "match_type": "domain", "reason": "Train-split domain match"}
        else:
            blacklist = {"applicable": True, "score": 0.0, "match_type": None, "reason": "No train-split match"}
        engines = {
            "rule_based": calculate_rule_based_score(text=text, url=url),
            "blacklist": blacklist,
            "ml": calculate_ml_score(text),
        }
        scores.append(calculate_final_risk_score(engines)["final_score"])
        labels.append(1 if row["label"] == "phishing" else 0)

    candidates = []
    for threshold in range(20, 91):
        predictions = [int(score >= threshold) for score in scores]
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
        false_positives = sum(pred == 1 and label == 0 for pred, label in zip(predictions, labels))
        candidates.append({"threshold": threshold, "precision": precision, "recall": recall, "f1": f1, "false_positives": false_positives})
    best = max(candidates, key=lambda item: (item["f1"], item["precision"], -item["false_positives"]))
    report = {
        "validation_samples": len(labels),
        "blacklist_protocol": "built from training-split phishing URLs only; validation/test feed rows were not seeded",
        "selected_high_threshold": best["threshold"],
        # The dataset is binary, so MEDIUM cannot be directly optimized. Keep it
        # close to the validated phishing threshold to protect boundary precision.
        "selected_medium_threshold": max(10, round(best["threshold"] * 0.85)),
        "validation_metrics_at_high_threshold": {key: round(value, 6) if isinstance(value, float) else value for key, value in best.items() if key != "threshold"},
        "warning": "Test-set metrics must be produced only after these thresholds are frozen.",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
