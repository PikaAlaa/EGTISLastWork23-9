"""Evaluate frozen hybrid scoring and individual engines on the held-out test split."""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.engines.ml import calculate_ml_score  # noqa: E402
from app.engines.risk_scoring import calculate_final_risk_score  # noqa: E402
from app.engines.rule_based import calculate_rule_based_score  # noqa: E402
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain  # noqa: E402
from app.engines.rule_based.url_utils import canonicalize_url  # noqa: E402
from app.engines.blacklist import SHARED_HOSTING_SUFFIXES  # noqa: E402

DATASET = ROOT / "data" / "processed" / "dataset.csv"
CALIBRATION = ROOT / "evaluation" / "reports" / "threshold_calibration.json"
REPORT = ROOT / "evaluation" / "reports" / "hybrid_test_metrics.json"


def choose_threshold(scores: list[float], labels: list[int]) -> int:
    choices = []
    # A zero threshold labels every sample phishing and is not a meaningful detector.
    for threshold in range(1, 101):
        predictions = [int(score >= threshold) for score in scores]
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
        choices.append((f1, precision, recall, threshold))
    return max(choices)[3]


def metric_set(scores: list[float], labels: list[int], threshold: int) -> dict:
    predictions = [int(score >= threshold) for score in scores]
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    false_positives = sum(pred == 1 and label == 0 for pred, label in zip(predictions, labels))
    negatives = max(1, sum(label == 0 for label in labels))
    return {
        "samples": len(labels), "threshold": threshold,
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision), 6), "recall": round(float(recall), 6), "f1": round(float(f1), 6),
        "roc_auc": round(float(roc_auc_score(labels, scores)), 6),
        "false_positive_rate": round(false_positives / negatives, 6),
    }


def main() -> None:
    with DATASET.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    train_bad_urls = {canonicalize_url(row["text"]) for row in rows if row["split"] == "train" and row["content_type"] == "url" and row["label"] == "phishing"}
    train_bad_domains = {normalize_domain(url) for url in train_bad_urls}
    outputs = {split: {name: ([], []) for name in ("rule_all", "blacklist_all", "hybrid_all", "ml_text_only")} for split in ("val", "test")}

    for row in rows:
        if row["split"] not in outputs:
            continue
        url = row["text"] if row["content_type"] == "url" else None
        text = row["text"] if row["content_type"] in {"text", "email"} else None
        rule = calculate_rule_based_score(text=text, url=url)
        if not url:
            blacklist = {"applicable": False, "score": None, "reason": "No URL supplied"}
        elif canonicalize_url(url) in train_bad_urls:
            blacklist = {"applicable": True, "score": 98.0, "reason": "Train exact match"}
        elif normalize_domain(url) in train_bad_domains and not any(
            normalize_domain(url) == suffix or normalize_domain(url).endswith(f".{suffix}")
            for suffix in SHARED_HOSTING_SUFFIXES
        ):
            blacklist = {"applicable": True, "score": 75.0, "reason": "Train domain match"}
        else:
            blacklist = {"applicable": True, "score": 0.0, "reason": "No train match"}
        ml = calculate_ml_score(text)
        hybrid = calculate_final_risk_score({"rule_based": rule, "blacklist": blacklist, "ml": ml})
        label = int(row["label"] == "phishing")
        for name, score in (("rule_all", rule["score"] or 0.0), ("blacklist_all", blacklist["score"] or 0.0), ("hybrid_all", hybrid["final_score"])):
            outputs[row["split"]][name][0].append(score)
            outputs[row["split"]][name][1].append(label)
        if text:
            outputs[row["split"]]["ml_text_only"][0].append(ml["score"] or 0.0)
            outputs[row["split"]]["ml_text_only"][1].append(label)

    calibration = json.loads(CALIBRATION.read_text(encoding="utf-8"))
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": "Thresholds selected on validation only; metrics reported on held-out test only; blacklist built from train split only.",
        "test_metrics": {},
    }
    for name, (test_scores, test_labels) in outputs["test"].items():
        if name == "hybrid_all":
            threshold = int(calibration["selected_high_threshold"])
        else:
            val_scores, val_labels = outputs["val"][name]
            threshold = choose_threshold(val_scores, val_labels)
        report["test_metrics"][name] = metric_set(test_scores, test_labels, threshold)
    report["notes"] = [
        "ML is reported on the text/email subset because it is intentionally not applicable to URL-only rows.",
        "BiLSTM results and validation-based model selection are reported separately.",
        "Commercial-tool comparison requires an authorized external API key and is not claimed.",
    ]
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
