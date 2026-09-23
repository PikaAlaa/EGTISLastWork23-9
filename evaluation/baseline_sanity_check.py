"""Train reproducible text baselines and save honest held-out metrics."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from lightgbm import LGBMClassifier
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "processed" / "dataset.csv"
ARTIFACT = ROOT / "ml" / "artifacts" / "text_model.joblib"
REPORT = ROOT / "evaluation" / "reports" / "baseline_metrics.json"


def load_text_rows() -> dict[str, tuple[list[str], list[int]]]:
    splits = {name: ([], []) for name in ("train", "val", "test")}
    with DATASET.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            if row["content_type"] not in {"text", "email"}:
                continue
            texts, labels = splits[row["split"]]
            texts.append(row["text"])
            labels.append(1 if row["label"] == "phishing" else 0)
    return splits


def metrics(model, texts: list[str], labels: list[int]) -> dict:
    predictions = model.predict(texts)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    result = {
        "samples": len(labels),
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
    }
    if hasattr(model, "predict_proba") and len(set(labels)) == 2:
        result["roc_auc"] = round(float(roc_auc_score(labels, model.predict_proba(texts)[:, 1])), 6)
    return result


def main() -> None:
    splits = load_text_rows()
    train_x, train_y = splits["train"]
    val_x, val_y = splits["val"]
    test_x, test_y = splits["test"]
    majority = DummyClassifier(strategy="most_frequent").fit(train_x, train_y)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=40_000, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=2_000, class_weight="balanced", random_state=42)),
    ])
    model.fit(train_x, train_y)
    lightgbm = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=40_000, sublinear_tf=True)),
        ("classifier", LGBMClassifier(
            n_estimators=350, learning_rate=0.05, num_leaves=31,
            class_weight="balanced", random_state=42, n_jobs=-1, verbosity=-1,
        )),
    ])
    lightgbm.fit(train_x, train_y)
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACT)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "text and email rows only; tokenizer/vectorizer fit on train split only",
        "split_sizes": {name: len(values[1]) for name, values in splits.items()},
        "test_metrics": {
            "majority_class": metrics(majority, test_x, test_y),
            "tfidf_logistic_regression": metrics(model, test_x, test_y),
            "tfidf_lightgbm": metrics(lightgbm, test_x, test_y),
        },
        "validation_metrics": {
            "tfidf_logistic_regression": metrics(model, val_x, val_y),
            "tfidf_lightgbm": metrics(lightgbm, val_x, val_y),
        },
        "artifact": str(ARTIFACT.relative_to(ROOT)).replace("\\", "/"),
        "notes": [
            "These are held-out text/email metrics, not full hybrid-system metrics.",
            "LightGBM and logistic regression use independently fitted train-only TF-IDF vectorizers.",
            "Commercial-tool comparison requires an authorized external API key and is not claimed here.",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
