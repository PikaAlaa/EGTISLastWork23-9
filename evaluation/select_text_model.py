"""Select the deployed text model on validation data, then report test once."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml"))
from preprocess_lstm_data import load_splits  # noqa: E402
sys.path.insert(0, str(ROOT / "evaluation"))
from baseline_sanity_check import load_text_rows  # noqa: E402

REPORT = ROOT / "evaluation" / "reports" / "text_model_selection.json"


def metric_set(labels, probabilities) -> dict:
    predictions = (probabilities >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
    }


def main() -> None:
    import tensorflow as tf

    normalized_splits = load_splits()
    raw_splits = load_text_rows()
    baseline = joblib.load(ROOT / "ml" / "artifacts" / "text_model.joblib")
    bilstm = tf.keras.models.load_model(ROOT / "ml" / "artifacts" / "bilstm.keras")
    probabilities = {}
    for split in ("val", "test"):
        texts, labels = raw_splits[split]
        normalized_texts, _ = normalized_splits[split]
        probabilities[split] = {
            "labels": np.asarray(labels),
            "baseline": baseline.predict_proba(texts)[:, 1],
            "bilstm": bilstm.predict(tf.data.Dataset.from_tensor_slices(normalized_texts).batch(32), verbose=0).reshape(-1),
        }

    candidates = []
    for baseline_weight in np.linspace(0, 1, 11):
        values = probabilities["val"]
        blended = baseline_weight * values["baseline"] + (1 - baseline_weight) * values["bilstm"]
        candidates.append((metric_set(values["labels"], blended)["f1"], float(baseline_weight)))
    _, selected_weight = max(candidates, key=lambda item: (item[0], item[1]))
    strategy = "tfidf_logistic_regression" if selected_weight == 1 else "bilstm" if selected_weight == 0 else "weighted_ensemble"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selection_protocol": "Model/ensemble weight selected by validation F1 at threshold 0.5; test metrics reported after selection.",
        "selected_strategy": strategy,
        "baseline_weight": selected_weight,
        "bilstm_weight": 1 - selected_weight,
        "validation_candidates": {str(weight): score for score, weight in candidates},
        "metrics": {},
    }
    for split in ("val", "test"):
        values = probabilities[split]
        blended = selected_weight * values["baseline"] + (1 - selected_weight) * values["bilstm"]
        report["metrics"][split] = metric_set(values["labels"], blended)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
