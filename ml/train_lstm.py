"""Train the planned small BiLSTM; writes artifacts and a real metrics report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

from preprocess_lstm_data import load_splits

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "ml" / "artifacts"
REPORT = ROOT / "evaluation" / "reports" / "lstm_metrics.json"


def main() -> None:
    try:
        import tensorflow as tf
    except ImportError as exc:
        raise SystemExit("TensorFlow is required for this optional run: pip install -r requirements-ml.txt") from exc

    tf.keras.utils.set_random_seed(42)
    splits = load_splits()
    train_x, train_y = splits["train"]
    val_x, val_y = splits["val"]
    test_x, test_y = splits["test"]
    vectorizer = tf.keras.layers.TextVectorization(max_tokens=20_000, output_sequence_length=220)
    vectorizer.adapt(tf.data.Dataset.from_tensor_slices(train_x).batch(64))
    model = tf.keras.Sequential([
        tf.keras.Input(shape=(), dtype=tf.string),
        vectorizer,
        tf.keras.layers.Embedding(20_000, 96, mask_zero=True),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(48, dropout=0.25)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    classes = np.unique(train_y)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=np.array(train_y))
    class_weight = {int(label): float(weight) for label, weight in zip(classes, weights)}
    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True),
        tf.keras.callbacks.ReduceLROnPlateau(monitor="val_loss", patience=1, factor=0.5, min_lr=1e-5),
    ]
    train_ds = tf.data.Dataset.from_tensor_slices((train_x, train_y)).shuffle(len(train_x), seed=42).batch(32).prefetch(tf.data.AUTOTUNE)
    val_ds = tf.data.Dataset.from_tensor_slices((val_x, val_y)).batch(32).prefetch(tf.data.AUTOTUNE)
    test_ds = tf.data.Dataset.from_tensor_slices(test_x).batch(32)
    history = model.fit(
        train_ds,
        validation_data=val_ds,
        epochs=20, batch_size=32, callbacks=callbacks,
        class_weight=class_weight, verbose=2,
    )
    probabilities = model.predict(test_ds, verbose=0).reshape(-1)
    predictions = (probabilities >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(test_y, predictions, average="binary", zero_division=0)
    metrics = {
        "samples": len(test_y),
        "accuracy": round(float(accuracy_score(test_y, predictions)), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "roc_auc": round(float(roc_auc_score(test_y, probabilities)), 6),
    }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    model.save(ARTIFACTS / "bilstm.keras")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": 42,
        "split_sizes": {name: len(values[1]) for name, values in splits.items()},
        "epochs_run": len(history.history["loss"]),
        "class_weight": class_weight,
        "test_metrics": metrics,
        "notes": [
            "Text/email rows only; threshold fixed at 0.5",
            "Text vectorizer adapted on training split only",
            "Class weights computed from training labels only",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
