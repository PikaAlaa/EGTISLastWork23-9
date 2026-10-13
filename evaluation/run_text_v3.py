"""Freeze train/validation message IDs and compare local text models only.

The generated split manifest omits all `test` rows. It contains no message text.
No network service receives data from this script.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
import time
import csv
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.pipeline import FeatureUnion

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
from app.core.text_utils import normalize_arabic_text, text_windows
from evaluation.metrics import binary_metrics

OUT = ROOT / "evaluation" / "reports" / "2026-10-v3"
MODEL_DIR = OUT / "models"
PRED_DIR = OUT / "predictions"
DATA = ROOT / "evaluation" / "local-results" / "v3-data" / "dataset.csv"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def versions() -> dict:
    import importlib.metadata as md
    names = ["numpy", "pandas", "scikit-learn", "joblib", "tldextract", "lightgbm", "tensorflow-cpu"]
    result = {}
    for name in names:
        try: result[name] = md.version(name)
        except md.PackageNotFoundError: pass
    return result


def build_split(data_path: Path = DATA) -> tuple[pd.DataFrame, dict]:
    # Stream only train/validation rows. In particular, never deserialize test text.
    kept = []
    with data_path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row.get("split") in {"train", "val"} and row.get("content_type") in {"text", "email"}:
                kept.append(row)
    d = pd.DataFrame(kept).fillna("")
    if d.id.astype(str).duplicated().any():
        raise ValueError("Text row IDs are not unique")
    if d.groupby("group_id").split.nunique().max() != 1:
        raise ValueError("A near-duplicate group crosses train and validation")
    records = []
    for row in d.itertuples():
        content_hash = hashlib.sha256(str(row.text).encode("utf-8")).hexdigest()
        records.append({"row_id": str(row.id), "content_sha256": content_hash,
                        "group_id": str(row.group_id), "split": str(row.split),
                        "label": str(row.label), "source": str(row.source),
                        "language": str(row.language), "content_type": str(row.content_type)})
    canonical = json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    frozen_hash = hashlib.sha256(canonical).hexdigest()
    manifest = {"version": "etis-v3-text-split-1",
                "dataset_identity": {"dataset_sha256": frozen_hash, "method": "train-validation row IDs and content hashes only"},
                "data_sha256": frozen_hash,
                "text_split_sha256": frozen_hash,
                "rows": records, "test_rows_included": False,
                "libraries": versions(),
                "model_sha256": None}
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / 'text_split.json').exists():
        frozen = json.loads((OUT / 'text_split.json').read_text(encoding='utf-8'))
        if frozen['data_sha256'] != frozen_hash:
            raise ValueError('Development rows differ from the frozen split; refusing to overwrite it')
        return d.reset_index(drop=True), frozen
    (OUT / "text_split.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return d.reset_index(drop=True), manifest


def ece(y, p, bins=15):
    y, p = np.asarray(y, dtype=int), np.asarray(p, dtype=float)
    if not len(y):
        return None
    edges = np.linspace(0, 1, bins + 1)
    result = 0.0
    for i in range(bins):
        mask = (p >= edges[i]) & (p < edges[i + 1] if i < bins - 1 else p <= edges[i + 1])
        if mask.any():
            result += mask.mean() * abs(y[mask].mean() - p[mask].mean())
    return float(result)


def choose_threshold(y, p, target_recall=None, max_fpr=None):
    y, p = np.asarray(y, dtype=int), np.asarray(p, dtype=float)
    positives, negatives = y == 1, y == 0
    candidates = np.unique(np.r_[p, 1.0000001, 0.0])
    feasible = []
    for threshold in candidates:
        pred = p >= threshold
        recall = float((pred & positives).sum() / max(positives.sum(), 1))
        fpr = float((pred & negatives).sum() / max(negatives.sum(), 1))
        if target_recall is not None and recall >= target_recall:
            feasible.append((float(threshold), recall, fpr))
        elif max_fpr is not None and fpr <= max_fpr:
            feasible.append((recall, float(threshold), fpr))
    if not feasible:
        return (1.0000001, 0.0, 0.0)
    return max(feasible, key=lambda x: x[0]) if max_fpr is not None else max(feasible, key=lambda x: x[0])


def model_metrics(y, p, threshold_95=None, threshold_1=None):
    y, p = np.asarray(y, dtype=int), np.asarray(p, dtype=float)
    # Highest score threshold that retains at least 95% phishing recall.
    high_threshold = threshold_95
    if high_threshold is None:
        high_threshold = max(float(t) for t in np.unique(p[y == 1])
                             if float((p[y == 1] >= t).mean()) >= .95) if (y == 1).any() else 0.0
    pred = p >= high_threshold
    tp = int(((y == 1) & pred).sum()); fn = int(((y == 1) & ~pred).sum())
    fp = int(((y == 0) & pred).sum()); tn = int(((y == 0) & ~pred).sum())
    # Most conservative threshold with FPR <= 1% maximizes recall under the constraint.
    neg_scores = p[y == 0]
    allowed_fp = math.floor(.01 * len(neg_scores))
    ordered = np.sort(neg_scores)
    fpr_threshold = threshold_1
    if fpr_threshold is None:
        fpr_threshold = float(np.nextafter(ordered[len(ordered) - allowed_fp - 1], np.inf)) if len(ordered) and allowed_fp < len(ordered) else 0.0
    r_at_1 = float((p[y == 1] >= fpr_threshold).mean()) if (y == 1).any() else None
    f1_threshold = float(2 * tp / max(2 * tp + fp + fn, 1))
    macro = float((f1_threshold + 2 * tn / max(2 * tn + fp + fn, 1)) / 2)
    return {"n": len(y), "phishing_n": int((y == 1).sum()), "legitimate_n": int((y == 0).sum()),
            "threshold_at_recall_95": high_threshold,
            "macro_f1_at_recall_95": macro,
            "legitimate_fpr_at_recall_95": float(fp / max(fp + tn, 1)),
            "phishing_recall_at_recall_95": float(tp / max(tp + fn, 1)),
            "recall_at_fpr_le_1pct": r_at_1,
            "threshold_at_fpr_le_1pct": fpr_threshold,
            "ece_15_bins": ece(y, p),
            "confusion_at_recall_95": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def _expand(rows):
    texts, labels, owner = [], [], []
    for i, row in rows.reset_index(drop=True).iterrows():
        for window in text_windows(str(row.text)):
            texts.append(normalize_arabic_text(window))
            labels.append(int(row.label == "phishing"))
            owner.append(i)
    return texts, np.asarray(labels), np.asarray(owner)


def _score_windows(model, texts, owners, row_count):
    expanded = np.asarray(model.predict_proba(texts)[:, 1], dtype=float)
    result = np.zeros(row_count, dtype=float)
    for idx, score in zip(owners, expanded):
        result[idx] = max(result[idx], float(score))
    return result


def _latency_ms(model, texts_by_row):
    # Warm the exact batch-size-one path, then time each validation message.
    if texts_by_row:
        model.predict_proba(texts_by_row[0])
    durations = []
    for item in texts_by_row:
        start = time.perf_counter()
        model.predict_proba(item)
        durations.append((time.perf_counter() - start) * 1000)
    arr = np.asarray(durations)
    return {"batch_size": 1, "cpu_only": True,
            "p50_ms": float(np.percentile(arr, 50)) if len(arr) else None,
            "p95_ms": float(np.percentile(arr, 95)) if len(arr) else None,
            "n": len(arr)}


def make_models(seed=42):
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)
    word = TfidfVectorizer(ngram_range=(1, 2), max_features=12000, sublinear_tf=True)
    char_w = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=50000, sublinear_tf=True)
    return {
        "char_tfidf_logistic": (char, LogisticRegression(C=10, max_iter=2000, class_weight="balanced", random_state=seed)),
        "char_tfidf_calibrated_svm": (char, CalibratedClassifierCV(LinearSVC(class_weight="balanced", random_state=seed), method="sigmoid", cv=3)),
        "word_char_tfidf_logistic": (FeatureUnion([("word", word), ("char", char_w)]),
                                     LogisticRegression(C=3, max_iter=2000, class_weight="balanced", random_state=seed)),
        "tfidf_lightgbm": (TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True), None),
    }


def _row_hashes(rows):
    return [hashlib.sha256(str(t).encode("utf-8")).hexdigest() for t in rows.text]


def _metrics_by_group(rows, y, p):
    result = {}
    global_metrics = model_metrics(y, p)
    for col in ("language", "source"):
        result[col] = {}
        for key, positions in rows.groupby(col, sort=True).indices.items():
            result[col][str(key)] = model_metrics(y[positions], p[positions],
                global_metrics["threshold_at_recall_95"], global_metrics["threshold_at_fpr_le_1pct"])
    return result


def train_local(data_path: Path = DATA, train_bilstm=True):
    rows, split_manifest = build_split(data_path)
    train = rows[rows.split == "train"].reset_index(drop=True)
    val = rows[rows.split == "val"].reset_index(drop=True)
    x, y_windows, owners = _expand(train)
    vx, _, vowners = _expand(val)
    y_train = (train.label == "phishing").astype(int).to_numpy()
    y_val = (val.label == "phishing").astype(int).to_numpy()
    if set(y_train) != {0, 1} or set(y_val) != {0, 1}:
        raise ValueError("Both classes are required in train and validation")
    trainval_path = ROOT / "evaluation" / "local-results" / "v3-data" / "text-trainval-only.csv"
    trainval_path.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(trainval_path, index=False, lineterminator="\n")
    MODEL_DIR.mkdir(parents=True, exist_ok=True); PRED_DIR.mkdir(parents=True, exist_ok=True)
    overall = {"stage": "development_validation", "final_test_run": False,
               "data_sha256": split_manifest["dataset_identity"]["dataset_sha256"],
               "text_split_sha256": split_manifest["text_split_sha256"],
               "libraries": versions(), "models": {}, "provisional_rule_applied": None,
               "limitations": ["No authentic Egyptian SMS validation cohort; source mix is not representative.",
                               "No English validation guarantee beyond the supplied data."]}
    predictions = {}
    for name, (vectorizer, classifier) in make_models().items():
        if classifier is None:
            from lightgbm import LGBMClassifier
            classifier = LGBMClassifier(n_estimators=300, class_weight="balanced", random_state=42,
                                        n_jobs=2, verbosity=-1)
        from sklearn.pipeline import make_pipeline
        model = make_pipeline(vectorizer, classifier)
        model.fit(x, y_windows)
        scores = _score_windows(model, vx, vowners, len(val))
        path = MODEL_DIR / f"{name}.joblib"
        joblib.dump({"pipeline": model, "version": split_manifest["dataset_identity"]["dataset_sha256"][:16]}, path)
        model_hash = sha(path)
        per_message_windows = [[normalize_arabic_text(w) for w in text_windows(str(t))] for t in val.text]
        group_results = _metrics_by_group(val, y_val, scores)
        # Report the dialectal Kaggle slice by its explicit source name and disclaimer.
        dialect_key = "kaggle_dialectal_arabic_sms"
        group_results["kaggle_dialectal_source"] = {
            "source": dialect_key,
            "geographic_interpretation": "Non-Egyptian and templated, as specified by project context",
            "metrics": group_results["source"].get(dialect_key)}
        metrics = model_metrics(y_val, scores)
        metrics.update({"macro_f1_by_language_and_source": group_results,
                        "latency": _latency_ms(model, per_message_windows),
                        "model_size_bytes": path.stat().st_size,
                        "model_sha256": model_hash})
        overall["models"][name] = metrics
        records = [{"row_id": str(row.id), "content_sha256": h,
                    "label": int(label), "score": float(score)}
                   for row, h, label, score in zip(val.itertuples(), _row_hashes(val), y_val, scores)]
        pred_obj = {"model": name, "seed": 42, "data_sha256": overall["data_sha256"],
                    "text_split_sha256": overall["text_split_sha256"], "model_sha256": model_hash,
                    "libraries": versions(), "rows": records}
        pp = PRED_DIR / f"{name}_seed42.json"
        pp.write_text(json.dumps(pred_obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        predictions[name] = scores
    if train_bilstm:
        import os
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
        from ml.train_bilstm_candidate import train as train_bilstm_candidate
        bilstm_path = MODEL_DIR / "bilstm_candidate.keras"
        bilstm_report = train_bilstm_candidate(trainval_path, bilstm_path, epochs=20)
        bilstm_report.update(data_sha256=overall['data_sha256'],
                             model_sha256=sha(bilstm_path), libraries=versions())
        bilstm_path.with_suffix('.json').write_text(json.dumps(bilstm_report, indent=2), encoding='utf-8')
        import pickle
        import tensorflow as tf
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        model = tf.keras.models.load_model(bilstm_path, compile=False)
        tokenizer = pickle.loads(bilstm_path.with_suffix(".tokenizer.pkl").read_bytes())
        def score_one(ws):
            encoded = pad_sequences(tokenizer.texts_to_sequences(ws), maxlen=200, padding="post", truncating="post")
            return float(np.max(model.predict(encoded, batch_size=1, verbose=0).ravel()))
        starts = time.perf_counter(); scores=[]; durations=[]
        for row in val.itertuples():
            windows = [normalize_arabic_text(w) for w in text_windows(str(row.text))]
            a=time.perf_counter();scores.append(score_one(windows));durations.append((time.perf_counter()-a)*1000)
        scores = np.asarray(scores)
        model_hash = sha(bilstm_path)
        tm = model_metrics(y_val, scores)
        tm.update({"macro_f1_by_language_and_source": _metrics_by_group(val, y_val, scores),
                   "latency": {"batch_size":1,"cpu_only":True,"p50_ms":float(np.percentile(durations,50)),"p95_ms":float(np.percentile(durations,95)),"n":len(durations)},
                   "model_size_bytes":bilstm_path.stat().st_size,
                   "tokenizer_sha256":sha(bilstm_path.with_suffix(".tokenizer.pkl")),
                   "model_sha256":model_hash})
        overall["models"]["bilstm"] = tm
        recs=[{"row_id":str(row.id),"content_sha256":h,"label":int(label),"score":float(score)}
              for row,h,label,score in zip(val.itertuples(),_row_hashes(val),y_val,scores)]
        (PRED_DIR/"bilstm_seed42.json").write_text(json.dumps({"model":"bilstm","seed":42,
             "data_sha256":overall["data_sha256"],"text_split_sha256":overall["text_split_sha256"],
             "model_sha256":model_hash,"tokenizer_sha256":tm["tokenizer_sha256"],
             "libraries":versions(),"rows":recs},separators=(",",":")),encoding="utf-8")
    revised_rule = OUT / 'review-2026-10-13/model_selection_rule.json'
    if revised_rule.exists():
        overall['model_sha256'] = None
        overall['provisional_rule_applied'] = {'status':'Delegated to source-held-out and everyday-probe comparison', 'rule':str(revised_rule.relative_to(ROOT))}
        (OUT/'text_local_metrics.json').write_text(json.dumps(overall,indent=2),encoding='utf-8')
        from evaluation.run_text_review import main as review_selection
        review_selection()
        return overall
    rule = json.loads((OUT / "model_selection_rule.json").read_text(encoding="utf-8"))
    eligible = {n:m for n,m in overall["models"].items() if m["latency"]["p95_ms"] <= rule["max_p95_cpu_ms"]}
    best = max(m["macro_f1_at_recall_95"] for m in eligible.values()) if eligible else None
    within = {n:m for n,m in eligible.items() if m["macro_f1_at_recall_95"] >= best-rule["macro_f1_tolerance"]}
    order = rule["simplicity_order"]
    winner = min(within, key=lambda n:(within[n]["legitimate_fpr_at_recall_95"],order.index(n))) if within else None
    overall["provisional_rule_applied"] = {"eligible_within_tolerance": list(within), "winner": winner,
         "best_macro_f1": best, "final_model_choice_waits_for_transformers": True,
         "deployed_model_changed": False}
    overall["model_sha256"] = None
    (OUT / "text_local_metrics.json").write_text(json.dumps(overall, indent=2), encoding="utf-8")
    (OUT / "local_model_selection.json").write_text(json.dumps({"winner":winner,
        "rule":rule,"data_sha256":overall["data_sha256"],"text_split_sha256":overall["text_split_sha256"],
        "model_sha256":overall["models"].get(winner,{}).get("model_sha256"),"libraries":versions(),
        "final_choice":False,"final_test_run":False},indent=2),encoding="utf-8")
    return overall


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--dataset",type=Path,default=DATA)
    parser.add_argument("--skip-bilstm",action="store_true")
    args=parser.parse_args()
    print(json.dumps(train_local(args.dataset,train_bilstm=not args.skip_bilstm),indent=2))
