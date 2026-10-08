"""Text-model comparison on the existing test split (text + email rows).

Settings (all trained on the train split only, decision threshold 0.5 on P(phishing)):
- BiLSTM: the shipped model via app.engines.deep_learning.lstm_inference (score / 100).
- Word TF-IDF + LightGBM: TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True);
  LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=31, random_state=42, verbose=-1).
- Char TF-IDF + logistic regression: TfidfVectorizer(analyzer='char_wb', ngram_range=(2,5), sublinear_tf=True);
  LogisticRegression(C=10, max_iter=2000, class_weight='balanced').
Metrics:
- ECE: 10 equal-width bins on P(phishing); sum over bins of (n_bin/N) * |mean(label) - mean(p)|.
- 95% interval for F1: percentile bootstrap, 2,000 resamples of test rows, seed 42.
- "Without test duplicates": test rows whose normalised text (lower-case, collapsed whitespace) appears in train are dropped.
"""
import json, os, time, pickle, logging, warnings
logging.disable(logging.CRITICAL); warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score
from lightgbm import LGBMClassifier
from app.engines.deep_learning.lstm_inference import calculate_lstm_phishing_score as L

REPO = os.environ.get("ETIS_REPO", "/home/claude/etis-group")
d = pd.read_csv(f"{REPO}/data/processed/dataset.csv")
t = d[d.content_type.isin(["text", "email"])].copy()
t["y"] = (t.label == "phishing").astype(int)
t["n"] = t.text.str.lower().str.split().str.join(" ")
tr, te = t[t.split == "train"], t[t.split == "test"]
rng = np.random.default_rng(42)


def ece(y, p, bins=10):
    e = np.clip((p * bins).astype(int), 0, bins - 1)
    return float(sum((e == b).mean() * abs(y[e == b].mean() - p[e == b].mean()) for b in range(bins) if (e == b).any()))


def metrics(y, p):
    yhat = (p >= 0.5).astype(int)
    boot = []
    for _ in range(2000):
        i = rng.integers(0, len(y), len(y))
        boot.append(f1_score(y[i], yhat[i], zero_division=0))
    return {"n": int(len(y)), "positives": int(y.sum()), "auc": round(roc_auc_score(y, p), 4), "f1": round(f1_score(y, yhat), 4),
            "f1_95ci": [round(float(np.percentile(boot, 2.5)), 3), round(float(np.percentile(boot, 97.5)), 3)],
            "accuracy": round(float((yhat == y).mean()), 4), "legitimate_scored_ge_0_9": int(((p >= 0.9) & (y == 0)).sum()),
            "precision": round(precision_score(y, yhat), 4), "recall": round(recall_score(y, yhat), 4), "ece": round(ece(y, p), 4)}


y = te.y.values
out = {}
p_lstm = np.array([L(x)["score"] / 100 for x in te.text])
out["bilstm"] = metrics(y, p_lstm)
keep = ~te.n.isin(set(tr.n)).values
out["bilstm_without_test_duplicates"] = metrics(y[keep], p_lstm[keep])

t0 = time.perf_counter()
wv = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
lgb = LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=31, random_state=42, verbose=-1)
lgb.fit(wv.fit_transform(tr.text), tr.y)
out["word_tfidf_lightgbm"] = metrics(y, lgb.predict_proba(wv.transform(te.text))[:, 1])
out["word_tfidf_lightgbm"]["fit_seconds"] = round(time.perf_counter() - t0, 1)

t0 = time.perf_counter()
cv = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)
lr = LogisticRegression(C=10, max_iter=2000, class_weight="balanced")
lr.fit(cv.fit_transform(tr.text), tr.y)
out["char_tfidf_logreg"] = metrics(y, lr.predict_proba(cv.transform(te.text))[:, 1])
out["char_tfidf_logreg"]["fit_seconds"] = round(time.perf_counter() - t0, 1)
out["char_tfidf_logreg"]["model_mb"] = round(len(pickle.dumps((cv, lr))) / 1e6, 1)
out["note"] = "Test split as shipped (not yet deduplicated or rebuilt). Use for comparison only; repeat on the rebuilt split."

json.dump(out, open("results/model_comparison.json", "w"), indent=1)
print(json.dumps(out, indent=1))
