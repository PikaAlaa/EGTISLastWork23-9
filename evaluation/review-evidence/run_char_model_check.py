"""Model outputs of the shipped BiLSTM and a character TF-IDF + logistic regression model on a few
hand-written probes (A3 in the completion plan).

These are single-example model outputs (P(phishing) x 100), NOT detection accuracy. They show how each
model reacts to specific situations (long filler, very short text, English) and motivate regression tests.

Character model settings: TfidfVectorizer(analyzer='char_wb', ngram_range=(2,5), sublinear_tf=True);
LogisticRegression(C=10, max_iter=2000, class_weight='balanced'); trained on the train split of
data/processed/dataset.csv at commit bd56f3b (text + email rows).
"""
import json, os, logging, warnings
logging.disable(logging.CRITICAL); warnings.filterwarnings("ignore")
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from app.engines.deep_learning.lstm_inference import calculate_lstm_phishing_score as L
from cases import PHISH_TEXT, ROBUSTNESS

REPO = os.environ.get("ETIS_REPO", "/home/claude/etis-group")
d = pd.read_csv(f"{REPO}/data/processed/dataset.csv")
t = d[d.content_type.isin(["text", "email"])]
tr = t[t.split == "train"]
cv = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)
lr = LogisticRegression(C=10, max_iter=2000, class_weight="balanced").fit(cv.fit_transform(tr.text), (tr.label == "phishing").astype(int))
C = lambda s: round(float(lr.predict_proba(cv.transform([s]))[0, 1]) * 100, 1)
B = lambda s: round(float(L(s)["score"]), 1)

FILLER = "أخبار الفريق والمشروع ماشية كويس والحمد لله"
probes = [("phishing SMS alone", PHISH_TEXT),
          ("same SMS after 10 filler sentences", " ".join([FILLER] * 10) + " " + PHISH_TEXT),
          ("same SMS after 40 filler sentences", " ".join([FILLER] * 40) + " " + PHISH_TEXT)]
probes += [(cid, txt) for cid, _, txt, _ in ROBUSTNESS if "BLACKLISTED" not in txt]
out = {"note": "Single-example model outputs, P(phishing) x 100; not detection accuracy.",
       "filler_sentence": FILLER,
       "probes": [{"probe": n, "text": s if len(s) < 300 else s[:120] + f"... [{len(s)} chars]", "bilstm": B(s), "char_model": C(s)} for n, s in probes]}
json.dump(out, open("results/char_model_check.json", "w"), ensure_ascii=False, indent=1)
for p in out["probes"]:
    print(f"{p['probe']:40s} BiLSTM {p['bilstm']:5.1f}  char {p['char_model']:5.1f}")
