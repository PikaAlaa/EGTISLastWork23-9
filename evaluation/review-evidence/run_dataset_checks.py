"""Dataset and evaluation-design checks (E1-E4, E11-E12, transactional wording, lengths, rules-only URL recall).

Definitions used:
- Duplicate text: lower-cased, whitespace collapsed (str.split + join). No Arabic letter folding.
- Hostname: urllib.parse.urlsplit(url).hostname (lower-cased, port and userinfo removed).
- ETIS normaliser: app.engines.rule_based.domain_typosquatting_detector.normalize_domain.
- Blacklist membership: SHA-256 of the raw URL string, the same hash the app uses, looked up in blacklist_entries.
- Unseen host: parsed hostname not among hostnames of training-split phishing URLs.
- Rules-only decision: calculate_rule_based_score(url=u)['score'] >= 50 (the evaluation script's rule).
"""
import json, os, re, hashlib, logging, warnings
from urllib.parse import urlsplit
logging.disable(logging.CRITICAL); warnings.filterwarnings("ignore")
import pandas as pd
from sqlalchemy import create_engine, text as sql
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain
from app.engines.rule_based.rule_based_engine import calculate_rule_based_score

REPO = os.environ.get("ETIS_REPO", "/home/claude/etis-group")
d = pd.read_csv(f"{REPO}/data/processed/dataset.csv")
out = {}


def host(u):
    try:
        return urlsplit(u if "://" in u else "http://" + u).hostname
    except ValueError:
        return None

# Blacklist: source rows vs unique seeded entries
eng = create_engine(os.environ["DATABASE_URL"])
with eng.connect() as c:
    db_hashes = {r[0] for r in c.execute(sql("select url_hash from blacklist_entries"))}
ph = d[(d.content_type == "url") & (d.label == "phishing")]
ph_hash = ph.text.map(lambda u: hashlib.sha256(u.encode()).hexdigest())
out["blacklist_counts"] = {"phishing_url_source_rows": len(ph), "unique_raw_urls_in_source": int(ph_hash.nunique()),
                           "unique_entries_in_database": len(db_hashes)}

# E12: Egyptian brand share among unique phishing URLs.
# Strict: a host token (host split on "." and "-") equals an Egyptian brand label or short name, or the host ends in .eg.
# Loose (for comparison only): the lower-cased URL contains the substring "nbe" -- this was the source of an earlier,
# incorrect figure of 48, and the matches are unrelated (e.g. fnbevants.weebly.com).
EG_TOKENS = {"cibeg", "cib", "nbe", "banquemisr", "qnbalahli", "aaib", "instapay", "fawry", "egyptair", "breadfast",
             "jumia", "talabat", "etisalat", "eand", "vodafone", "orange", "noon"}
ph_u = ph.drop_duplicates("text")
H = ph_u.text.map(lambda u: host(u) or "")
tok = H.map(lambda h: set(re.split(r"[.\-]", h)))
strict = tok.map(lambda s: bool(s & EG_TOKENS)) | H.str.endswith(".eg")
out["E12_egyptian"] = {"denominator": "unique phishing URLs (= unique database entries)", "denominator_n": len(ph_u),
                       "strict_token_or_dot_eg": int(strict.sum()), "strict_matches": ph_u[strict].text.tolist(),
                       "token_matches_by_brand": {k: int(tok.map(lambda s: k in s).sum()) for k in sorted(EG_TOKENS) if tok.map(lambda s: k in s).sum()},
                       "loose_substring_nbe": int(ph_u.text.str.lower().str.contains("nbe", regex=False).sum()),
                       "loose_nbe_examples": ph_u[ph_u.text.str.lower().str.contains("nbe", regex=False)].text.str[:60].head(5).tolist()}

# E2/E3: test phishing URLs in blacklist; shared hostnames with training
te = ph[ph.split == "test"]; tr = ph[ph.split == "train"]
te_hash = te.text.map(lambda u: hashlib.sha256(u.encode()).hexdigest())
tr_hosts = set(tr.text.map(host)); tr_norm = set(tr.text.map(normalize_domain))
te_host = te.text.map(host)
shared = te_host.isin(tr_hosts)
out["E2_E3"] = {"test_phishing_urls": len(te), "in_blacklist_exact": int(te_hash.isin(db_hashes).sum()),
                "share_parsed_hostname_with_train": int(shared.sum()),
                "share_etis_normalised_domain_with_train": int(te.text.map(normalize_domain).isin(tr_norm).sum())}

# E4: rules-only on URL rows
scores = te.text.map(lambda u: calculate_rule_based_score(url=u)["score"])
unseen = ~shared
out["E4_rules_only_url"] = {"all_test_phishing": {"n": len(te), "score_ge_50": int((scores >= 50).sum()), "score_gt_0": int((scores > 0).sum())},
                            "unseen_host": {"n": int(unseen.sum()), "score_ge_50": int((scores[unseen] >= 50).sum()),
                                            "score_gt_0": int((scores[unseen] > 0).sum())}}

# E1: duplicate texts
t = d[d.content_type.isin(["text", "email"])].copy()
t["n"] = t.text.str.lower().str.split().str.join(" ")
g = t.groupby("n").agg(splits=("split", "nunique"), rows=("split", "size"), labels=("label", "nunique"))
dup = g[g.rows > 1]; cross = g[g.splits > 1]
tr_n = set(t[t.split == "train"].n)
out["E1_duplicates"] = {"groups": len(dup), "rows": int(dup.rows.sum()), "cross_split_groups": len(cross),
                        "cross_split_rows": int(cross.rows.sum()), "conflicting_label_groups": int((dup.labels > 1).sum()),
                        "test_rows_also_in_train": int(t[(t.split == "test") & t.n.isin(tr_n)].shape[0]),
                        "val_rows_also_in_train": int(t[(t.split == "val") & t.n.isin(tr_n)].shape[0])}

# E11: language of text rows
out["E11_text_language"] = t.groupby(["language", "split"]).size().unstack(fill_value=0).to_dict()
eng_rows = t[t.language == "en"]
out["E11_english_rows"] = {"n": len(eng_rows), "sources": eng_rows.source.value_counts().to_dict(), "splits": eng_rows.split.value_counts().to_dict()}

# Transactional wording and length by label (all splits)
TX = re.compile(r"(جنيه|رصيد|حسابك|تم خصم|تم تحويل|تم إيداع|تم ايداع|بطاقتك)")
t["tx"] = t.text.str.contains(TX)
t["words"] = t.text.str.split().str.len()
out["transactional_wording"] = {"pattern": TX.pattern,
                                "legitimate": {"n": int((t.label == "legitimate").sum()), "with_wording": int(t[(t.label == "legitimate")].tx.sum())},
                                "phishing": {"n": int((t.label == "phishing").sum()), "with_wording": int(t[(t.label == "phishing")].tx.sum())}}
out["median_words"] = t.groupby("label").words.median().to_dict()
out["sources_text"] = t.source.value_counts().to_dict()

json.dump(out, open("results/dataset_checks.json", "w"), ensure_ascii=False, indent=1, default=str)
print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
