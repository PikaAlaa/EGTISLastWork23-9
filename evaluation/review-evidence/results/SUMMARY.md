# Evidence summary

Blacklisted URL used: `https://rllling.shop/spid/`

## API cases

| ID | Case | HTTP | Verdict | Score | Engine scores | Pass |
| --- | --- | --- | --- | --- | --- | --- |
| D1a | Userinfo trick: official host before @, real host after | 200 | LOW | 0.0 | {'rule_based': 46.4, 'blacklist': 0.0, 'lstm': 99.68} | no (accept HIGH) |
| D1b | Same URL, no text | 200 | LOW | 0.0 | {'rule_based': 33.0, 'blacklist': 0.0} | no (accept HIGH) |
| D2 | Official CIB URL with a phishing message | 200 | LOW | 0.0 | {'rule_based': 20.0, 'blacklist': 0.0, 'lstm': 99.68} | no (accept HIGH) |
| D4 | CIB impersonation message and look-alike link | 200 | MEDIUM | 44.77 | {'rule_based': 49.6, 'blacklist': 0.0, 'lstm': 99.64} | no (accept HIGH) |
| D5a | Blacklisted URL inside the message, URL field empty | 200 | MEDIUM | 2.92 | {'rule_based': 0.0, 'lstm': 3.9} | no (accept HIGH) |
| D5b | Same blacklisted URL in the URL field (reference) | 200 | HIGH | 51.43 | {'rule_based': 0.0, 'blacklist': 90.0} | yes (accept HIGH) |
| D6a | Short-name look-alike: NBE | 200 | MEDIUM | 3.43 | {'rule_based': 8.0, 'blacklist': 0.0} | no (accept HIGH) |
| D6b | Short-name look-alike: CIB | 200 | MEDIUM | 6.86 | {'rule_based': 16.0, 'blacklist': 0.0} | no (accept HIGH) |
| D6c | Short-name look-alike: QNB | 200 | MEDIUM | 3.43 | {'rule_based': 8.0, 'blacklist': 0.0} | no (accept HIGH) |
| D7 | Official CIB subdomain | 200 | MEDIUM | 40.71 | {'rule_based': 95.0, 'blacklist': 0.0} | no (accept LOW) |
| D8a | Unrelated word containing a brand label | 200 | MEDIUM | 40.71 | {'rule_based': 95.0, 'blacklist': 0.0} | no (accept LOW) |
| D8b | Unrelated word containing a brand label | 200 | MEDIUM | 40.71 | {'rule_based': 95.0, 'blacklist': 0.0} | no (accept LOW) |
| D9a | Blacklisted URL with upper-case host | 200 | MEDIUM | 34.29 | {'rule_based': 0.0, 'blacklist': 60.0} | no (accept HIGH) |
| D9b | Blacklisted URL with a fragment | 200 | MEDIUM | 34.29 | {'rule_based': 0.0, 'blacklist': 60.0} | no (accept HIGH) |
| D9c | Blacklisted URL with a tracking parameter | 200 | MEDIUM | 34.29 | {'rule_based': 0.0, 'blacklist': 60.0} | no (accept HIGH) |
| D10a | Popular legitimate link | 200 | MEDIUM | 48.57 | {'rule_based': 0.0, 'blacklist': 85.0} | no (accept LOW) |
| D10b | WhatsApp click-to-chat link | 200 | MEDIUM | 45.71 | {'rule_based': 0.0, 'blacklist': 80.0} | no (accept LOW) |
| D10c | Microsoft Forms link | 200 | MEDIUM | 48.57 | {'rule_based': 0.0, 'blacklist': 85.0} | no (accept LOW) |
| D10d | OneDrive short link | 200 | MEDIUM | 42.86 | {'rule_based': 0.0, 'blacklist': 75.0} | no (accept LOW) |
| D12a | javascript: scheme | 500 |  |  |  | no (accept 400, 422) |
| D12b | Invalid port | 500 |  |  |  | no (accept 400, 422) |
| D13 | 50,000-character URL | 200 | MEDIUM | 3.43 | {'rule_based': 8.0, 'blacklist': 0.0} | no (accept 400, 413, 422) |
| D14 | Plain word in the URL field | 200 | MEDIUM | 3.43 | {'rule_based': 8.0, 'blacklist': 0.0} | no (accept 400, 422) |
| long_legit | Legitimate message longer than 200 tokens | 200 | MEDIUM | 0.26 | {'rule_based': 0.0, 'lstm': 0.34} | no (accept LOW) |
| long_phish_tail | Phishing request placed after 200 tokens of filler | 200 | MEDIUM | 5.25 | {'rule_based': 20.0, 'lstm': 0.33} | no (accept HIGH) |
| short_phish | Very short phishing message | 200 | HIGH | 56.39 | {'rule_based': 0.0, 'lstm': 75.18} | yes (accept HIGH) |
| mixed_lang | Mixed Arabic and English phishing | 200 | HIGH | 64.44 | {'rule_based': 0.0, 'lstm': 85.92} | yes (accept HIGH) |
| english_phish | English phishing | 200 | HIGH | 69.17 | {'rule_based': 20.0, 'lstm': 85.56} | yes (accept HIGH) |
| english_legit | English legitimate | 200 | MEDIUM | 0.56 | {'rule_based': 0.0, 'lstm': 0.75} | no (accept LOW) |
| multi_link | Message with a clean link then a blacklisted link | 200 | MEDIUM | 6.27 | {'rule_based': 0.0, 'lstm': 8.36} | no (accept HIGH) |

Everyday SMS (E14): 2 HIGH, 10 MEDIUM, 0 LOW of 12

## Direct and controlled

D1 parsing: {'input': 'https://cibeg.com:443@evil.example/login', 'etis_normalize_domain': 'cibeg.com', 'urllib_hostname': 'evil.example'}

- D3: input url=None, fixed={'lstm': 95}, engines={'rule_based': 20.0, 'lstm': 95.0} -> HIGH 76.25
- D3: input url=https://www.example.com/, fixed={'lstm': 95}, engines={'rule_based': 20.0, 'blacklist': 0.0, 'lstm': 95.0} -> MEDIUM 34.5
- D3: input url=https://rllling.shop/spid/, fixed={}, engines={'rule_based': 0.0, 'blacklist': 90.0} -> HIGH 51.43
- D3: input url=https://rllling.shop/spid/, fixed={'lstm': 5}, engines={'rule_based': 0.0, 'blacklist': 90.0, 'lstm': 5.0} -> MEDIUM 37.5

D6-D8 brand checker: {'http://nbe-online-login.com/': 0.0, 'http://cib-eg.net/login': 0.0, 'http://qnb-verify-account.com/': 0.0, 'https://ebanking.cibeg.com/': 95.0, 'https://bm-online.banquemisr.com/': 95.0, 'https://web.vodafone.com.eg/': 95.0, 'https://afternoon.com/': 95.0, 'https://elite.eg/': 95.0, 'https://cibeg.com/': 0.0}
Boundaries: {'0.0': 'LOW', '0.01': 'MEDIUM', '49.99': 'MEDIUM', '50.0': 'MEDIUM', '50.01': 'HIGH'}
E10 example: {'engine_scores': {'rule_based': 0.0, 'blacklist': 0.0, 'lstm': 95.0}, 'result': {'score': 52.5, 'coverage': 100.0, 'agreement': 5.0, 'engines_considered': 3}}
E9 committed report, wrong verdicts marked OK: [{'id': 6, 'expected': 'LOW', 'actual': 'MEDIUM', 'score': 13.01, 'status': 'OK', 'verdict_matches': False}, {'id': 7, 'expected': 'HIGH', 'actual': 'MEDIUM', 'score': 21.77, 'status': 'OK', 'verdict_matches': False}, {'id': 8, 'expected': 'LOW', 'actual': 'MEDIUM', 'score': 1.25, 'status': 'OK', 'verdict_matches': False}]

- Model pair Bank notice: with money wording 94.49, without 88.05
- Model pair Wallet notice: with money wording 68.05, without 92.32
- Model pair Clinic reminder: with money wording 83.89, without 2.95
- Model pair Delivery: with money wording 92.31, without 3.79

## Dataset

```
{
 "blacklist_counts": {
  "phishing_url_source_rows": 65101,
  "unique_raw_urls_in_source": 65090,
  "unique_entries_in_database": 65090
 },
 "E2_E3": {
  "test_phishing_urls": 9765,
  "in_blacklist_exact": 9765,
  "share_parsed_hostname_with_train": 5164,
  "share_etis_normalised_domain_with_train": 5213
 },
 "E4_rules_only_url": {
  "all_test_phishing": {
   "n": 9765,
   "score_ge_50": 2,
   "score_gt_0": 3016
  },
  "unseen_host": {
   "n": 4601,
   "score_ge_50": 0,
   "score_gt_0": 1034
  }
 },
 "E1_duplicates": {
  "groups": 29,
  "rows": 64,
  "cross_split_groups": 13,
  "cross_split_rows": 31,
  "conflicting_label_groups": 0,
  "test_rows_also_in_train": 8,
  "val_rows_also_in_train": 6
 },
 "E11_text_language": {
  "test": {
   "ar": 251,
   "en": 0,
   "mixed": 50
  },
  "train": {
   "ar": 1173,
   "en": 4,
   "mixed": 235
  },
  "val": {
   "ar": 252,
   "en": 0,
   "mixed": 50
  }
 },
 "E11_english_rows": {
  "n": 4,
  "sources": {
   "synthetic_egyptian_brands": 4
  },
  "splits": {
   "train": 4
  }
 },
 "transactional_wording": {
  "pattern": "(جنيه|رصيد|حسابك|تم خصم|تم تحويل|تم إيداع|تم ايداع|بطاقتك)",
  "legitimate": {
   "n": 1399,
   "with_wording": 14
  },
  "phishing": {
   "n": 616,
   "with_wording": 191
  }
 },
 "median_words": {
  "legitimate": 12.0,
  "phishing": 45.0
 },
 "sources_text": {
  "kaggle_arabic_phishing_fully_dataset": 1250,
  "kaggle_dialectal_arabic_sms": 333,
  "salloum_gaber_bilingual_corpus": 300,
  "github_arabic_text_spam_detection": 78,
  "synthetic_egyptian_brands": 54
 },
 "E12_brand_field": {
  "n": 65090,
  "other_or_blank": 59234,
  "share_other": 0.91,
  "top_named": {
   "Allegro": 2495,
   "Internal Revenue Service": 824,
   "Facebook": 346,
   "Microsoft": 304,
   "Amazon.com": 289
  }
 }
}
{"denominator": "unique phishing URLs (= unique database entries)", "denominator_n": 65090, "strict_token_or_dot_eg": 10, "token_matches_by_brand": {"orange": 9}, "loose_substring_nbe": 48, "loose_nbe_examples": ["https://www.google.com/share.google?q=XM6nBEx3X8YysB1Uy", "https://fnbevants.weebly.com/", "https://twint.kundenbereich-1821.info/", "https://www.h2betloginbet.com/cocoemenz", "http://www.h2betloginbet.com/cocoemenz/"]}
```

## Models

```
{
 "bilstm": {
  "n": 301,
  "positives": 92,
  "auc": 0.9639,
  "f1": 0.9355,
  "f1_95ci": [
   0.894,
   0.971
  ],
  "accuracy": 0.9601,
  "legitimate_scored_ge_0_9": 3,
  "precision": 0.9255,
  "recall": 0.9457,
  "ece": 0.0313
 },
 "bilstm_without_test_duplicates": {
  "n": 293,
  "positives": 91,
  "auc": 0.9632,
  "f1": 0.9348,
  "f1_95ci": [
   0.894,
   0.969
  ],
  "accuracy": 0.959,
  "legitimate_scored_ge_0_9": 3,
  "precision": 0.9247,
  "recall": 0.9451,
  "ece": 0.0325
 },
 "word_tfidf_lightgbm": {
  "n": 301,
  "positives": 92,
  "auc": 0.9138,
  "f1": 0.8025,
  "f1_95ci": [
   0.73,
   0.865
  ],
  "accuracy": 0.8937,
  "legitimate_scored_ge_0_9": 2,
  "precision": 0.9286,
  "recall": 0.7065,
  "ece": 0.0826,
  "fit_seconds": 3.9
 },
 "char_tfidf_logreg": {
  "n": 301,
  "positives": 92,
  "auc": 0.9934,
  "f1": 0.9255,
  "f1_95ci": [
   0.88,
   0.963
  ],
  "accuracy": 0.9535,
  "legitimate_scored_ge_0_9": 1,
  "precision": 0.9062,
  "recall": 0.9457,
  "ece": 0.0517,
  "fit_seconds": 4.3,
  "model_mb": 3.8
 },
 "note": "Test split as shipped (not yet deduplicated or rebuilt). Use for comparison only; repeat on the rebuilt split."
}
```

## Runtime

```
{"rss_mb_before": 714, "sequential_10_s": 1.22, "concurrent_10_s": 0.87, "statuses": [200], "rss_mb_after": 714, "rate_limit_codes_22_requests": [200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429, 429], "first_429_at_request": 21}
{"first_start": {"startup_s": 7.9, "idle_rss_mb": 661, "first_text_scan_s": 1.65, "warm_text_scan_s_median": 0.1, "warm_url_scan_s_median": 0.008, "rss_after_scans_mb": 714}, "second_start": {"startup_s": 4.2, "idle_rss_mb": 666, "first_text_scan_s": 1.38, "warm_text_scan_s_median": 0.096, "warm_url_scan_s_median": 0.009, "rss_after_scans_mb": 715}, "note": "first_start may include cold disk cache; second_start is the warm start-up figure."}
{"internet_reachable": false, "engines_applied": ["rule_based", "blacklist", "lstm"], "verdict": "MEDIUM", "final_score": 22.58}
```