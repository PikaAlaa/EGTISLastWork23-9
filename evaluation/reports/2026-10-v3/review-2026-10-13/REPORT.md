# ETIS review implementation — 13 October 2026

This report supersedes the 9–10 October URL experiment and text selection. ETIS is a six-member AAST graduation project. The deployed URL model uses host-only features from the original repository data. The deployed September text model is unchanged; the revised comparison has a different provisional winner. No sealed final evaluation ran and authentic Egyptian SMS benchmark count remains **0**.

**Pending:** legitimate URLs with genuine paths could not be imported. PhiUSIIL was downloaded and inspected, but all 134,850 legitimate entries have no non-root path or query. The GramBeddings authors provide academic access through a personal-details form. Attach `grambeddings_dataset_main.zip` and its accompanying terms to finish this step. No paths were generated and no form was submitted.

## A. URL shortcuts and current host model

Only existing `data/raw/tranco_raw.csv` and `tranco_final_approved.csv` identify the current legitimate Tranco pool. The original list ID and retrieval date are **not recorded**. The earlier PY35J file remains as historical evidence, but is not used by the current model. Existing manual legitimate URLs are also roots, so they do not remedy the missing-path problem.

The old 9,496-row aggregate confusion was reproduced exactly on reconstructed development rows. Because the old report lacks row IDs, matching confusion counts alone cannot prove identical membership. The following are paired replays of the same reconstructed cohort with the pristine baseline engine and training-only frozen blacklist:

| Baseline input | Phishing recall | TP / 6,531 | FP / 2,965 | FPR |
|---|---:|---:|---:|---:|
| Full URL | 17.18% | 1122 | 15 | 0.51% |
| Remove path/query; preserve scheme | 12.94% | 845 | 15 | 0.51% |
| Host-only input; fixed HTTPS scheme | 1.84% | 120 | 15 | 0.51% |

Path removal and scheme standardization are separate diagnostics. The host-only replay is a transformed input to the old rules, not the learned host classifier. No transformed URL is presented as a newly collected legitimate URL.

The new paired classifier comparison uses 45,465 training rows and 8,889 validation rows after excluding cross-class domains and any overlapping train/validation registered domains. A pinned offline PSL includes private entries. The retained PSL groups refine the frozen original groups, checked without reading sealed records. All variants use identical rows; full-URL models are diagnostic only.

| Representation / model | Recall ≤1% FPR | Actual FP / 2,916 | Recall ≤0.1% FPR | Actual FP / 2,916 | PR-AUC | ECE | CPU p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| host_only / char_logistic | 81.13% | 29 | 37.99% | 2 | 0.9855 | 0.1111 | 0.72 |
| host_only / char_calibrated_svm | 76.03% | 29 | 55.67% | 2 | 0.9850 | 0.0504 | 4.21 |
| host_only / lightgbm | 87.74% | 29 | 73.56% | 2 | 0.9876 | 0.0430 | 1.71 |
| full_url / char_logistic | 94.34% | 29 | 90.69% | 2 | 0.9966 | 0.0491 | 1.46 |
| full_url / char_calibrated_svm | 94.34% | 29 | 87.33% | 2 | 0.9964 | 0.0159 | 3.42 |
| full_url / lightgbm | 96.62% | 29 | 94.22% | 2 | 0.9976 | 0.0146 | 1.98 |
| shortcut_only / lightgbm | 92.06% | 14 | 89.52% | 2 | 0.9936 | 0.0140 | 1.33 |

Selected host-only model: **lightgbm**, threshold **0.979680498647069**. At that validation operating point: 73.56% recall, 2/2,916 false positives (0.07%). This is classifier recall, not a comparison against the old policy on an identical cohort.

The shortcut-only model sees total length, path/query length, path/query presence and HTTPS, without host identity or lexical n-grams. Its high score demonstrates severe dataset separability from collection artifacts; it is not a deployed detector. Host length can still encode popularity/source differences even after removing paths.

| Full model, fixed ≤0.1% threshold | Recall with paths | Recall after path/query removal | Recall drop (points) | Mean phishing probability drop | FP before / after |
|---|---:|---:|---:|---:|---:|
| char_logistic | 90.69% | 59.89% | 30.81 | 0.1691 | 2 / 2 |
| char_calibrated_svm | 87.33% | 68.24% | 19.09 | 0.0711 | 2 / 2 |
| lightgbm | 94.22% | 65.23% | 29.00 | 0.1134 | 2 / 2 |

These paired changes measure sensitivity to path/query removal, not a causal percentage of model quality. Legitimate strings are already roots, so their scores do not change. This dataset cannot estimate false alarms on genuine legitimate paths. Bootstrap intervals (300 registered-domain resamples) and the corresponding 1% ablation are in `url_review_metrics.json`; thresholds are reselected per bootstrap sample, so intervals are not independent deployment guarantees.

The integrated current scanner, including existing rules and host-model suppression on official/shared hosts, obtains 75.62% MEDIUM-or-HIGH recall with 17/2,916 false positives (0.58%) on the cleaned validation cohort. See `url_policy_replay.json`.

The updated character-logistic domain-recency stress test uses the repository Tranco pool: recall 38.50% at ≤1% FPR and 26.00% at ≤0.1%. Whole domains are assigned by their latest source timestamp, so validation can contain earlier URLs from those domains. Negative-list date is unknown. This is not a strictly forward-time evaluation or a temporal measurement of the selected LightGBM.

## B. Text selection and provenance

The revised rule was saved before new comparisons; it was informed by previous exposed results, not independently preregistered. Primary loss averages three equally weighted quantities: source-mean false-negative rate, source-mean false-positive rate, and MEDIUM-or-HIGH rate on the 12 existing invented everyday probes. CPU p95 must be ≤300 ms. Validation macro-F1 is only a tie-breaker. Equal weighting is a project decision, not an estimate of population prevalence.

The original 282-row validation is small and saturated. Excluding the 55 dialectal validation rows leaves 227 rows (53 phishing / 174 legitimate), all from translated sources. Frozen rows/groups/splits are unchanged. Dialectal validation rows are not moved into training. Only its existing 234 training rows remain available; 54 pre-existing synthetic-brand training rows also remain, labelled synthetic. No new SMS was generated.

| Candidate | Source-mean FNR, translated sources | Source-mean FPR, translated sources | Alerts / 12 invented probes | HIGH / 12 invented probes | Primary loss | Tie-break F1, translated validation |
|---|---:|---:|---:|---:|---:|---:|
| char_tfidf_logistic | 9.85% | 14.46% | 8 | 0 | 0.303263 | 0.9814 |
| word_char_tfidf_logistic | 9.60% | 7.42% | 8 | 0 | 0.278966 | 0.9814 |
| char_tfidf_calibrated_svm | 8.79% | 33.47% | 8 | 0 | 0.363085 | 0.9814 |
| tfidf_lightgbm | 18.09% | 12.22% | 2 | 0 | 0.156583 | 0.9520 |
| bilstm | 13.13% | 16.56% | 5 | 0 | 0.237850 | 0.9636 |

Provisional winner: **tfidf_lightgbm**. It trades lower everyday-fixture alerting for worse source-held-out phishing recall than the character models. Its lower validation F1 does not override the frozen primary rule. The original deployed text model remains unchanged. Final selection requires transformer source-held-out and everyday-probe evidence; six validation-only prediction files are insufficient.

| Candidate | Held source and provenance | Phishing / legitimate rows | Held-source recall | Held-source FPR | Held-source macro-F1 |
|---|---|---:|---:|---:|---:|
| char_tfidf_logistic | Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS | 203 / 822 | 95.57% | 10.46% | 0.8713 |
| char_tfidf_logistic | Salloum/Gaber: translated parallel emails, not Egyptian SMS | 131 / 130 | 84.73% | 18.46% | 0.8314 |
| word_char_tfidf_logistic | Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS | 203 / 822 | 96.06% | 12.53% | 0.8534 |
| word_char_tfidf_logistic | Salloum/Gaber: translated parallel emails, not Egyptian SMS | 131 / 130 | 84.73% | 2.31% | 0.9115 |
| char_tfidf_calibrated_svm | Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS | 203 / 822 | 93.10% | 6.93% | 0.8988 |
| char_tfidf_calibrated_svm | Salloum/Gaber: translated parallel emails, not Egyptian SMS | 131 / 130 | 89.31% | 60.00% | 0.6242 |
| tfidf_lightgbm | Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS | 203 / 822 | 78.33% | 15.21% | 0.7724 |
| tfidf_lightgbm | Salloum/Gaber: translated parallel emails, not Egyptian SMS | 131 / 130 | 85.50% | 9.23% | 0.8812 |
| bilstm | Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS | 203 / 822 | 93.60% | 30.05% | 0.7047 |
| bilstm | Salloum/Gaber: translated parallel emails, not Egyptian SMS | 131 / 130 | 80.15% | 3.08% | 0.8843 |

For each held source, training uses only other-source training rows, with any shared near-duplicate group removed. Threshold selection and BiLSTM early stopping use other-source eligible validation only. All development rows from the excluded source are scored. The 12 invented fixtures are exposed selection diagnostics and must never become a final test. Raw fold thresholds, confusion counts, model hashes and per-probe verdicts are retained in `text_review_metrics.json`.

The dialectal raw file is 500 rows (250 phishing / 250 safe), 333 unique text-label pairs. It has Moroccan/Levantine markers and template-like repetitions, but also Egyptian-associated wording such as `النهارده` and `متتأخرش` in safe rows. The requested claim “no Egyptian markers found” is contradicted by the actual file. Collection origin and licence remain unverified; training-only usage and no Egyptian-performance claim are retained.

Language correction: 43 of the 55 dialectal validation rows are Arabic-script-only (`ar`); 12 contain Arabic plus Latin letters (`mixed`). The overlay also identifies 171 Arabic-only and 63 mixed training rows. This changes reporting metadata only, not split membership or content hashes. The Decision-v2 demotion total remains 82 phishing development rows: corrected language counts are 74 Arabic and 8 mixed; source counts are 30 translated Kaggle, 18 translated Salloum and 34 apparently templated mixed-regional dialectal diagnostics.

## C. Documentation and data hygiene

`docs/data-licences.md` inventories all 89 raw files, with source, quoted terms or 'not stated', and public redistribution status. `data/raw-sources-manifest.json` pins every file hash. `restore_raw_data.py` verifies existing files, imports authorised originals, and downloads the pinned PhiUSIIL archive when absent. Both ZIP and CSV hashes were verified by an actual second download into an isolated directory. Unknown historical snapshots require an authorised attachment; current feeds are never silently substituted.

No raw data was deleted. The team should resolve permissions or replace the identified raw and derived data in its future public distribution. OpenPhish current terms restrict third-party distribution; several other sources have unestablished redistribution permission. The delivered archive preserves the user-provided data and is a local review package, not a declaration that all contents are cleared for public publication.

The historical September guide is in `docs/history/claude-guide-2026-09.md`; current `CLAUDE.md` describes the six-member AAST team and current constraints. `LICENSE` is explicitly a placeholder. The team must choose the project-code licence and copyright holders; no licence was selected for it.

## Verification and reproduction

Backend: **161 tests passed**. Initialization, frontend installation, build and lint exit codes: initialize=0, frontend_install=0, frontend_build=0, frontend_lint=0.

Regression replay: 23/23 detection, 7/7 robustness, 15/15 follow-up; NBE remains non-HIGH. Deployed text policy on the invented everyday probes remains 0 HIGH, 8 MEDIUM, 4 LOW. Candidate comparison results above do not replace deployment behavior.

Checks ran locally on Windows; GitHub Linux/Python 3.12/Node 24 CI itself was not run. `npm ci` reports one high-severity dependency finding; dependencies were not upgraded in this change. The original September data/model/tokenizer, reviewed 8 October reports, targets and frozen text split are verified unchanged. No phishing destination was fetched or resolved, and no SMS/URL data was sent to an external analysis service.

With the existing local development files and candidate artifacts, run from the repository root:

```text
python evaluation/run_url_review.py
python evaluation/run_url_review_followup.py
python evaluation/run_text_review.py
python evaluation/finalize_text_review.py
python evaluation/run_decision_metrics_v3.py
python evaluation/run_followup.py
python evaluation/audit_raw_sources.py
python data/scripts/restore_raw_data.py --check-all
python evaluation/run_checks_v3.py
python evaluation/summarize_review.py
```

For a clean reproduction, first use the original-data rebuild described in the historical report (without synthetic augmentation), and train local candidates with `run_text_v3.py`; it now delegates selection to the revised rule. The pristine baseline replay additionally needs a separate extraction of the supplied original ZIP via `replay_legacy_url_review.py --baseline <pristine-root>`. Do not run sealed final evaluation commands.

Sources: [PhiUSIIL/UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset); [GramBeddings authors](https://web.cs.hacettepe.edu.tr/~selman/grambeddings-dataset/); [GramBeddings academic access form](https://docs.google.com/forms/d/e/1FAIpQLScuwosnH9JIJYKUeTeR26xxiG6bWXhxYoHjoNSketW5MrCUxQ/viewform). Detailed licence sources are linked beside their claims in `docs/data-licences.md`.
