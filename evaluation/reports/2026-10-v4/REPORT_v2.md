> Historical v2 report. Superseded by [REPORT.md](REPORT.md), which gates model contribution.

# ETIS URL selection v2 follow-up

Deployed **corroboration_only** with `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/combined_full_url_char_calibrated_svm.joblib` at **0.85206987301336179** (`full_url`). The deployed text model remains unchanged.

The v1 selection was unacceptable on ETIS legitimate main domains: **78/2,916 false positives (2.675%)**, versus **2/2,916 (0.069%)** for old v3. The old subdomain-only gate did not protect this cohort. [Rule v2](url_selection_rule_v2.md) was written **after seeing v1 results and before new v2 computation**. These are exposed development comparisons, not independent final validation.

## Frozen selection and outcome

Hard limits: PhreshPhish benign-subdomain FPR ≤1%, ETIS-validation FPR ≤0.5%, and overall PhreshPhish-test FPR ≤0.5%. Among passing candidates, maximize overall PhreshPhish-test recall. Ordinary deployment also has to meet these limits in the integrated scanner.

Evaluated **36 distinct existing URL artifacts × six calibration FPR caps** (1%, 0.5%, 0.1%, 0.05%, 0.01%, 0%), deduplicated to **202 model/threshold candidates**. Every candidate was also evaluated under corroboration-only. Text artifacts are excluded. Byte-identical URL copies are aliases; all historical, time, shortcut, host and full-URL URL models are included. No model was refitted.

The threshold table was saved before evaluation predictions in [url_v2_frozen_thresholds.json](url_v2_frozen_thresholds.json). PhreshPhish-protocol artifacts use their original setting-specific calibration partition. Historical ETIS artifacts use external calibration excluding all ETIS training domains and the entire archived PY35J Tranco domain list; historical validation-selected thresholds are comparators only. Frozen fitting/calibration fingerprints and evaluation membership are checked. Historical models retain their original fitting exposure; this does not claim that old fitting excluded the later external test domains.

Passing model candidates: **97**; passing ordinary integrated policies: **0**; passing corroboration-only integrated policies: **0**.

The highest-recall v2 model is `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/combined_full_url_lightgbm.joblib` at **0.99032868461552581** (58.562% model recall).

**No ordinary integrated policy satisfies rule v2. The required fallback is deployed.** The URL model never creates MEDIUM alone; it only contributes alongside brand resemblance, a pattern flag, a blacklist domain match, or a secret request. Official/shared-host suppression and decisive/incomplete precedence remain. A bare model alert also cannot corroborate a high text-model score into HIGH.

**The fallback itself does not satisfy all three total-scanner FPR limits.** Existing non-model signals exceed the limits. This is the explicitly requested fallback, not a passing-FPR deployment claim. Their remaining false alarms require separate rule-policy work.

ETIS validation without model support: **15/2916 (0.514%)**; benign alert reasons: `brand_resemblance`: 13, `url_patterns`: 1, `domain_embedding`: 1.

PhreshPhish test without model support: **5544/91260 (6.075%)**; benign alert reasons: `brand_resemblance`: 871, `url_patterns`: 4659, `brand_label_reuse`: 11, `domain_embedding`: 3.

## Model hard-limit comparison

| Model / threshold | Test recall | Test FP / benign (FPR) | ETIS FP / benign (FPR) | Subdomain FP / benign (FPR) | Model gate |
|---|---:|---:|---:|---:|---|
| old v3, 0.97968049864706896 | 61.051% | 43696/91260 (47.881%) | 2/2916 (0.069%) | 11344/23610 (48.047%) | fail |
| v1 selected, 0.98106572597550756 | 38.219% | 141/91260 (0.155%) | 78/2916 (2.675%) | 61/23610 (0.258%) | fail |
| best v2, 0.99032868461552581 | 58.562% | 48/91260 (0.053%) | 2/2916 (0.069%) | 0/23610 (0.000%) | pass |

## Integrated scanner: MEDIUM or HIGH

Denominators: ETIS validation **5,973 phishing / 2,916 benign**; PhreshPhish test **76,800 phishing / 91,260 benign**. All original rows are retained.

| Policy | ETIS recall | ETIS FP / benign (FPR) | PhreshPhish-test recall | PhreshPhish-test FP / benign (FPR) |
|---|---:|---:|---:|---:|
| old v3 deployed | 75.707% | 17/2916 (0.583%) | 74.164% | 45493/91260 (49.850%) |
| v1 selected | 64.792% | 93/2916 (3.189%) | 57.699% | 5679/91260 (6.223%) |
| best v2 model, ordinary policy | 27.156% | 17/2916 (0.583%) | 71.189% | 5586/91260 (6.121%) |
| corroboration-only (deployed) | 17.294% | 15/2916 (0.514%) | 24.811% | 5544/91260 (6.075%) |

| Policy | Integrated benign-subdomain FP / benign (FPR) |
|---|---:|
| old v3 deployed | 11877/23610 (50.305%) |
| v1 selected | 2447/23610 (10.364%) |
| best v2 model, ordinary policy | 2389/23610 (10.119%) |
| corroboration-only (deployed) | 2389/23610 (10.119%) |

All policies use the same final sourced registry, original cohort rows, and isolated healthy empty blacklist. Thus the comparison isolates model/policy effects; old v3 and v1 names refer to their historical artifacts and thresholds, not a claim of reproducing all historical feed/registry state. URLs are submitted in the URL field, with no fabricated SMS or sender context. Invalid/overlength inputs abstain and count as phishing misses. Outer whitespace is stripped as in the runtime. No live blacklist recall or SMS-context recall is measured.

Every row first goes through the integrated scanner with URL-model support absent. For URL-only inputs the exact MEDIUM/HIGH result is that baseline OR an unsuppressed model alert. Under corroboration-only, each authorized corroborator already creates a warning, so the model adds no new MEDIUM/HIGH detections on these URL-only cohorts. This exact factoring avoids repeating invariant brand/SQL checks for every threshold. Boundary, model-only, baseline-positive and invalid rows are rescanned through the complete scanner for **every candidate**, with equivalence asserted. Per-candidate model, ordinary, corroboration and subdomain results and check counts are in [url_v2_comparison.json](url_v2_comparison.json).

Evaluation-only acceleration uses `rapidfuzz==3.14.6` for exact unit-cost Levenshtein distance (no preprocessing or cutoff), checked against the production dynamic-programming implementation on **7506 pairs**. The production brand implementation is unchanged. [API semantics](https://rapidfuzz.github.io/RapidFuzz/Usage/distance/Levenshtein.html) and the saved equivalence counts document this speedup; no matching threshold or rule changed.

## Recall cost

All corroboration-only candidates have the same MEDIUM/HIGH outcomes on these URL-only rows. The underlying fallback artifact and threshold follow the frozen deterministic tie rule (integrated recall, summed cohort FPR, artifact path, threshold). This tie does not establish that its model is superior or that its threshold is optimal for SMS with secret requests.

* ETIS validation: corroboration-only recall **17.294%**, a loss of **47.497 percentage points** versus v1 ordinary support, and **68.140 points** versus ordinary support from the same underlying model/threshold, **9.861 points** versus the best v2 model's ordinary policy.
* PhreshPhish test: corroboration-only recall **24.811%**, a loss of **32.888 percentage points** versus v1 ordinary support, and **63.389 points** versus ordinary support from the same underlying model/threshold, **46.378 points** versus the best v2 model's ordinary policy.

This cost is the loss of model-only warnings. It does not measure the model’s possible benefit when genuine message context, secret requests or live threat intelligence are available.

## Benign-domain flags and Vodafone

[v1_etis_validation_benign_flags.json](v1_etis_validation_benign_flags.json) lists all **78 rows / 78 unique domains**, their registered domains, row IDs, probabilities and the v1 threshold. These domains were not visited or resolved.

Added `vodafone.com` as **Vodafone Group**, separate from Vodafone Egypt and Vodafone Cash. The [official Group company page](https://www.vodafone.com/our-company/vodafone-at-a-glance) links directly to `careers.vodafone.com` in its Careers navigation. See [brand-sources.md](../../../docs/brand-sources.md) for the dated provenance. The careers subdomain itself was not visited. Generic official-domain handling now covers it.

Final legitimate-host probes: **0/17 MEDIUM/HIGH**, with 3 raw model flags. Probe results are exposed regressions, not population FPR estimates. See [probe_v2.json](probe_v2.json).

## Verification and handover

* `pytest`: exit **0**, **237 passed**.
* `initialize`: exit **0**.
* `frontend_build`: exit **0**.
* `frontend_lint`: exit **0**.
* Replays: **23/23 detection**, **7/7 robustness**, **15/15 follow-up**. The NBE notice remains non-HIGH.

Actual logs: [final_checks.json](v2_final_checks.json), [followup_v2.json](followup_v2.json). Packaged `score_url` and the original production scanner also match the evaluated decisions on **328 selected boundary/regression rows**, including v1 benign flags and invalid inputs; [deployment verification](deployed_scanner_verification.json). The local Python 3.12.10 interpreter was repaired inside the ignored workspace after the prior venv’s base interpreter was found missing. Dependencies and research data remain local. Pytest uses a writable local cache. Existing upstream deprecation and frontend bundle-size warnings are retained in logs; no hosted CI or browser interaction is claimed. The [initial v2 check attempt](v2_initial_checks.json) exposed an inaccessible optional tldextract disk cache (four test failures). The parser now disables that cache while retaining the same offline bundled suffix snapshot and grouping rules. The complete checks and replays were rerun successfully after this fix.

## Preserved scope and limits

The earlier sender-display feature, registry entries, dependency fix, data untracking and local release-artifact retention remain. Historical hygiene, licences and the original engineering evidence are in [REPORT_v1.md](REPORT_v1.md), [data_hygiene.json](data_hygiene.json), [release_manifest.json](release_manifest.json) and [data licences](../../../docs/data-licences.md). Removed data remains in Git history and on GitHub; no history rewrite was performed. September model/tokenizer, the deployed text model, targets and frozen partitions are preserved.

Genuine Egyptian SMS test count remains **0**. No sealed final test ran. PhreshPhish test and ETIS validation have now informed repeated development selection and cannot substantiate independent final or Egyptian-traffic performance claims. Row-wise uncertainty does not account for repeated domains; live feed state and message context are not available in the URL cohorts. Corroboration-only can still warn on benign URLs through existing brand/pattern rules. No candidate URLs were visited, resolved or sent to external analysis services.

## Reproduction

```text
python evaluation/run_url_selection_v2.py calibrate
python evaluation/run_url_selection_v2.py evaluate
python evaluation/promote_url_v2.py
python evaluation/verify_url_v2_deployment.py
python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_v2.json
python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_v2.json
python evaluation/run_checks_v4.py final
python evaluation/report_url_v2.py
```

Restore authorized local data and research artifacts using the earlier pinned manifests before evaluation. The packaged scanner and backend checks do not require those corpora. Stop after committing on `fix/url-subdomains-and-hygiene`; **no push or merge**.
