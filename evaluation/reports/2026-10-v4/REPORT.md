# V4 selected candidate deployed with owner-approved test corrections

Candidate **`ee0ba9f0077c1fd140aa`** is deployed with the **ordinary** policy, **`host_path`** input and the exact frozen threshold **`0.9870690448552604`**. Source: `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/phreshphish_full_url_lightgbm.joblib`. The numerical selection, rule and frozen thresholds are unchanged; the v4 evaluation was not rerun. [Deployment metadata](deployment.json), [completion evidence](url_v4_deployment_completion.json).

The project owner explicitly authorized rewriting the **29 tests that encoded the old shortcut/artifact/policy assumptions**. The preserved [22 October decision](url_v4_decision.json) records `blocked_engineering`, 363 passes and 29 failures before that approval. It remains an unchanged historical snapshot; the completion record above supplies current deployment status. There was no reranking, fallback substitution, new fitting or threshold adjustment.

## Corrected engineering contract

`test_url_query_shortcut.py` now requires benign query URLs to remain LOW with no raw alert or model support. For `host_path`, it compares actual raw probabilities on the same host/path with queries, fragments, both, and neither. The tests no longer require the former classifier to score benign queries above threshold. Ordinary model support alone is tested as MEDIUM, and model-plus-secret-request escalation uses an explicit mocked alert rather than depending on the historical shortcut. Independent structural evidence, exact query-bearing blacklist identity and unavailable-check handling remain covered.

`test_review_data_integrity.py` and `test_url_legit_subdomains.py` read `ml/models/url_host_deployment.json`, verify its packaged hash, representation/input mode and exact threshold, and match the declared source/input mode to its frozen inventory entry. The direct vectorizer/classifier check applies the declared model-input preprocessing independently. Historical promotion/report guards now also reject overwriting a v4 deployment, even though its policy is ordinary.

The historical combined full-URL classifier flagged **35/52 benign PhreshPhish query URLs**, with only three benign queries in fitting. That is a documented historical regression, never a requirement on the deployed classifier. [Historical diagnosis and containment](query-shortcut/REPORT.md). The scanner retains the complete URL for blacklist identity, brand/pattern checks and displayed evidence; only model input excludes queries and fragments.

## Before and after

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Before: corroboration-only | 2,205/76,800 (2.9%) | 206/91,260 | 94/5,973 (1.6%) | 8/2,916 |
| After: selected v4 ordinary, deployed | 32,474/76,800 (42.3%) | 227/91,260 | 764/5,973 (12.8%) | 14/2,916 |

These are the already recorded frozen v4 measurements for the before/after configurations, not a new evaluation run. Model-added false positives after deployment are **21/91,260** on PhreshPhish and **6/2,916** on ETIS, above non-model baselines of 206 and 8. Own-model false positives are 1/23,610 on PhreshPhish benign subdomains, 21/91,260 overall and 6/2,916 on ETIS. Natural PhreshPhish benign-query raw/scanner false positives are 0/52; ETIS has no benign-query coverage. Phishing abstentions remain misses.

## Release verification

The deployed working tree passes **392/392 pytest tests**, **40/40 query-invariance tests**, **23/23 detection, 7/7 robustness and 15/15 follow-up replays**, **17/17 host probes** with zero raw alerts or MEDIUM/HIGH verdicts, and **88/88 query/path probes LOW** with zero raw model alerts. Isolated database initialization, frontend build and lint all exit 0. [Actual release outputs](url_v4_release_checks.json), [replays](url_v4_release_replays.json), [hosts](url_v4_release_host_probes.json), [query/path probes](url_v4_release_query_probes.json).

A newly created venv installed only `requirements-runtime.txt`: **383 passed, 5 optional PyArrow skips**, zero failures. RapidFuzz and PyArrow are absent; `pip check` passes. Module-level optional skips explain the collection/count difference. [Runtime-only output and package inventory](url_v4_runtime_only_checks.json).

The packaged classifier weights and vectorizer match the selected source exactly. Against existing frozen predictions, the real deployed scorer and scanner match **332 valid samples**, with **10 expected invalid-input abstentions**, zero mismatches and maximum probability difference 0.0. This checks only the selected deployment; it does not rerun v4 selection or cohort evaluation. [Deployment verification](url_v4_release_scanner_verification.json). Existing Starlette deprecation and frontend bundle-size warnings remain.

## Frozen provenance and limits

Source SHA-256: `40f229dfa5bf22542fce994eedaf66881fc4e388b0f1ad32fe405e51aee73985`. Packaged SHA-256: `1b964f155ef290beeb2487f7f5804a8ab9587ee6864260664af0802964c10e52`. Packaging adds the declared deployment schema and frozen operating threshold; fitted weights and vectorizer are unchanged.

Rule SHA-256: `6164475a6fe752e19a6797e2e17f2b988189c391ddd2539519bc1590c00b54fa`. Inventory SHA-256: `5882b7210d07ea9c82ab98a7764bacec813efc5902363da98ba02fc22884df44`. The original 202 pairs plus 87 host/path pairs, all 36 source artifacts and the prepared URL-only cache are unchanged. The rule's malformed 63-character coverage-audit digest remains documented in the original inventory; it was not corrected. [Original comparison](url_v4_comparison.json), [original engineering results](url_v4_engineering.json), [original parity](url_v4_runtime_parity.json), [provenance](url_v4_provenance.json). Their historical test failures are not relabelled as passes.

The original selection has 122 primary numerical passers; candidate `ee0ba9f0077c1fd140aa` remains selected exactly as recorded. No other candidate was reevaluated. Natural benign-query coverage remains sparse; neither cohort supplies benign-fragment coverage, and ETIS has no benign-query rows. Repeated exposed development selection is not independent final validation. Genuine Egyptian SMS final-test count remains **0**.

No destination requests, DNS resolution, PhreshPhish HTML-column access, data upload, sealed final test, frozen-input changes, push or merge. Commit locally on `fix/url-subdomains-and-hygiene`, then stop.

<!-- V4 HISTORICAL REPORT -->

The section below preserves the historical v3 record verbatim. Any “current” or
“deployed” labels within it refer to that earlier period; the v4 release above supersedes them.


## Historical v3 record (superseded deployment)

# URL model contribution and pattern follow-up

**Superseded deployment, 18 October:** the query-shortcut review of `16fc7a5`
reproduced 8/8 raw alerts for ordinary order-query URLs. Current URL-model support
is **corroboration-only**, with the same artifact/threshold. See the
[mitigation report](query-shortcut/REPORT.md) for current checks and the substantial
recall cost. The measurements below describe the historical ordinary-policy
selection; passing those gates did not establish query robustness. The historical
promotion/report commands below now reject attempts to restore that deployment.

Deployed **ordinary URL-model support** from the existing combined full-URL LightGBM at **0.99032868461552581**. It passes rule v3's own-model and incremental-scanner FP limits. The independently frozen pattern proposal also passes its acceptance rule. The text model is unchanged.

[Rule v3](url_selection_rule_v3.md) was written **after seeing v2 results, before any new v3 computation**. V2 had incorrectly required the whole scanner to meet the model gates. V3 gates the URL model's own alerts and the extra benign warnings it adds above a matched non-model baseline. Total scanner FPR is reported separately. [REPORT_v2.md](REPORT_v2.md) preserves the prior result; [REPORT_v1.md](REPORT_v1.md) preserves the earlier work.

## Frozen model selection

Reused all **202 existing model/threshold pairs from 36 distinct artifacts** in [url_v2_frozen_thresholds.json](url_v2_frozen_thresholds.json). **No thresholds were added or changed; no model was fitted.** Existing predictions and row membership were reused, with matching fingerprints. All thresholds were originally chosen on calibration data, never test/validation. Historical v3/v1 thresholds remain comparators only. Historical fitting exposure is unchanged; this does not claim that old training excluded later external test domains.

A candidate must meet all three own-model FPR limits below, plus **at most 0.5 percentage points of extra scanner FP on each complete benign cohort**. Among passing candidates maximize integrated PhreshPhish-test MEDIUM/HIGH recall. Exact ties follow the rule's declared order. **97/202 pass**, both before and after the separately accepted pattern/registry changes. The same LightGBM wins both stages; ETIS recall is not the optimization target.

| Selected model's own alerts | FP / benign (FPR) | Limit | Outcome |
|---|---:|---:|---|
| Benign subdomains, PhreshPhish test | 0/23610 (0.000%) | 1% | pass |
| ETIS validation | 2/2916 (0.069%) | 0.5% | pass |
| All PhreshPhish test | 48/91260 (0.053%) | 0.5% | pass |

Final incremental scanner FP: **48/91,260 = 0.052597 percentage points** on PhreshPhish and **2/2,916 = 0.068587 points** on ETIS; both are below 0.5 points. Own-model recall is **58.562%** on PhreshPhish and **16.960%** on ETIS.

Source: `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/combined_full_url_lightgbm.joblib`. Source SHA-256: `44b6f1334cc82c56d1852d0ee5ba15529244a518eee6419c3ba46dbd196aded1`. Packaged SHA-256: `4fb9b6afbb4b356e54b842490e9192628a74db22a6dc88bb60d6c1054ce335f8`. [Deployment metadata](deployment.json) records the frozen-file, rule and proposal hashes.

## Integrated scanner comparisons

All four policies below use the **same final sourced registry, accepted pattern policy, cohort rows and healthy empty blacklist**. Original v3 and v1 refer to their original model/threshold, with ordinary support; these rows isolate model/policy effects under today's non-model baseline. Historical deployed-state measurements are retained in [REPORT_v2.md](REPORT_v2.md), rather than mixed with this changed baseline. Corroboration-only uses the newly selected LightGBM. On these URL-only cohorts all its permitted corroborators already alert, so its MEDIUM/HIGH outcome equals the no-model baseline.

Extra rate = model-added benign FP / **all benign rows** in that cohort. Total FP = non-model FP + model-added FP, without double counting. No whole-scanner gate was substituted for the model-contribution gate.

### PhreshPhish test

| Policy | MEDIUM/HIGH recall | Total FP / benign (FPR) | Non-model FP | Model-added FP (extra rate) |
|---|---:|---:|---:|---:|
| Original v3, ordinary | 61.826% (47482/76800) | 42741/91260 (46.834%) | 206 | 42535 (46.609 pp) |
| v1 selected, ordinary | 39.965% (30693/76800) | 347/91260 (0.380%) | 206 | 141 (0.155 pp) |
| **v3 contribution gate, ordinary (deployed)** | 59.479% (45680/76800) | 254/91260 (0.278%) | 206 | 48 (0.053 pp) |
| Corroboration-only, selected model | 2.871% (2205/76800) | 206/91260 (0.226%) | 206 | 0 (0.000 pp) |

### ETIS validation

| Policy | MEDIUM/HIGH recall | Total FP / benign (FPR) | Non-model FP | Model-added FP (extra rate) |
|---|---:|---:|---:|---:|
| Original v3, ordinary | 72.192% (4312/5973) | 10/2916 (0.343%) | 8 | 2 (0.069 pp) |
| v1 selected, ordinary | 59.535% (3556/5973) | 86/2916 (2.949%) | 8 | 78 (2.675 pp) |
| **v3 contribution gate, ordinary (deployed)** | 17.294% (1033/5973) | 10/2916 (0.343%) | 8 | 2 (0.069 pp) |
| Corroboration-only, selected model | 1.574% (94/5973) | 8/2916 (0.274%) | 8 | 0 (0.000 pp) |

With the original v2 registry/pattern baseline, the v3 gate already selected the same model:

| Cohort | Recall | Total FP / benign | Non-model FP | Model-added FP |
|---|---:|---:|---:|---:|
| phreshphish_test | 71.189% | 5586/91260 | 5544 | 42 |
| etis_grouped_validation | 27.156% | 17/2916 | 15 | 2 |

The sourced registry fixes alone reduce that baseline's non-model FP from 5,544 to 4,852 on PhreshPhish and from 15 to 8 on ETIS. The pattern change then reduces PhreshPhish non-model FP to 206; ETIS remains 8. Initial and final complete candidate tables: [initial selection](url_v3_initial_selection.json), [final selection](url_v3_final_selection.json).

## Pattern false-alarm diagnosis and frozen acceptance

[Pattern acceptance rule](url_pattern_acceptance_rule_v3.md) was written **before new pattern measurements**. Four nested proposal families and the training-only choice rule were specified in advance. Selection used **274,393 official PhreshPhish TRAINING rows** from the existing combined fitting/calibration pools, excluding ETIS-source rows. Test and ETIS validation did not choose flags or parameters. The single choice and its measurements were saved in [pattern_training_proposal_v3.json](pattern_training_proposal_v3.json) before held-out evaluation; there was no retry after seeing test/replay results.

The old non-model scanner flagged **5,544/91,260 (6.075%)** PhreshPhish benign URLs. Raw pattern observations account for **4,677 unique benign rows**; per-flag counts overlap and do not sum to that number. The scanner's prior primary reason `url_patterns` counted 4,659 because reason precedence/suppression differs from raw observations. These are offline counts only; no PhreshPhish example hosts are printed or visited.

| Observed flag | PhreshPhish-test benign count | ETIS-validation benign count | Alerts under accepted policy |
|---|---:|---:|---|
| `ip_address_host` | 0 | 0 | yes |
| `userinfo_in_url` | 0 | 0 | yes |
| `non_standard_port` | 0 | 0 | yes |
| `punycode_domain` | 17 | 1 | yes |
| `no_https` | 532 | 0 | diagnostic only |
| `suspicious_path_keyword` | 2799 | 0 | diagnostic only |
| `long_url` | 594 | 0 | diagnostic only |
| `many_subdomains` | 818 | 0 | diagnostic only |

The same raw detections remain available in API `pattern_observations`; only `patterns`/`alert_flags` create pattern support or corroboration. `no_https`, keyword, long URL and many-subdomain observations cannot create a warning or corroborate a text/model alert by themselves. Independent brand, blacklist, secret-request and ordinary model evidence still operate normally.

| Training-only proposal | Pattern recall | FP / benign (FPR) | Training FPR ≤0.5% |
|---|---:|---:|---|
| `structural_or_weak_pair` | 3.031% | 937/105386 (0.889%) | fail |
| `structural_only` | 1.761% | 881/105386 (0.836%) | fail |
| `four_structural_only` | 0.540% | 37/105386 (0.035%) | pass |
| `userinfo_or_punycode` | 0.164% | 37/105386 (0.035%) | pass |

Frozen choice: **`four_structural_only`**. It has the highest training recall among qualifying proposals. Acceptance required test pattern FPR ≤1% and no replay loss. Observed **17/91,260 (0.018628%)** test pattern FPR, versus 4,677/91,260 (5.125%) previously; ETIS pattern FP stays **1/2,916**. **23/23, 7/7 and 15/15** replays pass with the actual packaged ordinary policy, so the proposal is accepted. All flag counts and evaluation metrics are in [pattern_evaluation_v3.json](pattern_evaluation_v3.json); acceptance execution is in [pattern_acceptance_replay_v3.json](pattern_acceptance_replay_v3.json).

### Recall cost of reducing pattern alerts

This is a substantial tradeoff, accepted under the requested FPR/replay rule; there was no additional recall floor. Integrated changes below hold the selected model, threshold and final registry constant and change only pattern policy.

| Cohort | Old pattern-only recall | Accepted pattern-only recall | Change | Integrated recall, old → accepted patterns |
|---|---:|---:|---:|---:|
| PhreshPhish test | 24.111% | 2.069% | -22.042 pp | 71.189% → 59.479% (-11.710 pp) |
| ETIS validation | 16.340% | 0.536% | -15.804 pp | 27.156% → 17.294% (-9.861 pp) |

Relative to corroboration-only on the **same final baseline**, ordinary selected-model support recovers **56.608 percentage points** of PhreshPhish recall and **15.721 points** of ETIS recall. The final ETIS recall of **17.294%** remains low; passing the FP gates is not evidence of strong ETIS detection.

## Thirteen brand-resemblance pairs

The requested offline list is [etis_brand_resemblance_pairs_v3.json](etis_brand_resemblance_pairs_v3.json), with original matched domains, techniques and dispositions. These are the 13 pairs from the pre-fix ETIS baseline; no cohort URL or listed root host was opened.

| Benign domain | Incorrect matched brand / registry domain | Outcome |
|---|---|---|
| `amazon.com` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `media-amazon.com` | Amazon Egypt / `amazon.eg` | Known limitation; no supported official-domain addition |
| `amazon.de` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `amazon.co.jp` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `amazon.com.mx` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `amazon.co.za` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `amazon.se` | Amazon Egypt / `amazon.eg` | Fixed: sourced official domain |
| `orange.pl` | Orange Egypt / `orange.eg` | Fixed: sourced official domain |
| `vorwerk-digital.com` | Egypt e-Government portal / `digital.gov.eg` | Known limitation; no supported official-domain addition |
| `faire.com` | Fawry / `fawry.com` | Known limitation; no supported official-domain addition |
| `amazon.eu` | Amazon Egypt / `amazon.eg` | Known limitation; no supported official-domain addition |
| `bm-ads.io` | Banque Misr / `banquemisr.com` | Known limitation; no supported official-domain addition |
| `siege-amazon.com` | Amazon Egypt / `amazon.eg` | Known limitation; no supported official-domain addition |

**Seven fixes, six known limitations.** Only cited missing official domains were added: six global Amazon stores and Orange Polska. [Brand sources](../../../docs/brand-sources.md) cite [Amazon's developer marketplace tables](https://www.developer.amazon.com/docs/app-submission/distribute-your-app-internationally.html), [Amazon's South Africa launch](https://www.aboutamazon.com/news/retail/amazon-south-africa), and [Orange Group's website directory](https://www.orange.com/en/our-websites). Other pairs lack an official-domain addition justified by those sources; aliases/edit-distance rules were not weakened. The six listed limitations remain false alarms. Of the final eight ETIS non-model FP, six are these brand pairs; the other two retain the pre-existing pattern/domain-embedding behavior.

The previously sourced Vodafone Group entry remains; the careers/root probes pass. The user-requested [78 v1 benign-domain probabilities](v1_etis_validation_benign_flags.json) remain unchanged. No data-derived URL was submitted to an external analysis service.

## Method and checks

Integrated cohort evaluation factors the exact URL-only scanner decision into the non-model baseline OR an eligible ordinary model alert, with official/shared-host suppression and invalid-input handling. All original rows remain in denominators; invalid inputs count as phishing misses (133 runtime abstentions on PhreshPhish, zero ETIS). Every model/threshold pair is measured, not just the winner. Blacklist state is isolated, healthy and empty; there is no fabricated SMS context or claim of live-feed recall.

Offline brand acceleration uses exact unit-cost RapidFuzz Levenshtein distance, previously checked against production on 7,506 pairs. Production still uses its unchanged implementation. The original production scanner verifies the factorization on **1,619 policy/cohort row checks**, including boundaries, model-only benign alerts, official, diagnostic-pattern and invalid rows, plus both no-model baselines: **zero mismatches**. Actual packaged probabilities match cached selected-model probabilities exactly on the checked samples. See [deployment verification](deployed_scanner_verification_v3.json).

* **251 pytest tests pass**; initialize, frontend build and lint all exit 0: [final_checks.json](final_checks.json).
* **23/23 detection, 7/7 robustness, 15/15 follow-up**: [followup_v3.json](followup_v3.json).
* **17/17 host probes avoid MEDIUM/HIGH**, with zero raw model alerts: [probe_v3.json](probe_v3.json).

The logged pytest Starlette deprecation and frontend bundle-size warning remain. Check logs identify the parent HEAD while exercising this working tree; no hosted CI or browser interaction is claimed. Protected model/tokenizer, split/target and local-retention checks: [integrity.json](integrity.json). Data hygiene and licence limits remain as documented in [REPORT_v1.md](REPORT_v1.md) and [data licences](../../../docs/data-licences.md); historical restricted copies remain in Git history and no history rewrite occurred.

These are exposed development comparisons after v1/v2 results. Repeated test/validation selection prevents an independent final-performance claim. **No sealed final test; genuine Egyptian SMS test count remains 0.** No live destination visits, feed refresh, push or merge. Remaining work includes the six brand false alarms, lost pattern recall and independent evaluation with real Egyptian SMS.

## Reproduction

Restore authorized local data, frozen scores and original candidate artifacts using the existing manifests. Do not regenerate calibration thresholds. Rule files must exist before any evaluation, and each training-only proposal must be frozen before held-out evaluation.

```text
python evaluation/run_url_followup_v3.py train_patterns
python evaluation/run_url_followup_v3.py select_initial
python evaluation/run_url_followup_v3.py audit
python evaluation/run_url_followup_v3.py finalize_brand_review
python evaluation/run_url_followup_v3.py evaluate_patterns
python evaluation/run_url_followup_v3.py baseline_components
python evaluation/run_url_followup_v3.py select_final
python evaluation/run_url_followup_v3.py promote
python evaluation/run_url_followup_v3.py accept_patterns
python evaluation/verify_url_v3_deployment.py
python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_v3.json
python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_v3.json
python evaluation/run_checks_v4.py final
python evaluation/verify_hygiene_v4.py
python evaluation/report_url_v3.py
```

Stop after a local commit on `fix/url-subdomains-and-hygiene`. **Do not push or merge.**
