# ETIS v4: legitimate subdomains, repository hygiene and sender context

All new figures below are generated from JSON saved in this directory by scripts actually run. This is exposed development evidence, not a sealed final test or Egyptian deployment validation.

Deployed **combined/host_only/char_calibrated_svm** at **0.9810657259755076**, selected under the [pre-result rule](url_selection_rule.md). The September text model is unchanged. The fallback policy change was not required because fresh candidates passed the subdomain gate.

## Engineering before and after

| Check | Before editing | After changes |
|---|---|---|
| Backend | 161 passed, 1 optional module skipped | 227 passed |
| Database initialization | passed | passed |
| Frontend clean install/build/lint | passed | passed |
| npm high-severity findings / total after | 1 high | 0 total |
| Data-free tracked-tree export | not run | 227 tests and initialization passed |

Evidence: [baseline](baseline_checks.json), [final](final_checks.json), [patched clean install](npm_ci_patched.json), [clean export](clean_tree_checks.json), [audit before](npm_audit_before.json), [audit after](npm_audit_after.json). The optional PhreshPhish safety tests became active after installing the evaluation requirements. The initial premature baseline attempt is retained separately; the successful baseline preceded application edits. The first clean export exposed the selection-rule newline hash problem; the exact pre-result bytes were then pinned in Git, with normalized content unchanged, and the export rerun passed. The upstream test-client deprecation and frontend bundle-size warnings remain. No browser-interaction, hosted CI or deployment check is claimed.

## Frozen protocol and deployment choice

The original PhreshPhish protocol is unchanged. Fresh combined fitting uses ETIS training phishing plus both PhreshPhish training classes, with ETIS benign excluded as prescribed. Evaluation registered domains are excluded from fitting/calibration; mixed-label domains and duplicate training URLs are removed. The historical deployed comparator was not refit to impose these later exclusions. The fresh fit and calibration membership hashes exactly match the frozen research run ([split reproduction](split_reproduction.json), [data audit](data_audit.json)). Only the permitted projection was acquired; no HTML data chunks or destination pages were retrieved.

Before fresh predictions, the deployment rule fixed the 0.1%-calibration-FPR threshold for each fresh model. The 1%-calibration operating point below is diagnostic only and was not an alternative selected after seeing test results. The current artifact retains its historical threshold, originally selected on ETIS validation; its evaluation is a comparator, not a newly calibration-selected model. No evaluation-derived ROC threshold is used here.

A candidate must have at most 1% actual FPR on benign PhreshPhish test hosts with a non-www subdomain label. Among passing candidates at their predeclared deployment point, select highest whole-test recall. The pinned private PSL defines the subdomain; www alone does not qualify, while www alongside another label does. Evaluation rows remain fixed, and invalid hosts abstain; phishing abstentions count as misses.

### phreshphish_test

| Model | Fixed threshold source | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---|---:|---:|---:|---:|---:|
| current_artifact | historical deployed | 61.051% | 43696/91260 | 47.881% | 1.272% | 0.127% |
| combined/host_only/lightgbm | calibration 1% (diagnostic) | 48.758% | 645/91260 | 0.707% | 41.067% | 6.460% |
| combined/host_only/lightgbm | calibration 0.1% | 33.014% | 78/91260 | 0.085% | 79.599% | 27.884% |
| combined/host_only/char_calibrated_svm | calibration 1% (diagnostic) | 61.158% | 1654/91260 | 1.812% | 25.420% | 3.267% |
| combined/host_only/char_calibrated_svm | calibration 0.1% | 38.219% | 141/91260 | 0.155% | 71.417% | 19.847% |

### etis_grouped_validation

| Model | Fixed threshold source | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---|---:|---:|---:|---:|---:|
| current_artifact | historical deployed | 73.564% | 2/2916 | 0.069% | 91.550% | 51.776% |
| combined/host_only/lightgbm | calibration 1% (diagnostic) | 74.217% | 228/2916 | 7.819% | 8.749% | 0.941% |
| combined/host_only/lightgbm | calibration 0.1% | 34.338% | 21/2916 | 0.720% | 32.506% | 4.555% |
| combined/host_only/char_calibrated_svm | calibration 1% (diagnostic) | 81.517% | 353/2916 | 12.106% | 6.369% | 0.670% |
| combined/host_only/char_calibrated_svm | calibration 0.1% | 59.200% | 78/2916 | 2.675% | 18.271% | 2.167% |

### Benign-subdomain subset

| Model | Fixed calibration point | FP / benign | Actual FPR | Deployment gate |
|---|---|---:|---:|---|
| current_artifact | deployed | 11344/23610 | 48.047% | fail |
| combined/host_only/lightgbm | 1pct | 259/23610 | 1.097% | diagnostic only |
| combined/host_only/lightgbm | 0_1pct | 13/23610 | 0.055% | pass |
| combined/host_only/char_calibrated_svm | 1pct | 301/23610 | 1.275% | diagnostic only |
| combined/host_only/char_calibrated_svm | 0_1pct | 61/23610 | 0.258% | pass |

Recall and prevalence-adjusted PPV are undefined in this benign-only subset; both are null in JSON rather than fabricated from absent phishing examples. The PPV columns in the full cohorts use assumed prevalence, not measured Egyptian precision. Wilson intervals and conservative marginal bounds are in [url_comparison.json](url_comparison.json); they are not domain-cluster confidence intervals.

The selected SVM gives 38.219% PhreshPhish-test recall and 61/23610 benign-subdomain false positives (0.258%). ETIS-validation recall is 59.200%, with 78/2916 false positives (2.675%); its recall change from the prior artifact is -14.365 percentage points. The gate deliberately prioritizes subdomain behaviour; it does not imply improvement on every source. The SVM has the highest recall among gate-passing models at the predeclared deployment point. The former artifact fails the gate. No threshold was adjusted to make the probe list pass. The existing supporting-signal policy and official/shared-host suppression remain.

## Reviewer-supplied legitimate host probes

| Host | Old model probability | Selected probability | Old scanner | New scanner |
|---|---:|---:|---|---|
| `login.microsoftonline.com` | 0.998800 | 0.577733 | MEDIUM | LOW |
| `outlook.office365.com` | 0.999245 | 0.651527 | MEDIUM | LOW |
| `teams.microsoft.com` | 0.996963 | 0.229896 | MEDIUM | LOW |
| `secure.paymob.com` | 0.997124 | 0.413589 | MEDIUM | LOW |
| `accept.paymob.com` | 0.997632 | 0.738505 | MEDIUM | LOW |
| `careers.vodafone.com` | 0.997522 | 0.207145 | MEDIUM | MEDIUM |
| `booking.egyptair.com` | 0.997602 | 0.348303 | LOW | LOW |
| `vendor.talabat.com` | 0.997378 | 0.247230 | LOW | LOW |
| `ebanking.cibeg.com` | 0.997492 | 0.391308 | LOW | LOW |
| `bm-online.banquemisr.com` | 0.998774 | 0.437771 | LOW | LOW |
| `microsoftonline.com` | 0.170415 | 0.751518 | LOW | LOW |
| `paymob.com` | 0.122840 | 0.783017 | LOW | LOW |
| `vodafone.com` | 0.057299 | 0.277659 | MEDIUM | MEDIUM |
| `egyptair.com` | 0.074339 | 0.442616 | LOW | LOW |
| `talabat.com` | 0.058864 | 0.395353 | LOW | LOW |
| `cibeg.com` | 0.027739 | 0.625768 | LOW | LOW |
| `banquemisr.com` | 0.078414 | 0.750658 | LOW | LOW |

Raw above-threshold probes: 10/17 before, 0/17 after. Scanner MEDIUM/HIGH: 7 before, 2 after. The remaining Vodafone root/careers alerts are **brand_resemblance**, not URL-model evidence; they are explicitly retained as a separate limitation. No unsupported Vodafone global-domain entry was guessed. All requested subdomains avoid alerts from the URL model alone. Probe inputs are exposed regression strings and do not estimate population FPR.

The full scanner probes use an empty isolated in-memory blacklist with availability forced healthy. No feed is fetched or live database altered. All model/threshold/scanner findings are in [probe_before.json](probe_before.json), [probe_after.json](probe_after.json) and the candidate probe entries of [url_comparison.json](url_comparison.json).

Model FP/benign and actual FPR on this benign-only probe list are below. Recall and PPV are undefined; all nullable metrics and the scanner alert rates are explicit in [probe_metrics.json](probe_metrics.json).

| Model | Fixed point | FP / benign | Actual probe FPR |
|---|---|---:|---:|
| current_artifact | deployed | 10/17 | 58.824% |
| combined/host_only/lightgbm | 1pct | 0/17 | 0.000% |
| combined/host_only/lightgbm | 0_1pct | 0/17 | 0.000% |
| combined/host_only/char_calibrated_svm | 1pct | 0/17 | 0.000% |
| combined/host_only/char_calibrated_svm | 0_1pct | 0/17 | 0.000% |

## Regression replay

Detection: 23/23; robustness: 7/7; follow-up: 15/15. The known NBE notice remains non-HIGH. These are existing exposed development fixtures, not a final test ([replay JSON](followup_final.json)).

## Public-tree hygiene

Untracked 92 data/export files: 89 raw files and 3 derived exports. All existing local bytes are retained and verified. Moved 54 historical candidate binaries out of Git, including 47 under the v3 report tree (76568834 bytes). The local release manifest contains 57 files, including the fresh candidates and former deployed URL artifact. Only deployed models plus the explicitly preserved September model remain under ml/models in Git. The original tokenizer is also unchanged. The original September processed dataset remains byte-identical locally but is untracked as an uncleared derived export.

Exact removed paths are in [REMOVED-FILES.md](REMOVED-FILES.md) and [data_hygiene.json](data_hygiene.json). The SHA-256 release map is [release_manifest.json](release_manifest.json), copied from `release-artifacts/MANIFEST.json`. The ignored local files are ready for the team to review for a GitHub Release; no upload occurred and the manifest does not clear redistribution rights.

**These files remain in Git history and on GitHub.** Making the repository private limits public access; removing historical copies requires a separately authorized history rewrite. This branch does neither a history rewrite nor a push. Untracking alone does not purge public history.

`restore_raw_data.py --check-all` inventories every file and explains authorized local restoration. Missing historical snapshots require checksum-matching originals, not current feeds. PhiUSIIL retains its pinned official download. Inventory recognizes exact newline-only variants; import verification remains byte-exact. Recovery and inherited model-data licence limitations are in [data licences](../../../docs/data-licences.md). `source-map-js` was changed only from the vulnerable lock entry to its patched entry; the dependency manifest was unchanged. The audit, clean install, build and lint passed.

## Sourced brand registry

All 10 requested brands are documented; 9 domain/host entries were added. InstaPay, Fawry and Digital Egypt already existed and were rechecked. Vodafone Cash uses the official service host while the pre-existing Vodafone parent retains ownership. Database seeding is idempotent and shares the same registry and verification dates. Official-domain and dot/hyphen-plus-action lookalike tests pass.

| Brand | Domains | Status |
|---|---|---|
| Paymob | `paymob.com`, `paymob.eg` | Added |
| InstaPay | `instapay.eg` | Existing `Instapay` entry rechecked |
| Vodafone Cash | `web.vodafone.com.eg`, `vodafone.com.eg` | Added service entry; existing parent retained |
| ValU | `valu.com.eg`, `valugroup.com` | Added |
| Fawry | `fawry.com` | Already exists; rechecked |
| Bosta | `bosta.co` | Added |
| Aramex Egypt | `aramex.com` | Added |
| Egypt Post | `egyptpost.org` | Added; root page timed out, official subdomain supplied evidence |
| Digital Egypt portal | `digital.gov.eg` | Existing `Egypt e-Government portal` entry rechecked; root page unavailable to browser |
| Egyptian Tax Authority | `eta.gov.eg` | Added |

Official links, access dates and evidence limits are in [brand-sources.md](../../../docs/brand-sources.md) and [brand_sources.json](brand_sources.json). Root pages unavailable to the browser use the cited official service/subdomain evidence, not an inferred domain. No source-needed domain was added.

## Sender display context

POST /analyze and the scan form accept optional company_name, short_code, mobile_number or unknown. A financial/telecom sender claim from a mobile-number display adds brand_claim_from_mobile_number, a supporting MEDIUM signal. It cannot independently produce HIGH or corroborate the text model into HIGH. Other decisive evidence and incomplete-check precedence remain. The curated claim vocabulary is a heuristic, not an exhaustive language detector; it excludes unrelated casual mentions in the unit fixtures.

Arabic and English advice explains normal company-name bank senders and spoofable sender names. The submitted category is transient, with no input column, echo, browser storage or logging added. The computed reason code follows the existing minimal outcome-metadata/retention policy. The API contract and privacy detail are in [api-v2.md](../../../docs/api-v2.md). All newly authored message fixtures are labelled synthetic test-only strings, not real/Egyptian data.

## Limitations and preservation

Genuine Egyptian SMS test count remains **0**. No sealed ETIS final test was run. PhreshPhish test remains evaluation-only, but its use for this explicitly requested deployment selection means it is exposed selection evidence, not a fresh final performance claim. Its benign source, webpage-language tags and limited Egyptian representation do not validate Egyptian users. Domain exclusions alter the fitting distribution; repeated URLs per domain limit row-wise FPR uncertainty. Host-only models cannot distinguish malicious and benign paths on a shared host. The runtime length limit differs from research scoring; long/invalid rows and abstentions are reported in JSON. Model recall remains incomplete, and the selected ETIS FPR is materially worse than the old artifact despite better external subdomain behaviour. The remaining Vodafone rule false alarms are unresolved.

Protected reports, targets, frozen splits, September models/tokenizer and retained local data bytes were verified in [integrity.json](integrity.json). No destination was opened/resolved and no messages or URL samples were sent to an external analysis service. Official-source browsing and dataset/package acquisition were limited to the authorized provenance/dependency work.

## Reproduction

Use the Python environment and versions recorded in the check/setup JSON. Restore authorized data inputs first; raw/processed corpora and research weights are intentionally absent from fresh clones. The packaged scanner and tests do not require those removed corpora.

```text
python -m pip install -r requirements-runtime.txt -r requirements-phreshphish.txt
python data/scripts/restore_raw_data.py --check-all
python data/scripts/rebuild_dataset.py --output evaluation/local-results/v3-data
python -c "import data.scripts.download_phreshphish as d; from pathlib import Path; d.REPORT=Path('evaluation/reports/2026-10-v4'); d.main()"
python evaluation/run_url_subdomains_v4.py
python evaluation/promote_url_v4.py
python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_after.json
python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_final.json
python evaluation/run_checks_v4.py final
python evaluation/prepare_release_artifacts.py
python evaluation/verify_hygiene_v4.py --clean-tree
python evaluation/report_v4.py
```

For a pre-change probe after promotion, load the hash-checked former artifact in `release-artifacts/prior-deployment/`; the training runner recovers it from the original Git commit when needed. Historical reports remain intact. No push is included in these commands.
