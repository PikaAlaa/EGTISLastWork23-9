# PhreshPhish URL comparison — 13 October 2026

All 18 fits completed: three source settings, host-only and full-URL representations, and character TF-IDF logistic regression, calibrated linear SVM and engineered-feature LightGBM. These are research artifacts; no model was automatically promoted. The existing host-only application model is unchanged.

**Finding:** ETIS-only thresholds transfer poorly to the varied benign URLs in PhreshPhish. At the threshold calibrated for 1% false positives, the ETIS-only host LightGBM flags 81.245% of PhreshPhish benign rows; its full-URL counterpart flags 97.530%. PhreshPhish-only host LightGBM gives 48.169% recall and 0.686% false positives at its corresponding fixed threshold. These are retrained research models, not a replay of the deployed artifact. The evidence does not support a claim that the deployed scanner is validated on Egyptian traffic.

Adding licensed benign URLs with paths is now possible: PhreshPhish contains 257,396 such benign training rows and 83,180 test rows (non-root path or query). This supplies the missing research data without a GramBeddings attachment. It does not supply authentic Egyptian SMS.

## Source, acquisition and limits

- [Pinned PhreshPhish card](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md), version 1.0.1, dated 7 February 2026; downloaded 13 October 2026. Citation: Dalton et al. (2025), arXiv preprint, [10.48550/arxiv.2507.10854](https://doi.org/10.48550/arxiv.2507.10854). CC BY 4.0; the card additionally requests anti-phishing research use only.
- The card does not identify the source of benign URLs. Labels and language tags are supplied by the dataset and were not independently confirmed by visiting websites. No destination was opened.
- The card lists 91,260 benign and 76,876 phishing test rows, which exceed its stated total by 76. Measured files contain **91,260 benign + 76,800 phishing = 168,060**.
- The first web preview of the card included truncated HTML snippets before switching to repository metadata. Local acquisition thereafter used only the five allowed data columns plus structural Parquet metadata. No HTML data chunks were downloaded by the script, decoded or saved.
- Exactly `url`, `label`, `target`, `date`, `lang` were projected from 77 upstream shards. Dataset files and row-level predictions are excluded from Git and delivery archives. `data/phreshphish-lock.json` records upstream-declared whole-file hashes and independently measured selected-range/projection hashes; whole-file hashes were not locally verified because whole-file downloads would include excluded content.
- ETIS uses the existing Tranco files. Their list ID/date remain unrecorded. ETIS benign rows remain heavily biased toward homepages; source differences and feature effects must not be confused with proof of real-world phishing detection.

## Frozen evaluation design

The protocol was saved before training and prediction. Official PhreshPhish train/test membership is preserved: all 168,060 test rows remain evaluation-only. Within the official training pool, registered domains are grouped using the pinned private-PSL rules, then deterministically assigned 80/20 to fitting/calibration. Domains seen in either PhreshPhish test or the frozen ETIS validation cohort are excluded from all fitting/calibration pools using input metadata only. Thus this is a stricter filtered training protocol, not training on every official training row. Mixed-label training domains and exact same-label duplicate URLs are excluded with counts below.

“ETIS current data” means retraining from the eligible current ETIS training pool after these common exclusions; it does not mean the old artifact or its old threshold. “Combined” means ETIS phishing plus both PhreshPhish classes, excluding ETIS benign. Every model is evaluated on the same 168,060 PhreshPhish test rows and 8,889 ETIS grouped validation rows (5,973 phishing; 2,916 benign). ETIS sealed final tests were not evaluated.

| Setting | Input rows | Evaluation-domain overlap removed | Mixed-domain rows removed | Duplicates removed | Fit rows | Calibration rows |
|---|---:|---:|---:|---:|---:|---:|
| etis | 45,465 | 6,032 | 0 | 0 | 32,995 | 6,438 |
| phreshphish | 498,255 | 218,065 | 720 | 0 | 222,139 | 57,070 |
| combined | 530,184 | 220,967 | 925 | 4,795 | 242,644 | 60,592 |

There are also 261 unparseable-host rows excluded from each PhreshPhish-containing training pool. Official test retains all 122 unparseable-host rows as abstentions: phishing abstentions count as missed detections; benign abstentions do not alert. Coverage is therefore 167,938/168,060. Excluding overlapping/mixed domains changes the training distribution substantially; results are conditional on this protocol. Long URLs remain eligible offline (7 official training rows and 11 test rows exceed 2,048 characters), unlike the application’s length limit.

## Fixed calibration thresholds — primary transfer evidence

Each cap sets a threshold using only the setting’s internal calibration negatives. That threshold is then frozen for both evaluation cohorts. **The cap is not a guarantee of the evaluation false-positive rate.** PPV columns apply Bayes’ rule at assumed phishing prevalence of 1% and 0.1%: prior × recall / (prior × recall + (1 − prior) × FPR). They are scenario estimates, not measured Egyptian precision. A point estimate of 100% with zero observed false positives does not establish perfect precision; JSON includes marginal Wilson intervals and conservative bounds, not domain-cluster intervals.

### phreshphish_test

| Setting / representation / model | Calibration cap | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---:|---:|---:|---:|---:|---:|
| etis/host_only/char_logistic | 1pct | 60.904% | 37573/91260 | 41.171% | 1.472% | 0.148% |
| etis/host_only/char_logistic | 0_1pct | 37.582% | 5758/91260 | 6.309% | 5.675% | 0.593% |
| etis/host_only/char_calibrated_svm | 1pct | 61.171% | 36847/91260 | 40.376% | 1.507% | 0.151% |
| etis/host_only/char_calibrated_svm | 0_1pct | 39.931% | 7409/91260 | 8.119% | 4.733% | 0.490% |
| etis/host_only/lightgbm | 1pct | 78.503% | 74144/91260 | 81.245% | 0.967% | 0.097% |
| etis/host_only/lightgbm | 0_1pct | 74.333% | 73908/91260 | 80.986% | 0.919% | 0.092% |
| etis/full_url/char_logistic | 1pct | 88.289% | 78359/91260 | 85.863% | 1.028% | 0.103% |
| etis/full_url/char_logistic | 0_1pct | 82.423% | 70313/91260 | 77.047% | 1.069% | 0.107% |
| etis/full_url/char_calibrated_svm | 1pct | 88.660% | 77783/91260 | 85.232% | 1.040% | 0.104% |
| etis/full_url/char_calibrated_svm | 0_1pct | 83.180% | 68905/91260 | 75.504% | 1.101% | 0.110% |
| etis/full_url/lightgbm | 1pct | 92.794% | 89006/91260 | 97.530% | 0.952% | 0.095% |
| etis/full_url/lightgbm | 0_1pct | 90.211% | 88916/91260 | 97.432% | 0.927% | 0.093% |
| phreshphish/host_only/char_logistic | 1pct | 58.698% | 1963/91260 | 2.151% | 21.608% | 2.659% |
| phreshphish/host_only/char_logistic | 0_1pct | 35.673% | 145/91260 | 0.159% | 69.399% | 18.350% |
| phreshphish/host_only/char_calibrated_svm | 1pct | 59.513% | 1715/91260 | 1.879% | 24.236% | 3.073% |
| phreshphish/host_only/char_calibrated_svm | 0_1pct | 35.431% | 125/91260 | 0.137% | 72.321% | 20.568% |
| phreshphish/host_only/lightgbm | 1pct | 48.169% | 626/91260 | 0.686% | 41.497% | 6.568% |
| phreshphish/host_only/lightgbm | 0_1pct | 30.668% | 66/91260 | 0.072% | 81.073% | 29.799% |
| phreshphish/full_url/char_logistic | 1pct | 84.806% | 1954/91260 | 2.141% | 28.576% | 3.814% |
| phreshphish/full_url/char_logistic | 0_1pct | 54.940% | 89/91260 | 0.098% | 85.053% | 36.058% |
| phreshphish/full_url/char_calibrated_svm | 1pct | 85.227% | 2083/91260 | 2.282% | 27.387% | 3.603% |
| phreshphish/full_url/char_calibrated_svm | 0_1pct | 57.443% | 113/91260 | 0.124% | 82.413% | 31.712% |
| phreshphish/full_url/lightgbm | 1pct | 81.954% | 615/91260 | 0.674% | 55.125% | 10.852% |
| phreshphish/full_url/lightgbm | 0_1pct | 71.460% | 98/91260 | 0.107% | 87.050% | 39.980% |
| combined/host_only/char_logistic | 1pct | 60.694% | 1867/91260 | 2.046% | 23.058% | 2.884% |
| combined/host_only/char_logistic | 0_1pct | 40.354% | 175/91260 | 0.192% | 68.007% | 17.400% |
| combined/host_only/char_calibrated_svm | 1pct | 61.158% | 1654/91260 | 1.812% | 25.420% | 3.267% |
| combined/host_only/char_calibrated_svm | 0_1pct | 38.219% | 141/91260 | 0.155% | 71.417% | 19.847% |
| combined/host_only/lightgbm | 1pct | 48.758% | 645/91260 | 0.707% | 41.067% | 6.460% |
| combined/host_only/lightgbm | 0_1pct | 33.014% | 78/91260 | 0.085% | 79.599% | 27.884% |
| combined/full_url/char_logistic | 1pct | 86.182% | 2141/91260 | 2.346% | 27.064% | 3.547% |
| combined/full_url/char_logistic | 0_1pct | 60.293% | 97/91260 | 0.106% | 85.141% | 36.217% |
| combined/full_url/char_calibrated_svm | 1pct | 86.507% | 2263/91260 | 2.480% | 26.056% | 3.374% |
| combined/full_url/char_calibrated_svm | 0_1pct | 60.260% | 101/91260 | 0.111% | 84.615% | 35.277% |
| combined/full_url/lightgbm | 1pct | 81.900% | 630/91260 | 0.690% | 54.512% | 10.615% |
| combined/full_url/lightgbm | 0_1pct | 69.909% | 95/91260 | 0.104% | 87.152% | 40.200% |

### etis_grouped_validation

| Setting / representation / model | Calibration cap | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---:|---:|---:|---:|---:|---:|
| etis/host_only/char_logistic | 1pct | 68.056% | 11/2916 | 0.377% | 64.568% | 15.297% |
| etis/host_only/char_logistic | 0_1pct | 12.707% | 0/2916 | 0.000% | 100.000% | 100.000% |
| etis/host_only/char_calibrated_svm | 1pct | 70.969% | 7/2916 | 0.240% | 74.914% | 22.836% |
| etis/host_only/char_calibrated_svm | 0_1pct | 15.168% | 0/2916 | 0.000% | 100.000% | 100.000% |
| etis/host_only/lightgbm | 1pct | 88.180% | 24/2916 | 0.823% | 51.974% | 9.686% |
| etis/host_only/lightgbm | 0_1pct | 81.433% | 3/2916 | 0.103% | 88.883% | 44.206% |
| etis/full_url/char_logistic | 1pct | 93.069% | 28/2916 | 0.960% | 49.470% | 8.844% |
| etis/full_url/char_logistic | 0_1pct | 88.230% | 1/2916 | 0.034% | 96.295% | 72.031% |
| etis/full_url/char_calibrated_svm | 1pct | 93.554% | 20/2916 | 0.686% | 57.944% | 12.014% |
| etis/full_url/char_calibrated_svm | 0_1pct | 89.369% | 0/2916 | 0.000% | 100.000% | 100.000% |
| etis/full_url/lightgbm | 1pct | 96.568% | 27/2916 | 0.926% | 51.302% | 9.453% |
| etis/full_url/lightgbm | 0_1pct | 95.463% | 1/2916 | 0.034% | 96.566% | 73.590% |
| phreshphish/host_only/char_logistic | 1pct | 79.223% | 340/2916 | 11.660% | 6.422% | 0.676% |
| phreshphish/host_only/char_logistic | 0_1pct | 57.442% | 66/2916 | 2.263% | 20.404% | 2.477% |
| phreshphish/host_only/char_calibrated_svm | 1pct | 79.357% | 324/2916 | 11.111% | 6.729% | 0.710% |
| phreshphish/host_only/char_calibrated_svm | 0_1pct | 56.605% | 71/2916 | 2.435% | 19.017% | 2.274% |
| phreshphish/host_only/lightgbm | 1pct | 73.012% | 216/2916 | 7.407% | 9.055% | 0.977% |
| phreshphish/host_only/lightgbm | 0_1pct | 19.337% | 15/2916 | 0.514% | 27.521% | 3.626% |
| phreshphish/full_url/char_logistic | 1pct | 82.722% | 669/2916 | 22.942% | 3.514% | 0.360% |
| phreshphish/full_url/char_logistic | 0_1pct | 27.474% | 140/2916 | 4.801% | 5.464% | 0.570% |
| phreshphish/full_url/char_calibrated_svm | 1pct | 82.354% | 627/2916 | 21.502% | 3.725% | 0.382% |
| phreshphish/full_url/char_calibrated_svm | 0_1pct | 33.802% | 143/2916 | 4.904% | 6.509% | 0.685% |
| phreshphish/full_url/lightgbm | 1pct | 75.958% | 322/2916 | 11.043% | 6.497% | 0.684% |
| phreshphish/full_url/lightgbm | 0_1pct | 60.171% | 30/2916 | 1.029% | 37.137% | 5.531% |
| combined/host_only/char_logistic | 1pct | 81.651% | 333/2916 | 11.420% | 6.736% | 0.711% |
| combined/host_only/char_logistic | 0_1pct | 64.155% | 81/2916 | 2.778% | 18.916% | 2.260% |
| combined/host_only/char_calibrated_svm | 1pct | 81.517% | 353/2916 | 12.106% | 6.369% | 0.670% |
| combined/host_only/char_calibrated_svm | 0_1pct | 59.200% | 78/2916 | 2.675% | 18.271% | 2.167% |
| combined/host_only/lightgbm | 1pct | 74.217% | 228/2916 | 7.819% | 8.749% | 0.941% |
| combined/host_only/lightgbm | 0_1pct | 34.338% | 21/2916 | 0.720% | 32.506% | 4.555% |
| combined/full_url/char_logistic | 1pct | 83.225% | 671/2916 | 23.011% | 3.525% | 0.361% |
| combined/full_url/char_logistic | 0_1pct | 32.463% | 132/2916 | 4.527% | 6.754% | 0.713% |
| combined/full_url/char_calibrated_svm | 1pct | 84.263% | 680/2916 | 23.320% | 3.521% | 0.360% |
| combined/full_url/char_calibrated_svm | 0_1pct | 34.522% | 135/2916 | 4.630% | 7.004% | 0.741% |
| combined/full_url/lightgbm | 1pct | 78.051% | 317/2916 | 10.871% | 6.762% | 0.714% |
| combined/full_url/lightgbm | 0_1pct | 60.974% | 18/2916 | 0.617% | 49.944% | 8.998% |

## Recall at evaluation FPR caps — descriptive ROC evidence

These thresholds are calculated retrospectively from each evaluation cohort’s scores to describe recall at ≤1% and ≤0.1% empirical FPR. They are not deployment thresholds and were not used for fitting, hyperparameter choice or promotion. Ties can make actual FPR lower than the cap.

### phreshphish_test

| Setting / representation / model | FPR cap | Recall | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---:|---:|---:|---:|---:|
| etis/host_only/char_logistic | 1pct | 19.520% | 0.995% | 16.539% | 1.926% |
| etis/host_only/char_logistic | 0_1pct | 6.250% | 0.100% | 38.767% | 5.904% |
| etis/host_only/char_calibrated_svm | 1pct | 19.958% | 0.774% | 20.672% | 2.517% |
| etis/host_only/char_calibrated_svm | 0_1pct | 6.164% | 0.100% | 38.439% | 5.827% |
| etis/host_only/lightgbm | 1pct | 17.221% | 0.988% | 14.966% | 1.714% |
| etis/host_only/lightgbm | 0_1pct | 4.816% | 0.100% | 32.791% | 4.612% |
| etis/full_url/char_logistic | 1pct | 7.337% | 0.999% | 6.904% | 0.730% |
| etis/full_url/char_logistic | 0_1pct | 2.460% | 0.100% | 19.946% | 2.410% |
| etis/full_url/char_calibrated_svm | 1pct | 5.270% | 0.999% | 5.057% | 0.525% |
| etis/full_url/char_calibrated_svm | 0_1pct | 2.104% | 0.100% | 17.570% | 2.069% |
| etis/full_url/lightgbm | 1pct | 5.137% | 0.976% | 5.046% | 0.524% |
| etis/full_url/lightgbm | 0_1pct | 0.488% | 0.100% | 4.713% | 0.488% |
| phreshphish/host_only/char_logistic | 1pct | 54.413% | 0.971% | 36.148% | 5.312% |
| phreshphish/host_only/char_logistic | 0_1pct | 28.038% | 0.100% | 73.960% | 21.964% |
| phreshphish/host_only/char_calibrated_svm | 1pct | 58.720% | 0.985% | 37.582% | 5.631% |
| phreshphish/host_only/char_calibrated_svm | 0_1pct | 33.689% | 0.100% | 77.338% | 25.272% |
| phreshphish/host_only/lightgbm | 1pct | 51.427% | 0.999% | 34.202% | 4.899% |
| phreshphish/host_only/lightgbm | 0_1pct | 32.009% | 0.091% | 78.046% | 26.052% |
| phreshphish/full_url/char_logistic | 1pct | 80.280% | 0.999% | 44.795% | 7.443% |
| phreshphish/full_url/char_logistic | 0_1pct | 55.378% | 0.100% | 84.871% | 35.729% |
| phreshphish/full_url/char_calibrated_svm | 1pct | 77.605% | 0.999% | 43.959% | 7.213% |
| phreshphish/full_url/char_calibrated_svm | 0_1pct | 55.174% | 0.100% | 84.823% | 35.645% |
| phreshphish/full_url/lightgbm | 1pct | 83.210% | 0.999% | 45.683% | 7.694% |
| phreshphish/full_url/lightgbm | 0_1pct | 70.953% | 0.100% | 87.786% | 41.598% |
| combined/host_only/char_logistic | 1pct | 57.865% | 0.999% | 36.904% | 5.479% |
| combined/host_only/char_logistic | 0_1pct | 31.561% | 0.100% | 76.174% | 24.060% |
| combined/host_only/char_calibrated_svm | 1pct | 59.940% | 0.890% | 40.493% | 6.317% |
| combined/host_only/char_calibrated_svm | 0_1pct | 32.633% | 0.082% | 80.043% | 28.442% |
| combined/host_only/lightgbm | 1pct | 52.561% | 0.999% | 34.695% | 5.002% |
| combined/host_only/lightgbm | 0_1pct | 34.525% | 0.100% | 77.764% | 25.738% |
| combined/full_url/char_logistic | 1pct | 80.464% | 0.999% | 44.852% | 7.459% |
| combined/full_url/char_logistic | 0_1pct | 59.464% | 0.100% | 85.762% | 37.380% |
| combined/full_url/char_calibrated_svm | 1pct | 78.259% | 0.999% | 44.166% | 7.269% |
| combined/full_url/char_calibrated_svm | 0_1pct | 59.229% | 0.100% | 85.714% | 37.288% |
| combined/full_url/lightgbm | 1pct | 83.283% | 0.999% | 45.705% | 7.700% |
| combined/full_url/lightgbm | 0_1pct | 69.410% | 0.100% | 87.548% | 41.065% |

### etis_grouped_validation

| Setting / representation / model | FPR cap | Recall | Actual FPR | PPV at 1% | PPV at 0.1% |
|---|---:|---:|---:|---:|---:|
| etis/host_only/char_logistic | 1pct | 78.453% | 0.995% | 44.346% | 7.319% |
| etis/host_only/char_logistic | 0_1pct | 36.029% | 0.069% | 84.142% | 34.462% |
| etis/host_only/char_calibrated_svm | 1pct | 78.537% | 0.995% | 44.373% | 7.326% |
| etis/host_only/char_calibrated_svm | 0_1pct | 32.195% | 0.069% | 82.583% | 31.967% |
| etis/host_only/lightgbm | 1pct | 88.565% | 0.995% | 47.356% | 8.185% |
| etis/host_only/lightgbm | 0_1pct | 80.529% | 0.069% | 92.224% | 54.029% |
| etis/full_url/char_logistic | 1pct | 93.119% | 0.995% | 48.607% | 8.569% |
| etis/full_url/char_logistic | 0_1pct | 88.749% | 0.069% | 92.893% | 56.432% |
| etis/full_url/char_calibrated_svm | 1pct | 94.073% | 0.995% | 48.862% | 8.650% |
| etis/full_url/char_calibrated_svm | 0_1pct | 90.273% | 0.069% | 93.004% | 56.850% |
| etis/full_url/lightgbm | 1pct | 96.702% | 0.995% | 49.550% | 8.870% |
| etis/full_url/lightgbm | 0_1pct | 95.480% | 0.069% | 93.361% | 58.220% |
| phreshphish/host_only/char_logistic | 1pct | 32.463% | 0.995% | 24.796% | 3.164% |
| phreshphish/host_only/char_logistic | 0_1pct | 0.988% | 0.069% | 12.700% | 1.421% |
| phreshphish/host_only/char_calibrated_svm | 1pct | 31.207% | 0.995% | 24.068% | 3.045% |
| phreshphish/host_only/char_calibrated_svm | 0_1pct | 0.988% | 0.069% | 12.700% | 1.421% |
| phreshphish/host_only/lightgbm | 1pct | 36.581% | 0.995% | 27.090% | 3.551% |
| phreshphish/host_only/lightgbm | 0_1pct | 9.811% | 0.069% | 59.098% | 12.525% |
| phreshphish/full_url/char_logistic | 1pct | 10.514% | 0.995% | 9.648% | 1.047% |
| phreshphish/full_url/char_logistic | 0_1pct | 3.114% | 0.069% | 31.442% | 4.347% |
| phreshphish/full_url/char_calibrated_svm | 1pct | 9.643% | 0.995% | 8.921% | 0.961% |
| phreshphish/full_url/char_calibrated_svm | 0_1pct | 3.449% | 0.069% | 33.684% | 4.792% |
| phreshphish/full_url/lightgbm | 1pct | 60.054% | 0.960% | 38.715% | 5.892% |
| phreshphish/full_url/lightgbm | 0_1pct | 16.457% | 0.069% | 70.792% | 19.367% |
| combined/host_only/char_logistic | 1pct | 36.246% | 0.995% | 26.908% | 3.520% |
| combined/host_only/char_logistic | 0_1pct | 4.587% | 0.069% | 40.319% | 6.275% |
| combined/host_only/char_calibrated_svm | 1pct | 31.257% | 0.995% | 24.097% | 3.050% |
| combined/host_only/char_calibrated_svm | 0_1pct | 1.038% | 0.069% | 13.260% | 1.492% |
| combined/host_only/lightgbm | 1pct | 52.151% | 0.995% | 34.627% | 4.987% |
| combined/host_only/lightgbm | 0_1pct | 12.171% | 0.069% | 64.190% | 15.084% |
| combined/full_url/char_logistic | 1pct | 10.681% | 0.995% | 9.787% | 1.064% |
| combined/full_url/char_logistic | 0_1pct | 4.102% | 0.069% | 37.659% | 5.648% |
| combined/full_url/char_calibrated_svm | 1pct | 10.480% | 0.995% | 9.621% | 1.044% |
| combined/full_url/char_calibrated_svm | 0_1pct | 4.252% | 0.069% | 38.510% | 5.844% |
| combined/full_url/lightgbm | 1pct | 62.381% | 0.995% | 38.785% | 5.908% |
| combined/full_url/lightgbm | 0_1pct | 17.395% | 0.069% | 71.924% | 20.247% |

## Full URL versus host-only

Host-only remains the primary representation. The table gives full minus host results at separately calibrated thresholds. Full URL includes path, query, scheme and their contribution to total length/character statistics. This is an ablation comparison, not a causal percentage of a model’s score attributable to paths; changed representation also changes the learned model and threshold.

| Setting / model | Evaluation | Calibration cap | Recall change (points) | FPR change (points) |
|---|---|---:|---:|---:|
| etis/char_logistic | phreshphish_test | 1pct | +27.385 | +44.692 |
| etis/char_logistic | phreshphish_test | 0_1pct | +44.841 | +70.737 |
| etis/char_logistic | etis_grouped_validation | 1pct | +25.013 | +0.583 |
| etis/char_logistic | etis_grouped_validation | 0_1pct | +75.523 | +0.034 |
| etis/char_calibrated_svm | phreshphish_test | 1pct | +27.490 | +44.856 |
| etis/char_calibrated_svm | phreshphish_test | 0_1pct | +43.249 | +67.385 |
| etis/char_calibrated_svm | etis_grouped_validation | 1pct | +22.585 | +0.446 |
| etis/char_calibrated_svm | etis_grouped_validation | 0_1pct | +74.201 | +0.000 |
| etis/lightgbm | phreshphish_test | 1pct | +14.292 | +16.285 |
| etis/lightgbm | phreshphish_test | 0_1pct | +15.878 | +16.445 |
| etis/lightgbm | etis_grouped_validation | 1pct | +8.388 | +0.103 |
| etis/lightgbm | etis_grouped_validation | 0_1pct | +14.030 | -0.069 |
| phreshphish/char_logistic | phreshphish_test | 1pct | +26.108 | -0.010 |
| phreshphish/char_logistic | phreshphish_test | 0_1pct | +19.267 | -0.061 |
| phreshphish/char_logistic | etis_grouped_validation | 1pct | +3.499 | +11.283 |
| phreshphish/char_logistic | etis_grouped_validation | 0_1pct | -29.968 | +2.538 |
| phreshphish/char_calibrated_svm | phreshphish_test | 1pct | +25.714 | +0.403 |
| phreshphish/char_calibrated_svm | phreshphish_test | 0_1pct | +22.012 | -0.013 |
| phreshphish/char_calibrated_svm | etis_grouped_validation | 1pct | +2.997 | +10.391 |
| phreshphish/char_calibrated_svm | etis_grouped_validation | 0_1pct | -22.803 | +2.469 |
| phreshphish/lightgbm | phreshphish_test | 1pct | +33.785 | -0.012 |
| phreshphish/lightgbm | phreshphish_test | 0_1pct | +40.792 | +0.035 |
| phreshphish/lightgbm | etis_grouped_validation | 1pct | +2.947 | +3.635 |
| phreshphish/lightgbm | etis_grouped_validation | 0_1pct | +40.834 | +0.514 |
| combined/char_logistic | phreshphish_test | 1pct | +25.488 | +0.300 |
| combined/char_logistic | phreshphish_test | 0_1pct | +19.939 | -0.085 |
| combined/char_logistic | etis_grouped_validation | 1pct | +1.574 | +11.591 |
| combined/char_logistic | etis_grouped_validation | 0_1pct | -31.693 | +1.749 |
| combined/char_calibrated_svm | phreshphish_test | 1pct | +25.349 | +0.667 |
| combined/char_calibrated_svm | phreshphish_test | 0_1pct | +22.042 | -0.044 |
| combined/char_calibrated_svm | etis_grouped_validation | 1pct | +2.746 | +11.214 |
| combined/char_calibrated_svm | etis_grouped_validation | 0_1pct | -24.678 | +1.955 |
| combined/lightgbm | phreshphish_test | 1pct | +33.142 | -0.016 |
| combined/lightgbm | phreshphish_test | 0_1pct | +36.895 | +0.019 |
| combined/lightgbm | etis_grouped_validation | 1pct | +3.834 | +3.052 |
| combined/lightgbm | etis_grouped_validation | 0_1pct | +26.637 | -0.103 |

The earlier [A–C review](../review-2026-10-13/REPORT.md) preserves the legacy 17.18% recall replay and its path/scheme ablations. Those figures use a different artifact/protocol and must not be silently substituted for these retrained comparisons.

## Arabic and Egyptian registry target subsets

Official training has 164 Arabic-tagged rows (102 phishing, 62 benign); official test has **46 (32 phishing, 14 benign; 40 registered domains)**. Language tags describe webpages, not SMS dialect or the recipient’s location. Strict Egyptian-registry target matches are **0 training, 1 test**: `qnb_al_ahli`, a phishing row. Generic international brand families are separately counted as ambiguous in `data_audit.json`; they are not evidence of Egyptian targeting. The one matched row has no benign comparator: FPR, FPR-constrained ROC and prevalence-adjusted precision are undefined. These subset sizes cannot establish Egyptian performance.

| Setting / representation / model | Calibration cap | Arabic detected / 32 | Arabic FP / 14 | Egyptian target detected / 1 |
|---|---:|---:|---:|---:|
| etis/host_only/char_logistic | 1pct | 30/32 | 6/14 | 1/1 |
| etis/host_only/char_logistic | 0_1pct | 17/32 | 4/14 | 1/1 |
| etis/host_only/char_calibrated_svm | 1pct | 30/32 | 6/14 | 1/1 |
| etis/host_only/char_calibrated_svm | 0_1pct | 23/32 | 2/14 | 1/1 |
| etis/host_only/lightgbm | 1pct | 31/32 | 12/14 | 1/1 |
| etis/host_only/lightgbm | 0_1pct | 30/32 | 12/14 | 1/1 |
| etis/full_url/char_logistic | 1pct | 31/32 | 13/14 | 1/1 |
| etis/full_url/char_logistic | 0_1pct | 31/32 | 13/14 | 1/1 |
| etis/full_url/char_calibrated_svm | 1pct | 31/32 | 13/14 | 1/1 |
| etis/full_url/char_calibrated_svm | 0_1pct | 31/32 | 12/14 | 1/1 |
| etis/full_url/lightgbm | 1pct | 32/32 | 14/14 | 1/1 |
| etis/full_url/lightgbm | 0_1pct | 32/32 | 14/14 | 1/1 |
| phreshphish/host_only/char_logistic | 1pct | 31/32 | 1/14 | 1/1 |
| phreshphish/host_only/char_logistic | 0_1pct | 17/32 | 0/14 | 1/1 |
| phreshphish/host_only/char_calibrated_svm | 1pct | 31/32 | 1/14 | 1/1 |
| phreshphish/host_only/char_calibrated_svm | 0_1pct | 20/32 | 0/14 | 1/1 |
| phreshphish/host_only/lightgbm | 1pct | 6/32 | 1/14 | 1/1 |
| phreshphish/host_only/lightgbm | 0_1pct | 4/32 | 0/14 | 1/1 |
| phreshphish/full_url/char_logistic | 1pct | 32/32 | 1/14 | 1/1 |
| phreshphish/full_url/char_logistic | 0_1pct | 27/32 | 0/14 | 1/1 |
| phreshphish/full_url/char_calibrated_svm | 1pct | 32/32 | 2/14 | 1/1 |
| phreshphish/full_url/char_calibrated_svm | 0_1pct | 27/32 | 0/14 | 1/1 |
| phreshphish/full_url/lightgbm | 1pct | 32/32 | 2/14 | 1/1 |
| phreshphish/full_url/lightgbm | 0_1pct | 32/32 | 0/14 | 1/1 |
| combined/host_only/char_logistic | 1pct | 31/32 | 1/14 | 1/1 |
| combined/host_only/char_logistic | 0_1pct | 21/32 | 0/14 | 1/1 |
| combined/host_only/char_calibrated_svm | 1pct | 31/32 | 1/14 | 1/1 |
| combined/host_only/char_calibrated_svm | 0_1pct | 19/32 | 0/14 | 1/1 |
| combined/host_only/lightgbm | 1pct | 8/32 | 1/14 | 1/1 |
| combined/host_only/lightgbm | 0_1pct | 4/32 | 0/14 | 1/1 |
| combined/full_url/char_logistic | 1pct | 32/32 | 2/14 | 1/1 |
| combined/full_url/char_logistic | 0_1pct | 28/32 | 0/14 | 1/1 |
| combined/full_url/char_calibrated_svm | 1pct | 32/32 | 2/14 | 1/1 |
| combined/full_url/char_calibrated_svm | 0_1pct | 31/32 | 0/14 | 1/1 |
| combined/full_url/lightgbm | 1pct | 32/32 | 2/14 | 1/1 |
| combined/full_url/lightgbm | 0_1pct | 26/32 | 0/14 | 1/1 |

All subgroup recalls, actual FPRs, prior-adjusted precision and uncertainty intervals are in `model_comparison.json`; Arabic ROC points are also supplied there, but 14 benign examples cannot resolve a 0.1% or 1% false-positive rate reliably.

## Reproducibility and verification

Dataset projection-set SHA-256: `bad8f9344ee194529aa4627eb2040c64314ce265849d4f71ca3a2b81ce8e4a3f`. Frozen protocol SHA-256: `8c041773f302e59c4a7676b1c548db4362f984ff7c7903b18f3deb829bc3c7af`. Model SHA-256 values, exact thresholds, CPU batch-one latency, fit time, library versions and cohort counts are recorded in `model_comparison.json`. All 18 fits completed without convergence warnings.

Run the commands in [docs/phreshphish.md](../../../../docs/phreshphish.md). `verification.json` records actual local test/build outcomes; `integrity.json` checks preserved artifacts, split membership and model hashes. These are local Windows checks, not a claim that a hosted GitHub CI job ran. Project code licence remains the team’s decision; existing unresolved raw-data redistribution rights remain listed in `docs/data-licences.md`.

Local verification passed: **166 tests**, database initialization, frontend clean install, build and lint. The install output still reports one existing high-severity dependency vulnerability; no dependency upgrade is included in this research change.
