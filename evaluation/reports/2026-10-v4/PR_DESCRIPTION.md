# Evaluate query-invariant URL candidates and fix runtime-only CI

The historical full-URL classifier flags 35/52 benign query URLs despite seeing only three in fitting. Execute the unchanged v4 rule with 202 original candidates plus 87 host+path thresholds chosen only on calibration data and frozen before evaluation. Preserve all inputs, weights, registry entries, pattern policy and historical promotion guards.

The numerical winner is `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/phreshphish_full_url_lightgbm.joblib` with **host_path**, threshold **0.98706904485526037**. **Deployment is blocked**: it passes v3 and QUERY-INVARIANCE but fails 29 assertions in the unchanged backend suite. All 289 candidates receive that suite, the 40-query tests, 23/7/15 replays, 17 hosts and 88 shape cases. Keep corroboration-only active; do not silently rerank the numerical winner or reinterpret the fallback order. Historical-policy assertions and original-input metadata tests require an explicit resolution before ordinary replacement deployment.

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Historical v3 ordinary | 45,680/76,800 (59.479%) | 254/91,260 | 1,033/5,973 (17.294%) | 10/2,916 |
| Before this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| After this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| Numerical v4 winner, ordinary projection; NOT DEPLOYED | 32,474/76,800 (42.284%) | 227/91,260 | 764/5,973 (12.791%) | 14/2,916 |

The candidate row is an exposed development projection, not deployed performance. [Complete evidence and limitations](REPORT.md), including the malformed coverage hash in the unchanged rule, sparse natural-query/fragment coverage, every candidate's gates, paired diagnostics and engineering failures.

Move RapidFuzz into the evaluation function that uses it. Fresh venv with only runtime requirements: 383 passed, 5 optional skips; RapidFuzz absent. Current deployment checks: 392 backend tests, 40 query tests, 23/7/15 replays, 17 host probes, 88 shape probes, 1,619 scanner matches, isolated initialization, frontend build and lint pass. Keep the production model-input preprocessor inactive pending deployment clearance.

No rule/test weakening, frozen input changes, new fitting, destination/HTML access, sealed final test, push or merge. Genuine Egyptian SMS final-test count remains zero.
