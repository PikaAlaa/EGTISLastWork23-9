# Deploy the frozen host/path URL winner and correct historical shortcut tests

The selected candidate `ee0ba9f0077c1fd140aa` was blocked by 29 tests encoding the former query shortcut, artifact metadata and corroboration-only policy. **With explicit project-owner approval**, rewrite those expectations as benign-query safety, raw query/fragment invariance and deployment-metadata checks. Preserve independent evidence and exact blacklist identity coverage; keep historical shortcut observations as documentation.

Deploy `phreshphish_full_url_lightgbm.joblib` with **`host_path`**, **ordinary** policy and the exact selected threshold **`0.9870690448552604`**. The packaged weights/vectorizer match the frozen source. Protect this deployment from historical v3 promotion/report commands. Do not rerun v4 evaluation, rerank the selection, modify the rule/thresholds or refit anything.

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Before: corroboration-only | 2,205/76,800 (2.9%) | 206/91,260 | 94/5,973 (1.6%) | 8/2,916 |
| After: selected v4 ordinary, deployed | 32,474/76,800 (42.3%) | 227/91,260 | 764/5,973 (12.8%) | 14/2,916 |

These cohort figures reuse the frozen comparison. The original `blocked_engineering` decision and 363/29 result remain historical; [completion evidence](url_v4_deployment_completion.json) records the owner-approved resolution.

Validation: **392 pytest passes**; fresh venv with only `requirements-runtime.txt`: **383 passed, 5 optional PyArrow skips**, `pip check` clean. **40/40 query tests, 23/7/15 replays, 17 host probes, 88 query/path probes LOW**, 332 valid deployment/scanner sample matches plus 10 expected invalid-input abstentions, zero mismatches. Isolated initialize, frontend build and lint pass. [Actual outputs](url_v4_release_checks.json), [runtime-only output](url_v4_runtime_only_checks.json), [full report](REPORT.md).

No destination fetching, PhreshPhish HTML access, frozen-input changes or sealed test. Sparse natural benign-query/fragment coverage and repeated exposed selection remain limitations; genuine Egyptian SMS final-test count is 0. Existing deprecation/bundle warnings remain. Local commit only; no push or merge.
