# V4 handoff: selected candidate deployed

Branch `fix/url-subdomains-and-hygiene`, continuing `fe51b3f`. Candidate **`ee0ba9f0077c1fd140aa`** is deployed with **ordinary** support, **`host_path`** input and threshold **`0.9870690448552604`**, exactly as selected. Source SHA-256 `40f229dfa5bf22542fce994eedaf66881fc4e388b0f1ad32fe405e51aee73985`; packaged SHA-256 `1b964f155ef290beeb2487f7f5804a8ab9587ee6864260664af0802964c10e52`.

The owner authorized rewriting **29 obsolete shortcut/artifact/policy tests**. They now enforce benign-query safety, raw query/fragment invariance, deployment-metadata integrity and ordinary-policy evidence handling. Old artifact behavior is historical evidence only. Historical v3 promotion/report guards prevent replacement of this v4 deployment. [Report](REPORT.md), [current completion](url_v4_deployment_completion.json), [metadata](deployment.json).

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Before: corroboration-only | 2,205/76,800 (2.9%) | 206/91,260 | 94/5,973 (1.6%) | 8/2,916 |
| After: selected v4 ordinary, deployed | 32,474/76,800 (42.3%) | 227/91,260 | 764/5,973 (12.8%) | 14/2,916 |

Cohort figures reuse the existing frozen v4 measurements. **No evaluation rerun, rule/threshold/selection change or model fitting.** The original [decision](url_v4_decision.json) retains its historical `blocked_engineering` status and 363/29 result; current status is in the completion record.

The deployed working tree passes **392/392 pytest tests**, **40/40 query-invariance tests**, **23/23 detection, 7/7 robustness and 15/15 follow-up replays**, **17/17 host probes** with zero raw alerts or MEDIUM/HIGH verdicts, and **88/88 query/path probes LOW** with zero raw model alerts. Isolated database initialization, frontend build and lint all exit 0. [Actual release outputs](url_v4_release_checks.json), [replays](url_v4_release_replays.json), [hosts](url_v4_release_host_probes.json), [query/path probes](url_v4_release_query_probes.json).

A newly created venv installed only `requirements-runtime.txt`: **383 passed, 5 optional PyArrow skips**, zero failures. RapidFuzz and PyArrow are absent; `pip check` passes. Module-level optional skips explain the collection/count difference. [Runtime-only output and package inventory](url_v4_runtime_only_checks.json).

The packaged classifier weights and vectorizer match the selected source exactly. Against existing frozen predictions, the real deployed scorer and scanner match **332 valid samples**, with **10 expected invalid-input abstentions**, zero mismatches and maximum probability difference 0.0. This checks only the selected deployment; it does not rerun v4 selection or cohort evaluation. [Deployment verification](url_v4_release_scanner_verification.json). Existing Starlette deprecation and frontend bundle-size warnings remain.

Keep all frozen inputs unchanged. No URL fetching, PhreshPhish HTML, sealed test, push or merge. Exposed development results are not independent final validation; genuine Egyptian SMS final-test count is 0. Stop after the local commit.

Reproduce release checks with `.venv/Scripts/python.exe evaluation/check_url_release_v4.py`; it uses an isolated initialization database. To repeat runtime-only pytest, create a fresh venv, install only `requirements-runtime.txt`, and run `python -m pytest -q -rs -p no:cacheprovider --basetemp .local/pytest-v4-runtime-new`. Do not run historical evaluation/selection/report generators. Packaging, if needed, uses `evaluation/deploy_selected_url_v4.py` followed by all release checks; it reads the preserved decision without evaluating candidates.
