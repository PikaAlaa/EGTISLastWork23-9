# V4 handoff: numerical winner found; deployment blocked

Branch `fix/url-subdomains-and-hygiene`. Evaluation complete; **deployment completion is blocked** by the unchanged suite. Current policy stays **corroboration_only**, artifact `4fb9b6afbb4b356e54b842490e9192628a74db22a6dc88bb60d6c1054ce335f8`, threshold `0.99032868461552581`. Historical ordinary-promotion commands remain blocked. No push or merge.

Numerical selection: `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/phreshphish_full_url_lightgbm.joblib` with **host_path**, threshold **0.98706904485526037**. There are 122 primary numerical passers and 56 genuine host-only v3 passers. The winner's suite has 29 failures; every one of the 289 frozen candidates received the complete unchanged engineering bundle. The rule does not permit reranking or invoking fallback solely to evade this engineering blocker. See [REPORT.md](REPORT.md), [decision](url_v4_decision.json), [comparison](url_v4_comparison.json), [engineering outputs](url_v4_engineering.json) and [runtime parity](url_v4_runtime_parity.json).

The rule and original frozen inputs are unchanged. Inventory freeze SHA-256: `5882b7210d07ea9c82ab98a7764bacec813efc5902363da98ba02fc22884df44`; 202 original pairs plus 87 host+path pairs, chosen only on original calibration pools before any v4 evaluation. The rule's 63-character coverage-hash typo is documented without amending it.

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Historical v3 ordinary | 45,680/76,800 (59.479%) | 254/91,260 | 1,033/5,973 (17.294%) | 10/2,916 |
| Before this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| After this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| Numerical v4 winner, ordinary projection; NOT DEPLOYED | 32,474/76,800 (42.284%) | 227/91,260 | 764/5,973 (12.791%) | 14/2,916 |

The query finding remains 35/52 benign PhreshPhish query URLs flagged by the historical full-URL model, with only three benign query URLs in fitting. Natural benign fragments and ETIS benign queries have no coverage. The v4 row is an undeployed projection. Corpus predictions stay local; no HTML, fetching, sealed test or invented real-SMS claims. Genuine Egyptian SMS count 0.

CI fixed by importing RapidFuzz only inside its accelerator. Fresh runtime-only venv: 383 passed, 5 skipped, RapidFuzz absent. Retained deployment: 392 tests; 40 query tests; 23/7/15 replays; 17 hosts; 88 shape probes; 1,619 scanner matches, zero mismatches; isolated initialize, frontend build and lint pass. Actual outputs are linked in the report.

To resolve the release blocker, an explicit instruction is needed on reconciling historical-policy/model-specific tests with an ordinary replacement. No existing assertions were changed. Numerical thresholds and gates must remain frozen. Stop after the local commit; do not push or merge.
