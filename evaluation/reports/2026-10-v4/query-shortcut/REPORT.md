# 22 October v4 evaluation update

Current policy remains **corroboration_only**. The unchanged v4 rule produced a numerical winner (`release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/phreshphish_full_url_lightgbm.joblib` with **host_path**, threshold **0.98706904485526037**), but its unchanged engineering suite blocks deployment. No fallback tier was invented to bypass that blocker. See [the complete v4 report](../REPORT.md), [decision](../url_v4_decision.json) and [candidate checks](../url_v4_engineering.json). The RapidFuzz CI import failure is fixed and verified in a fresh runtime-only venv.

| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |
|---|---:|---:|---:|---:|
| Historical v3 ordinary | 45,680/76,800 (59.479%) | 254/91,260 | 1,033/5,973 (17.294%) | 10/2,916 |
| Before this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| After this session: corroboration-only | 2,205/76,800 (2.871%) | 206/91,260 | 94/5,973 (1.574%) | 8/2,916 |
| Numerical v4 winner, ordinary projection; NOT DEPLOYED | 32,474/76,800 (42.284%) | 227/91,260 | 764/5,973 (12.791%) | 14/2,916 |

The candidate row is a measured, undeployed projection. Before/after deployment metrics are unchanged. The historical query diagnosis and containment evidence below remain valid; current checks are in the v4 report.

<!-- V4 QUERY HISTORY -->
# Query-string shortcut: local containment after 16fc7a5

The full-URL `combined_full_url_lightgbm` classifier at the unchanged threshold
**0.9903286846155258** overreacts to ordinary query strings. Current scanner policy
is **corroboration_only**. A model alert alone cannot create MEDIUM or turn a
text-model HIGH score into a HIGH verdict. This is containment: the raw classifier
is still biased and has not been retrained or repaired.

## Reproduction and diagnosis

[Offline probes](probes.json) use the real packaged artifact, the production brand
registry and an isolated, explicitly healthy, empty in-memory blacklist. No URL is
visited or resolved. Each of the eight supplied hosts is tested with eleven URL
shapes. The nine query variants cover order IDs, root/search queries, encoded
spaces, pagination/sorting, tracking parameters, fragments, multiple parameters
and login redirects. Both `/track/12345` and `/login` serve as query-free controls.

| URL shape | Raw model alerts | Ordinary scanner MEDIUM/HIGH | Current scanner MEDIUM/HIGH |
|---|---:|---:|---:|
| `/track/12345` | 0/8 | 0/8 | 0/8 |
| `/track?order=12345` | 8/8 | 4/8 | 0/8 |
| `/?utm_source=sms` | 8/8 | 4/8 | 0/8 |
| `/login` | 0/8 | 0/8 | 0/8 |
| `/login?next=/home` | 8/8 | 4/8 | 0/8 |
| Other six query variants | 48/48 | 24/48 | 0/48 |
| All variants | 72/88 | 36/88 | 0/88 |

The raw 8/8 result matches the review. In this checkout `noon.com`, `breadfast.com`,
`bosta.co` and `aramex.com` already have official-domain suppression; the other four
do not. Thus the production scanner's ordinary-policy result is 4/8, rather than
8/8. No registry additions or host exceptions were made for this mitigation.

For `/track?order=12345`, raw probabilities range from **0.992419 to 0.998129**.
Setting only the feature `query_len` to zero, while preserving all other extracted
features, lowers all eight probabilities below threshold (**0.274554–0.905374**).
This counterfactual supports a query-length shortcut in the classifier. It is a
diagnostic experiment only, not a valid replacement feature representation.
The probes establish failure on these exposed examples, not that every possible
query string is flagged or a population false-positive rate. No claim about the
training distribution is inferred from these probes.

## Query coverage and conditional false positives

The separate [aggregate distribution audit](distribution.json) measures existing
combined fitting/calibration pools and exposed evaluation cohorts, using a
nonempty parsed query (the same definition as `query_len`). No row-level data or
URLs are exported. The model, protocol and data fingerprints match deployment;
cached evaluation predictions and scanner components match row IDs exactly.

| PhreshPhish benign subset | Query URLs / all benign | Query prevalence | Raw model FP on query URLs |
|---|---:|---:|---:|
| Selected model fitting pool | 3/84,208 | 0.00356% | Not rescored |
| Selected model calibration pool | 3/21,178 | 0.01417% | 3/3 (100%) |
| Official exposed test | 52/91,260 | 0.05698% | 35/52 (67.308%) |

The same test model flags **13/91,208 query-free benign URLs (0.01425%)**.
Combining them hides the query failure behind **48/91,260 = 0.05260% aggregate
FPR**. All **35** query false positives also create ordinary-policy scanner
alerts above a non-model baseline of **0/52**; thus this is a scanner failure as
well as a diagnostic model failure. In contrast, **18,398/76,800 (23.956%)**
PhreshPhish phishing test URLs have queries. The frozen ETIS validation benign
cohort has **zero query URLs among 2,916 rows**, so its aggregate gate provides
no benign-query coverage.

These measurements substantiate severe query underrepresentation and a label
association in the evaluated data. They explain how the aggregate gate could
pass while ordinary query URLs produce MEDIUM via `url_model`. The historical
gate calculations remain numerically correct, but do not establish robustness to
ordinary benign query traffic. The small query denominators do not establish a
precise population FPR; the three calibration errors especially cannot support
query-specific threshold tuning. No subgroup gate or replacement threshold was
selected after inspecting these results.

## Runtime and release changes

The existing corroboration policy now applies by default to all hosts and URL
shapes. An above-threshold model needs brand evidence, an alerting pattern on the
same link, domain blacklist evidence, or an explicit secret request. Existing
official/shared-host suppression and decisive/incomplete precedence remain.
Raw probabilities and `url_model_raw_above_threshold` remain visible; eligible
support is reported separately as `url_model_above_threshold`.

The full URL, query evidence and exact blacklist identity remain intact. There is
no query removal, feature substitution, threshold retuning or host allowlist.
The packaged artifact SHA-256 remains
`4fb9b6afbb4b356e54b842490e9192628a74db22a6dc88bb60d6c1054ce335f8`.
Both deployment metadata copies identify the policy override. Original v3 gate
passes remain historical cohort facts, not evidence of query robustness.
The historical `promote` command rejects ordinary deployment while the review
block is present, before modifying artifacts. Its historical report generator
also rejects overwriting current reports with ordinary-policy deployment claims.

## Detection cost

These are the **previously measured exposed URL-only comparison rows** from
[url_v3_final_selection.json](../url_v3_final_selection.json), with the same
artifact, registry, pattern policy and healthy empty blacklist. They are not a
new sealed evaluation or measured live-feed recall.

| Cohort | Ordinary recall | Corroboration-only recall | Ordinary FP / benign | Corroboration-only FP / benign |
|---|---:|---:|---:|---:|
| PhreshPhish test | 45,680/76,800 (59.479%) | 2,205/76,800 (2.871%) | 254/91,260 | 206/91,260 |
| ETIS grouped validation | 1,033/5,973 (17.294%) | 94/5,973 (1.574%) | 10/2,916 | 8/2,916 |

The recall reductions are **56.608 and 15.721 percentage points**, respectively.
On URL-only inputs the permitted corroborators already alert, so this fallback
adds no URL-only detections beyond the non-model baseline. It is not an acceptable
claim of strong phishing detection. A replacement requires representative benign
full URLs and query/no-query subgroup checks on both labels, with training and
calibration separate from evaluation. These now-exposed reviewer probes are
regressions, not independent validation or a basis for threshold tuning.

## Verification

* **392 backend tests pass**, including 141 new query/policy regressions and all
  40 cases in `backend/tests/test_url_query_invariance.py`. That file uses the
  real packaged model without official/shared-host suppression masking support.
* All **88/88** URL-shape probes return LOW under the active policy and the
  matched no-model baseline.
* Real-artifact controls preserve exact blacklist HIGH (including a query URL),
  brand impersonation HIGH, the four structural warning families, explicit
  secret-request escalation, and INCOMPLETE on unavailable checks. A query-only
  model alert cannot escalate unrelated high-scoring text.
* [Retained reviewer replays](retained-followup.json): **23/23 detection,
  7/7 robustness, 15/15 follow-up**.
* [Retained legitimate-host probes](retained-host-probes.json): **17/17 LOW**, with
  zero raw model alerts and zero MEDIUM/HIGH outcomes.
* [Full production scanner verification](scanner-verification.json): **1,619 checks,
  zero mismatches** across sampled policy/cohort rows; packaged probabilities
  match the frozen predictions exactly. The verifier now evaluates the active
  deployment policy rather than forcing ordinary support.
* Isolated database initialization, frontend build and lint pass. The existing
  Starlette deprecation and frontend bundle-size warnings remain.

Latest backend/replay/host commands and actual output are in
[retained-checks.json](retained-checks.json); earlier initialize/frontend logs
are in [checks.json](checks.json). The first default
pytest run had 306 passes and 20 temp-folder permission errors; rerunning with a
fresh workspace temp directory passed all 328 tests, including two subsequently
added release-script guards. Adding the reviewer's exact SMS tracking and login
cases expanded the suite to 352 passing tests; the requested 40-case file then
brought the full passing suite to 392. PowerShell's `npm.ps1` execution restriction was
avoided by invoking the installed `npm.cmd` entry point.

```powershell
.venv/Scripts/python.exe evaluation/probe_query_shortcut.py
.venv/Scripts/python.exe evaluation/audit_query_distribution.py
.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider --basetemp .local/pytest-query-shortcut-fresh
.venv/Scripts/python.exe evaluation/run_followup.py --output evaluation/reports/2026-10-v4/query-shortcut/followup.json
.venv/Scripts/python.exe evaluation/verify_url_v3_deployment.py
```

Use a fresh `--basetemp` path for reruns. No live database/feed changes, model
fitting, threshold changes, sealed final test, push or merge. Genuine Egyptian SMS
final-test count remains zero. Changes are local and uncommitted for review.
