# URL selection rule v4: query and fragment coverage

Written on **2026-10-18**, after the review of `16fc7a5` and the existing
query/fragment audits, **before any new v4 candidate evaluation or selection**.
This is an exposed development protocol, not an independent final-test protocol.
The known reviewer failures and previously measured conditional FPR are disclosed
inputs to this rule; they are not new held-out results.

Pre-result amendment: incorporate the user's completed QUERY-INVARIANCE gate.
This supersedes the initial v4 draft, SHA-256
`b55b83d33763361ab5201abf27ed090aa9ee5cfeb444364a2997ea467ff043c8`.
No new v4 candidate rescoring or evaluation occurred between that draft and this
amendment. The completed gate below is frozen before its new results.

Further pre-result amendment: allow the user's host+path variants, using existing
full-URL weights and thresholds re-chosen on calibration data only. This
supersedes the query-invariance draft, SHA-256
`9e6dd9a13dfd054fc87470929f0f7516d47104bd79e4944f02b86d4f489fdaff`.
No v4 calibration, candidate rescoring or evaluation occurred before this
amendment. The original candidate family and every v3 gate remain in force.

Further pre-result amendment: incorporate the user's completed fallback order:
host_only under the v3 gates, then corroboration-only if that also fails. This
supersedes the host+path draft, SHA-256
`eeaa3c00976054a954b8e35feacd47ac432effd809e3fc98dd8a683246147a57`.
The primary selection criteria are the unchanged v3 gates plus QUERY-INVARIANCE.
The earlier draft's additional natural-subgroup FPR and 200-row coverage vetoes
were assistant-added assumptions, not user requirements; they are withdrawn
before any new v4 scores. Natural-subgroup rates and sparse coverage remain
mandatory reporting, not additional selection gates. No v4 calibration,
candidate rescoring or evaluation has occurred before this amendment.

Further pre-result amendment: require the complete existing backend suite,
23/7/15 replays and 17 legitimate-host probes to keep passing. This supersedes
the fallback-order draft, SHA-256
`b2574df67459644b2285144f57c29f73b8c4662071f6d57e28d7c11e58a6ef3b`.
Current-scanner regression checks are engineering verification, not a new v4
candidate comparison, calibration run or threshold-selection result.

## Frozen inputs and scope

Use all existing model/threshold pairs in `url_v2_frozen_thresholds.json`.
Its SHA-256 is
`cc85a74db40f420daf2414efdbfe255891e64302933d00caf13bcab13496e7ca`.
Preserve that file, source artifacts, original fitting/calibration assignments,
PhreshPhish official test membership and ETIS grouped-validation membership.

The pre-result coverage audit is
`query-shortcut/query-fragment-counts.json`, SHA-256
`b248342ee2357e36bfff43059a71d2708f5e17480a682c7edeedc5fa1370d06`.
It distinguishes PhreshPhish-only pools from the PhreshPhish rows in the selected
combined-model pools; do not combine ETIS-source rows with PhreshPhish counts.

The candidate family consists of the unchanged v2 model/threshold pairs plus
the explicitly defined host+path variants below. Do not fit model weights or
change a fitted vectorizer, classifier or feature schema. Do not derive or
adjust thresholds for the original candidates. Only the new host+path variants
may receive new thresholds, chosen on calibration data as specified below.
Other replacement-training, representation or additional-data experiments need
their own specification frozen before new results; do not add them silently.

## Host+path candidates and calibration-only thresholds

For each distinct existing full-URL model artifact in the v2 inventory, allow an
additional candidate with `input_mode=host_path`. Despite the name, retain the
original scheme, authority (including userinfo/port) and path characters. Remove
only query and fragment using the stripped-input operation defined below, then
score that string with the existing full-URL model's unchanged fitted schema.
Do not substitute host-only features or re-fit the model on stripped data.

Apply this input operation consistently to the candidate's calibration,
evaluation and probe inputs. Candidate identity includes source artifact SHA-256,
input mode, preprocessing definition/hash, original representation/schema and
the threshold. Existing candidates have `input_mode=original`. The original
full-URL model/threshold pairs remain comparators and candidates in their own
right; never overwrite their artifact or v2 threshold records.

Use each artifact's original v2 calibration pool and exclusions. Rescore that
pool with the host+path input operation and its existing labels. Re-choose
thresholds only from those calibration predictions using the existing
`evaluation.phreshphish_utils.threshold_at_fpr` implementation and the unchanged
v2 cap family: **1%, 0.5%, 0.1%, 0.05%, 0.01% and 0% calibration-negative FPR**.
Deduplicate identical thresholds within an artifact/input-mode pair while
retaining all corresponding cap labels. Preserve the helper's conservative
tie/abstention behavior; do not derive a threshold from test, ETIS validation,
reviewer probes, query-invariance deltas, or a desired recall value.

Before any new evaluation or probe predictions, save the expanded candidate and
threshold inventory as `url_v4_frozen_thresholds.json`, including the v4 rule
hash, source artifacts, input modes, schema, cap labels, calibration row-membership
fingerprints, transformed-calibration input fingerprint and threshold derivation.
Reference the unchanged v2 inventory/hash for original candidates. Freeze and
verify this expanded inventory's hash before evaluation; no retries, threshold
adjustments or additional candidate families after seeing evaluation results.
Calibration predictions used to derive these thresholds are calibration-only
work, not held-out evaluation. Record all inherited fitting exposure honestly:
the existing full-URL weights were not newly trained on host+path inputs.

Keep the production registry and `four_structural_only` pattern-alert policy
fixed. Model/policy comparisons must use identical non-model evidence. Do not add
reviewer hosts to the registry or an allowlist to make a candidate pass.

## Definitions and required measurements

A query or fragment is present when the corresponding `urllib.parse.urlsplit`
component is nonempty, using the same scheme fallback as the frozen feature
schema. A bare trailing `?` or `#` does not count. Record parsing failures
separately; never silently move them into an absent-component group.

Report counts by benign/phishing label for fitting, calibration and their union,
and for the complete PhreshPhish test split. Include total rows, query-present,
query-absent, fragment-present, fragment-absent, both present and parsing failures.
Keep these aggregate-only; export no corpus URLs, domains or row predictions.

For every model/threshold pair, report raw-model FP/benign and recall with their
integer numerators and denominators on the complete evaluation cohorts and on
each query-present, query-absent, fragment-present and fragment-absent subgroup.
Subgroups overlap; their counts must not be added as disjoint categories.
Also report distinct registered-domain counts, coverage and abstentions.

Evaluate URL-only scanner outcomes with an isolated healthy empty blacklist,
under ordinary support, corroboration-only support and the matched no-model
baseline. Report MEDIUM/HIGH recall, total scanner FP, non-model FP and
model-added FP separately, overall and for those component subgroups. Keep raw
model alerts separate from official/shared-host suppression and final verdicts.

## QUERY-INVARIANCE gate

For **every candidate/threshold pair in the expanded frozen inventory**, rescore
the same benign rows in three forms, then apply that candidate's declared input
mode and unchanged fitted representation, feature schema and frozen threshold:

1. **Original (O):** the existing URL, unchanged.
2. **Stripped (S):** remove the query and fragment. Remove the first `#` and
   everything after it, then the first `?` and everything after it. Preserve the
   remaining scheme, authority, userinfo, port and path characters exactly; do
   not decode, normalize, substitute a hostname, or alter the path.
3. **Neutral query (N):** append exactly `?utm_source=sms` to S. This replaces
   any original query rather than creating a second `?`, and leaves no fragment.

Apply these transformations only as evaluation counterfactuals. They do not
change production inference, training data, corpus labels or fitted models.
For host+path candidates, apply the same stripping preprocessor to O, S and N
before model scoring; do not bypass it on N to manufacture a failure. All three
therefore reach the model as S, and a deterministic host+path pipeline should be
invariant by construction. Verify that behavior rather than assuming it.
The candidate retains one calibration-frozen threshold across O, S and N; do
not choose a separate threshold for any query-invariance test variant.

Run and gate each of these benign cohorts **separately**:

* Each candidate's original calibration-negative pool used by the v2 frozen
  thresholds, also reused for its host+path variant's recalibration. Preserve
  recorded source-setting/domain exclusions and row membership; do not
  substitute another calibration pool.
* All 91,260 PhreshPhish-test benign rows.
* All 2,916 ETIS grouped-validation benign rows, as a separate existing cohort.
* The 88 exposed query/path probes: `HOSTS` crossed with `VARIANTS` in
  `evaluation/probe_query_shortcut.py`, whose pre-result source SHA-256 is
  `d5b385111e83b433f43ccf53ac9d877cf9aab168440530c9bc36378e602b4f86`.
* The 17 legitimate-host root probes in `evaluation/probe_legit_hosts.py`, whose
  pre-result source SHA-256 is
  `0542f04ff6c442f1cfa424b60f4be09321eb30f6f5f22a477aecdca101463a95`.

Do not pool calibration, test, validation or probes to dilute a failing delta.
Use **raw candidate-model alerts**, `probability >= frozen threshold`, after its
declared input mode but before registry,
shared-host, pattern, blacklist or corroboration suppression. Host-only models
still use their original host-only representation for all three inputs.

For a cohort of n original benign rows, let A(O), A(S), A(N) be model-alert
counts, and R(V) = A(V) / n. Preserve the same row IDs and denominator in every
variant. An empty cohort is not a passing result. Preserve original abstentions
and report them; any additional transformation-induced parsing/scoring failure
blocks the gate rather than becoming a non-alert or an excluded row.

The permitted increase is **at most 0.5 percentage points**, i.e. **0.005 in
rate units**, for every candidate and every cohort. Require all of:

* R(O) - R(S) <= 0.005: original queries/fragments must not produce excessive
  additional benign alerts relative to the stripped control.
* R(N) - R(S) <= 0.005: appending the neutral query must not produce excessive
  additional benign alerts relative to the stripped control.
* R(S) - R(O) <= 0.005 and R(N) - R(O) <= 0.005: neither requested rescore may
  increase the benign alert rate excessively relative to the original inputs.

Use exact counts for each comparison: for variant V and baseline B, test
`200 * (A(V) - A(B)) <= n`. This is an absolute percentage-point limit, not a
0.5% relative increase. A decrease passes that comparison. Do not round before
testing. On either probe cohort a single net additional alert exceeds the cap.

Save aggregate JSON for every candidate, with artifact/threshold identity, rule
hash, cohort fingerprint, n, variant alert/abstention counts, all signed deltas
in percentage points, individual comparisons and overall gate pass/fail.
Also report paired newly-alerting and no-longer-alerting counts so net-rate
cancellation is visible; these are diagnostics, not a replacement gate.
Keep row-level predictions local and export no corpus URLs/domains.

These transformed benign inputs test sensitivity to query/fragment presence.
They are synthetic paired diagnostics, not additional independently labelled
traffic, evidence that natural query/fragment coverage is adequate, or a new
phishing-recall test. Retain every v3 gate below.

## Eligibility gates

Retain all v3 numerical gates:

* Raw-model PhreshPhish-test benign-subdomain FPR <= 1%.
* Raw-model ETIS-validation FPR <= 0.5%.
* Raw-model overall PhreshPhish-test FPR <= 0.5%.
* Model-added scanner FP <= 0.5 percentage points on each complete benign
  evaluation cohort, relative to the identical no-model baseline.

For primary v4 eligibility, add QUERY-INVARIANCE to those unchanged v3 gates:

* Pass QUERY-INVARIANCE on every specified cohort; a failure cannot be offset
  by aggregate FPR, scanner suppression, higher recall or another cohort.

Report raw-model FPR, total scanner FP and model-added FP with their denominators
for the natural query-present/absent and fragment-present/absent subgroups. A
suppressed raw-model false positive still counts in raw-model reporting. A zero
denominator means **not estimable**, not zero FPR. Sparse coverage is a mandatory
limitation, not an additional numeric acceptance gate. Do not inflate original
cohort support with duplicate or synthetic variants.

Keep **all existing backend tests**, including the 40 cases in
`backend/tests/test_url_query_invariance.py`, passing. Keep all **23 detection,
7 robustness and 15 follow-up** replay expectations passing. All **17 legitimate
host probes** must avoid MEDIUM/HIGH with a healthy empty blacklist. Preserve
the 88 exposed query/path regressions as well. Do not delete, skip or weaken
existing tests or replay expectations to accommodate a selected candidate.
These are required engineering checks before completing deployment in **every
tier**, including host_only and corroboration-only fallback. A failure blocks
completion until fixed; report it explicitly. These checks are separate from
the model-FPR gates and do not substitute for any v3 gate.

The probe/replay inputs remain synthetic/exposed regressions, not independent
performance estimates. QUERY-INVARIANCE on the probes continues to use the exact
raw-model delta criterion above; a passing model gate does not excuse a scanner
regression, or vice versa.

Use the original cohort membership and abstention conventions: phishing
abstentions count as misses; benign abstentions do not alert. Report abstentions
explicitly so selective failure cannot be represented as robust detection.
Failure of a v3 or QUERY-INVARIANCE gate makes a candidate ineligible for primary
v4 selection; higher recall cannot compensate. The host_only fallback tier is
governed by the v3 gates alone, as explicitly specified below.

The known coverage audit has only 52 query-present benign test URLs and zero
fragment-present benign test URLs. These natural subgroups cannot establish
robust performance on ordinary query/fragment traffic by themselves. Report that
limitation alongside the paired invariance results; neither a zero denominator
nor synthetic transformations create independent benign-traffic validation.

## Selection, fallback and release boundary

Among candidates passing every v3 gate and QUERY-INVARIANCE, select highest integrated ordinary-support
PhreshPhish-test MEDIUM/HIGH recall. Exact ties prefer fewer model-added ETIS
false positives, then fewer model-added PhreshPhish false positives, then
lexicographic source artifact path and ascending threshold. Report the complete
candidate table, all gate outcomes and natural-subgroup coverage. If source
artifact and threshold also tie across input modes, use lexicographic input mode
as the final deterministic tie-breaker; preserve all earlier v3 tie-breakers.

Use the following deployment order without relaxing gates after seeing scores:

1. **Primary:** deploy the highest-integrated-recall candidate passing all v3
   gates and QUERY-INVARIANCE, with its declared original or host+path input mode
   and ordinary model support.
2. **Host-only fallback:** if no primary candidate passes, restrict the unchanged
   v2 inventory to genuinely `host_only` artifacts. Among those passing every
   v3 gate, deploy the one with highest integrated-scanner PhreshPhish-test
   MEDIUM/HIGH recall and ordinary support, using the same v3 tie-breakers. Reuse
   its existing frozen threshold. This tier is tested under **v3 gates alone**;
   report its invariance and natural-subgroup diagnostics without inventing new
   vetoes. Do not relabel a full-URL or host+path artifact as host_only.
3. **Corroboration-only fallback:** if no host_only candidate passes the v3
   gates either, keep the current corroboration-only policy and unchanged
   packaged artifact/threshold. Explicitly report both failed candidate tiers
   and the fallback's measured recall cost; a fallback does not certify the raw
   classifier or the non-model scanner as robust.

Preserve the ordinary deployed-at-16fc7a5 model as a historical comparator,
together with prior v3/v1 comparators and the matched no-model baseline.

Once evaluation is requested and run, record the selected tier and gate evidence
and deploy according to that order. Preserve the existing ordinary-deployment
block against historical promotion commands; only the recorded v4 decision may
replace the fallback. Writing this rule alone runs no evaluation and changes no
runtime behavior or deployed artifact.

Any later qualifying host+path deployment must package its declared preprocessor
and calibration-frozen threshold with the unchanged source model/schema and
verify calibration/evaluation/runtime probability parity. Stripping applies to
the URL-model input only: reputation/exact-blacklist identity, brand and pattern
analysis, displayed URL evidence and all other scanner checks still receive the
complete original URL. Do not erase query or fragment evidence globally.

## Provenance and restrictions

Before running v4 results, record this file's SHA-256 with the candidate-table,
artifact, data, protocol and cohort fingerprints in the evaluation output. Read
and verify the same rule bytes again before writing final results. Retain the
rule hash with each result so later edits cannot masquerade as preregistration.
If requirements change before evaluation, record the superseded hash and reason;
after evaluation, use a newly versioned protocol rather than rewriting this one.

Use inert URL strings only: no destination visits, DNS resolution, HTML access or
external analysis submissions. No sealed ETIS final test, invented real-SMS
claims, data upload, push or merge. Genuine Egyptian SMS final-test count remains
zero. Do not commit or deploy merely as a side effect of writing this rule.
