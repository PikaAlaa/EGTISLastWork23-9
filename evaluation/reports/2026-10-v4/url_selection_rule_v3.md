# URL selection rule v3

Written on 2026-10-17 **after seeing the v2 results**, before any new v3
computation. This corrects v2's overly broad deployment gate: gate the URL
MODEL's own alerts and its incremental scanner false positives, not the total
scanner false-positive rate. These cohorts are exposed development evidence.

Use every existing model/threshold pair in `url_v2_frozen_thresholds.json`.
Do not fit models, derive thresholds, add thresholds, or change that frozen file.

A candidate passes only if all of the following hold:

* Model PhreshPhish-test benign-subdomain FPR <= 1%.
* Model ETIS-validation FPR <= 0.5%.
* Model overall PhreshPhish-test FPR <= 0.5%.
* Extra scanner false positives above the non-model baseline <= 0.5 percentage
  points on ETIS validation AND <= 0.5 percentage points on PhreshPhish test.

Extra false positives are benign rows alerted MEDIUM/HIGH with ordinary model
support but not alerted by the otherwise identical scanner with no URL model.
Divide by ALL benign rows in that cohort; do not use the number of baseline LOW
rows as denominator. Use a matched non-model baseline for each registry/pattern
policy. Retain original cohort membership and invalid-input miss conventions.

Among passing candidates select highest integrated MEDIUM/HIGH recall on
PhreshPhish test. Exact ties prefer fewer model-added ETIS false positives, then
fewer model-added PhreshPhish false positives, then artifact path and threshold.
Deploy with ordinary support. Keep original v3 and v1 artifact/threshold
comparators and corroboration-only (the latter using the selected model).
Report recall, total FP/benign, non-model FP and model-added FP on both cohorts.

First select under the current pattern/registry baseline, then repeat the same
fixed candidate selection under any independently accepted pattern/official
registry changes to obtain the final deployment. Report both stages, without
changing thresholds. Non-model changes are governed separately below and in
`url_pattern_acceptance_rule_v3.md`.

Use isolated healthy empty blacklist databases, URL-field inputs without invented
message context, and offline string analysis. No destination visits or URL
submission to external services. Official brand provenance pages may be checked.
No sealed final test, push or merge. Commit on the existing branch and stop.
