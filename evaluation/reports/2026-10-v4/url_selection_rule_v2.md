# URL deployment selection rule v2

Written on 2026-10-17 **after seeing v1 results**, including the selected model's
78/2,916 ETIS-validation benign false positives (2.675%). This is an exposed
development selection, not an independent final test. This file is written before
any new computation for v2.

## Frozen eligibility and selection

Candidates are all existing URL model artifacts crossed with thresholds chosen
**only on calibration data**, never on PhreshPhish test or ETIS validation.
For every model, choose thresholds at empirical calibration-negative FPR caps
of 1%, 0.5%, 0.1%, 0.05%, 0.01%, and 0% using the existing conservative
threshold_at_fpr implementation. Deduplicate identical model/threshold pairs.
Keep historical deployed thresholds as comparators only if they were selected
on validation; they are not eligible v2 thresholds. Do not refit models.

Inventory all existing URL artifacts in the release manifest, v4 candidate
directory and deployed/prior-deployed paths (text models are out of scope).
Deduplicate byte-identical artifacts. PhreshPhish-protocol artifacts use their
original source-setting calibration pool. Historical ETIS-trained artifacts use
the PhreshPhish calibration pool with every ETIS training registered domain
excluded, so calibration does not reuse their fitting rows. Record historical
fitting/evaluation exposure rather than claiming newly disjoint training.

A candidate must satisfy all three model hard limits:

* PhreshPhish-test benign-subdomain FPR <= 1%.
* ETIS grouped-validation FPR <= 0.5%.
* Overall PhreshPhish-test FPR <= 0.5%.

Use the existing frozen cohorts, labels, private PSL, domain exclusions and
abstention conventions. Among candidates satisfying all three, choose highest
overall PhreshPhish-test recall. Exact ties prefer lower ETIS-validation FPR,
then lower overall PhreshPhish-test FPR, then artifact path and threshold for a
deterministic result. Never derive or adjust a threshold using evaluation scores.

## Integrated policy evaluation and deployment

Evaluate every candidate in the integrated scanner, both with ordinary URL-model
support and with corroboration-only support. Corroboration-only means the URL
model never creates MEDIUM alone and contributes only when brand resemblance,
a URL pattern flag, a blacklist domain match, or a secret request also fires.
Retain all other scanner signals and precedence. Use an isolated healthy empty
blacklist, no destination/network access, and the same input construction for
all policies. Report the limitation that corpus rows do not supply live blacklist
or message-context evidence.

Report integrated MEDIUM-or-HIGH recall and FP/benign on ETIS validation and
PhreshPhish test for historical v3, v1 selected, best eligible v2, and
corroboration-only. An ordinary deployment must also meet the same three FPR
limits in the integrated scanner; report any additional scanner false positives
that prevent this. If no ordinary candidate satisfies rule v2, deploy
corroboration-only and report its measured recall cost. For fallback choose the
underlying candidate by highest PhreshPhish-test integrated recall among
corroboration policies satisfying the same limits; if none satisfies them,
report that explicitly and choose highest integrated recall, then lowest summed
cohort FPR, then artifact path and threshold. A fallback does not imply that
non-model scanner signals meet the hard limits.

List the v1 ETIS-validation benign model flags and probabilities without visiting
them. Official brand-source checks may visit only known official provenance
pages. No sealed final test, new SMS claim, destination visit, push or merge.
