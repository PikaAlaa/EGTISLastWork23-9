# URL deployment selection rule — saved before the v4 fits and predictions

This is a development selection exercise on already exposed external data, not an independent final test. The user explicitly authorizes promotion under this rule, superseding the v3 protocol's no-promotion policy only; all its data exclusions, representations, model settings and domain partitions stay fixed.

Compare the current deployed artifact at its existing threshold with fresh combined/host_only/lightgbm and combined/host_only/char_calibrated_svm fits under the frozen PhreshPhish protocol. Combined means ETIS phishing plus both PhreshPhish training classes; ETIS training benign is excluded as specified by that protocol.

Before evaluation, each fresh model gets one deployment threshold: the threshold attaining at most 0.1% empirical FPR on its eligible calibration negatives. This conservative operating point is fixed in advance. Also report the separately fixed 1% calibration operating point as diagnostic evidence, never as an alternative selected after viewing test results. Do not retune thresholds on either evaluation cohort or the probe list.

A deployment candidate passes only when its PhreshPhish-test benign-subdomain FPR is at most 1%. Define this subset with the pinned private PSL: at least one non-www label in the subdomain component (including a non-www label alongside www); retain each original test row and use benign rows only. Report missing/invalid hosts explicitly, and do not turn unparseable hosts into subdomains.

Among the passing candidates, pick the highest overall PhreshPhish-test recall at the predeclared deployment threshold. Exact ties prefer the current artifact, then LightGBM, then calibrated SVM. Report ETIS grouped-validation recall as a secondary figure. Report FP/benign, actual FPR and PPV at assumed 1% and 0.1% prevalence on both full evaluation cohorts; on benign-only subsets recall and PPV are undefined.

If none passes, retain the current model and require a second URL-side signal on the same URL (brand resemblance, URL pattern flag or blacklist domain match) before its score can contribute supporting evidence. A secret request alone does not satisfy this URL-side condition. In all cases model-only evidence must not make the specified legitimate regression hosts MEDIUM or HIGH; report any additional generic policy safeguard needed, without using probes to tune a model or threshold.

No sealed final test, generated Egyptian SMS, destination access or external analysis service is permitted. Genuine Egyptian SMS test count remains zero.
