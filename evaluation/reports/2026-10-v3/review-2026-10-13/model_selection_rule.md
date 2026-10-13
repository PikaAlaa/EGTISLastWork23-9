# Revised text selection rule — frozen before the 13 October rerun

This rule is informed by the previous v3 results; it is not a prospective independent preregistration. No new comparison has run at the time recorded in the JSON.

1. Preserve all frozen row IDs, content hashes, groups and split assignments. Correct language metadata through a separate overlay.
2. Treat the Kaggle dialectal source as training-only: use its existing training rows, exclude its existing validation rows from model-selection scores, and do not move them into training. Historical diagnostics remain labelled non-Egyptian/templated, not benchmark evidence.
3. Run leave-one-source-out on the translated Kaggle fully dataset and translated/parallel Salloum-Gaber email source. Train on other sources' training partitions, exclude all groups present in the held source, and tune the threshold for at least 95% phishing recall on other-source validation. Evaluate all development rows in the excluded source. Never score sealed tests.
4. Replay all 12 existing invented everyday fixtures for every candidate using the same Decision-v2 policy, with that candidate's eligible-validation 95%-recall high threshold and the existing 0.2 low threshold. Count MEDIUM or HIGH as a false alarm; also report HIGH separately.
5. Primary loss = (equal-source mean LOSO false-negative rate + equal-source mean LOSO false-positive rate + everyday MEDIUM-or-HIGH rate) / 3. Lower is better. Equal weights are an explicit project choice, not an estimate of deployment prevalence. Report the three components, counts, and source provenance beside each result.
6. Reject candidates with CPU p95 above 300 ms. For primary losses within 0.000001, use eligible frozen-validation macro-F1 only as a tie-breaker, then the original simplicity order. The final selection still waits for transformer results.

The translated/non-Egyptian material and invented probes cannot establish authentic Egyptian SMS performance. The 282-row pooled validation remains descriptive only; the eligible selection subset excludes the training-only dialectal source.
