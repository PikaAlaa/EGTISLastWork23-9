> Historical rule. Superseded by [the 13 October source/probe rule](review-2026-10-13/model_selection_rule.md).

# Text-model selection rule — frozen before v3 comparison

Date: 2026-10-09. Evaluation split: the single frozen, near-duplicate-grouped training/validation split recorded in `text_split.json`; sealed `test` rows are excluded.

1. Compute validation macro-F1 for each local model at its validation threshold selected to achieve at least 95% phishing recall (highest qualifying score threshold). Report the threshold and the resulting legitimate false-positive rate. Also report recall at a validation threshold whose false-positive rate is at most 1%, expected calibration error, artifact size, and batch-size-1 CPU latency (p50/p95).
2. Let `F1_best` be the highest macro-F1 among models with p95 CPU latency no greater than 300 ms. Exclude models slower than 300 ms p95.
3. Among eligible models with macro-F1 at least `F1_best - 0.01`, select the one with the lowest legitimate false-positive rate at the threshold for at least 95% phishing recall.
4. If false-positive rates tie, prefer the simpler model: character TF-IDF + logistic regression, then word+character TF-IDF + logistic regression, calibrated linear SVM, LightGBM on TF-IDF, then BiLSTM.
5. Report a provisional local winner only. The final choice waits for the three-seed MARBERTv2 and CAMeLBERT-DA comparison. Do not copy any candidate into the deployed model or change the September model, data or tokenizer in this pass.

All thresholds and selection statistics come from validation only. No sealed test rows may be read for model choice.
