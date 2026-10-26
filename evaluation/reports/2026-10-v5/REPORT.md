# ETIS Phase 2 text model selection — 26 October 2026

Selected **tfidf_lightgbm**, primary loss **0.156583**, new common-protocol CPU p95 **1.474980 ms**.

This is exposed development selection under the unchanged 13 October rule. It is not an independent final evaluation or a claim of Egyptian SMS accuracy. **Genuine Egyptian SMS test count: 0. No sealed final test ran.**

## Rule, import and retrospective amendment

Starting branch `feat/text-model-selection`, HEAD `b13501a`, clean working tree. The strict importer accepted all six returned runs, including hashes, row/group membership, source identity, validation-only thresholds and Decision-v2 probe replay. No model was fitted or threshold retuned during Phase 2.

Frozen rule: [13 October model_selection_rule.md](../2026-10-v3/review-2026-10-13/model_selection_rule.md). The [latency amendment](latency_amendment.md) was initially written after seeing Colab timings and before importing seed means; the owner-authorized all-seven common protocol was recorded before any new timing. An incomplete eager-BiLSTM attempt was subsequently preserved and excluded; the compiled-executor correction was disclosed before re-timing all seven from scratch. This timing amendment is retrospective, not prospective preregistration.

`loss = (mean_source(FN/phishing_n) + mean_source(FP/legitimate_n) + everyday_MEDIUM_or_HIGH/12) / 3`.

Each source has equal weight, regardless of size. All twelve existing invented probes use the existing Decision-v2 policy, candidate eligible-validation high threshold, low threshold 0.2 and the unchanged deployed URL model. Text-only HIGH still requires corroboration. Seed aggregation was declared before computation: arithmetic mean of the three seed losses; per-seed values and their min/max are retained. Seeds are not pooled and none is cherry-picked. Local candidates retain their single frozen seed-42 fit. Reject p95 >300 ms using only new timings; within loss tolerance 0.000001, use eligible-validation macro-F1 then frozen simplicity order.

## Complete comparison

All rates are fractions, not percentages. Transformer rows average three seeds; their probe counts below are listed in seed order 42/43/44. Lower loss is better.

| Candidate | Mean LOSO FNR | Mean LOSO FPR | Everyday M/H rate | M/H counts /12 | HIGH counts /12 | Primary loss | Min–max loss | Eligible val macro-F1 | New p95 ms | Gate |
| --- | ---: | ---: | ---: | --- | --- | ---: | --- | ---: | ---: | --- |
| char_tfidf_logistic | 0.098503 | 0.144619 | 0.666667 | 8 | 0 | 0.303263 | 0.303263–0.303263 | 0.981416 | 2.101840 | PASS |
| word_char_tfidf_logistic | 0.096040 | 0.074191 | 0.666667 | 8 | 0 | 0.278966 | 0.278966–0.278966 | 0.981416 | 3.230540 | PASS |
| char_tfidf_calibrated_svm | 0.087918 | 0.334672 | 0.666667 | 8 | 0 | 0.363085 | 0.363085–0.363085 | 0.981416 | 3.118070 | PASS |
| tfidf_lightgbm | 0.180893 | 0.122188 | 0.166667 | 2 | 0 | 0.156583 | 0.156583–0.156583 | 0.952008 | 1.474980 | PASS |
| bilstm | 0.131256 | 0.165628 | 0.416667 | 5 | 0 | 0.237850 | 0.237850–0.237850 | 0.963552 | 20.264760 | PASS |
| marbertv2 | 0.106218 | 0.432578 | 0.444444 | 6/6/4 | 0/0/0 | 0.327747 | 0.293769–0.352629 | 0.979406 | 2398.248580 | REJECT |
| camelbert_da | 0.092919 | 0.576340 | 0.611111 | 9/7/6 | 0/0/0 | 0.426790 | 0.398841–0.464867 | 0.983453 | 2470.099670 | REJECT |

The minimum eligible loss selects **tfidf_lightgbm**. Loss-tied candidates: `['tfidf_lightgbm']`; no tie-breaker changes the winner in this comparison. LightGBM also has the lowest loss before applying the latency gate. Its mean LOSO miss rate is higher than the transformers' (18.09% versus 10.62% and 9.29%); the project's equal-weight objective favors its lower source-held-out false-positive and everyday-alarm rates. This is an explicit tradeoff.

### Per-seed loss components

| Candidate | Seed | Source-mean FNR | Source-mean FPR | Everyday M/H /12 | HIGH /12 | Primary loss |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| char_tfidf_logistic | 42 | 0.098503 | 0.144619 | 8/12 | 0/12 | 0.303263 |
| word_char_tfidf_logistic | 42 | 0.096040 | 0.074191 | 8/12 | 0/12 | 0.278966 |
| char_tfidf_calibrated_svm | 42 | 0.087918 | 0.334672 | 8/12 | 0/12 | 0.363085 |
| tfidf_lightgbm | 42 | 0.180893 | 0.122188 | 2/12 | 0/12 | 0.156583 |
| bilstm | 42 | 0.131256 | 0.165628 | 5/12 | 0/12 | 0.237850 |
| marbertv2 | 42 | 0.074249 | 0.436281 | 6/12 | 0/12 | 0.336843 |
| marbertv2 | 43 | 0.116722 | 0.441166 | 6/12 | 0/12 | 0.352629 |
| marbertv2 | 44 | 0.127684 | 0.420288 | 4/12 | 0/12 | 0.293769 |
| camelbert_da | 42 | 0.096529 | 0.548072 | 9/12 | 0/12 | 0.464867 |
| camelbert_da | 43 | 0.117587 | 0.495602 | 7/12 | 0/12 | 0.398841 |
| camelbert_da | 44 | 0.064641 | 0.685345 | 6/12 | 0/12 | 0.416662 |

### Source counts at the frozen LOSO thresholds

K = `kaggle_arabic_phishing_fully_dataset` (1,025 rows: 203 phishing, 822 legitimate). S = `salloum_gaber_bilingual_corpus` (261 rows: 131 phishing, 130 legitimate). Counts are per fitted fold/seed, never summed across repeated seeds to imply independent data.

| Candidate | Seed | Source | TP | FN / phishing | FP / legitimate | TN | Fold high threshold |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| char_tfidf_logistic | 42 | K | 194 | 9/203 | 86/822 | 736 | 0.841005816894 |
| char_tfidf_logistic | 42 | S | 111 | 20/131 | 24/130 | 106 | 0.6418587866 |
| word_char_tfidf_logistic | 42 | K | 195 | 8/203 | 103/822 | 719 | 0.817292087611 |
| word_char_tfidf_logistic | 42 | S | 111 | 20/131 | 3/130 | 127 | 0.598345679027 |
| char_tfidf_calibrated_svm | 42 | K | 189 | 14/203 | 57/822 | 765 | 0.910810281919 |
| char_tfidf_calibrated_svm | 42 | S | 117 | 14/131 | 78/130 | 52 | 0.785410326194 |
| tfidf_lightgbm | 42 | K | 159 | 44/203 | 125/822 | 697 | 0.967760122048 |
| tfidf_lightgbm | 42 | S | 112 | 19/131 | 12/130 | 118 | 0.185947767648 |
| bilstm | 42 | K | 190 | 13/203 | 247/822 | 575 | 0.966566205025 |
| bilstm | 42 | S | 105 | 26/131 | 4/130 | 126 | 0.982866942883 |
| marbertv2 | 42 | K | 193 | 10/203 | 47/822 | 775 | 0.950272679329 |
| marbertv2 | 42 | S | 118 | 13/131 | 106/130 | 24 | 0.995336353779 |
| marbertv2 | 43 | K | 199 | 4/203 | 74/822 | 748 | 0.872890174389 |
| marbertv2 | 43 | S | 103 | 28/131 | 103/130 | 27 | 0.995426118374 |
| marbertv2 | 44 | K | 193 | 10/203 | 46/822 | 776 | 0.967225015163 |
| marbertv2 | 44 | S | 104 | 27/131 | 102/130 | 28 | 0.993830919266 |
| camelbert_da | 42 | K | 201 | 2/203 | 98/822 | 724 | 0.98228764534 |
| camelbert_da | 42 | S | 107 | 24/131 | 127/130 | 3 | 0.339991956949 |
| camelbert_da | 43 | K | 194 | 9/203 | 56/822 | 766 | 0.987017095089 |
| camelbert_da | 43 | S | 106 | 25/131 | 120/130 | 10 | 0.495605587959 |
| camelbert_da | 44 | K | 200 | 3/203 | 330/822 | 492 | 0.384117722511 |
| camelbert_da | 44 | S | 116 | 15/131 | 126/130 | 4 | 0.0192158464342 |

## Provenance and frozen membership

| Source | Provenance / use |
| --- | --- |
| kaggle_arabic_phishing_fully_dataset | translated fraud letters and translated UCI ham; not Egyptian SMS |
| salloum_gaber_bilingual_corpus | translated/parallel emails; not Egyptian SMS |
| kaggle_dialectal_arabic_sms | non-Egyptian; templated; collection/licence unverified; training only |
| everyday_probes | 12 existing invented development fixtures; not authentic SMS |

The full fit uses the same 1,347 frozen training rows and 227 eligible validation rows (53 phishing, 174 legitimate). The 55 dialectal-source validation rows remain excluded; its 234 training rows remain training-only. Held-source folds exclude every held-source group from fitting and threshold validation: K-excluded fit has 501 training / 48 threshold-validation rows; S-excluded fit has 1,134 / 179. No split, target, row identity, source label or frozen rule changed.

## CPU latency: new common protocol

CPU: **Intel(R) Core(TM) i9-14900HX**; 32 logical processors reported by the OS. **Two threads** for every candidate. Each runs sequentially in a fresh process; Torch intra/inter-op, TensorFlow intra/inter-op and BLAS/OpenMP pools use two; LightGBM prediction uses two; tokenizer parallelism is disabled. Raw samples and effective thread-pool settings remain in ignored `evaluation/local-results/text-transformers/`.

Every candidate sees the same ordered 227 eligible validation messages, one complete message per call, three warmups on the first message. The timer includes normalization, 150-word windows with stride 75, tokenization/vectorization, all-window inference and max probability. Transformer windows retain the Colab scorer's cap of eight per internal batch and 256-token truncation; BiLSTM uses the frozen 200-token padding/truncation and compiled `tf.function` inference, traced during its first warmup with a dynamic window-batch signature. Complete-message batch size is one throughout. Loading and warmups are outside timing. This is model-path latency, not end-to-end API latency.

Transformers use the exact public pretrained revisions below plus explicitly untrained two-class heads, without fitting. Architecture, tokenizer and windowing drive inference cost; the proxy does not measure the unavailable fine-tuned artifacts. PyTorch is CPU-only and stays outside the runtime `.venv`. Scheduling, power state and other laptop load were not experimentally controlled.

| Candidate | New p50 ms | New p95 ms | p95 ≤300 ms |
| --- | ---: | ---: | --- |
| char_tfidf_logistic | 0.504700 | 2.101840 | True |
| word_char_tfidf_logistic | 1.155700 | 3.230540 | True |
| char_tfidf_calibrated_svm | 1.523100 | 3.118070 | True |
| tfidf_lightgbm | 0.729200 | 1.474980 | True |
| bilstm | 17.654300 | 20.264760 | True |
| marbertv2 | 185.231700 | 2398.248580 | False |
| camelbert_da | 204.832900 | 2470.099670 | False |

### Historical timings — descriptive only, excluded from the new gate

Historical local timings used 282 validation messages and a different warmup/preprocessing path. These are retained from the reviewed report, not replaced or combined with the new measurements.

| Local candidate | Historical p50 ms | Historical p95 ms |
| --- | ---: | ---: |
| char_tfidf_logistic | 0.421200 | 1.515450 |
| word_char_tfidf_logistic | 0.916850 | 2.257025 |
| char_tfidf_calibrated_svm | 1.394200 | 2.594325 |
| tfidf_lightgbm | 0.639400 | 0.837230 |
| bilstm | 48.204250 | 59.952035 |

Colab recorded Intel Xeon CPU at 2.00 GHz, two Torch threads, 227 eligible messages, three warmups, full preprocessing. The owner described it as a two-core Colab CPU; the returned contract records CPU description and Torch threads, not a physical-core inventory.

The five local candidates were not timed on Colab; no such measurements are inferred.

| Transformer | Seed | Colab p50 ms | Colab p95 ms |
| --- | ---: | ---: | ---: |
| marbertv2 | 42 | 112.393121 | 801.451363 |
| marbertv2 | 43 | 112.004868 | 806.796656 |
| marbertv2 | 44 | 113.506767 | 791.263333 |
| camelbert_da | 42 | 111.394200 | 796.952487 |
| camelbert_da | 43 | 112.425273 | 802.376366 |
| camelbert_da | 44 | 114.343170 | 807.164609 |

### Public pretrained snapshots and versions

| Model | Exact pretrained commit |
| --- | --- |
| UBC-NLP/MARBERTv2 | `fe88db9db8ccdb0c4e1627495f405c44a5f89066` |
| CAMeL-Lab/bert-base-arabic-camelbert-da | `231698eab9ebf0ae7b518a64277b81b2fe829f2d` |

Snapshot file hashes are in [comparison.json](comparison.json). Only model/tokenizer files were downloaded; no project text or message URL was sent to Hugging Face. Package downloads used the authorized package indexes; inference was offline.

| Package | Isolated latency environment |
| --- | --- |
| torch | 2.11.0+cpu |
| transformers | 4.45.2 |
| safetensors | 0.8.0 |
| numpy | 2.1.3 |
| scipy | 1.18.1 |
| scikit-learn | 1.9.0 |
| joblib | 1.6.0 |
| lightgbm | 4.7.0 |
| tensorflow-cpu | 2.21.0 |
| keras | 3.15.1 |
| threadpoolctl | 3.7.0 |

Colab recorded Torch 2.11.0+cu130, Transformers 4.45.2, safetensors 0.8.0, NumPy 2.1.3 and Accelerate 0.34.2. Local CPU Torch keeps the same base version; Accelerate is unnecessary for this inference-only pass. The runtime `.venv` package inventory was checked unchanged.

## Deployment and everyday probes

Deployed the frozen **tfidf_lightgbm** pipeline at its existing eligible-validation high threshold `0.10124534067817578` and low threshold `0.2`. No weights were fitted or thresholds retuned. The legacy `deployed_char.joblib` path is retained for configuration compatibility; the artifact and runtime result identify the actual model. LightGBM was already a runtime dependency; no PyTorch was added.

Artifact SHA-256: `023808d71047b76b5b62e535ce512fddd8e3b1268af90a0a9c98e92b5fb13d83`.

Source artifact SHA-256: `bf26ca6de453a1fee6140fc9ae81fb610e7375a36d764fa25f2dca71cb47fb58`.

Metadata: [deployment.json](deployment.json) and [runtime deployment receipt](../../../ml/models/deployment_model.json).

The packaged pipeline fingerprint matches its frozen source pipeline. The managed backend was restarted to clear its previous model cache; local health is ready and the text model is available. The existing web process and feed worker were preserved.

Before: **0 HIGH, 8 MEDIUM, 4 LOW**. After: **0 HIGH, 2 MEDIUM, 10 LOW**. These twelve existing invented fixtures are exposed selection diagnostics.

| Existing probe index | Before | After |
| ---: | --- | --- |
| 1 | MEDIUM | LOW |
| 2 | MEDIUM | LOW |
| 3 | MEDIUM | MEDIUM |
| 4 | LOW | LOW |
| 5 | LOW | LOW |
| 6 | MEDIUM | LOW |
| 7 | MEDIUM | MEDIUM |
| 8 | MEDIUM | LOW |
| 9 | LOW | LOW |
| 10 | LOW | LOW |
| 11 | MEDIUM | LOW |
| 12 | MEDIUM | LOW |

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| pytest | 434 passed; one existing Starlette deprecation warning (exit 0) | [check-pytest.txt](check-pytest.txt) |
| initialize | isolated SQLite initialized (exit 0) | [check-initialize.txt](check-initialize.txt) |
| build | production build passed; existing bundle-size advisory (exit 0) | [check-build.txt](check-build.txt) |
| lint | passed (exit 0) | [check-lint.txt](check-lint.txt) |

Protected-file hash comparison: **474 files unchanged**. Frozen inputs/rules/splits/targets, September artifacts, reviewed reports and the URL deployment are preserved. Tests and initialization use isolated SQLite databases. No push, merge, history rewrite, data-URL fetch/resolution or sealed final test was performed.

## Reproduction

```powershell
.venv-latency/Scripts/python.exe evaluation/download_latency_models.py
.venv-latency/Scripts/python.exe evaluation/time_text_candidates.py
.venv/Scripts/python.exe evaluation/select_text_v5.py
```

The input bundle and returned predictions remain ignored/private; the download command fetches only the two public pretrained snapshots. The original deployment command is intentionally one-shot and refuses a changed baseline. Aggregate selection evidence is in [comparison.json](comparison.json); local raw timings, returned predictions, package freeze and rollback copies stay ignored.

The strict importer ran before deployment on the Phase 1 source. The later runtime change only makes the API model identifier read the packaged model name. Its file now differs from the input bundle's frozen replay-source hash: repeat strict import in a Phase 1 checkout at `b13501a`, preserving the bundle manifest, rather than weakening that guard. Decision-v2 verdict logic and all frozen inputs are unchanged.

## Limitations

- Translated fraud letters/UCI ham and translated/parallel emails dominate held-source evidence; they do not establish authentic Egyptian SMS performance.
- The dialectal source is non-Egyptian/templated with unverified collection/licence, and remains training-only. Existing synthetic training material retains its original identity.
- The twelve probes are invented and already exposed. Their use in selection prevents treating their false-alarm rate as an independent population estimate.
- Equal component and source weights are explicit project choices, not deployment prevalence. The rule was informed by earlier v3 results; the hardware amendment was made after Colab timing was visible. Three seeds describe training variability on the same data, not independent cohorts.
- Transformer prediction hashes/contracts detect corruption or stale/mismatched evidence; they cannot prove that an external runtime honestly performed training. Fine-tuned weights were not returned, and local transformer latency uses an architecture proxy.
- Latency reflects the declared inference implementations and library builds as well as hardware, tokenizer and windowing. The local CPU-only and Colab CUDA-enabled Torch builds share base version 2.11.0; their recorded CPU timings do not establish speed on other hardware or under other deployment optimizations.
- No genuine Egyptian SMS test messages are available (**count 0**); no sealed final test ran. English, real traffic generalization and final acceptance remain unestablished.
