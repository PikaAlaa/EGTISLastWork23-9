# Text transformer phase 1 audit — 23 October 2026

Branch: `feat/text-model-selection`, starting at `c67ed85`.
The [13 October rule](../evaluation/reports/2026-10-v3/review-2026-10-13/model_selection_rule.md)
is unchanged. No candidate was selected, trained locally or deployed. No network
requests were made during this preparation. No sealed test content was decoded,
exported, trained on or scored.

## Local data check

`data/processed/dataset.csv`, the frozen `text_split.json`, the JSON/Markdown
selection rule and `evaluation/local-results/v3-data/dataset.csv` are present.
The old `text_trainval.csv` and `text-trainval-only.csv` convenience exports are
absent. They are not required by the new notebook. The builder instead recovers
all 1,629 frozen development records from the local v3 CSV using a byte-level ID
allowlist before decoding records. All IDs, groups, labels, source metadata and
split assignments match. For 286 records, restoring CRLF to LF reproduces the
exact frozen content hash; every recovered text matches its frozen SHA-256.
The processed September dataset is checked for presence and never opened.

Frozen split file SHA-256:
`a404a48c0018143f5842018c602fc4d99499bacf9e1229ff5b05bfe21bee57f0`.
Frozen rule JSON SHA-256:
`0a4e57521b64567aa2ab4a26de999a0b41c47d891db4ef74b2e7dfac97cde0bb`.

## Notebook changes against the frozen rule

The previous notebook rejected hosted Colab and produced pooled validation
predictions only. It lacked LOSO fitting, eligible-validation-only thresholding,
everyday-probe scores and a complete return contract. Its old runtime-only status
record is preserved as historical evidence.

The notebook now calls the bundled, reviewable `transformer_colab.py` runner:

| Requirement | Prepared behavior |
|---|---|
| Models/seeds | `UBC-NLP/MARBERTv2`, `CAMeL-Lab/bert-base-arabic-camelbert-da`; 42, 43, 44 |
| Frozen membership | Exact existing IDs, hashes, groups and assignments; no resplitting |
| Dialectal source | Its 234 training rows remain training-only; 55 validation texts excluded |
| Synthetic material | Existing training rows retained with their original source identity; none added |
| LOSO fitting | Separate model per source per seed; exclude every held-source group from fitting and threshold validation |
| Thresholds | Highest threshold retaining at least 95% phishing recall on eligible validation; other-source validation for LOSO |
| Held predictions | All frozen development rows of each held source, including its original train and validation rows |
| Everyday probes | Exact existing 12 invented fixtures, content-hashed; full-model probabilities returned |
| Decision-v2 | Local import calls the existing `run_text_review.probe_results`, high = eligible-validation threshold, low = 0.2; counts HIGH and MEDIUM-or-HIGH |
| CPU timing | Separate CPU-loaded model after GPU scoring; 227 complete messages, three warmups, two Torch threads; raw samples, hardware, p50 and p95 retained |
| Return validation | Input/file hashes, exact training/validation/held membership and metadata, probe identities, thresholds and CPU timing checked before any output |
| Selection boundary | Imported evidence goes under ignored `evaluation/local-results`; no ranking, final choice or deployment |

| Fit | Training rows | Threshold-validation rows | Held-source rows |
|---|---:|---:|---:|
| Full | 1,347 | 227 | 0 |
| Exclude Kaggle fully | 501 | 48 | 1,025 |
| Exclude Salloum/Gaber | 1,134 | 179 | 261 |

The private ZIP contains the 1,574 necessary texts, text-free frozen development
manifest, unchanged rule, existing probes, runtime helpers, notebook, instructions
and SHA-256 manifest. No full dataset, raw source snapshot, secret, model weights
or test row is included. The [handoff instructions](transformer-colab.md) specify
upload, resumable free-GPU execution, downloads and local import.

## Verification and limits

- `python -m pytest -q -p no:cacheprovider --tb=short`: **416 passed**, one existing
  Starlette/httpx deprecation warning. Includes 26 transformer contract tests.
  Temporary-directory access required an approved run outside the sandbox.
- `python scripts/initialize.py`: exit 0, with `DATABASE_URL` pointing at an
  isolated ignored SQLite database under `evaluation/local-results`.
- `npm run build`: exit 0; existing bundle-size advisory.
- `npm run lint`: exit 0.
- Notebook code cells and Python runtime helpers pass AST syntax checks.
- The actual local upload ZIP passes its full manifest and frozen-row checks.
- Reviewed reports, frozen rules/splits, targets and deployed artifacts are unchanged.

These checks do not execute transformer training. Torch/Transformers/Accelerate
are absent locally, and no packages or weights were fetched. The notebook pins
Transformers 4.45.2 and Accelerate 0.34.2 and records actual library versions and
pretrained commit IDs when run. Free Colab availability and training completion
remain unverified; 18 fits may require multiple sessions. CPU timings describe
the recorded Colab host. Checksums detect stale/corrupted/mismatched files, not
proof that an external runtime honestly performed training. Translated source
data and invented probes cannot establish authentic Egyptian SMS performance.
