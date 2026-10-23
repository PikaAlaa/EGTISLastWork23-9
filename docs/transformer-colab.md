# ETIS text transformers: phase 1 Colab handoff

This is development evidence collection only. No selection, deployment, sealed
test evaluation, push or merge is performed. The frozen 13 October rule is copied
unchanged. Translated sources are not Egyptian SMS; the 12 existing invented
fixtures are exposed selection diagnostics. No messages are generated or translated.
Embedded URLs are inert strings and must never be fetched.

## Build locally

From the repository root, with the existing virtual environment:

```powershell
.venv/Scripts/python.exe -m evaluation.build_transformer_colab_bundle
```

The single upload archive is `colab-bundle/etis-text-input.zip`. This folder is
gitignored and private. `payload/manifest.json` hashes every input file, including
the notebook, rule, frozen development manifest, runtime code and probes.
`checksums.json` records archive and manifest hashes outside the ZIP.
Only 1,347 frozen training texts and 227 eligible validation texts are included.
The 55 training-only-source validation texts are excluded, with their existing
assignments preserved in the text-free frozen manifest. All test rows are absent.
The original processed dataset is checked for presence, but not opened; the local
v3 CSV supplies only allowlisted IDs. Non-allowlisted CSV records are skipped as
bytes without decoding message text. LF restoration is accepted only when the
result matches the pre-existing frozen content hash exactly.

This private upload is explicitly requested by the project owner. Source licence
limitations in `docs/data-licences.md` still apply; the bundle is not a public dataset.

## Upload and run on free Colab

1. Open Colab in your browser. Choose **File > Upload notebook**, then upload
   `colab-bundle/payload/transformer_compare.ipynb` (also available in `notebooks/`).
2. Choose **Runtime > Change runtime type > Python 3 > T4 GPU > Save**. The free
   GPU type and availability can vary. A GPU is required; do not fall back to CPU
   training. Keep the browser connected during each job.
3. Run the first two code cells to install libraries and upload the ZIP. Select
   **only** `colab-bundle/etis-text-input.zip` when the upload dialog appears.
   Do not upload the repository, full dataset, `.env`, raw data or model artifacts.
   The notebook prints and verifies the manifest SHA-256; compare it with the
   `manifest.json` value in local `colab-bundle/checksums.json`.
4. Run the setup cell and training cell. The default runs both model IDs with
   seeds 42, 43 and 44. Each seed trains a full model plus two LOSO models (18
   fine-tunes total), always for three epochs. Effective batch size is 16;
   gradient checkpointing and mixed precision limit GPU memory. Thresholds use
   eligible validation only; no held-source row or probe chooses a threshold.
5. CPU timing happens separately after GPU scoring, using a CPU-loaded full model,
   two Torch threads, three warmups, then all 227 eligible validation messages.
   Each timing includes normalization, tokenization and every message window.
   Colab CPU hardware is recorded; its timing is not a deployment-machine claim.
6. Run the final download cell after training (or after a completed seed if you
   need to stop). Save **`etis-text-results.zip`**. It contains six prediction JSON
   files and `results_manifest.json`; no model weights need downloading.

Free Colab quotas may require multiple sessions. To run one job, set `MODELS` to
`['marbertv2']` or `['camelbert_da']` and `SEEDS` to one or more of `[42, 43, 44]`
in the training cell. Download results after each session. In a fresh session,
upload the same input ZIP, run setup, then run the optional resume cell and upload
your latest `etis-text-results.zip` before training. Completed matching runs are
verified and skipped. The ZIP is refreshed after every completed seed; partial
folds within an interrupted seed must be rerun. Save each updated ZIP locally.
Continue until all six files are present. Free GPU availability/time is not guaranteed.
Only package installs and pretrained model downloads use the network; training
does not visit message URLs or send text to an analysis API. Do not add tracking
integrations, Drive mounts, URL-fetching cells or external evaluation services.

## Return the outputs to ETIS

Extract the final results ZIP into the gitignored folder:

```text
evaluation/local-results/text-transformers/returned/
  results_manifest.json
  marbertv2_seed42.json
  marbertv2_seed43.json
  marbertv2_seed44.json
  camelbert_da_seed42.json
  camelbert_da_seed43.json
  camelbert_da_seed44.json
```

Keep `colab-bundle/payload/` unchanged until import. From the repository root:

```powershell
.venv/Scripts/python.exe evaluation/merge_transformer_predictions.py
```

The importer checks every returned file hash, the original input manifest, current
frozen rule/split/probe hashes, exact training/validation/held row sets, content
hashes, labels, groups, sources, 95%-recall thresholds and CPU timings. Missing,
duplicate, stale, sealed or mismatching rows are rejected before writing output.
It replays probe scores locally through the same Decision-v2 implementation used
by `run_text_review.py`, at the candidate high threshold and low threshold 0.2.
The notebook returns probe scores; the importer supplies policy verdicts.

Validated evidence goes to
`evaluation/local-results/text-transformers/imported.json`. It retains per-seed
metrics, LOSO counts/provenance, probe HIGH and MEDIUM-or-HIGH counts, eligible
validation metrics and CPU latency. It does **not** select, deploy or rewrite any
reviewed report. Stop after this phase and review the evidence before selection.
