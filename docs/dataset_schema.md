# Dataset and feature contract — decision-v2

`data/processed/dataset.csv` is the preserved September review input, not the clean
evaluation dataset. Never rewrite it in place or cite its old split as final evidence.
It retains the nine historical columns: `id,text,content_type,label,language,source,
brand_impersonated,date_collected,split`. Raw source files remain under `data/raw/`.

Build current development inputs with:

```powershell
python data/scripts/rebuild_dataset.py --augment-synthetic
```

The ignored `data/processed/v2/dataset.csv` carries those fields plus `group_id` and
`sealed` provenance. `content_type` accepts `url`, `text`, `email`; labels admitted
to binary training are `phishing` and `legitimate`. Language tags are metadata, not
proof of dialect or English evaluation coverage. Existing translated email rows are
labelled `text`, so report source as well as content type and review genre labels.

## Required invariants

- Remove ambiguous GitHub spam-source rows and quarantine conflicting text groups.
- Normalize Arabic text and group character-TF-IDF near copies at cosine >=0.95
  before splitting. Whole connected groups stay together; synthetic groups are
  training-only. Fit model vocabulary on training data only.
- Canonicalize valid HTTP(S) URLs using the common parser. Quarantine conflicting
  labels on an identical canonical URL. Assign whole ICANN registered domains,
  including all subdomains and private-hosting tenants, to the same split.
- Use deterministic group-hash allocation with seed 42, nominally 70/15/15. Exact
  row proportions may differ because groups are indivisible; this is not a row-wise
  stratified split. Inspect label/source proportions before interpreting metrics.
- Private SMS imports require `text,label,consent,anonymized`, binary reviewed labels,
  and `yes` for both confirmations. Reserve up to 200 independent legitimate genuine
  SMS groups before ordinary training output. Private/sealed inputs are never committed.
- Validation selects thresholds and compares all three models. The final test stays
  gated until targets are approved and genuine independent samples are available.

## Portable identity and provenance

`manifest.json` and candidate reports use `etis-csv-content-v1`. `dataset_sha256`
identifies decoded CSV content with canonical column order and embedded LF newlines.
Row order, duplicate rows and cell values remain significant. `dataset_file_sha256`
retains the platform-specific file-byte hash. Source identity is recorded separately.
This does not promise identical model weights across platforms.

`date_collected` is not a verification timestamp. Retrospective PhishTank experiments
must use both submission and verification times from the raw feed. See
`evaluation/README.md` and `docs/validation-by-source.md` for the active evaluation
contract and limitations. Prior contracts are retained under `docs/history/`.
