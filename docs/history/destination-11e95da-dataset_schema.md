# Dataset and feature contract

`data/processed/dataset.csv` must contain exactly these columns, in this order:

| Column | Required | Allowed values / format |
|---|---:|---|
| `id` | yes | Unique stable string identifier |
| `text` | yes | UTF-8 URL, message, or email body |
| `content_type` | yes | `url`, `text`, `email` |
| `label` | yes | `phishing`, `legitimate` |
| `language` | yes | `ar`, `en`, `mixed` |
| `source` | yes | Lowercase source identifier |
| `brand_impersonated` | no | Brand label for applicable phishing rows |
| `date_collected` | yes | ISO date (`YYYY-MM-DD`) |
| `split` | yes | `train`, `val`, `test` |

## Invariants

1. IDs and text are non-empty; IDs are unique.
2. The same normalized text cannot occur in more than one split.
3. The same normalized text cannot carry conflicting labels.
4. Splits use the fixed seed `42` and are stratified on `(label, language, content_type)` after de-duplication.
5. Training scripts fit tokenizers/vectorizers on the training split only.
6. Validation chooses thresholds; the test split is used once for the final report.

Run `python data/scripts/validate_and_clean_dataset.py` to validate. Add `--write` to remove exact duplicates, apply documented conflict overrides, and rebuild the split.
