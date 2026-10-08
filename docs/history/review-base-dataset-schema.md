# ETIS Dataset Schema

Locked schema for `data/processed/dataset.csv`. All data-collection scripts should output rows matching this exactly.

| Column | Type | Description | Example |
|---|---|---|---|
| `id` | string | Unique ID, prefixed by source | `PT-000123`, `SYN-000045` |
| `text` | string | The URL, or the email/message body | `https://inst4pay-secure.com/login` |
| `content_type` | enum | `url` or `text` | `url` |
| `label` | enum | `phishing` or `legitimate` | `phishing` |
| `language` | enum | `ar`, `en`, or `mixed` | `ar` |
| `source` | string | Where the row came from | `phishtank`, `openphish`, `tranco`, `synthetic`, `manual` |
| `brand_impersonated` | string or empty | Brand being spoofed, if any | `Instapay`, `CIB`, `Vodafone`, (empty) |
| `date_collected` | date (YYYY-MM-DD) | When the row was pulled/created | `2026-07-11` |
| `split` | enum | Filled in later by the stratified splitter | `train`, `val`, `test` |

## ID prefix convention

- `PT-` PhishTank
- `OP-` OpenPhish
- `TR-` Tranco (legitimate)
- `SYN-` synthetic Arabic brand-impersonation samples
- `MAN-` manually collected/curated samples

## File locations

- `data/raw/` — untouched pulls from each source (e.g. `data/raw/phishtank_raw.csv`)
- `data/processed/dataset.csv` — the single unified file in this schema, used by everything downstream (rule engine testing, blacklist seeding, LSTM training)

## Notes

- `split` stays empty until the stratified 70/15/15 split step runs — don't hand-assign it earlier.
- One unified file (not separate URL/text files) keeps the LSTM pipeline and Chapter 3.4 statistics simpler.
