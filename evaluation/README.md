# Evaluation protocol

`review-evidence/` is the supplied **starting-point** evidence, not a claim about v2.
It contains live phishing URLs as inert data. Do not open those URLs. The old runner
defaults to another machine and its saved baseline does not evaluate this revision.

## Development (repeatable, does not open final test sets)

1. `python data/scripts/rebuild_dataset.py --augment-synthetic`
2. `python ml/train_character_model.py`
3. `python ml/train_bilstm_candidate.py`
4. `python ml/train_lightgbm_candidate.py`
5. `python ml/select_model.py --apply-local`
6. `python evaluation/run_development.py`
7. `python evaluation/run_url_benchmark.py --stage development`
8. `python evaluation/run_followup.py` — replay the supplied follow-up inputs in an isolated fixture

The reviewer follow-up originals, provenance and portable replay are documented in
[FOLLOWUP.md](FOLLOWUP.md). The known NBE-notice false alarm remains explicitly
recorded as one failed probe and one expected-failure regression. An otherwise
successful development replay must not be described as all follow-up cases passing.

All three candidates (character, BiLSTM and LightGBM) must match the **current** corpus
content fingerprint before selection. Missing candidates, legacy fingerprints, missing
subgroup reports and changed model/tokenizer artifacts are rejected. Character/BiLSTM
are supported runtime engines; if LightGBM wins, deployment stops until its runtime
support is implemented and tested.

Read [the source-level validation report](../docs/validation-by-source.md) before citing
pooled F1. Reports include source, language, content type and source/type intersections,
class counts, confusion counts and Wilson intervals. The current 282-row validation
set includes 179 translated-source messages and only 55 dialect-source messages.
This is not representative evidence for everyday bank SMS, even when pooled F1 is high.
Source labels alone do not prove dialect coverage. Zero false alarms in a small group
does not establish the required real-SMS false-alarm rate.

The corpus fingerprint uses `etis-csv-content-v1`: decoded CSV cells and column names,
normalized embedded newlines and deterministic JSON serialization. LF/CRLF, CSV quoting
and column order do not change identity. Row order, duplicate rows and cell values do.
`dataset_sha256` now means this versioned content fingerprint; `dataset_file_sha256`
retains the exact file-byte hash for provenance. Older byte-only reports are historical
and must not be compared as if they used the new method. A matching input fingerprint
does not guarantee bit-identical training across software/hardware environments.

The corpus hash, seed, parameters and chosen thresholds are saved. Grouping happens
before splitting; synthetic groups are training-only; the ambiguous spam source is
excluded. Registered-domain grouping uses the ICANN Public Suffix List. Private hosting tenants
under the same registered parent stay together, including all weebly.com subdomains.
Model selection and thresholds use validation only. September artifacts remain unchanged.
Development probe scores are **not** SMS detection accuracy. Existing labels still need
human adjudication; a source/language label is not proof of dialect coverage.

## Before final testing

Have the supervisor approve `targets.json`, including the minimum new-domain recall
chosen from development results. Record `approved_by` and `approved_at` before testing.
The suggested targets are not automatically approved by implementing this code.

Collect and anonymize genuine everyday Egyptian SMS and genuine shared links, with
consent and reviewed labels. Never invent messages to satisfy a sample-size target.
Use `rebuild_dataset.py --augment-synthetic --private-sms data/private/sms.csv` (columns:
`text,label,consent,anonymized`, with the last two equal to `yes`). Entire near-copy
groups are reserved before the sealed set is written. Review conflicts separately.
Require at least 200 independent legitimate examples of each kind. Do not commit them.
Rebuilding after collecting SMS changes the dataset hash, so repeat training/selection
on the remaining train/validation groups **before** approval and final scoring.

Build the retrospective URL protocol:
`python evaluation/build_url_protocol.py --cutoff 2026-07-01`
Both submission and verification must precede the cutoff. This is a surviving online-valid
July snapshot, not a complete historical archive; OpenPhish has no required dates and
is excluded from the time experiment. Grouped-domain experiments use training-domain
blacklists; time experiments use the pre-cutoff frozen blacklist. Neither uses live feeds.

Final text/SMS: `python evaluation/run_final.py`.
Final URLs: `python evaluation/run_url_benchmark.py --stage final --protocol evaluation/local-results/url-protocol --shared-links data/private/shared-links.csv`.
Each final runner creates an exclusive reservation file before scoring. Do not delete
the reservation to tune against sealed results. An interrupted run requires a recorded
review and a new evaluation version. Reports include Wilson 95% intervals and denominators.
Report source, language and content type separately; sparse groups are insufficient evidence.

Known-URL lookup is a functional check, not generalization accuracy. New-path cohorts
are phishing-only; report recall and genuine-negative false alarms, and avoid claiming
their apparent precision represents real traffic. The development URL limit uses a seeded shuffled validation sample; use --limit 0
for the entire validation cohort. Final evaluation has no limit.

For external-tool comparison, obtain approved Safe Browsing/VirusTotal credentials and
record timestamped observations of post-cutoff URLs only. Missing observations are
unavailable, never negative. No messages or links are submitted to third parties by these
scripts. Public-tool comparisons, real-data collection, independent label review, supervisor
approval and the final thesis interpretation remain human/data-dependent work.
