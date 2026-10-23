# PhreshPhish URL-only reproduction

For the current host-model change use `python evaluation/run_url_subdomains_v4.py`
after restoring the authorized ETIS development inputs and downloading the permitted
projection. Its aggregates go to `evaluation/reports/2026-10-v4/`; candidates and
row scores stay local. The original protocol below remains frozen; the v4 selection
rule explicitly records the user's promotion authorization. Historical candidate
binaries are now in ignored `release-artifacts/` with a SHA-256 manifest, rather
than in the Git tree. The original comparison commands below describe the historical
run and require restoring its candidate files to their manifest paths if reusing them.

Source: [PhreshPhish dataset card at the pinned revision](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md). Cite Dalton et al. (2025), *PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark*, arXiv preprint, [DOI 10.48550/arxiv.2507.10854](https://doi.org/10.48550/arxiv.2507.10854). The current card identifies version 1.0.1, dated 7 February 2026; commit `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a` pins the actual files.

The card states CC BY 4.0 and requests anti-phishing research use only. It does not state where benign URLs were sourced. Its test class counts sum to 168,136 although the stated total is 168,060, a difference of 76. Use locally measured label counts in the report.

## Download without HTML

```text
python -m pip install -r requirements-phreshphish.txt
python data/scripts/download_phreshphish.py
```

The downloader only fetches exact byte ranges for `url`, `label`, `target`, `date`, and `lang`, plus Parquet structural metadata. It rejects responses that ignore HTTP Range before reading their bodies. It does not fetch the HTML column's data chunks, decode HTML, open destination URLs, or download complete upstream Parquet files. The local projections contain exactly those five columns.

`data/phreshphish-lock.json` records source revision, version, acquisition date, upstream-declared whole-file SHA-256 values, verified selected-range hashes and measured local projection hashes. Whole upstream hashes cannot be independently verified without downloading excluded HTML, so that distinction is explicit. Pin PyArrow to the recorded version to reproduce projection serialization hashes. A changed checksum is an error, never an automatic replacement.

Dataset projections belong only in `data/external/phreshphish/`, which is Git-ignored and excluded from delivery archives. Processed rows and per-row scores belong only in ignored `evaluation/local-results/phreshphish/`. The committed material comprises code, metadata/hashes, aggregate reports and trained model artifacts, not dataset copies. The downloaded data was not added to ETIS's original dataset or sealed tests.

Hash scopes differ intentionally: the frozen protocol's `data_sha256` is the SHA-256 of the entire download-lock file. Result reports use the projection-set identity from that lock. `integrity.json` verifies and explains both, without rewriting the frozen protocol.

## Reproduce the comparison

```text
python evaluation/run_phreshphish.py
python evaluation/report_phreshphish.py
python evaluation/verify_phreshphish.py --run-checks
```

The frozen protocol under `evaluation/reports/2026-10-v3/phreshphish/protocol.json` defines all three source settings, both host-only and full-URL representations, and all three Task 2 models. Host-only remains primary. The official PhreshPhish test membership is preserved. Domains present in either evaluation cohort are excluded from training/calibration; remaining training domains are divided deterministically 80/20. Cross-class training domains are excluded consistently with the earlier Task 2 rule; counts are reported. No official test row becomes a training or calibration example.

Thresholds are calibrated separately for each model/source setting and then held fixed on both evaluation cohorts. Report actual false-positive rates as well as recall. Retrospective test ROC points are labelled descriptive and cannot be used to choose a deployment threshold. Precision at 1% and 0.1% phishing prevalence is a class-prior adjustment, not a measured rate in Egyptian traffic. Tiny Arabic/Egyptian-target subsets have correspondingly limited evidence.

This URL research comparison does not alter the deployed model or establish authentic Egyptian SMS accuracy. The application's URL length limit remains 2,048 characters; the offline research classifier accepts longer strings and reports their count.
