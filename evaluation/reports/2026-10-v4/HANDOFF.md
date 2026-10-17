# URL selection v2 handover

Branch: `fix/url-subdomains-and-hygiene`. This follow-up is committed locally; no push or merge.

Deployed `corroboration_only` using `release-artifacts/evaluation/reports/2026-10-v3/phreshphish/models/combined_full_url_char_calibrated_svm.joblib` at `0.85206987301336179`,
representation `full_url`. Packaged artifact SHA-256:
`cff31fd9f2a7cd1324190e1dfccf5523bdcfa663ccc23af2988288cf86b3a35a`.

Rule v2 was written after v1 results and before new computation. Model-passing candidates:
97; ordinary integrated passing candidates:
0; corroboration-only integrated passing candidates:
0. The report explicitly records any remaining
non-model FPR failures and the recall cost. Do not restore the v1 deployment from its historical report.

Checks: 237 pytest tests; initialize, frontend build and lint
all exit 0. Replays: 23/23,
7/7, 15/15.
Vodafone Group provenance is in `docs/brand-sources.md`; final legitimate-host warnings:
0/17.

Read [REPORT.md](REPORT.md), [PR_DESCRIPTION.md](PR_DESCRIPTION.md),
[url_v2_comparison.json](url_v2_comparison.json), and
[v1_etis_validation_benign_flags.json](v1_etis_validation_benign_flags.json).
The latter is the explicitly requested minimal benign-domain export; all other row predictions stay ignored.

Research data and historical weights remain local/ignored and hash-verified. No sealed final test,
authentic Egyptian SMS validation, feed refresh, history rewrite, push or merge. Further
scanner-rule FPR work and independent validation remain. Stop after this commit.
