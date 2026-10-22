# ETIS — reviewed October implementation

**18 October query-shortcut mitigation:** the full-URL LightGBM overreacts to
ordinary query strings. URL-model support now requires independent corroboration;
raw probabilities remain diagnostic. All 88 exposed URL-shape probes return LOW.
This contains the false alarms but substantially reduces URL-only recall; the
classifier itself still needs replacement. See the [review report](evaluation/reports/2026-10-v4/query-shortcut/REPORT.md).

The [17 October v4 report](evaluation/reports/2026-10-v4/REPORT.md)
records the legitimate-subdomain work and the historical v3 contribution gate.
The original cohort gates passed but did not establish query-string robustness.
A training-selected pattern policy also passes the test FPR and replay checks;
the report quantifies its substantial recall cost. The text model is unchanged.
The scan form/API now accept optional sender-display context, with Arabic/English
advice, and the [brand registry sources](docs/brand-sources.md) document the additions.
Restricted research data is untracked but retained locally; candidate weights and
their upload manifest are under ignored `release-artifacts/`. Historical data remains
in Git history; this work does not purge public copies. See [data licences](docs/data-licences.md).
These development results do not establish real Egyptian SMS accuracy.

**13 October update:** the [PhreshPhish comparison](evaluation/reports/2026-10-v3/phreshphish/REPORT.md) adds 18 measured URL models across three source settings, including genuine benign full URLs. ETIS-only thresholds transfer poorly to PhreshPhish; no research model was automatically promoted. Follow [reproduction instructions](docs/phreshphish.md) to download the five permitted columns with checksum verification; dataset copies are excluded from this repository/package. The [A–C review](evaluation/reports/2026-10-v3/review-2026-10-13/REPORT.md) documents the current host-only application model and source/probe-based text selection. The [raw-data licence inventory](docs/data-licences.md) identifies unresolved redistribution rights, and `LICENSE` awaits the six-member AAST team's choice.

An experimental Arabic-first phishing scanner with a bilingual interface.

The October plan's core scanner, URL rules, privacy, safe feed updates, local proxy,
data rebuilding, candidate-model comparison, migrations and evaluation tooling are
implemented in this copy. The 2026-10 v3 development report updates text corroboration
and compares lexical URL and text models; it still does not establish real-world
Egyptian SMS accuracy.

V4 uses corroboration-only URL-model support. Text-model HIGH alerts require corroboration.
All twelve existing everyday probes avoid HIGH, while eight remain
MEDIUM under the deployed text model. The revised local comparison provisionally
favors TF-IDF LightGBM; deployment still uses the preserved character model.
Final selection requires transformer source-held-out and everyday-probe results.

Start locally with `./Start-ETIS.ps1`, then open `http://127.0.0.1:5173/scan`.
For a fresh installation use `./Install-ETIS.ps1 -Start`.

- [Setup and start/stop instructions](SETUP.md)
- [Recorded implementation status and remaining work](LOCAL-IMPLEMENTATION.md)
- [API contract](docs/api-v2.md)
- [Evaluation protocol](evaluation/README.md)
- [Validation comparison by source](docs/validation-by-source.md)
- [Review follow-up fixes](docs/review-followup.md)
- [Recorded development evidence](evaluation/reports/reviewed-2026-10-08/README.md)
- [2026-10 v3 experiments and limitations](evaluation/reports/2026-10-v3/REPORT.md)
- [Repository integration notes](docs/repository-integration.md)

This reviewed build supersedes the earlier implementation on this repository's main
branch; its history is preserved. Optional reporting, accounts, history and Telegram
are deferred. Original September data and model artifacts remain
as historical evidence; their old accuracy claims are not current validation results.
