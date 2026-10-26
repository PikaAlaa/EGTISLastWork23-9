# ETIS — reviewed October implementation

**26 October text deployment:** the frozen source/probe rule selects TF-IDF
LightGBM after the six Colab runs and a common-protocol CPU pass for all seven
candidates. Its primary loss is 0.156583 and local p95 is 1.475 ms. The twelve
existing invented everyday probes now give 0 HIGH, 2 MEDIUM and 10 LOW, compared
with 0/8/4 previously. The URL deployment is unchanged. See the
[Phase 2 report](evaluation/reports/2026-10-v5/REPORT.md) for counts, provenance,
both machines' timings, the retrospective timing corrections and artifact hash.
Genuine Egyptian SMS test count remains 0; no sealed final test ran.

**Threshold ordering.** The deployed high threshold `0.10124534067817578`
(about `0.1012`) is below the low threshold `0.2`. The high check runs first,
so the text MEDIUM band is empty: any probability at or above the high threshold
is text-high. Text-high becomes HIGH with corroboration; without it, it produces
MEDIUM via `text_model_high_uncorroborated`, not `text_medium`. Existing invented
probe 3 illustrates this at probability `0.144231`. This is exactly the behavior
used to measure the selection loss. A legitimate message with a recognized phone
number or short link plus urgent-action wording would therefore be HIGH if its
probability reaches the deployed high threshold (about `0.10`; the exact cutoff
above applies). Any threshold change must be declared in a new dated rule before
measurement, never retuned on these results.

**23 October v4 deployment:** candidate `ee0ba9f0077c1fd140aa` uses host/path
model input at the frozen threshold `0.9870690448552604`, with ordinary URL-model
support. Queries and fragments do not affect its raw score. The owner authorized
replacing 29 obsolete historical-artifact/policy test expectations. All 88 exposed
URL-shape probes return LOW. See the [release report](evaluation/reports/2026-10-v4/REPORT.md)
for verification and the earlier query-shortcut history.

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

V4 uses ordinary URL-model support. Text-model HIGH alerts require corroboration.
All twelve existing invented everyday probes avoid HIGH, while two remain
MEDIUM under the deployed TF-IDF LightGBM text model. The completed comparison
includes both transformers across three seeds; neither passes the new local
CPU latency gate. These exposed development results do not establish authentic
Egyptian SMS accuracy.

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
