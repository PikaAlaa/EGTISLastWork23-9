# ETIS — reviewed October implementation

An experimental Arabic-first phishing scanner with a bilingual interface.

The October plan's core scanner, URL rules, privacy, safe feed updates, local proxy,
data rebuilding, candidate-model comparison, migrations and evaluation tooling are
implemented in this copy. The model still overflags routine bank notifications, so
this is **not a completed real-world accuracy validation**.

Start locally with `./Start-ETIS.ps1`, then open `http://127.0.0.1:5173/scan`.
For a fresh installation use `./Install-ETIS.ps1 -Start`.

- [Setup and start/stop instructions](SETUP.md)
- [Recorded implementation status and remaining work](LOCAL-IMPLEMENTATION.md)
- [API contract](docs/api-v2.md)
- [Evaluation protocol](evaluation/README.md)
- [Validation comparison by source](docs/validation-by-source.md)
- [Review follow-up fixes](docs/review-followup.md)
- [Recorded development evidence](evaluation/reports/reviewed-2026-10-08/README.md)
- [Repository integration notes](docs/repository-integration.md)

This reviewed build supersedes the earlier implementation on this repository's main
branch; its history is preserved. Optional reporting, accounts, history and Telegram
are deferred. Original September data and model artifacts remain
as historical evidence; their old accuracy claims are not current validation results.
