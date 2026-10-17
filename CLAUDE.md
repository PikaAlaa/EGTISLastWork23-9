# ETIS — current project guide

ETIS is a 6-member AAST team graduation project for defensive SMS and URL phishing detection.

Use README.md and LOCAL-IMPLEMENTATION.md for current behavior. The latest implementation evidence is under evaluation/reports/2026-10-v4/. The A–C review is under evaluation/reports/2026-10-v3/review-2026-10-13/; the subsequent research comparison is under evaluation/reports/2026-10-v3/phreshphish/. The September guide is archived at docs/history/claude-guide-2026-09.md.

- Preserve original September data/model/tokenizer, reviewed-2026-10-08 reports, evaluation/targets.json and frozen split assignments.
- URLs are inert strings. Never fetch phishing destinations or send messages/URLs to an external analysis service.
- No generated or translated message may be represented as real Egyptian SMS. Genuine Egyptian SMS final-test count remains 0.
- Use isolated databases for tests. Keep secrets, runtime databases and installed dependencies out of Git.
- Current decisions require corroboration for text-only HIGH. URL selection v3 deploys ordinary support from an existing full-URL LightGBM at a frozen calibration threshold; gate the model's own alerts and incremental false positives above a matched non-model baseline. Pattern observations are separate from alerting flags: only IP, userinfo, nonstandard port and punycode independently alert. See the v4 report for acceptance evidence and recall cost. Text selection primarily uses source-held-out and existing everyday-probe evidence.
- Consult docs/data-licences.md before redistributing data. LICENSE is a placeholder pending the team's choice.
- PhreshPhish acquisition permits only url, label, target, date and lang. Never fetch or decode its HTML column, visit destination URLs, or commit dataset projections/local predictions. The user explicitly requested the v1 ETIS benign-domain/probability export and the 13 benign brand/domain pairs; these are minimal row-export exceptions. Keep official test evaluation-only for thresholds and pattern proposals. URL selection v3 reuses every v2 frozen model/threshold pair, maximizing integrated test recall subject to the own-model and incremental-FP gates. Pattern proposals use only PhreshPhish training/calibration, with a frozen test-FPR/replay acceptance rule. Other research candidates remain local under ignored release-artifacts/. External-test selection is exposed development evidence, not independent final validation.
- Run pytest, database initialization, frontend build and lint after relevant changes. Do not run a sealed final test.
