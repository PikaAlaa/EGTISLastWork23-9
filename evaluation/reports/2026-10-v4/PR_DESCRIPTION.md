# Prevent URL-model-only false alarms under rule v2

The v1 subdomain gate selected a model that raised ETIS-validation benign false positives
from 2/2,916 to 78/2,916. Freeze rule v2 after disclosing those observed results, calibrate
all existing URL models without test/validation threshold tuning, and compare integrated
scanner outcomes under ordinary and corroboration-only support.

Deploy `corroboration_only` at `0.85206987301336179`. There are
0 ordinary policies satisfying all three integrated
FPR limits; the report quantifies fallback recall cost and residual non-model false positives.
Save the 78 benign-domain model flags and probabilities without visiting them. Source Vodafone
Group's `vodafone.com` from its official company page, fixing the careers/root registry alarms.

Validation: 237 pytest tests, database initialization,
frontend build and lint; replay 23/23 detection,
7/7 robustness,
15/15 follow-up; all
17 legitimate host probes produce 0 MEDIUM/HIGH warnings.

Earlier data hygiene, sender context, dependency and registry changes remain. No sealed final
test or genuine Egyptian SMS accuracy is claimed; the selection cohorts are exposed development
evidence. Historical restricted data remains in Git history. No push, merge, upload or history rewrite.
Detailed model and scanner tables, sources, checks and remaining work: `evaluation/reports/2026-10-v4/REPORT.md`.
