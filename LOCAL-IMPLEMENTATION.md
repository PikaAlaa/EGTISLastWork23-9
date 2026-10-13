# Local implementation handover — 8 October 2026

Current model evidence is in the [13 October review report](evaluation/reports/2026-10-v3/review-2026-10-13/REPORT.md). The older evaluation and selection claims below are historical. See [data licences](docs/data-licences.md) before publishing the preserved data.

The required engineering work has been implemented in this separate local copy.
**The full completion plan is not yet satisfied:** genuine-data evaluation, acceptance
approval and remaining detection weaknesses still need work. The original local review
base was `bd56f3b`. The user subsequently authorized publication to
`PikaAlaa/EGTISLastWork23-9`; see [repository integration notes](docs/repository-integration.md).
The source checkout's Mido-77 origin remains protected from pushes.

Open the running app: <http://127.0.0.1:5173/scan>.
Start/stop instructions and a fresh-install command are in [SETUP.md](SETUP.md).

## 9–10 October 2026 v3 follow-up

The text-only HIGH rule now requires a separate corroborating signal, the NBE probe
passes without an xfail, and an offline host-only lexical URL model is evaluated from
a pinned Tranco list and Public Suffix List. The original September data, deployed
model, tokenizer and reviewed baseline reports remain unchanged. The host-only URL
model uses LightGBM; the local text winner is character TF-IDF + logistic regression.
Text selection follows the frozen macro-F1/FPR/latency rule, with calibration also
reported; the final selection waits
for the MARBERTv2 and CAMeLBERT-DA runs. See the [v3 report](evaluation/reports/2026-10-v3/REPORT.md)
for exact metrics, source-held-out results, reproduction commands and limitations.
No final sealed test ran; authentic Egyptian SMS remains unavailable (count 0).
The twelve invented everyday probes now produce 0 HIGH, 8 MEDIUM and 4 LOW.
The sections below preserve the 8 October handover; use the v3 report for current results.

The review follow-up fixes validation reporting, the incomplete final candidate
comparison and platform-dependent dataset identity. All three candidates were
retrained locally on the same content and the character model remains selected.
See [validation results by source](docs/validation-by-source.md) and
[the review follow-up](docs/review-followup.md). These changes do not resolve the
known everyday-SMS false alarms or establish final accuracy.

The supplied reviewer follow-up inputs and captured outputs are now preserved with
checksums. [The portable replay](evaluation/FOLLOWUP.md) reproduces 23/23 detection
cases, 7/7 robustness probes and 14/15 additional probes. All 15 additional outcomes
match the supplied report, including the known NBE-notice HIGH false alarm. No model
was retrained or threshold changed while importing these now-exposed regressions.

## Implemented

- Decision-v2 collects all applicable evidence before choosing HIGH, INCOMPLETE,
  MEDIUM or LOW. Strong evidence is never diluted; an official domain cannot hide
  phishing text. Scores are indicator strengths rather than confidence percentages.
- One URL parser handles real hosts, usernames before @, Unicode/IDNA, strict schemes
  and ports, scheme-specific default ports, path/query preservation and fragment
  identity. Exact blacklist lookup precedes shared-hosting exceptions. Embedded,
  defanged and bare links are extracted; more than ten links is explicitly incomplete.
- Brand rules cover dot/hyphen tokens, action words, disguised userinfo, full-domain
  embedding and an extended, pinned Unicode confusable map. Official subdomains and
  unrelated substrings have negative regression tests.
- Arabic/English advice, translated errors, retry, incomplete explanations and
  non-clickable destination displays are integrated. Four banks have sourced official
  contact advice. The experimental warning explains the observed bank-message weakness.
- A same-origin proxy keeps keys out of the browser, issues signed session cookies,
  limits requests and checks Host/Origin and body size. Local servers bind to loopback.
- Privacy migrations remove raw submissions and old matched snippets, retaining only
  hashes and minimal outcome metadata. A worker runs retention every refresh cycle.
  Missing components degrade honestly; save failure preserves the verdict.
- Feed downloads are bounded and validated before transactional activation. Failed or
  partial refreshes retain the previous copy. Per-source observations support expiry
  and rollback without discarding another source's observations. Both feeds refreshed
  successfully in the recorded local run after an initial PhishTank download rejection.
- Data rebuilding removes ambiguous spam labels, groups near-copy text before splitting,
  groups all subdomains under their registered parent, and reserves genuine consented
  SMS groups before final testing. 112 authored synthetic examples are **training only**.
- Character, BiLSTM and LightGBM candidates were trained and compared on the same
  rebuilt validation set. Character was selected using validation F1 and is packaged
  with an artifact hash. Original September data, model and tokenizer are unchanged:
  **True**. Historical training scripts and evidence are labelled as historical.
- Alembic migrations, Windows install/start/stop scripts, Compose files and a local CI
  workflow are present. Evaluation tools use separate frozen blacklists, verification
  dates, source/language/content-type reports, 95% intervals and one-shot final gates.

## Recorded verification

| Check | Result |
| --- | --- |
| Backend tests | 144 passed, 1 expected failure (known NBE false alarm); one upstream test-client deprecation warning |
| Reviewer follow-up | 14/15 meet expectations; all 15 outcomes match the supplied capture, including the known miss |
| Evaluation guards | Portable LF/CRLF identity, subgroup false-alarm reporting, three-candidate dataset/artifact matching tested |
| Real selected-model development cases | 23/23 passed, including the reference case |
| Real selected-model robustness probes | 7/7 passed |
| Frontend build and lint | Passed on Node 22.12.0 |
| Installer | Rerun successfully in the prepared local copy |
| SQLite migrations | Tested from empty schema and legacy records; idempotent upgrade tested |
| Live local health | ready; both feeds fresh and text model available |
| Proxy/authentication/privacy | Passed; marker absent from database, logs and error responses |
| Concurrent local requests | 10 passed; latest recorded p95 149.6 ms |
| Browser | Arabic warning/advice and English UI checked; page refresh/navigation works; no browser errors observed |
| Phone layout | 390-pixel viewport; no horizontal page overflow |
| Known-URL development check | 1,000 canonical variants passed; functional lookup, not detection accuracy |
| Git | Publication authorized to PikaAlaa/EGTISLastWork23-9; original Mido-77 origin stays protected |

The exact installed Python environment is recorded in `requirements-windows.lock.txt`.
Reports are under ignored `evaluation/local-results/`. Model/data versions are saved
with them. The displayed app preview is [docs/local-preview.jpg](docs/local-preview.jpg).

## Important remaining work

1. **Routine SMS false alarms are unresolved.** On the review's twelve invented everyday
   messages, the selected model produced 5 HIGH,
   3 MEDIUM and 4 LOW.
   These are development probes, not a population estimate. Synthetic augmentation
   improved the short phishing regression but does not replace representative genuine
   bank-message training and independently sealed real SMS evaluation.
2. **New-domain detection remains weak.** On the complete grouped URL validation cohort
   (9,496 URLs), MEDIUM-or-HIGH phishing recall was
   17.18%. Report its saved 95% interval and dataset composition. This is a
   development result, not a final or real-traffic detection claim. General new-site
   protection cannot be claimed from the current rules/blacklist.
3. Collect at least 200 independent, consented, anonymized everyday SMS groups and
   200 genuine reviewed shared links. None were fabricated to meet those requirements;
   currently sealed genuine SMS count is 0. Review labels and
   dialect/formal-email coverage; additional phishing examples are needed for supported
   subgroups. English remains experimental and unvalidated.
4. Obtain supervisor approval of targets in `evaluation/targets.json`, including a
   development-derived new-domain minimum. The final runner was checked to refuse
   scoring while approval is missing. No final sealed test was run or peeked at.
5. Complete the final URL/time/SMS experiments and thesis interpretation. The July
   retrospective protocol uses both submission and verification before the cutoff;
   four late-verification records are excluded. It cannot reconstruct a full historical
   feed. External-tool comparisons need approved credentials and timestamped observations;
   no user messages or URLs were sent to Safe Browsing or VirusTotal.
6. Docker/PostgreSQL Compose and the GitHub-hosted workflow were **not executed** here:
   Docker is unavailable. The workflow is included for the now-authorized publication;
   its hosted result must be checked separately. Have another member
   verify a clean installation. Public deployment/TLS was not performed.

Reporting, user accounts/history and Telegram are deferred as requested. This is a
working local experimental implementation with recorded gaps, not a claim that every
Definition of Done criterion has passed.
