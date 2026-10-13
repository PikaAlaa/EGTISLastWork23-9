> Historical September guide. Retained for provenance; not current implementation instructions. Team description corrected on 13 October 2026.

# ETIS — Egypt-Specific Threat Intelligence System

6-member AAST team graduation project (final-year CS). Phishing detection platform for Egyptian SMEs, focused on Arabic-language threats. Goal: a defensible thesis with a live demo, not just a research document.

## Architecture

Three-engine hybrid detection, combined through a unified 0–100 risk scoring layer:

1. **Rule-based engine** (max 30 pts) — Arabic phishing keyword detection, a lightweight English scam-keyword detector (added 2026-08-27, see below), Levenshtein-distance domain typosquatting against Egyptian brands, URL pattern matching
2. **Threat intelligence blacklist** (max 40 pts) — PostgreSQL database seeded from PhishTank and OpenPhish
3. **Bidirectional LSTM model** (max 30 pts) — TensorFlow/Keras + camel-tools for Arabic NLP, trained on the text/email subset of the dataset (~2,015 rows, ~83% Arabic/mixed) — not the full ~86K-row dataset, which is 97.7% URL rows. URL structural analysis is handled by the rule-based and blacklist engines instead; the LSTM is scoped specifically to message-text/email classification, where Arabic phishing language actually lives in the data.

Scores combine into LOW / MEDIUM / HIGH buckets, with a per-engine contribution breakdown for explainability.

## Stack

- **Backend:** FastAPI + SQLAlchemy
- **Frontend:** React + TypeScript + Material-UI
- **Database:** PostgreSQL 15
- **ML:** TensorFlow/Keras, camel-tools
- **Deployment:** Docker + docker-compose + Nginx locally; Railway or Render for the hosted demo

## Demo scope (decided — don't relitigate)

Manual paste-and-scan interface only. User submits a URL/email/text for analysis. Automatic email scanning (e.g. Gmail API polling) is explicitly deferred to Chapter 7 (Future Work) — it was deliberately cut to reduce defense risk (OAuth scopes, handling user email data, etc.). Don't build this into current scope even if it seems like a natural extension.

## Coding conventions

**Naming:** Favor clear, descriptive names over short symbols, even if longer. Applies especially to engine/scoring code — prefer `calculate_levenshtein_domain_similarity_score` over `calc_lev_sim`, `lstm_phishing_classifier` over `lstm_clf`. The codebase should read clearly when revisited for thesis writeups or defense prep.

**Error handling (FastAPI backend):** Custom exception classes + a global exception handler, not bare try/except with HTTPException scattered through routes.
- Base `ETISException`, with subclasses like `EngineFailureError`, `BlacklistLookupError`, `InvalidScanInputError`
- Register a global handler via FastAPI's `@app.exception_handler`
- Routes and engine code raise custom exceptions, not construct `HTTPException` inline
- **Deliberate exception to this rule (Phase 6):** `POST /analyze` does NOT raise on persistence failure. See "Persistence failure handling" below.
- All exception classes live in `app/core/exceptions.py` (not `app/exceptions.py` — a naming trap that has repeatedly caused `ModuleNotFoundError` during Phase 6 development; same applies to `app/core/database.py`, not `app/database.py`)

**Testing:** pytest. One test file per engine (rule-based, blacklist lookup, LSTM inference) with a handful of cases each (clear phishing example, clear clean example, one edge case). Plus one integration test on the unified scoring endpoint. Don't over-invest — this is a thesis project on a deadline, not a production system.

## Scope guardrail

ETIS is a defensive detection tool, not a phishing-generation tool. Help with anything that improves detection. Realistic Arabic phishing examples are in scope specifically for thesis §5.8 (Detection Examples), framed as system test cases paired with the system's score/analysis — not as standalone reusable templates. Flag before generating phishing content untethered from a detection/evaluation context.

## Thesis structure (decided — don't restructure)

7 chapters: Introduction, Literature Review, Methodology, Implementation, Experiments/Results, Evaluation, Conclusion/Future Work, plus appendices. SRS elements live in thesis §3.2.x, not a separate document. Five non-negotiable figures: system architecture (§3.1), hybrid engine flow (§3.3), database ER diagram (§3.5), LSTM architecture (§3.6), Chapter 5 ML result figures.

## LSTM scope (decided — don't relitigate)

The LSTM trains on the text/email subset of the dataset, not raw URLs. Dataset composition check (2026-07-27) showed 84,677 of 86,692 rows are `content_type=url`, and of those, 84,657 are `language=en` — URLs are structurally near-universally ASCII regardless of the phishing target's audience, so training the LSTM on the full mixed dataset would let URL rows numerically dominate and drown out the Arabic signal. Arabic content is concentrated in the 2,015 text/email rows (~83% Arabic/mixed). The rule-based and blacklist engines already handle URL-shaped signals; the LSTM's job is specifically Arabic/English message-text classification.

Note (2026-08-27): "specifically Arabic/English" above was aspirational, not actually true in practice — see "English-language coverage gap" below. Of the 2,015 text/email rows, only 2 are English, so the LSTM has essentially never seen an English phishing example despite the stated dual-language scope. This is now compensated for at the rule-based layer, not the LSTM layer.

## Risk scoring thresholds — CALIBRATED (no longer provisional)

Thresholds were calibrated 2026-07-XX by running the full aggregator
against all 13,005 validation-split rows (evaluation/calibrate_thresholds.py)
and inspecting real score distributions by true label. Method: LOW's upper
edge = 95th percentile of legitimate scores; HIGH's lower edge = 5th
percentile of phishing scores. Result: LOW = 0, MEDIUM = 1–50, HIGH = 51–100
(constants named `CALIBRATED_LOW_MAX` / `CALIBRATED_MEDIUM_MAX` in
app/engines/risk_scoring.py). Note: the module docstring in risk_scoring.py
should describe these as calibrated, not provisional — was fixed once
already after a rename left the docstring stale; check it hasn't drifted
again if the file is touched.

Validation outcome: 0 of 9,858 phishing examples landed in LOW (no missed
phishing at lowest confidence). 1 of 3,147 legitimate examples landed in
HIGH (see shared-hosting-domain fix below). Full report and histogram:
evaluation/threshold_calibration_report.txt,
evaluation/threshold_calibration_histogram.png.

Product decision made during calibration: a bare blacklist exact-match at
the default reputation score (no corroborating rule-based signal) is
sufficient alone to reach HIGH, not just MEDIUM — chosen deliberately over
requiring corroboration, since ~69% of real phishing in validation would
otherwise land in MEDIUM rather than HIGH.

KNOWN CAVEAT: blacklist_entries was seeded from the full PhishTank/OpenPhish
feeds, not just the training split, so some validation-split phishing URLs
are themselves already in the blacklist, inflating their scores via
exact-match rather than genuine generalization. Thresholds reflect real
deployed-system behavior on these inputs but are not a clean measure of
generalization to unseen phishing. State as a limitation in Chapter 7.

## Shared-hosting domain list — expanded via calibration (Phase 5)

Calibration surfaced 4 false positives, all via the same mechanism the
original SHARED_HOSTING_DOMAINS list (Phase 3) was built to prevent for
docs.google.com etc., just on platforms that list didn't yet cover:
rebrand.ly, t.me, gravatar.com, genspark.ai (all confirmed via diagnostic
re-run showing blacklist match_type=domain with real PhishTank hit counts
4-17). Added to SHARED_HOSTING_DOMAINS in blacklist_lookup.py. Worth
noting in Chapter 6/7 as a legitimate example of validation-driven
iterative refinement, not a one-time Phase 3 decision.

Separately noted, not a code fix: the Al-Ahly Bank anti-fraud warning
email (score 43.35, MEDIUM) is a false positive from the Arabic keyword
detector — it uses phishing-adjacent vocabulary ("فوزكم", "تحديث بياناتكم")
while warning people not to fall for messages using those words. Keyword
matching can't distinguish a phishing message from a legitimate message
warning about phishing. Cite as a stated limitation, not something to
patch.

## Blacklist domain-match vs exact-match scoring (verified, not a bug)

Domain-level blacklist matches are deliberately capped below exact-match
confidence: `DOMAIN_MATCH_BASE_SCORE = 60.0`, `DOMAIN_MATCH_SCORE_CAP = 85.0`
("stays below a typical exact-match score" per blacklist_lookup.py's own
comment) vs. exact matches which return the entry's full reputation_score
directly (typically ~90). Confirmed via a live Phase 6 test:
allegro.831820hy451g4.top (a real PhishTank domain, hit_count=1) scored
exactly 60.0 via domain match, landing the overall verdict at MEDIUM
(41.14) rather than HIGH — this is correct, intended behavior, not a
miscalibration. The Phase 5 calibration note about exact-match alone being
sufficient for HIGH was correctly scoped to exact matches only; domain
matches are intentionally weaker evidence. Worth stating explicitly in
Chapter 5/6 as a deliberate confidence-tiering design choice if asked
during defense.

## Text-only engine weighting — asymmetric redistribution added (Phase 5.6 iteration)

Chapter 5.6 evaluation surfaced a real inconsistency: for text-only submissions (no URL), risk_scoring.py's default equal 30/30 redistribution between rule-based and LSTM produced a plain 50/50 average — exactly the failure mode rule_based_engine.py's own docstring warns a plain average causes ("badly understate a strong single-engine signal"), just one level up. Measured effect: hybrid recall on Arabic test rows was 65.67% versus LSTM-only's 92.54% on the same rows — the aggregator was making the system worse than its own LSTM component for the one input type (Arabic phishing text) the whole project is built around.

Fix: added TEXT_ONLY_ENGINE_MAX_POINTS = {"rule_based": 15.0, "lstm": 45.0}, applied only when applicable_engines == {"rule_based", "lstm"}. URL-only and both-provided weightings (30/40/30) are unchanged. Deliberately not a switch to noisy-OR at the top level — that would break the additive weighted_contributions invariant relied on by EngineBreakdownCard (frontend) and test_risk_scoring.py.

Verified outcome:

- pytest tests/test_risk_scoring.py: 5/5 passed, no assertion changes needed
- Calibrated thresholds unchanged (LOW=0, HIGH=51) — text-only rows are too small a fraction (~2.3%) of validation data to move the global cutoffs
- Test-split Full Hybrid: recall 99.54% → 99.95%, F1 99.75% → 99.94%, ROC-AUC 99.89% → 99.78% (small dip, acceptable)
- Arabic test rows (hybrid): recall 65.67% → 92.54%, now matching LSTM-only exactly
- Mixed-language test rows (hybrid): recall 12.00% → 100.00%

Known regression, accepted deliberately, not patched: the Al-Ahly Bank anti-fraud-warning false positive (documented above under "Known limitations") moved from 43.35 (MEDIUM) to 55.03 (HIGH) under the new weighting — LSTM's increased influence amplifies its confident mistakes along with its confident correct predictions. Validation-set legitimate examples in the HIGH bucket went from 1 → 4 (out of 3,147); phishing examples stuck below HIGH went from 41 → 2 (out of 9,858). Accepted per Section 5.2's stated recall-over-precision priority for a security tool — the trade ratio (39 more correctly-flagged phishing for 3 more false positives) favors recall. State both outcomes in Chapter 5.6/5.8/7.3, not just the improvement.

## LSTM artifact storage — RESOLVED

Model weights (ml/models/lstm_phishing_classifier.keras) and tokenizer
(ml/data/tokenizer.pkl) are committed directly to git via .gitignore
exceptions, rather than regenerated at deploy time -- confirmed already
tracked as of 2026-08-25 (git ls-files check). These are NOT
bit-identical-reproducible via retraining (weight init is random), so
committing them directly avoids needing a separate deploy-time artifact
step for Railway/Render. .npy preprocessing arrays remain gitignored
since those ARE deterministically regenerable from the tracked dataset.

## Testing conventions update

backend/tests/conftest.py now holds the shared `db` fixture (a
SessionLocal-backed session against the seeded dev database), previously
duplicated locally inside test_blacklist_lookup.py. New test files should
use this fixture rather than redefining it.

## Phase 6 — COMPLETE (backend API)

Built and verified end-to-end (not just unit-tested — every endpoint
confirmed against the real running server, real Postgres data, and real
engine output):

- `app/main.py` — FastAPI entrypoint. Schema creation via
  `Base.metadata.create_all()` runs automatically on startup through a
  lifespan handler (idempotent, safe to run every boot) — replaces the
  manual Python one-liner used through Phases 0–5. Global exception
  handler maps the `ETISException` hierarchy to structured JSON
  responses (`InvalidScanInputError` → 400, `BlacklistLookupError` →
  502, `EngineFailureError` → 500, default → 500).
- `app/core/security.py` — minimal API-key dependency (`verify_api_key`),
  checked against `ETIS_API_KEY` env var. If the env var is unset (local
  dev), the check is skipped entirely — no key needed locally, only once
  a real deployment sets the env var. Deliberately not full JWT/RBAC —
  same scope-cutting rationale as excluding STIX/TAXII from the group
  proposal.
- `POST /analyze` (`app/routers/analyze.py`) — thin wrapper around
  `calculate_final_risk_score()`. Verified working through all three
  engine-applicability cases via real HTTP calls: text-only (Arabic
  keyword + LSTM), url-only (rule-based + blacklist, confirmed against a
  real blacklisted domain), and the underlying "both" case shares the
  same code path so is implicitly covered.
  - **Persistence:** every scan is saved as a `ScanRequest` + `ScanResult`
    pair (see model changes below).
  - **Persistence failure handling (deliberate, documented deviation
    from the standard error-handling convention above):** if saving
    fails, the computed score is still returned to the caller — losing
    the score because of an unrelated storage problem is a worse
    failure mode for a security tool than losing history. Response
    includes `saved: bool` and `save_error: str | None`. Persistence
    failures are logged server-side via `logger.error(..., exc_info=True)`
    for debugging, without leaking exception internals into the
    user-facing message.
- `GET /threats` (`app/routers/threats.py`) — paginated (`limit`/`offset`),
  filterable (`source`, `is_active`) read access to `BlacklistEntry`.
  Returns domain-level metadata only (`domain`, `source`, `brand_target`,
  `reputation_score`, `is_active`, `first_seen`, `last_seen`) —
  deliberately NOT the raw `url`/`url_hash`, to avoid exposing 65K+ live
  phishing URLs in bulk through a public API, even though the underlying
  PhishTank/OpenPhish data is itself public.
- `GET /stats` (`app/routers/stats.py`) — summary numbers combining
  blacklist composition (total/active entries, breakdown by source) and
  live scan history (total scans, breakdown by verdict, average final
  score). Deliberately returns a plain dict rather than a rigid response
  model, since stats requirements are expected to grow (e.g. time-windowed
  counts, most-targeted brand) — each addition should be a one-line change
  to `_blacklist_stats()`/`_scan_stats()`, not a schema migration.

**Model change:** `app/models/scan.py` — `ScanRequest.input_type` +
`input_value` (single field) replaced with two independently nullable
columns, `url_value` and `text_value`. A scan can legitimately include a
URL, text, or both (per risk_scoring.py's three-case design); a single
tagged field would force an arbitrary priority choice or lose data.
`ScanResult.blacklist_score` and `ScanResult.lstm_score` are both now
nullable (previously only intended for blacklist, but LSTM needed the
same treatment for text-optional scans). Old `scan_requests`/
`scan_results` tables were dropped and recreated via `create_all()` since
neither had ever been written to before Phase 6.

**Bug fixed during Phase 6:** `risk_scoring.py`'s `_classify()` referenced
`PROVISIONAL_LOW_MAX`/`PROVISIONAL_MEDIUM_MAX`, which no longer existed
after the calibration rename to `CALIBRATED_LOW_MAX`/`CALIBRATED_MEDIUM_MAX`
— would have crashed on the first real `_classify()` call. Fixed before
first successful `/analyze` test.

## Environment gotchas (Windows PowerShell) — Phase 6 additions

- `app/core/exceptions.py` and `app/core/database.py`, NOT `app/exceptions.py`
  / `app/database.py` — this mistake recurred multiple times during Phase 6
  (in hand-written drafts of `main.py` and `security.py`) and produces
  `ModuleNotFoundError: No module named 'app.exceptions'` (or `.database`).
  Check `app/core/` first before searching the filesystem.
- `uvicorn` must be run from `backend/`, not the project root — same
  working-directory requirement as `pytest`. Running from the wrong
  directory produces `ModuleNotFoundError: No module named 'app'` (not
  the `app.core.X` variant above — a different, simpler error for a
  different cause).
- `psql` on Windows fails on Arabic text with
  `character with byte sequence 0xd8 0xb9 in encoding "UTF8" has no
  equivalent in encoding "WIN1252"` unless the client encoding is set
  explicitly first: `$env:PGCLIENTENCODING = "UTF8"` before running the
  query. `chcp 65001` alone does NOT fix this (different encoding layer —
  console codepage vs. psql client encoding).
- PowerShell + `curl` quoting with nested JSON and Arabic text is
  unreliable — use `Invoke-RestMethod` with a PowerShell hashtable
  piped through `ConvertTo-Json` instead, e.g.:
```powershell
  $body = @{ text = "..."; url = $null } | ConvertTo-Json
  Invoke-RestMethod -Uri "http://localhost:8000/analyze" -Method Post -Body $body -ContentType "application/json; charset=utf-8"
```
  Pipe the result through `ConvertTo-Json -Depth 10` to see nested fields
  (`engine_details`, etc.) — PowerShell's default console formatter hides
  nested objects otherwise.

## English-language coverage gap — found and fixed (2026-08-27)

Manual testing (pasting a plain English lottery-scam email through the
live dashboard, no URL, text-only) surfaced a real gap: the submission
scored only 0.70/100 despite being an obvious scam. Root cause was NOT a
scoring bug — both applicable engines correctly returned near-zero,
because neither was ever built to handle English:

- `arabic_keyword_detector.py` only contains Arabic terms — it's not
  "not applicable" to English text, it runs and correctly finds nothing.
- The LSTM's training data is ~99.9% Arabic/mixed for text rows (only 2
  of 2,015 text/email rows are English — see updated "LSTM scope" note
  above), so it has essentially never seen an English phishing example.

A same-text Arabic-language scam (inheritance/lottery scam) correctly
scored 74.86 (HIGH) via the existing engines, confirming this was an
English-specific gap, not a general scoring problem.

**Fix (deliberately "light," not a full English NLP engine — this
project's core scope remains Arabic/Egypt-specific per the thesis
research questions):** added a fourth rule-based sub-engine,
`app/engines/rule_based/english_keyword_detector.py`, mirroring
`arabic_keyword_detector.py`'s tiered HIGH/MEDIUM/LOW weighted-keyword
design (generic lottery/prize, advance-fee, and credential-harvesting
scam phrases — "wire transfer," "you have been selected," "bank account
number," etc.). Wired into `rule_based_engine.py`'s existing noisy-OR
combination as a new `english_keyword` engine_results key, alongside
`arabic_keyword`, `domain_typosquatting`, `url_pattern`. Text-only
submissions now run both keyword detectors unconditionally (Arabic input
just won't match English terms and vice versa — negligible cost).
`backend/tests/test_english_keyword_detector.py` added (6 cases,
following the project's one-file-per-engine convention).

Verified outcome: the same English lottery-scam text now scores
50.70/100 (rule-based sub-score 100/100, several HIGH-weight phrase
matches), landing HIGH per the existing calibrated thresholds. Full
suite: 54/54 passing after the fix (one test-authoring bug caught along
the way — an original test's sample text accidentally contained the
HIGH-weight phrase "verify your account," which is a detector-behaving-
correctly case, not a regression).

**Frontend gap found and fixed in the same session:** the dashboard
(`ScanPage.tsx`, `explainVerdict.ts`, `types.ts`) only ever read
`arabic_keyword` from `engine_results` — added before `english_keyword`
existed. This meant the *score* was correct post-fix but the UI still
showed "no keyword matches" and the verdict explanation said "no engine
found a strong indicator" even when the English engine had matched and
scored 100/100. `types.ts` gained `EnglishKeywordMatch` and the
previously-missing `allowlisted: boolean` field (present on the backend
response per `risk_scoring.py`'s Egyptian-brand allowlist override, but
never added to the frontend type). `explainVerdict.ts` now checks both
keyword engines' matches, and handles `result.allowlisted` as a
dedicated early-return case (previously an allowlisted exact-match
domain — e.g. `cibeg.com` — could show a "verified" badge next to
contradictory typosquat/URL-flag explanation text, since
`domain_typosquatting`'s `exact_match` technique still populates
`matched_brand` at score 0.0). `ScanPage.tsx`'s Rule-Based Analysis card
now renders chips from both keyword engines. Locale files
(`en.json`/`ar.json`) had the `reasonKeywordMatch` string's
Arabic-specific wording generalized (it's shared by both engines now)
and gained `allowlistedBadge`/`reasonAllowlisted` keys that existed in
the live app but were absent from the JSON the AI assistant had been
working from — worth re-pulling actual current locale files before
editing them again rather than reconstructing from an earlier
conversation snapshot.

Verified end-to-end in both languages (Arabic UI + English UI) against
the live backend: allowlist case, Arabic scam case, English scam case —
all three show correct scores, correct verdict-explanation text, and
correct chips. Committed in two commits (backend engine+tests, frontend
types+explanation+chips+locale).

Worth a sentence in thesis §3.6 (Rule-Based Detection Design, as a
documented design decision) or §7.3 (Limitations, framing English
coverage as intentionally light/keyword-only rather than LSTM-backed) —
useful material if asked at defense "does this only work in Arabic?"

Recalibration (2026-08-27, post-fix): re-ran evaluate/calibrate_thresholds.py after adding the English keyword engine — thresholds unchanged (LOW≤0, HIGH≥51), 0 of 3,147 legitimate validation examples landed in HIGH (down from previously-documented 1–4), confirming the addition is additive to phishing detection without introducing new false positives on Arabic/mixed-language legitimate text.

## Text-only weighting interaction with non-Arabic input (found via acceptance pass, 2026-09-03) -- documented limitation, not fixed

Ran the Phase 9 acceptance pass (`evaluation/run_acceptance_test.ps1`, 10 fixed
inputs against the live backend) after the English keyword engine had been in
place for a while. Surfaced a real, reproducible interaction between two
features that were each individually correct when added, but never jointly
re-validated together: the Chapter 5.6 asymmetric TEXT_ONLY_ENGINE_MAX_POINTS
(45/15, LSTM-weighted) and the English keyword engine (2026-08-27).

**Root cause:** the 45/15 split was deliberately tuned against Arabic
text-only recall, where the LSTM is the strong, well-trained signal. But the
LSTM's training data is ~99.9% Arabic/mixed (2 of 2,015 text/email rows are
English) -- so on English input specifically, the LSTM has essentially no
real signal, yet it still holds 75% of the text-only vote regardless of
input language.

**Two consequences, confirmed against live output, not just theorized:**

1. **Confident, correct English/mixed rule-based detections get outvoted.**
   Case 7 (acceptance pass): English lottery-scam text matched two
   HIGH-weight English keyword phrases, rule-based scored 80/100 -- a strong,
   correct catch. LSTM returned probability 0.024 (essentially "not
   phishing"). Final score 21.77, verdict MEDIUM instead of the expected
   HIGH. Case 9 (mixed-language phishing) shows the identical pattern:
   rule-based 36/100 with real matches ("prize", "get/obtain", "احصل"),
   LSTM probability 0.011, final score 9.8, MEDIUM. Mixed-language input is
   somewhat better-positioned than pure English (334 of 1,996 training text
   rows, ~17%, are mixed-language, vs. only 2 English rows), but the same
   failure shape still surfaced on this specific phrasing.

2. **LOW is effectively unreachable for text-only legitimate submissions.**
   CALIBRATED_LOW_MAX = 0 requires an exact 0.0 final score. URL-only
   legitimate submissions commonly hit exact 0.0 (rule-based and blacklist
   both cleanly return 0). But the LSTM's output is a continuous probability
   that essentially never rounds to exactly 0 -- so even clearly-legitimate
   text-only input lands just above the LOW cutoff. Confirmed on two
   independent cases: Arabic legitimate text (score 13.01, MEDIUM) and
   English legitimate text (score 1.25, MEDIUM). Both should read LOW to a
   human reviewer.

Verified this is NOT a weighting bug -- the observed contributions match
the documented 15/45 formula exactly once the redistribution scale_factor
(100 / 60-point pool) is accounted for. The system is doing exactly what
its calibration says to do; the calibration and 45/15 weighting were simply
derived from and validated against a corpus that is ~99% Arabic/mixed
(Section 3.4's language breakdown), and never re-validated jointly against
English input after the English keyword engine was added on top.

**Decision: documented as a limitation, not patched.** Reasoning: (1)
English support is already explicitly scoped as "light, keyword-only, not
a full second-language engine" per the 2026-08-27 entry above -- this is a
rough edge on already-secondary scope, not a defect in the Arabic-focused
core the thesis's research questions (RQ2) are about; (2) a real fix means
language-conditional weighting, re-calibration, and re-validation of
Chapter 5's numbers -- exactly the kind of risk_scoring.py change that has
twice already caused silent regressions this project (lost
TEXT_ONLY_ENGINE_MAX_POINTS; the analyze-parameter-rename bug); (3) this
fits the same evidence-based limitations pattern already used for the
Al-Ahly Bank false positive, blacklist leakage, and LightGBM underperformance
-- state it plainly with root cause, don't hide or over-patch it.

Worth a paragraph in Chapter 6.2 (Accuracy Evaluation / Error Analysis) and
Chapter 7.3 (Limitations): "the text-only redistribution weighting and
calibrated LOW/MEDIUM/HIGH thresholds were derived from and validated
against a corpus that is ~99% Arabic-dominant (Table 3.2); both the
weighting and the LOW threshold are measurably less reliable on
English-language or mixed-language text-only input, where the LSTM has
minimal or partial training exposure respectively." Cite the acceptance-
pass cases above (English: score 21.77/MEDIUM vs. expected HIGH; Arabic/
English legitimate: scores 13.01/1.25, both MEDIUM instead of LOW) as
concrete supporting evidence, not just an abstract claim.

## Post-English-engine evaluation rerun (2026-08-XX) -- COMPLETE

Re-ran all three stale evaluation scripts flagged in the previous
"Remaining work" entry (they predated the English keyword engine).
Two real findings came out of this, one cosmetic fix and one genuine
bug -- documented here in full since both are worth being able to
explain at defense.

**Finding 1 -- two more shared-hosting false positives (minor, fixed):**
`evaluation/calibrate_thresholds.py` re-run surfaced `beacons.ai` and
`taplink.cc` (both link-in-bio platforms, hit_count=3, phishtank) as new
top-5 false-positive candidates, scoring 40.0 via blacklist domain-match.
Same mechanism as the existing `SHARED_HOSTING_DOMAINS` entries
(rebrand.ly, t.me, gravatar.com, genspark.ai) -- added both to the set in
`blacklist_lookup.py`. Re-ran calibration after the fix: both dropped out
of the false-positive list, thresholds unchanged (LOW=0, HIGH=51).

A third candidate, `google.com.bn` (score 37.14, domain-match, hit_count=2),
surfaced on the second run. Deliberately NOT added to
`SHARED_HOSTING_DOMAINS` -- unlike the others, this is a single
organization's own domain, not a shared multi-tenant platform, so
suppressing domain-level matches on it would hide a potentially real
signal rather than fix a structural false-positive mechanism. It's not
currently causing any harm (score is well inside MEDIUM, 0 legitimate
examples in HIGH either way) -- noted here as a Chapter 6.2 error-analysis
example, not a code TODO.

**Finding 2 -- TEXT_ONLY_ENGINE_MAX_POINTS silently lost (real bug, fixed):**
`evaluation/evaluate_test_configurations.py`'s re-run showed Full Hybrid
test-split recall had regressed to 99.57% (matching the OLD, pre-Chapter-
5.6-fix equal-30/30-weighting number), instead of the documented 99.95%
the asymmetric 45/15 text-only fix was supposed to be giving. Root cause:
`risk_scoring.py` had lost the `TEXT_ONLY_ENGINE_MAX_POINTS` special-casing
entirely -- the file only had the single `ENGINE_MAX_POINTS` dict applied
uniformly to every case, most likely overwritten when the Egyptian brand
allowlist feature was added from an older base copy of the file.

Ruled out the allowlist itself as the cause first (wrote
`evaluation/diagnose_allowlist_recall_impact.py`, a one-off diagnostic:
0 of the 5 allowlist-overridden test-split URL rows were labeled
phishing, so the allowlist wasn't touching recall at all).

`test_risk_scoring.py`'s existing assertions didn't catch this because
they check the redistribution INVARIANT (contributions sum to
final_score), not the specific 45/15 ratio -- passes under either
weighting scheme. Worth a sentence in Chapter 6 methodology/limitations:
a passing test suite confirmed the aggregation was internally consistent,
not that it matched the intended design.

Fix: restored `TEXT_ONLY_ENGINE_MAX_POINTS = {"rule_based": 15.0, "lstm": 45.0}`
and the conditional `max_points` selection in `calculate_final_risk_score()`.
Verified: `pytest` 54/54 passing, `evaluate_test_configurations.py` re-run
gives Full Hybrid 99.91% accuracy / 99.95% recall / 99.94% F1 / 99.78%
ROC-AUC -- exact match to the pre-existing FYP_REPORT.docx Table 5.1 numbers.
`evaluate_arabic_breakdown.py` re-run also confirmed Table 5.3's Arabic
hybrid numbers (95.62% acc / 91.85% F1) still hold post-fix.

**Net conclusion for Chapter 5:** Table 5.1, 5.2, and 5.3's existing
numbers in FYP_REPORT.docx require NO changes -- the English keyword
engine's addition genuinely had zero measurable effect on any test-split
aggregate metric (expected: the test split's text/email subset has 0
English rows this run; English coverage was validated separately via the
manual lottery-scam test documented above, not via this dataset's
text/email subset). The only real delta this rerun produced was catching
and fixing an unrelated regression that predates the English engine
entirely.

## Commercial-tool comparison (2026-08-XX) -- COMPLETE

Master Plan Section 5's "worth adding" item: ran the test-split URL
subset through Google Safe Browsing and VirusTotal, for a real (not
just claimed) comparison against ETIS in Chapter 5.3/6.3. Two separate
scripts, since the two APIs have very different constraints:
`evaluation/evaluate_safe_browsing.py` and `evaluation/evaluate_virustotal.py`.

**Google Safe Browsing -- COMPLETE.** Ran against the FULL test-split URL
subset (12,702 rows) via the batched threatMatches:find endpoint (up to
500 URLs/request, ~26 requests total, finished in under a minute).

Results:
| Metric | Safe Browsing | ETIS Full Hybrid (same split) |
|---|---|---|
| Accuracy | 29.02% | 99.91% |
| Precision | 99.87% | 99.93% |
| Recall | 7.68% | 99.95% |
| F1 | 14.26% | 99.94% |
| ROC-AUC | not computable (binary match only) | 99.78% |

Confusion matrix: [[TN=2936, FP=1], [FN=9015, TP=750]] -- 750/12,702 flagged.

**Interpretation -- this is the part that must NOT be overclaimed in the
thesis.** Safe Browsing's near-zero false-positive rate (1 FP out of
2,937 legitimate URLs) shows it isn't a weak tool -- it is simply
evaluating a DIFFERENT question than ETIS's blacklist engine is. Safe
Browsing assesses live, current threat status against Google's real-time
database; ETIS's blacklist assesses historical membership in a static,
already-labeled PhishTank/OpenPhish feed. Phishing infrastructure is
typically taken down within hours to days, so a large fraction of this
static test set's phishing URLs are very likely no longer live threats
by the time this evaluation ran -- meaning Safe Browsing's low recall
here reflects "these specific historical URLs are mostly dead now," not
"Safe Browsing is a weak detector." The correct framing for Chapter 5.3/
6.3: this result demonstrates that a static historical blacklist
trivially wins against a live-threat detector WHEN TESTED AGAINST
HISTORICAL DATA -- a real and useful finding about evaluation methodology,
not evidence that ETIS's detection is fundamentally superior to Google's.
State this caveat explicitly, don't just report the headline numbers.

**VirusTotal -- COMPLETE.** Free-tier rate limit (4 req/min) makes the
full test set impractical (~53 hours), so this uses a stratified sample:
100 phishing + 100 legitimate = 200 URLs, seed=42, drawn from the same
test-split URL subset, via `evaluation/evaluate_virustotal.py`. Uses the
v3 URL-report lookup endpoint (existing community scan data, not a fresh
live rescan) -- URLs VT has never seen are treated as "not flagged,"
matching what a real user would see checking that URL on virustotal.com.

Results (N=200, 0 unseen, 0 errors):
| Metric | VirusTotal | ETIS (same 200-URL sample) |
|---|---|---|
| Accuracy | 96.00% | 100.00% |
| Precision | 92.59% | 100.00% |
| Recall | 100.00% | 100.00% |
| F1 | 96.15% | 100.00% |
| ROC-AUC | 99.90% | 100.00% |

VirusTotal confusion matrix: [[TN=92, FP=8], [FN=0, TP=100]] -- perfect
recall, but 8/100 legitimate URLs flagged (false positives).

**ETIS-on-same-sample was run separately** (`evaluation/evaluate_etis_on_vt_sample.py`,
identical seed/sampling logic to reproduce the exact same 200 rows) so
the comparison is genuinely apples-to-apples on N, not VT-on-a-sample vs.
ETIS-on-the-full-13,003-row-test-set.

**CRITICAL CAVEAT on ETIS's 100% -- do not present bare, ever:** a
perfect 1.0000 across every metric is a leakage red flag and must be
explained, not just reported. This is the SAME known mechanism already
documented under "Risk scoring thresholds": blacklist_entries was seeded
from the FULL PhishTank/OpenPhish feeds, not train-split-only, so some
test-split phishing URLs are literally already present in the blacklist
as exact-match entries -- this is exactly why "Blacklist Only" already
scored 99.87-100% on the full 12,702-row test set in
evaluate_test_configurations.py. A 200-row balanced sample landing at
literally zero errors is a small-sample expression of that same known
effect, not new evidence of flawless generalization. State this
explicitly in Chapter 5.3/6.3 immediately alongside the 100% figure --
plausibly VirusTotal is subject to a similar effect too, since it
aggregates many of the same public feeds ETIS's blacklist is seeded from.

**Three-way summary for Chapter 5.3/6.3 (the actually-useful headline,
not "ETIS wins"):** Safe Browsing and VirusTotal show OPPOSITE precision/
recall biases -- Safe Browsing is extremely conservative (99.87%
precision, 7.68% recall), VirusTotal is extremely sensitive (100%
recall, 92.59% precision, 8% FPR on legitimate URLs). ETIS's fusion
architecture achieves both simultaneously on its full test set (99.93%
precision, 99.95% recall) WITHOUT the leakage caveat on the full-set
numbers being as severe (full test set is much larger than the 200-row
leakage-affected sample). Frame the finding as "different commercial
tools optimize for different tradeoffs; a fused, localized system avoids
having to choose" -- not as a flat superiority claim.

All three reports saved to `evaluation/safe_browsing_comparison_report.txt`,
`evaluation/virustotal_comparison_report.txt`, and
`evaluation/etis_on_vt_sample_report.txt` -- each includes its own
methodology-notes section (source overlap with ETIS's own blacklist seed
feeds, sample-size/rate-limit disclosure, binary-vs-continuous-score
distinction) that must be carried into the thesis verbatim, not
summarized away.

## Homoglyph/confusable-character detection added (2026-08-XX) -- COMPLETE

Master Plan Section 5 "consider only if time allows" item: extended
`domain_typosquatting_detector.py` with a 5th technique catching a real
gap the existing four don't cover -- IDN homograph attacks. A domain
using visually-confusable Unicode characters (Cyrillic а/е/о/р/с/х/у,
Greek α/ο/ρ, etc., or a punycode-encoded label that decodes to such
characters) renders identically to a real brand domain in a browser
address bar, but is a completely different string to a computer. Neither
Levenshtein (characters aren't "close" in an edit-distance sense, they
just visually resemble the real letter) nor `url_pattern_analyzer.py`'s
existing `punycode_domain` flag (which flags ANY punycode domain as
structurally suspicious but doesn't decode it or identify which brand,
if any, it's impersonating) catches this specifically.

**Implementation:** `_decode_punycode_labels()` decodes any `xn--`
labels back to real Unicode (falls back gracefully to the original label
on malformed punycode, doesn't crash). `_skeletonize()` maps each
character through `CONFUSABLE_CHAR_MAP` (a curated ~20-entry set of the
most common Cyrillic/Greek phishing lookalikes -- deliberately NOT the
full ~6,000-entry Unicode Consortium confusables table, consistent with
this project's existing "don't over-invest" scope philosophy) back to
its Latin form. If the skeletonized domain exactly matches a real brand
domain but the raw candidate did not (guarded by `is_potential_homoglyph`
so a domain that's already pure ASCII can't spuriously trigger this),
that's `technique: "homoglyph_confusable"`, `score: 92.0` -- just below
domain_embedding's 95 (both are deliberate impersonation techniques, but
embedding additionally still contains the brand's real string verbatim,
a marginally stronger signal).

**Bug found and fixed during test-writing (worth citing at defense as an
example of tests actually doing their job, not just passing):** the
first version placed the homoglyph check AFTER Levenshtein in the
per-brand loop. A single confusable-character substitution (e.g.
Cyrillic "е" for Latin "e" in `cibeg.com`) is also just "1 edit" in
plain Levenshtein-distance terms -- similarity ~0.89 against the
existing 0.75 threshold -- so Levenshtein matched FIRST and `continue`d
to the next brand before the more specific homoglyph check ever got a
chance to run for that same brand. Two of the five new tests
(`test_homoglyph_cyrillic_letter_substitution_detected`,
`test_homoglyph_greek_letter_substitution_detected`) caught this
immediately: `assert 'levenshtein' == 'homoglyph_confusable'`. Fixed by
reordering the loop -- homoglyph is now checked BEFORE Levenshtein
(technique 3, not 5; Levenshtein and brand-label-reuse renumbered to 4
and 5). Module docstring's documented technique order updated to match.

**Verified end-to-end, not just unit-tested:** 59/59 pytest passing
(54 existing + 5 new, all in `backend/tests/test_homoglyph_additions.py`
-- TODO: fold into `test_domain_typosquatting_detector.py` per the
one-file-per-engine convention, not yet done). Live API check via
`POST /analyze` with `https://cib` + Cyrillic "е" + `g.com/login`
confirmed `domain_typosquatting.technique: "homoglyph_confusable"`,
`matched_brand: "Commercial International Bank (CIB)"`, `score: 92.0`,
correctly combined via noisy-OR with the `url_pattern` engine's
`suspicious_path_keyword` flag into a 92.64 rule-based sub-score. Final
verdict landed at MEDIUM (39.7), not HIGH -- correct, expected behavior
per the existing 30/40/30 architecture: with no blacklist match, a
URL-only submission's rule-based score can contribute at most
`100/70 * 30 ≈ 42.9` points when rescaled, the same structural ceiling
already documented for the `allegro.831820hy451g4.top` domain-match
example. Not a bug, don't relitigate if this comes up again.

Also added rate limiting (20/min via slowapi) to `POST /analyze` in the
same session -- caught and fixed a related bug during that work: the
`AnalyzeRequest` body parameter had to be renamed from `request` to
`payload` to avoid colliding with slowapi's required `Request` object,
and the function body's internal references were initially missed,
which would have silently saved the API's OWN endpoint URL into scan
history instead of the user's submitted URL. Caught before commit via a
live `psql` check against `scan_requests.url_value`. `/threats` and
`/stats` deliberately left unlimited (cheap reads, not worth protecting).

## Remaining work

- [x] Blacklist domain-match scoring -- resolved, verified not a bug
- [x] Phase 7 frontend -- COMPLETE
- [x] Five non-negotiable diagrams -- generated; insertion into
      FYP_REPORT.docx still pending (report task, deferred)
- [x] pytest testing pattern -- done
- [ ] Docker deployment + public demo (Railway/Render) -- not started,
      explicitly deferred (not being deployed yet)
- [x] LSTM artifact storage -- resolved
- [x] Chapter 5 experiments -- complete, re-confirmed valid against the
      current 4-engine system
- [x] LightGBM second baseline -- run, supports the "small purpose-fit
      architecture" argument
- [x] VirusTotal/Safe Browsing commercial-tool comparison -- complete,
      leakage caveat documented, must carry into Chapter 5.3/6.3
- [x] Rate limiting on /analyze -- added, verified (429 after 20/min),
      live end-to-end check confirmed correct data flow post-fix
- [x] Homoglyph/confusable-character detection -- added, verified live
      and via 5 new tests, bug found+fixed during testing (see above)
- [x] Frontend redesign verification -- confirmed 2026-09-02/03:
      `npx tsc -b --noEmit` clean, `npm run dev` loads correctly (RTL
      default, language toggle, all three tabs, Nile-blue styling all
      verified). Also fixed a high-severity `nanoid` vulnerability
      flagged by `npm audit` during the same session (`npm audit fix`,
      0 vulnerabilities after).
- [x] Fold test_homoglyph_additions.py into
      test_domain_typosquatting_detector.py (tidiness only, not urgent)
- [ ] Write remaining thesis sections (5.7, 6, 7) -- deferred, project/
      code work prioritized first per current session's direction
- [ ] Duplicate diagram cleanup in FYP_REPORT.docx -- deferred, needs the
      real .docx file opened directly to identify which two figures are
      duplicated
