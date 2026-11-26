# BEC and payment-change rules v1 — design

Status: **design only**, 26 November 2026. Proposed engine `phishing.payment_rules`.
Uses [provider registry v1](provider-registry-v1.md) and
[email auth check v1](email-auth-check-v1.md). No code, corpus or results included.

## 0. Constraints

Apply `CLAUDE.md`, `README.md`, [core v1](core-v1.md),
[engine authors](../engine-authors.md) and [host design](host-engine-v1.md).
Local, offline, defensive analysis of explicitly supplied email/SMS only.
Never fetch/resolve a URL or contact any address, bank, payment service or
recipient. No DNS, WHOIS, online lookups or external submission of text, URLs,
hashes or headers. Every external fact absent from the repo is **to verify**.

This batch adds this document only. Existing files, `evaluation/`, targets,
frozen rules/splits, `data/`, `ml/models`, deployed models/thresholds, tests and
dependencies remain untouched. Future rules produce separate Findings through
`record_findings`, never alter existing verdicts or become their corroboration.
Install nothing; no secrets, push, merge or history rewrite. All generated
messages, headers, identities and URLs are **invented**, never real Egyptian data.

## 1. Scope and inputs

Explicitly imported `.eml` body/subject in memory via document 2's bounded parser,
or a user-selected SMS text and optional sender context. Accept document 1's
finished claim/proof observations and document 2's finished header observations
for that same input. Reject cross-message or different-version evidence joins.
Do not read contacts, payment accounts, mailboxes or transaction histories.

Detect payment-diversion and authority-pressure patterns, not proof of a
compromised account, unlawful intent, valid banking coordinates or completed
financial loss. An ordinary payment request is not necessarily fraud. An
executive title alone establishes only a claimed role, not the identity of the
user's actual manager. Registry coverage is for providers, not employees.

“New recipient” in v1 means an explicit change/new-recipient statement in this
message, optionally contrasting old/new destinations. No unseen-history or
first-contact inference. Unknown recipient history stays unknown. Personal
counterparty baselines and employer directories are out of scope.

## 2. Detection logic

### 2.1 Fixed predicates

Use deterministic versioned phrase tables, never a generated translation,
online LLM, new model or retuned threshold. Claim normalization follows document
1; account/destination values are never normalized with a confusable transform
that could merge different recipients. Clause boundaries are newline, full stop,
semicolon and Arabic question mark; punctuation inside a parsed URL or mailbox
does not split that token. Require request and payment object in the same
clause. Cross-clause change/authority references require an explicit deterministic
pronoun/reference rule frozen with the phrase manifest; absent that rule,
coverage is unavailable rather than guessed.

The following are **invented lexical examples**, chosen as design inputs, not
observed frequency, linguistic coverage or authentic Egyptian messages:

| Predicate | Invented English / Arabic / Egyptian dialect / Franco-Arabic cues |
| --- | --- |
| `request` | **invented:** “send”; “حوّل”; “ابعت”; “eb3at” |
| `payment_object` | **invented:** “payment”; “دفعة”; “فلوس”; “floos” |
| `change` | **invented:** “replace the account”; “غيّر الحساب”; “الحساب اتغير”; “el 7esab etghayar” |
| `urgency` | **invented:** “pay now”; “الدفع فوراً”; “ادفع دلوقتي”; “edfa3 delwa2ty” |
| `new_recipient` | **invented:** “new recipient”; “مستفيد جديد”; “لحد جديد”; “le 7ad gedeed” |
| `gift_card` | **invented:** “gift card”; “بطاقة هدايا”; “كارت هدية”; “kart hedeya” |
| `authority` | **invented:** “CEO”, “manager”; “المدير التنفيذي”; “أنا مديرك”; “ana modeerak” |
| `bypass_verification` | **invented:** “do not call to verify”; “لا تتصل للتأكد”; “ماتتصلش تتأكد”; “matetesselsh tet2aked” |

These seed cues are not a complete executable lexicon. Before fixtures are run,
freeze an explicit finite manifest of phrases, token boundaries, inflections,
negation/quotation contexts and destination extraction grammar with its digest.
Unlisted spellings are uncovered, not automatically translated. Phrase expansion
after results requires a new version and fresh report families (§4).

Destination types: bank-account token, IBAN-labelled token, wallet phone/handle,
or payment-app handle. An explicit label plus syntactically extractable value is
required; a bare number, price, order number or a mere provider mention does not
qualify. Bank/IBAN format/checksum and app-handle semantics are **to verify**;
do not claim validation or ownership. Until a format grammar is verified, use
`destination_label_present` and cap dependent rules at low/undetermined.

Quoted/forwarded blocks, signatures, negation, advice and fraud-awareness examples
must not be promoted to active requests. Document 2 supplies parser quote
boundaries. SMS uses only frozen explicit quote/negation rules; ambiguous scope
sets `payment_context_ambiguous` and prevents medium/high escalation. No silent
semantic certainty from keywords.

### 2.2 Fixed rule list

`P` is active request + payment object, with no negation/quotation/ambiguity.
`D` is an extractable payment destination under the frozen grammar. `R` is a
fresh actionable provider claim/proof conflict from document 1. `H` is a usable
user-attested provider failure from document 2; untrusted/error/ARC reports do
not count. Several authentication methods are one `H` family.

| Rule / reason code | Fixed condition | Base kind / severity |
| --- | --- | --- |
| B1 `payment_destination_change` | `P` + change + bank-account/IBAN-labelled `D` | `payment_change_request` / low |
| B2 `payment_urgent_request` | `P` + urgency | `payment_pressure_request` / low |
| B3 `payment_new_transfer_recipient` | `P` + wallet/payment-app context + explicit new recipient/change + `D` | `payment_change_request` / low |
| B4 `payment_gift_card_request` | Active purchase/send request + gift-card object + urgency or request to send redemption code | `payment_pressure_request` / low |
| B5 `payment_authority_claim` | B1–B4 plus active first-person executive/manager claim or imperative explicitly attributed to that claimed role | `payment_authority_request` / low |
| B6 `payment_request_source_conflict` | B1–B5 plus independent `R` or `H` | `payment_source_conflict` / medium |
| B7 `payment_diversion_corroborated` | B1 or B3, plus `R` and independent `H`; for SMS, plus `R` containing independently mismatched fresh domain and sender/callback families instead of `H` | `payment_diversion_suspected` / high |
| Context `payment_verification_bypass` | B1–B5 plus bypass-verification cue | Evidence modifier only; no severity increase by itself |

For payment-app context, “InstaPay” is a requested brand-word match, not an
assertion about that service's transfer API, identifier format or ownership.
Other app/wallet words require the frozen manifest. No actual account numbers,
phone recipients or provider sender IDs are supplied here.

Run all rules; do not convert a model score into `R` or `H`. Header/registry
outcomes that share the same From-domain mismatch are one source-conflict
family, not two. B7 requires an independent provider-reported failure (email) or
separate sender/callback mismatch (SMS), as well as the payment diversion request.
Deployed URL/text models can be displayed separately but never satisfy B6/B7.

## 3. Data and sources

Use exclusively **invented** scenario fixtures for this v1 design. Each carries
`invented=true`, language, channel, template family, intended request/quote state,
expected rule IDs, severity, confidence and header/registry trust state.
Invented email headers and destination strings stay explicitly labelled. Use
`example.com`-style domains for any future invented email/link fixtures and
opaque invalid payment placeholders, never plausible live bank recipients.
If invalid placeholders cannot exercise a verified grammar, use a synthetic
test-only grammar; never claim that it validates real bank/app identifiers.

Do not relabel generated/translated material as genuine Egyptian messages or
use it to assert local fraud prevalence. Existing exposed project probes are
regression controls only, not new independent test evidence. Future real SMS
research needs separate consent/provenance/licence review and a new protocol;
none is authorized here. Current genuine Egyptian final-test count stays as
recorded in `README.md`, with no new real observations from this batch.

## 4. Evaluation rule — before measurement

Initial pre-result rule dated **26 November 2026**. Before any measurement,
freeze this rule SHA-256, complete B1–B7/phrase/grammar manifests, parser limits,
invented fixture labels/family lists, dependency digests and failure policy.
Use a separately authorized report location, without writing `evaluation/` now.

Construct development and report families before running. For every B rule,
cover all four language varieties and both supported channels where applicable,
with matching, partial and absent registry/header evidence. Each family contains
a positive and a minimal negative for every required predicate; keep paraphrases
and translations within one split. Include unknown-newness, bare numbers,
negated requests, forwarded awareness examples, executive-title signatures,
normal invoices, legitimate urgent payments, gift-card shopping, legitimate
announced account changes and approved wallet-recipient changes.

Labels describe rule predicates, **not proven fraud**. A legitimate active
account-change request may intentionally produce low informational review;
benign labels must not be rewritten as attacks to improve counts. Adversarial
fixtures specify fabricated contradictory source evidence explicitly. A second
reviewer signs expected labels before execution; unresolved cases are frozen as
ambiguous and count as false alarms if escalated.

Gates (normative choices, not measured claims):

- Every fixed rule's expected positive/negative and every severity/confidence
  row must pass on development; no rule is silently dropped or tuned.
- **Zero medium/high Findings on all invented benign or ambiguous controls**,
  both per rule and for the union of the candidate set. Low Findings are also
  reported as review burden, not hidden as successful benign classification.
- **Zero high Findings from content alone**, from untrusted headers, unknown
  recipient history, or one duplicated source-conflict family.
- Zero existing verdict differences, external network attempts, leaked content
  or persisted payment destinations, including destination hashes (§7).

Freeze the whole candidate set before one report-set pass. Report-set gate
failures block release; disclose exposure and use fresh report families after a
fix. Report per-rule/union confusion counts for each severity, language/channel,
request family and trust/coverage stratum; denominators, ambiguous/excluded
cases, unavailable checks, low review burden, and source-rule ablation counts.
Show raw request detection separately from suspected-diversion detection.

No measurement is made here. Invented correctness/false-alarm checks do not
estimate Egyptian population accuracy. No sealed final test is opened or run.
Amendments are dated pre-result records citing the previous hash, rationale and
fresh affected family manifest; no retrospective threshold/gate relaxation.

## 5. ATT&CK

Checked 26 November 2026 against the read-only v20.0 fallback catalogues and
exact pinned hashes recorded in [provider registry §5](provider-registry-v1.md#5-attack).
Enterprise `T1684.001` Impersonation and `T1657` Financial Theft are present,
neither revoked nor deprecated. The latter describes financial theft, but a
request is not evidence that money was stolen: **do not emit `T1657` in v1**.

Emit Enterprise `T1684.001` only when B5's active claimed role or a provider
self-claim participates in B6/B7 with independent contradictory identity
evidence, basis `payment_claim_identity_conflict`. A role title plus header
failure without an identity contradiction is insufficient. Financial-request
rules B1–B4 alone map to nothing. Mobile `T1660` is locally checked as active;
use only for explicitly SMS-channel deceptive requests also satisfying document
1's `sms_deceptive_action` basis, never for any payment SMS by default. No
mapping from verdict, urgency, successful authentication or a model score.
Validate mappings again through core `record_findings`.

## 6. Findings

`finding-v1`, domain `phishing`, engine `phishing.payment_rules`, version pins
rules/phrases/grammar/registry/profile digests. Source `scan` or `import`, opaque
local ref. One Finding per matched rule and message/scan; several matches of one
phrase do not multiply alerts. B6/B7 are separate rule Findings with references
to their supporting rule IDs; do not delete or overwrite dependency Findings.
The union false-alarm count is one input with any medium/high Finding; per-rule
counts count each emitted rule once. UI groups a message's Findings for review
without summing scores or changing the deployed verdict.

| Kind / reason | Severity |
| --- | --- |
| B1–B5 request/change/pressure/authority observations | low |
| B6 source conflict | medium |
| B7 independently corroborated suspected diversion | high |
| `payment_check_incomplete`, unavailable/ambiguous context | info |

| Basis | Confidence |
| --- | --- |
| Content family only | single_signal |
| Content plus independent usable source-conflict family | corroborated |
| Unknown grammar, stale/partial source proof or ambiguous scope | undetermined; cannot qualify for B6/B7 |

Never `confirmed` or `critical`. Urgency, claimed authority, gift-card and
verification-bypass wording from one message are one content family, not
independent identity proof. B7's higher severity reflects diversion plus
independent source evidence, not a calibrated loss estimate.

Evidence contains codes, phrase-rule IDs (not matched words), destination type,
explicit-change flag, coverage/trust enums, dependency Finding IDs and version
digests. Never amount, currency value, bank/IBAN digits, beneficiary names,
wallet handles, redemption codes, body/header snippets or generated summaries.

Indicators: only rule-relevant hash-only suspicious delivery URL/domain/email
or sender/callback phone, normalized by core, `value=None`, registered-domain
hash as applicable. Never bank accounts, IBANs, wallet handles/phones used as
payment recipients, or gift-card codes, even hashed. Do not coerce payment data
into the core `hash` type. A phone used only as recipient is not a contact pivot;
if its role is ambiguous, withhold it. Correlation uses only permitted delivery
indicators through unchanged `record_findings`, with official/shared-service
exclusions. No pivot by role title, amount, payment app, claimed provider or
message-level rule reference. Content-only Findings may have no indicators and
stay unassigned; accept this limitation rather than inventing a pivot.

## 7. Privacy

Read source content only in memory, discard parsed payments immediately after
rule outcomes. Store fixed codes/types/versions, opaque source refs and permitted
hash-only delivery indicators. Do not persist payment-recipient values or their
hashes anywhere, including import identifiers, logs, caches and exports. Reuse
document 2's import ID; do not hash the payment substring to create a reference.
No payment/call/send button, contact sync or external telemetry.

For mail imports, file hashes remain import-layer identifiers under document 2,
not payment evidence or correlation keys. Import deletion/expiry uses the
configured core retention period, removes Findings/orphan indicators and cleans
derived incident references; scan-only cascades cannot cover imports. Implement
that ownership before enabling storage. The user keeps the original file; ETIS
does not copy it. No runtime DB/key or private mail is committed.

## 8. Test plan

Invented minimal pairs for each B1–B7 predicate and each §6 row; language/script
normalization and ambiguity; explicit/unknown new recipient; bank labels versus
invoice IDs; urgency and gift-card shopping; CEO/manager signatures versus active
claims; denial/quotation/forwarding; verified-grammar unavailable state. Test
header pass does not suppress content observations, forged headers cannot
escalate, and shared From-domain evidence cannot count twice.

Use isolated databases and blocked sockets. Marker tests inspect logs, errors,
exports and storage for raw or hashed payment identifiers and private snippets.
Verify dependency IDs match the same import/version, retention, idempotence,
official-contact exclusions and indicator-free Findings. Future implementation
runs existing verdict parity, pytest, database initialization, frontend build and
lint at each relevant commit. No new model measurement or sealed final test.

## 9. Implementation steps (small commits)

1. Freeze finite phrase/grammar/context manifests and invented expected labels.
2. Pure clause/quote/negation parser with privacy and unavailable-coverage tests.
3. B1–B5 request detectors with fixed reason codes and low-only content results.
4. B6/B7 adapters to documents 1 and 2 with explicit independence checks.
5. Findings adapter via `record_findings`, import deletion and no-payment-storage checks.
6. Bilingual grouped review display separate from existing verdicts/models.
7. Freeze §4 evaluation manifests and run the exposed protocol; report all gates
   and limitations. Apply §8 checks throughout future implementation.

### Open questions

- Who reviews the finite Arabic/dialect/Franco lexicon and invented scenario labels before execution?
- Which verified local grammar can recognize bank/IBAN/wallet destinations without pretending to validate ownership?
- How will quote/negation ambiguity be exposed clearly in the import review UI?
- Is a separately consented employer/counterparty baseline desired in a later version? It is absent from v1.
- What import deletion owner satisfies the shared retention dependency in documents 1 and 2?

## 10. To verify

- **To verify:** IBAN/account syntax and any checksum rules; read the official
  SWIFT IBAN registry and official provider publications. Do not infer Egyptian
  formats or lengths from examples or invent recipient data.
- **To verify:** InstaPay and wallet identifier semantics, official contacts and
  delegation; use official provider publications researched separately under
  document 1. No account/app behavior is assumed here.
- **To verify:** mail authentication/trust/MIME standards and provider profiles;
  use document 2's RFC/provider reading list before those predicates can escalate.
- **To verify:** language/quotation coverage, parser limits and phrase provenance;
  obtain documented local reviewer decisions before freezing the manifests.
  Invented cues establish no prevalence or linguistic performance fact.
- **To verify:** data/financial-message retention and processing obligations;
  read official Egyptian legislation and `docs/data-licences.md`. No legal or
  financial advice or compliance certification is implied.

## Sources

Local: `CLAUDE.md`, `README.md`, `docs/design/core-v1.md`,
`docs/engine-authors.md`, `docs/design/host-engine-v1.md`,
`docs/design/provider-registry-v1.md`, `docs/design/email-auth-check-v1.md`,
`backend/app/core/findings.py`, `backend/app/core/indicators.py`,
`backend/app/services/findings.py`, `data/attack-lock.json` and the read-only
local Enterprise/Mobile v20.0 catalogues (§5).

Unopened official reference, **to verify**, not an example payment destination:
[SWIFT IBAN information and registry](https://www.swift.com/standards/data-standards/iban).
Provider/RFC reading is inherited explicitly from documents 1 and 2; no fraud
statistics, bank contact details or external case study is asserted here.
