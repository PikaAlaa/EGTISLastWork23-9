# Email authentication check v1 — design

Status: **design only**, 26 November 2026. Proposed engine `phishing.email_headers`.
Depends on [provider registry v1](provider-registry-v1.md); no implementation or
measurement accompanies this document.

## 0. Constraints

Apply `CLAUDE.md`, `README.md`, [core v1](core-v1.md),
[engine authors](../engine-authors.md) and [host design](host-engine-v1.md).
Read user-selected local files only. Never resolve or fetch any address, URL,
remote image or key; never send messages, URLs, hashes or headers to an external
service. No DNS, WHOIS, mailbox API, mail sending or online lookups. All external
standards/provider details below are **to verify**, with sources in §10.

This batch adds this design only: no changes to existing files, `evaluation/`,
targets, frozen rules/splits, models, thresholds, `data/`, tests or dependencies.
Future rules return separate Findings through `record_findings`; they cannot
change `/analyze` or corroborate its deployed text/URL policy. No installations,
secrets, push, merge or history rewrite. Every generated header/message/address
example is **invented** and no genuine Egyptian corpus is claimed.

## 1. Scope and inputs

Import an explicitly selected `.eml` file read in place. There is no automatic
mailbox watching, provider login or remote upload. Parse message headers and
bounded text/HTML body parts in memory. Never execute/render HTML, load external
resources, open attachments or recurse into attached messages. Encrypted,
unsupported or malformed parts are unavailable coverage, never clean results.

The user optionally selects a previously reviewed local receiving-provider
profile and attests that the file is an unmodified export from that mailbox.
No profile is guessed from an email domain or from the headers themselves.
Profiles hold exact permitted `authserv-id` values, header-boundary selection,
duplicate handling and documented export provenance. Real provider profiles are
empty until separately verified. Numeric byte/part/depth/token limits and parser
choice must be frozen before parsing fixtures (§10); over-limit input fails
closed for this import, with no partial success presented as a complete check.

## 2. Detection logic

### 2.1 Reported authentication, not re-verification

Authentication-Results, ARC-Authentication-Results, ARC-Seal,
ARC-Message-Signature and Received-SPF are **reported statements in a file**.
An attacker can supply a file containing plausible headers. No content-only
algorithm establishes their provenance. The default state is
`untrusted_header_report`. Even a reviewed profile plus user attestation gives
`user_attested_provider_report`, not cryptographically verified authentication.

Provider-specific ordering/stripping and header semantics are **to verify**
(RFC 8601, RFC 8617, RFC 7208 and provider export documentation). The design
requires a deterministic profile selector that refuses ambiguous or duplicate
candidate trusted blocks; it must never choose whichever result says pass/fail.
`authserv-id` equality alone cannot establish trust. Headers outside the chosen
receiving boundary, lower injected blocks and forwarded copies cannot override
it. If no safe documented boundary exists, report untrusted coverage only.

Parse method/result tokens using a pinned grammar, retaining `pass`, `fail`,
`softfail`, `neutral`, `none`, `temperror`, `permerror`, `unknown` as distinct
observations where applicable. A missing/unknown/error result is not `fail`.
Do not apply one method's vocabulary to another without verification. Multiple
methods reported in the same provider block are one evidence family.

| Code | Predicate / interpretation |
| --- | --- |
| `email_provider_auth_failure_reported` | Selected user-attested provider block explicitly reports DMARC fail, or explicitly reports failure for every available SPF/DKIM method with no pass. Method/result grammar must be verified before enabling. A pass for one method prevents this fallback predicate. |
| `email_auth_report_conflict` | Selected Authentication-Results and Received-SPF reports disagree for the same identity/method, or duplicate trusted candidates conflict; downgrade to unavailable trust, do not pick a result. |
| `email_auth_report_untrusted` | Missing safe profile, ambiguous boundary or absent export attestation; diagnostic only. |
| `email_auth_not_visible` | No usable method results, parse/coverage failure or unavailable profile. Diagnostic only. |

Keep individual reported method states even when the aggregate rule does not
fire. Received-SPF is supplemental and never promotes an untrusted block.
ARC presence/order/result tokens are displayed only as `reported_arc_present`,
`reported_arc_incomplete` or `reported_arc_conflict`. ETIS does **not** validate
seals, recover trust from an ARC pass, recompute SPF/DKIM/DMARC, or infer ARC
trust from an instance number. No DNS or public-key retrieval.

### 2.2 Identity comparison and provider impersonation

Parse From, Reply-To and Return-Path into structured mailbox identities before
comparison; decode display names in memory. Reject ambiguous multiple From
identities for identity rules. Empty Return-Path, forwarding, lists, separate
bounce domains and approved delegated senders are explicit controls, not proof
of compromise. Standards semantics are **to verify** (§10).

| Code | Fixed predicate |
| --- | --- |
| `email_reply_to_domain_differs` | Single usable From and Reply-To have different canonical domains and no reviewed explicit delegation; observation only. |
| `email_return_path_domain_differs` | Nonempty usable Return-Path domain differs from From, with no explicit delegation; observation only. |
| `email_provider_display_claim_conflict` | Unambiguous self-identifying display-name registry claim and a fresh documented From-domain mismatch under provider-registry-v1. Partial/stale sets retain that design's uncertainty caps. |
| `email_link_model_signal` | A body link's unchanged deployed URL-model scorer supplies a signal at its existing frozen threshold; a separate low-severity Finding, never an assertion that the link is malicious. |

Use exact host comparison first. Registrable-domain comparison is labelled
separately, depends on document 1's pinned offline suffix policy, and cannot
silently bless all sibling subdomains. Different local parts alone do not make
a domain mismatch. Registry match does not authenticate a sender. Any delegated
sender exception requires its own reviewed channel/purpose provenance; unknown
delegation is not invented as an exception.

### 2.3 Body links

Extract only explicit HTTP(S) destination strings from text and inert HTML link
attributes; do not follow redirects, resolve relative links against remote
resources, decode data URLs or inspect remote/embedded payloads. Other schemes
are unsupported coverage and never fetched. Label anchor-versus-target host
differences as observations, not independent corroboration of the same host.
Deduplicate canonical targets in memory without persisting a link inventory.

A local orchestration service calls the existing pure URL-model scorer with its
unchanged input preparation/model/threshold and passes the finished observation
to the engine. Do not call the saving `/analyze` endpoint for each link and do
not import or alter `risk_scoring` inside this engine. Expose model unavailability
and raw support separately from existing policy eligibility. Scores are indicator
strengths, not calibrated probabilities or email authentication results. The
deployed text model is not trained on imported email by this design.

## 3. Data and sources

No real mailbox or provider behavior is researched here. Future local profiles
must cite the provider's official header/export documentation, read date,
verifier and selection algorithm digest. Freeze parser/grammar versions,
registry digest, optional delegation-table digest and model identity. Unknown
providers run only untrusted-report and identity/body checks with explicit
coverage flags. Parsing a familiar-looking header is not a verified profile.

Fixtures are exclusively **invented** `.eml` constructions with expected parse
trees, trust state and rule outcomes. Include realistic-looking forged headers
labelled invented; never source them from real private mail. No data files are
created in this batch and no received message is reproduced in this document.

## 4. Evaluation rule — before measurement

Initial pre-result rule: **26 November 2026**, no measurements. Before execution,
freeze the rule SHA-256, fixture-label/family manifest, profiles, parser limits,
registry/suffix digests and unchanged model version/threshold. Use a separately
authorized report destination; never alter `evaluation/` in this batch.

Data strata: invented authentic-looking provider reports, injected duplicate
blocks, forged exports, missing headers, forwarding/list/bounce cases, display
claims, inert HTML and link-model availability states. Build minimal pairs
changing only one predicate. Freeze exposed development/report family lists
before any run; related encodings and language variants stay together. Expected
body-model numeric outputs are not fabricated: deterministic scorer stubs test
the boundary logic, and a separately reported real-scorer smoke check discloses
actual outputs without selecting new thresholds.

Gates: all declared parse/trust/rule expectations pass; zero medium/high Findings
on invented benign forwarding/list/delegation controls; zero cases in which
untrusted headers are promoted to trusted results; zero high Findings from
header method multiplicity alone; zero network attempts, retained content or
existing verdict differences. Fail the candidate as a whole, with no selection
on report outcomes. Freeze candidate before one report-family pass; report
failures block release and expose that set for future versions.

Report per-rule TP/FP/FN/TN counts and denominators against intended fixture
labels, by trust/coverage/language stratum; parser failures, links skipped,
unavailable checks, method disagreements and correlation counts separately.
These are invented-fixture correctness results, not Egyptian mail accuracy,
spam prevalence or authentication validation. No sealed final test is run.
Dated pre-result amendments must cite the previous rule hash and freeze fresh
affected report families before measurement; post-result edits disclose exposure
and require a new version, never a retroactive gate change.

## 5. ATT&CK

Local verification on 26 November 2026 uses the read-only fallback catalogues
and exact lock hashes documented in [provider registry §5](provider-registry-v1.md#5-attack).
Enterprise v20.0 `T1684.001` Impersonation is present, not revoked/deprecated.
Map it only for an unambiguous provider self-claim plus actionable conflicting
identity evidence, basis `email_provider_identity_conflict`. No ATT&CK mapping
for authentication failure, Reply-To difference, ARC state or URL-model score
alone. Body link existence does not establish spearphishing delivery; further
link-technique mapping is **to verify** and disabled. Never infer execution,
account compromise or completed fraud. No verdict-only mapping; validate through
`record_findings` again when emitting.

## 6. Findings

Use `finding-v1`, domain `phishing`, engine `phishing.email_headers`; version
pins parser/profile/registry/rule digests and model identity. Source
`{kind: import, ref: <opaque local import ID>}`. One Finding per rule/message,
except link-model observations grouped per canonical target hash. Reimport of
the same file within the retained import scope is idempotent; new rule versions
are separately labelled, never backfilled as newly observed messages.

| Kind / condition | Severity |
| --- | --- |
| `email_auth_reported_failure`: usable user-attested provider failure | low |
| `email_identity_difference`: Reply-To or Return-Path domain difference | low |
| `email_provider_impersonation`: actionable fresh provider conflict | medium; low when registry coverage is partial |
| Same kind plus an independent user-attested provider failure or independently mismatched callback | high; never from link spelling plus display spelling alone |
| `email_link_model_observation`: existing frozen model support only | low |
| `email_check_incomplete`: missing/untrusted/conflicting input coverage | info |

| Basis | Confidence |
| --- | --- |
| One usable identity, header-report or model family | single_signal |
| Actionable registry conflict and independent usable header/callback family | corroborated, explicitly still user-attested provenance |
| Missing, conflicting or untrusted report, or partial registry coverage | undetermined |

Never `confirmed` or `critical`. Two SPF/DKIM/DMARC results from one header block
are one family. From/Return-Path mismatch derived from that same authentication
identity is not a second independent family. Pass reports never suppress other
rules; compromised legitimate accounts are outside what these headers can prove.

Indicators are hash-only normalized suspicious `email`, `domain`, `url`, `phone`
as applicable, `value=None`, with core registered-domain hashes. Recipient
addresses and Received hop IPs never become indicators. Emit only indicators
actually relevant to the rule, not every identity or link in the file.
Evidence: fixed reason/method/result/trust enums, parser/profile/registry/model
versions, coverage flags, import ref and rule ID. Store file SHA-256 and hashed
Message-ID as local dedup identifiers only, never as `hash` threat indicators.
Do not store `authserv-id` raw from the message; retain the approved profile ID.

All Findings go through `record_findings`. Existing shared-hosting/official
provider-domain/contact/stoplist exclusions apply. Same suspicious delivery host
can correlate with other phishing Findings. Shared provider, receiving service,
Message-ID, import/file digest or authentication result never pivots incidents.
No invented sender-ID indicator type. Document 1's exclusion integration is a
dependency, not permission to change frozen brand rules.

## 7. Privacy

| Stored locally | Never persisted or transmitted externally |
| --- | --- |
| Opaque import ID; file digest; hashed Message-ID; rule/version/trust enums and coverage flags | `.eml` bytes, file name/path, raw headers, Message-ID, display/recipient names and addresses |
| Relevant hash-only indicator refs with `value=None` | Body, subject, snippets, attachment names/bytes, signatures, raw ARC/DKIM material |
| Core observation timestamps generated at import | Received chains/IPs, original message timestamps, full link lists or parser error excerpts |

Identifiers use local SHA-256 over pinned normalization; hashes remain
pseudonymous (core v1), never anonymous. Use opaque source references, never a
raw Message-ID. Parsing buffers are discarded on success/failure; no temporary
mail copies, debug dumps, telemetry or HTML previews. The user's original file
is never edited or deleted by ETIS. Logs and errors contain fixed codes only.

Before implementation, add explicit import retention/deletion ownership using
the configured core retention period, cascading imported Findings and cleaning
orphan indicators and derived incident references. Existing scan cascades alone
are insufficient. No raw mail or runtime keys/databases enter Git.

## 8. Test plan

Invented folded/encoded headers; duplicate/authserv-ID spoofing; attested versus
untrusted exports; ARC pass that grants no trust; null/multiple/malformed
addresses; legitimate forwarding/lists/bounce/delegation; registry freshness and
display-claim ambiguity. Verify inert HTML extraction, no remote images,
attachments/data-URL decoding, link dedup, model-unavailable state and unchanged
model input/threshold behavior. Bounded parser and cancellation cases must not
leave content in storage or logs. Use marker strings and isolated databases;
test source refs, hash normalization, core correlation and deletion. Block all
sockets. Future implementation runs parity, pytest, database initialization,
frontend build and lint; no sealed final test.

## 9. Implementation steps (small commits)

1. Freeze parser/limits/trust-profile schema; add invented-only parsing fixtures.
2. Pure header report selector with untrusted default and ARC observation states.
3. Identity and registry matcher adapter; delegated-sender coverage controls.
4. Inert body extractor and existing-model observation wrapper, with no scan saves.
5. Findings/health adapter through `record_findings`; idempotent import metadata.
6. Retention, privacy/correlation checks and local bilingual import review UI.
7. Freeze §4 manifests, then run the exposed evaluation; implementation checks
   from §8 apply to each relevant commit. No provider research implied.

### Open questions

- Which receiving-provider export profiles can establish a documented boundary, and how will users attest provenance?
- Which parser and explicit resource limits cover malformed MIME safely on the project PC?
- How should legitimate delegated senders be curated without treating partial coverage as fraud?
- Which import owner handles deletion and dedup retention without preserving private mail metadata?

## 10. To verify

- **To verify:** Authentication-Results grammar, trust boundary and method result
  semantics; read RFC 8601 and official receiving-provider header/export docs.
- **To verify:** SPF/DKIM/DMARC identity and reported-result semantics, null reverse
  paths and current standards status; read RFC 7208, RFC 6376, RFC 7489 and their
  official updates. No DNS or signature checking will be implemented here.
- **To verify:** ARC grammar, ordering and trust limitations; read RFC 8617.
- **To verify:** mailbox syntax, encoding, folding and MIME parser limitations;
  read RFC 5322, RFC 2045, RFC 2047 and the selected parser's official docs.
- **To verify:** provider/delegation facts and suffix/confusable pins; use document
  1's verification list and official provider publications, never inferred claims.
- **To verify:** applicable email-retention/processing law and fixture licence
  obligations; read official legislation and `docs/data-licences.md`. No legal
  compliance is claimed by hashing alone.

## Sources

Local sources read: `CLAUDE.md`, `README.md`, `docs/design/core-v1.md`,
`docs/engine-authors.md`, `docs/design/host-engine-v1.md`,
`docs/design/provider-registry-v1.md`, `backend/app/core/findings.py`,
`backend/app/core/indicators.py`, `backend/app/services/findings.py`,
`backend/app/engines/registry.py`, `docs/api-v2.md`, `data/attack-lock.json` and
the read-only local v20.0 catalogues (§5).

Unopened reading sources, all **to verify**, not example mail destinations:
[RFC 8601](https://www.rfc-editor.org/rfc/rfc8601),
[RFC 8617](https://www.rfc-editor.org/rfc/rfc8617),
[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208),
[RFC 6376](https://www.rfc-editor.org/rfc/rfc6376),
[RFC 7489](https://www.rfc-editor.org/rfc/rfc7489),
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322),
[RFC 2045](https://www.rfc-editor.org/rfc/rfc2045),
[RFC 2047](https://www.rfc-editor.org/rfc/rfc2047).
