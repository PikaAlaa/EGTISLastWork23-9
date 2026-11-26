# Provider registry v1 — design

Status: **design only**, 26 November 2026. Proposed engine `phishing.provider_claim`.
No registry file, provider research, implementation, measurement or download is included.

## 0. Constraints

Follow `CLAUDE.md`, `README.md`, [core v1](core-v1.md),
[engine authors](../engine-authors.md) and [host design](host-engine-v1.md).
Everything runs locally. URLs are inert strings: no DNS, WHOIS, redirects, HTTP
requests or external submissions of messages, URLs, hashes or headers. Source
references below are reading tasks, not permission to contact them in this batch.
External facts absent from the repository are **to verify**.

This batch creates this document only. Existing files, `evaluation/`, its targets,
frozen rules/splits, `data/`, `ml/models`, dependencies and deployed models and
thresholds are untouched. Future detections are additive Findings through
`record_findings`; they cannot become corroboration for the existing verdict path.
No secrets, installation, push, merge or history rewrite. All generated examples
are **invented**, never genuine Egyptian observations.

## 1. Scope and inputs

Curate Egyptian banks, mobile operators, payment apps (including InstaPay as a
requested research category, with no asserted contacts), government services and
couriers. The registry expresses documented contact scope, never a complete list
of legitimate traffic. Unknown providers and missing fields mean unknown.

Inputs are the locally pinned registry and an explicit user scan/import carrying
message text, channel and optional sender-display string, sender ID or phone.
Sender-display and sender ID are claims, not authenticated identities. Email
display names use this matcher through [email auth check](email-auth-check-v1.md).
No contact-book access or automatic sender inference is included.

### 1.1 Proposed registry schema

The future versioned JSON file has `schema_version`, `registry_version`,
`released_at`, `example_only` and `entries`. A separate release manifest pins its
exact byte SHA-256, schema SHA-256, normalization version and matching-table
SHA-256. Do not put a file's own digest inside the bytes being hashed.

| Entry field | Required meaning |
| --- | --- |
| `provider_id`, `category`, `display_name`, `invented` | Stable internal ID; one of the categories above; public name; explicit example flag. |
| `aliases[]` | Exact reviewed alias, language/script tag (`ar`, Egyptian dialect, Franco-Arabic, English), claim context and provenance reference. Empty means no alias coverage. |
| `domains[]` | ASCII canonical host, `match_scope: exact_host|subdomains|registrable_domain`, channel, purpose and provenance reference. No wildcard implied by an exact host. |
| `sender_ids[]` | Literal alphanumeric ID, channel and documented comparison policy; source per ID. |
| `sms_short_codes[]`, `hotlines[]` | Separately typed contact, documented channel/purpose, normalized value and source. A hotline is not automatically an outbound SMS sender. |
| `sources[]` | Official source URL, `read_at` date, local verifier reference, supported field paths and source-note digest. |
| `coverage` | Per-channel/per-field `documented_partial|documented_complete|unknown`, supported by provenance. Completeness is never assumed. |
| `verified_at`, `review_due_at`, `status` | Actual review dates; `active|stale|withdrawn|example_only`. Missing dates cannot imply freshness. |

**Invented example only** (documentation fixture, no actual provider or working
contact; every name, alias and domain in this block is invented):

```json
{
  "schema_version": "provider-registry-v1",
  "registry_version": "example-only",
  "released_at": null,
  "example_only": true,
  "entries": [{
    "provider_id": "invented_example_bank",
    "category": "bank",
    "display_name": "Invented Example Bank",
    "invented": true,
    "aliases": [
      {"value": "بنك المثال المخترع", "language": "ar", "source_ref": "invented_source"},
      {"value": "Invented Example Bank", "language": "en", "source_ref": "invented_source"}
    ],
    "domains": [{"host": "example.com", "match_scope": "exact_host", "channel": "web", "purpose": "invented", "source_ref": "invented_source"}],
    "sender_ids": [{"value": "INVENTEDBANK", "channel": "sms", "comparison": "literal", "source_ref": "invented_source"}],
    "sms_short_codes": [],
    "hotlines": [],
    "sources": [{"id": "invented_source", "url": "https://example.com/invented-provider-source", "read_at": null, "verifier": "invented-not-a-verifier", "field_paths": [], "note_digest": null}],
    "coverage": {"sms": "unknown", "web": "unknown", "phone": "unknown"},
    "verified_at": null,
    "review_due_at": null,
    "status": "example_only"
  }]
}
```

No data file is created in this batch. At later implementation the file must be
empty of real entries, containing only this invented fixture until separate
research is authorized. Empty phone lists deliberately avoid fabricated official
numbers. Example records are rejected by the production loader and enabled only
in explicitly labelled demonstration/test mode. Missing real provenance is
invalid for an active entry, while null dates are allowed only for this fixture.

## 2. Detection logic

### 2.1 Claim versus proof

1. Use versioned exact alias tables with token boundaries. Normalize Arabic
   diacritics/tatweel and selected letter variants only in a documented claim
   view; retain literal input only in memory. English case folding and explicitly
   curated Egyptian dialect/Franco-Arabic aliases are separate views. No
   translation, generated aliases or unrestricted transliteration at runtime.
2. A claim requires a provider identity assertion, sender display/ID, or reviewed
   self-identification phrase. Mere mentions, quoted warnings and unrelated brand
   words do not establish a claim. Ambiguous/multiple provider claims produce
   `provider_claim_ambiguous`, with no mismatch alert until disambiguated.
3. Extract each claimed provider's action destination: link host, actual sender
   ID/phone, callback phone. Compare like roles only. A quoted hotline cannot
   authenticate an unrelated link. Keep `match`, `outside_documented_set`,
   `unknown`, `invalid`, `stale` distinct for every proof channel.
4. Exact host matching uses the existing offline URL/IDNA parser. Explicit
   subdomain permission requires a label boundary. Registrable-domain matching
   uses a pinned local suffix snapshot only after §10 is resolved; otherwise that
   check is unavailable. Never reduce a host to its last two labels. IP literals,
   userinfo, malformed hosts and absent links never become domain matches.
5. Compare ASCII/punycode hosts literally; a decoded Unicode view and a pinned
   confusable table may produce a look-alike observation. Punycode alone is not
   proof of impersonation. Skeleton equality never grants an official match.
   Suffix and Unicode standards details are **to verify** (§10).
6. A fresh documented mismatch plus an action directed to that mismatched
   destination produces a rule Finding. Missing/partial coverage caps a mere
   outside-set observation at low severity; absence from a curated list does not
   prove fraud. No match proves the message legitimate or suppresses a model.

### 2.2 Fixed reason codes

| Code | Predicate |
| --- | --- |
| `provider_domain_outside_set` | Unambiguous claim, actionable link and host outside the claimed provider's documented scope. |
| `provider_sender_outside_set` | Claim and comparable sender ID/number outside the documented outbound set. |
| `provider_callback_outside_set` | Claim and requested callback outside the documented callback set. |
| `provider_lookalike_host` | Claimed provider, nonmatching host and exact match under the pinned confusable transform; never skeleton-only identity proof. |
| `provider_claim_ambiguous` | Claim cannot be attributed uniquely; coverage metadata only. |
| `provider_registry_stale`, `provider_registry_unavailable`, `provider_suffix_unavailable` | Required pinned material is stale, missing or invalid; do not fabricate a mismatch. |

Identical link mismatch and look-alike derivations are one evidence family.
Registry failures degrade this engine only. The existing model results remain
unchanged and separately visible.

## 3. Data and sources

No real contacts are asserted or researched here. Future curation requires an
official provider publication for each field, actual read date, named local
verifier and independent reviewer. Search snippets, crowd reports and another
message's claims cannot establish official contacts. Existing
`docs/brand-sources.md`, brand domains and contacts are reference candidates;
they do not establish sender-ID or short-code coverage automatically.

Validation rejects unknown fields, duplicate IDs, conflicting contact ownership
without explicit shared-service scope, invalid provenance references, active
invented entries, missing dates, invalid normalization and unsupported scope.
Update process: separately authorized research → proposed field/provenance diff
→ reviewer sign-off → schema/offline-fixture checks → immutable release plus
digests → atomic local activation. Retain previous release for explicit rollback;
each scan records the release digest. No silent runtime refresh.

`review_due_at` is chosen by the curator with a documented rationale, not an
invented provider lifetime. Mark an entry stale when due, withdrawn, or source
support is disputed. Stale fields cannot support medium/high mismatch alerts;
keep their official-contact exclusions conservative until reviewed. Invalid
release digests fail closed for this engine without disabling existing scanners.

## 4. Evaluation rule — before measurement

Initial pre-result rule dated **26 November 2026**. No measurement has run.
Before execution, freeze this rule's byte SHA-256, fixture/expected-label manifest,
alias/confusable tables, registry/suffix digests and engine version in a new
separately authorized report location; this batch never writes `evaluation/`.

Data: exclusively **invented** positives and minimal-pair negatives across the
four language varieties, provider categories and proof roles; labelled unknown,
ambiguous, stale and partial-coverage cases are separate strata. Every fixture
has an invented label, template-family ID, expected reason/severity and evidence
family. Freeze family assignment into exposed development and report sets
before running; variants/translations remain in the same family. Freeze actual
counts before execution; no population size or accuracy is asserted here.

Gates: every declared predicate and expected outcome must pass in development;
zero medium/high Findings on invented benign/unknown/stale controls; zero
high Findings from a single proof family; zero verdict-parity differences; zero
network attempts or private-content persistence. Failure blocks the whole v1
rule set, with no result-driven pruning. Freeze the candidate manifest before
one report-set pass. Report every failure, per-rule confusion counts, denominators,
language/category/coverage strata, duplicate handling and unavailable checks.
Report-set failures block release; that set becomes exposed and cannot be reused
as independent confirmation of a fix.

This is correctness evidence on invented scenarios, never real Egyptian accuracy.
No sealed final test is opened or run. Amendments must be dated, cite the previous
rule SHA-256, explain the change and precede results on the affected fresh report
families. Post-result changes require a new version and disclose prior exposure.

## 5. ATT&CK

Checked locally on 26 November 2026, read-only from
`../ETIS/data/external/attack/` because this worktree lacks the catalogues.
Both hashes match `data/attack-lock.json`: Enterprise
`2339a3c36353d5ee2c07e98af3fafbf00761e0e3979ede06402657445b7b4278`;
Mobile `c7d6c923c1f8462ab1c5db0195d81e2585db9949d574128391c682f229c6695a`.

| Mapping | Required observed basis |
| --- | --- |
| Enterprise `T1684.001` Impersonation, v20.0, active | Unambiguous provider self-claim plus actionable mismatched proof; basis `provider_claim_proof_conflict`. Mere mention/outside-set alone gets no mapping. |
| Mobile `T1660` Phishing, v20.0, active | Explicit SMS channel plus an impersonating request to disclose a secret or follow a mismatched link; basis `sms_deceptive_action`. No mapping from sender mismatch alone. |

These objects were present, neither revoked nor deprecated. Enterprise `T1656`
was checked and is revoked; do not emit it. No inference of adversary domain
registration, successful compromise or financial loss. Verdict alone maps to
nothing. `record_findings` validates every emitted mapping again.

## 6. Findings

`finding-v1`, domain `phishing`, engine `phishing.provider_claim`, version pins
rule/registry/matcher digests. Group once per rule, claimed provider, observation
and mismatched proof hash. Source is `scan` or `import` with an opaque local ref.

| Kind / condition | Severity |
| --- | --- |
| `provider_proof_mismatch`: outside partial set without stronger evidence | low |
| `provider_proof_mismatch`: documented-complete fresh proof mismatch plus actionable self-claim; or pinned look-alike plus actionable self-claim | medium |
| Same kind, independently mismatched fresh domain and sender/callback, with action directed to the mismatch | high |
| `provider_check_incomplete`: stale/ambiguous/missing material | info; diagnostic only, no malicious assertion |

| Evidence | Confidence |
| --- | --- |
| One proof family with an unambiguous claim | single_signal |
| Independent domain and sender/callback families | corroborated |
| Partial/stale/ambiguous or unavailable check | undetermined |

Never `confirmed` or `critical`. A matching sender string is not authentication.
One host's spelling and confusable skeleton are not independent corroboration.
Only comparable fresh fields contribute to the high row.

Indicators: hash-only normalized `url`, `domain`, `phone` for mismatched action
destinations, with existing core normalization and `registered_domain_hash` for
domain/URL refs; `value=None`. Alphanumeric sender IDs are not a core indicator
type: retain only a comparison outcome, never invent a new type. Evidence holds
reason codes, provider ID, field/coverage status, rule/registry/suffix versions
and opaque local observation ref; no text, alias snippet or raw sender.

Use `record_findings` exclusively. Core correlation excludes official domains,
hotlines, short codes, shared hosting and stoplisted services. Do not emit official
matched contacts as suspicious pivots. Future registry exclusion integration
must preserve existing exclusions and analyst rows without editing frozen brand
rules. If integration cannot guarantee that, withhold affected indicators and
record the limitation. Claim/provider ID alone never links incidents.

## 7. Privacy

Messages and sender strings live only in memory. Persist allowed codes/versions,
hash-only indicators and opaque source references; no plaintext scan content,
phone lists, source file paths, matched snippets or telemetry. Hashes are
pseudonyms, not anonymity, especially for low-entropy phones (core v1).
Public registry provenance stays distinct from submitted evidence. Verifier
references are local team IDs, not personal contact details.

Import-derived Findings need explicit deletion/retention ownership before
implementation: expire with the configured core retention period, remove orphan
indicators, and redact derived incident references without retaining content.
Do not rely on scan-only cascades for imports. No key or runtime database enters Git.

## 8. Test plan

Offline invented fixtures cover literal/subdomain/registrable boundaries, Unicode
and punycode, Arabic normalization collisions, Franco ambiguity, quoted brands,
shared providers, legitimate third-party services, stale/missing releases and
digest rollback. Test every §6 table row and no double counting of evidence.
Block sockets, use isolated databases, assert normalization hash parity and
`record_findings` correlation exclusions. Marker strings must be absent from
database/log/error/export surfaces. Test import retention and engine-only health
failures. Future implementation checks include existing `/analyze` parity,
pytest, database initialization, frontend build and lint. No sealed-test run.

## 9. Implementation steps (small commits)

Future work only; each implementation commit runs the applicable project checks.

1. Schema, validator, invented-only fixture and exact-byte release lock.
2. Offline alias/proof normalizer and deterministic reason-code rules.
3. Pinned suffix/confusable adapters after verification; unavailable-check tests.
4. Findings adapter, health and safe exclusion integration through core services.
5. Import retention, privacy tests and separate rule-result console display.
6. Freeze the evaluation manifests; run only the exposed protocol in §4.
7. Separately authorized real-provider research and reviewed registry release.

### Open questions

- Who curates and independently reviews each provider category, and assigns review due dates?
- Which official publications explicitly describe outbound sender IDs, delegation and completeness?
- Which suffix/confusable snapshots and normalization policy can be pinned without changing core identity?
- What exact import deletion ownership and registry exclusion adapter fit the current core services?

## 10. To verify

- **To verify:** actual contacts, official domains, aliases, provider ownership,
  delegation and publication rights; read each provider's official contact/security
  publication during separately authorized research. No real source URL is guessed.
- **To verify:** public suffix snapshot provenance, licence, private-suffix policy,
  acquisition and SHA-256 pin; read the Public Suffix List documentation and inspect
  the repository's existing offline suffix handling. No automatic download.
- **To verify:** IDNA/Unicode confusable and Arabic normalization behavior and
  licence/version pin; read Unicode UTS #46 and UTS #39 and local parser behavior.
- **To verify:** telephone/short-code and sender-ID comparison semantics by
  channel; read official provider/operator numbering publications and ITU E.164.
- **To verify:** legal retention and redistribution obligations for public contact
  provenance and verifier references; read official Egyptian legislation and
  `docs/data-licences.md` before research or distribution. No legal claim here.

## Sources

Read locally: `CLAUDE.md`, `README.md`, `docs/design/core-v1.md`,
`docs/engine-authors.md`, `docs/design/host-engine-v1.md`,
`backend/app/core/findings.py`, `backend/app/core/indicators.py`,
`backend/app/services/findings.py`, `data/attack-lock.json`, and the two catalogues
at the read-only fallback path in §5. `docs/brand-sources.md` is a future curation
input, not newly verified official sender coverage.

Unopened reference sources, all **to verify**, not example destinations:
[Public Suffix List](https://publicsuffix.org/list/),
[UTS #46](https://www.unicode.org/reports/tr46/),
[UTS #39](https://www.unicode.org/reports/tr39/),
[ITU E.164](https://www.itu.int/rec/T-REC-E.164).
