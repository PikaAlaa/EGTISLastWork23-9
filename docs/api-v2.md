# Analyze API — decision-v2

`POST /analyze`, protected by server-side `X-API-Key` when configured. The browser uses
same-origin `/api/analyze` through the Node proxy and receives no key. Send JSON:

```json
{"url":"https://example.com/","text":"Optional suspicious message","sender_type":"unknown"}
```

At least one nonempty string is required. Text max 5,000 characters; URL max 2,048;
unknown fields, invalid hosts, schemes and ports return 400. HTTP(S), bare domains,
IDNA, userinfo and scheme-specific default ports use the shared parser. Fragments do
not change reputation identity; path/query case and content remain evidence. An
additional tracking-stripped lookup key never rewrites the analyzed URL.

`sender_type` is optional: `company_name`, `short_code`, `mobile_number` or `unknown`.
Omitting it or sending `null` means unknown. It describes what the user sees in the
SMS sender display; do not submit the actual number or sender name. Invalid enum
values/types return 400. The browser sends this field only with message text.

A bank, wallet, payment/finance or telecom sender claim together with
`sender_type=mobile_number` adds `brand_claim_from_mobile_number`. Named claims
use the eligible brand registry and curated Arabic/English keyword lists; branded
prefixes, sender signatures and explicit generic bank/wallet/telecom claims are
recognized. Casual mid-sentence brand mentions alone are insufficient. This is a
heuristic, not verified sender identity or an exhaustive claim parser.

This signal alone produces MEDIUM. It does not corroborate a high text-model score
into HIGH. Other independent decisive findings keep their normal precedence; missing
required checks still produce INCOMPLETE. Advice explains that banks normally send
under their company name, but sender names can be faked. A company-name/short-code
selection never reduces existing evidence or proves legitimacy.

The sender field is transient: no database column, input echo, browser storage or
logging is added. Existing minimal scan metadata can retain the computed reason code,
as it retains other supporting signals; the submitted sender category itself is not
stored. The existing privacy/retention policy is otherwise unchanged.

The response includes:

| Field | Meaning |
| --- | --- |
| verdict | LOW, MEDIUM, HIGH, INCOMPLETE |
| decisive_reason | Stable reason/rule code, translated by the client |
| supporting_signals | All applicable supporting/decisive reason codes |
| checked_links | Up to 10 destinations, real hosts, brand/pattern/blacklist findings |
| links_truncated | Additional destinations were present; analysis is incomplete |
| text_finding | Model output, model/artifact version and window count; nullable |
| analysis_complete | Whether every required applicable check completed |
| checks_unavailable | Stable failure codes without private snippets |
| final_score | Heuristic indicator strength; not calibrated confidence |
| policy_version | decision-v2 |
| timing_ms | Processing time |
| saved, save_error | Persistence outcome independent of the verdict |

The decision order is decisive HIGH, otherwise INCOMPLETE, otherwise supporting MEDIUM,
otherwise LOW. All applicable checks run before deciding. Official domains bypass only
brand resemblance; they never override text or exact-blacklist evidence. No arithmetic
fusion, confidence percentage or unvalidated two-signal escalation is used.

The current URL deployment uses corroboration-only model support at the frozen
calibration threshold, following the query-shortcut review of `16fc7a5`.
A raw model alert alone cannot create MEDIUM or corroborate text HIGH. Independent
brand evidence, an alerting pattern on the same link, domain blacklist evidence,
or an explicit secret request is required for URL-model support.
`url_model_raw_above_threshold` still reports the uncorrected classifier result;
`url_model_above_threshold` reports eligible support after policy and suppression.
See the [mitigation and recall cost](../evaluation/reports/2026-10-v4/query-shortcut/REPORT.md).
Text-only HIGH still requires corroboration. `checked_links[].patterns` contains flags eligible to
support a warning; `pattern_observations` retains all detected pattern flags,
including diagnostic observations that cannot create a warning alone. The
separately evaluated pattern policy and acceptance results are recorded in the
v4 report and deployment metadata. Official/shared-host model suppression and
decisive/incomplete precedence remain.

Brand findings can include `official_contact`: a manually verified organization-owned
contact page, Egyptian retail hotline and verification date. Details are from the
registry, never from submitted content. Four banks currently have sourced hotlines;
other brands fall back to advice to use an independently trusted app/contact channel.
Sources and dates are in `backend/app/core/brand_contacts.py`.

Raw message text is not echoed. Checked URLs are returned for the immediate analysis,
including path/query evidence, but are never persisted as scan submissions. Scan records
contain hashes, verdicts, reason codes and versions only. Model output probabilities
describe classifier output, not a validated probability that the user's message is fraud.

Database/model failures cannot silently become LOW. Missing authentication is 401,
throttling 429, unexpected unavailable service 503. Saving failure is a normal 200
verdict with `saved=false`. Health has separate live and component-aware ready routes.

## Core v1 additions (November 2026)

Design: [core v1](design/core-v1.md). None of these routes or records changes a verdict,
threshold, model or the `/analyze` response shape.

**Findings from `/analyze`.** With `ETIS_FINDINGS_ENABLED=1` (the default), HIGH,
MEDIUM and INCOMPLETE-with-signals scans also record one `finding-v1` Finding in the same
transaction as the scan record. LOW and signal-free INCOMPLETE record none. Indicators
from scans are stored as SHA-256 hashes only. If recording fails, the verdict is still
returned with `saved=false`, and neither the scan nor its finding is kept. Set
`ETIS_FINDINGS_ENABLED=0` to reproduce pre-core behaviour exactly. Retention
(`ETIS_RETENTION_DAYS`) deletes scan-derived findings and orphaned scan-only indicators.
Incidents keep a `findings_expired` event with the count.

**`GET /health/ready`** adds `engines`: per-engine `{domain, version, available, reason}`.
Today the only engine is `phishing.analyze`. The `status` field and the HTTP code are
computed exactly as before.

All routes below require `X-API-Key` when configured. The browser reaches them through
the same-origin proxy as `/api/...`. The proxy forwards only the listed paths and methods
and keeps its Host/Origin, session-cookie and rate-limit checks. Errors use
`{error, detail}` with fixed codes and never echo submitted values. Validation failures are
400 `invalid_input`, unknown ids 404 `not_found`, and refused workflow actions 409 with a code.

| Method and path | Purpose |
| --- | --- |
| `GET /incidents?status=&severity=&domain=&brand=&since=&until=&limit=&offset=` | Incident list. `brand` matches brands recorded in the incident's findings; dates filter last activity (UTC). |
| `GET /incidents/{id}` | Detail: findings timeline, indicators (URL values never listed; scan values hash-only), ATT&CK techniques, events, related/merge links, campaign, `expired_findings`. |
| `PATCH /incidents/{id}` | `{status?, resolution?, note?}`. Transitions: open→investigating, open/investigating→resolved (resolution required), resolved→open (note required). A note alone adds a note event. Codes: `invalid_transition`, `resolution_required`, `reopen_note_required`. |
| `POST /incidents/{id}/merge` | `{into, note?}`: moves findings and indicators into `into`; the source becomes resolved/duplicate with a `merged_into` link. Never automatic. |
| `GET /campaigns`, `POST /campaigns` | List; create `{name, description?}` (201). |
| `POST /campaigns/{id}/incidents` | `{incident_id}`: assign an incident to a campaign. |
| `GET /campaigns/suggestions` | Pairs of incidents sharing a phone/email, or a brand plus a pivotable indicator. Suggestions only. |
| `GET /indicators?type=&q=&hash_algo=` | Exact lookup: `q` is normalized and hashed. Returns the stored value only on this exact match. No partial search, no export. `q` is not stored or logged. |
| `GET /indicators/{id}` | Indicator detail: sightings, findings (up to 100), incidents. |
| `GET /community-reports?status=`, `PATCH /community-reports/{id}` | Analyst review `{status: confirmed\|rejected, indicator_type?}`. Confirming creates a community sighting only; it never adds to `blacklist_entries`. |
| `GET /attack/techniques?matrix=enterprise\|mobile` | Local catalogue (pinned v20.0) with tactic order, `installed` flag and MITRE copyright statement. |
| `GET /attack/coverage?matrix=&since=&until=` | Per-tactic technique grid with finding and incident counts, plus technique ids recorded but not in the catalogue. |
| `GET /attack/techniques/{technique_id}?matrix=` | Technique, finding count and linked incidents. The MITRE URL is data for inert display only. |

Analyst actions are recorded with actor `local-operator`; user accounts remain deferred.
