# ETIS core v2 — STIX export, recommended actions, device risk and de-fanged display

Status: **design only** (26 November 2026). Branch `feat/core-v2-design`, created from
`origin/main` at `40ee6c5` (network-windows readers, malware freeze, BEC rules and provider
registry merged). No code, schema, migration, download or behaviour change accompanies this
document. A fact about an external standard is marked **verified** only when it was read on
the cited page; every other such fact is marked **to verify** and listed again in §8. No
number in this document comes from a measurement.

Core v2 adds four platform features on top of [core v1](core-v1.md) (Findings, indicator
store, incidents, ATT&CK) and the engines built since:

| # | Feature | Requirement |
| --- | --- | --- |
| 1 | Offline STIX 2.1 export of indicators and incidents to a local file | FR-12 |
| 2 | A fixed, reviewed recommended action per Finding, in Arabic and English | FR-14 |
| 3 | A cross-engine, rule-based risk score per device, with its explanation | — |
| 4 | De-fanged indicators (`hxxps://evil[.]com`) everywhere in the console | — |

The FR numbers come from the team's requirements list, which is not in this repository. The
wording above is taken from the owner's request of 26 November 2026. §7 asks for the
requirement text so that the acceptance criteria can be checked against it.

## 0. Constraints this design must keep

| Constraint | How core v2 keeps it |
| --- | --- |
| Free and local only | Python standard library and existing dependencies only. The export is a CLI that writes a file on the owner's disk. Nothing is uploaded, posted, shared through TAXII or sent by e-mail. |
| URLs are inert strings | No feature resolves, fetches or opens an indicator. The export never contacts a STIX/TAXII server or a validator service. De-fanging (§4) adds a second, display-level guard on top of the existing non-clickable `InertValue`. |
| Verdicts, thresholds, frozen models, v4 rule and selection unchanged | All four features read stored Findings after they are recorded. None of them is read by `calculate_final_risk_score`, by an engine or by correlation. `AnalyzeResponse` gets no new field, so the `/analyze` parity gate (`backend/tests/test_findings_parity.py`) stays as it is. |
| Frozen engines unchanged | The malware v1 rule (frozen in #31), the host and network-windows rule lists, and the phishing mapping are not edited. Device attribution (§3.2) is added by `record_findings` and the import commands, not inside engine logic. |
| Privacy minimization | Scan-derived indicators remain hash-only and are **never exported** (§1.4). Pseudonyms (`host_ref`, `device_ref`, `account_ref`, `path_ref`), analyst notes and `evidence.details` are never exported. The device score is computed when it is read and never stored. |
| ETIS never acts on the system | Recommended actions are fixed text for a person to read. No action is executed, scheduled or offered as a button. ETIS never blocks, quarantines, deletes, disconnects or reports anything (§2.5). |
| No ML in the device score | The score uses a fixed points table and fixed counting rules (§3). It is not trained, calibrated or tuned on any data. |
| Generated/translated text never presented as real Egyptian SMS | Test fixtures are invented and labelled so. The Arabic action texts are guidance written by the team, not messages. The genuine Egyptian SMS final-test count remains 0. |
| Isolated test databases; secrets and runtime databases out of Git | Tests use the existing in-memory SQLite fixture. Export output goes to ignored `var/exports/` by default. |
| No sealed final test; v4 evaluation not rerun | No evaluation step is part of this plan. |

Out of scope: TAXII (client or server), STIX import, automatic sharing, user accounts and
public deployment (unchanged deferrals from the README).

## 1. STIX 2.1 offline export (FR-12)

### 1.1 Shape

A command, `python data/scripts/export_stix.py`, reads the local database and writes **one
STIX 2.1 bundle** (JSON) to a local file. Following the pattern of the malware scan command,
the console does not run the export. The Incidents page shows the command as inert text with
a copy button.

```
python data/scripts/export_stix.py [--incident ID ... | --since YYYY-MM-DD | --open]
                                   [--include-resolved-benign] [--tlp amber|green|clear]
                                   [--out PATH]
```

- **Scope.** By default the export holds open and investigating incidents. With `--incident`
  it holds the named incidents; with `--since` it holds incidents with activity on or after
  that date. Incidents resolved `false_positive` or `benign` are left out unless
  `--include-resolved-benign` is given, because they would distribute wrong indicators.
- **Output.** The default is `var/exports/etis-stix-<UTC yyyymmddThhmmssZ>.json` (`var/` is
  already ignored by Git). The command refuses to overwrite an existing file, writes to a
  temporary name and then renames, and prints only the path, object counts and the number
  of indicators withheld (§1.4). It never prints indicator values.
- **No network.** The script imports no HTTP library and opens no socket. A test runs it with
  `socket.socket` patched to raise (§6, step 4).
- **Deterministic.** The same database state and arguments give the same bytes, apart from
  the bundle id and the export timestamp. Objects are sorted by type and then by id.

### 1.2 Object mapping

STIX object types and properties named here follow the STIX 2.1 specification (**to verify**
against the OASIS 2.1 specification text, §8 V1–V6, before step 3).

| ETIS source | STIX 2.1 object | Mapping |
| --- | --- | --- |
| The ETIS installation | `identity` | `name: "ETIS local instance"`, `identity_class: "system"`. Every other object has `created_by_ref` pointing to it. It never names the owner, the team or an organisation. |
| `incidents` row | `incident` | `name` = `title`; `description` = fixed text "Exported from ETIS. Status and severity are ETIS categories."; `created` = `opened_at`; `modified` = `last_activity_at`; custom `x_etis_status`, `x_etis_severity`, `x_etis_resolution`, `x_etis_domain`, `x_etis_finding_counts` (counts by kind, engine and severity, including findings whose indicators were withheld). Analyst notes (`incident_events.note`) are **not** exported. |
| `indicators` row with plaintext `value` linked to an exported incident | `indicator` | `pattern` per §1.3; `pattern_type: "stix"`; `valid_from` = `first_seen`; `indicator_types: ["malicious-activity"]`; custom `x_etis_type`, `x_etis_sources` (source kinds and names from `indicator_sightings`, e.g. `feed:openphish`) and `x_etis_pattern_defanged` (§1.5). |
| `findings` row ↔ exported indicator (`finding_indicators`) | `sighting` | `sighting_of_ref` = the indicator; `first_seen` = `last_seen` = `observed_at`; `count: 1`; `where_sighted_refs` = ETIS identity; custom `x_etis_finding_id`, `x_etis_engine` (name and version), `x_etis_kind`, `x_etis_severity`, `x_etis_confidence`, `x_etis_reasons` (reason codes only). `evidence.details` is not exported. |
| `finding_attack` technique used by an exported finding | `attack-pattern` | `id` = the MITRE `stix_id` stored in `attack_techniques`, so consumers deduplicate against their own ATT&CK copy; `name` from the local v20.0 catalogue; `external_references: [{source_name: "mitre-attack", external_id, url}]`. A technique that is not in the catalogue is exported as an `x_etis_attack_ids` value on the incident, not as an object. |
| Incident ↔ indicator / attack pattern | `relationship` | `incident related-to indicator`; `incident related-to attack-pattern` (with custom `x_etis_basis`, the mapping basis codes); `indicator indicates attack-pattern` when the indicator's finding carries that technique. |
| Export-wide | `marking-definition` (TLP) | All objects carry `object_marking_refs` to the TLP marking chosen by `--tlp` (default AMBER, open question Q3). |
| Export-wide | `note` | The required ATT&CK notice ("Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.", `docs/data-licences.md`), the de-fanging notice (§1.5) and the withheld count, with `object_refs` set to the incidents. |

Not exported: campaigns (analyst-created groupings, often still in progress; listed as open
question Q5), `indicator_sightings` rows without a finding (the feed projection, which is
large and comes from public feeds anyway), device pseudonyms, `path_ref`, account pseudonyms,
scan requests and results, and community reports.

**Numeric confidence.** STIX has an integer `confidence` property (0–100, **to verify**, V4).
ETIS does **not** fill it. ETIS confidence is categorical because its scores are indicator
strengths, not calibrated probabilities (core v1 §1.1). A number would mislead the recipient.
The category is exported as `x_etis_confidence`.

**Incident extension.** The 2.1 `incident` object is minimal. OASIS has published an
incident core extension (**to verify**, V5). v2 uses only `x_etis_*` custom properties,
because they are simple and need no extension definition. Moving to the extension is open
question Q4.

### 1.3 Patterns per indicator type

| ETIS type | Pattern (values shown de-fanged as exported, §1.5) |
| --- | --- |
| `url` | `[url:value = 'hxxps://evil[.]example/login']` |
| `domain` | `[domain-name:value = 'evil[.]example']` |
| `ip` (v4 / v6) | `[ipv4-addr:value = '203.0.113[.]7']` / `[ipv6-addr:value = '2001[:]db8[:][:]1']` |
| `email` | `[email-addr:value = 'payroll[@]evil[.]example']` |
| `hash` | `[file:hashes.'SHA-256' = '…']` (also `SHA-1`, `MD5` by `hash_algo`); hashes are not de-fanged |
| `phone` | **No pattern.** STIX 2.1 has no telephone-number observable (**to verify**, V3). Phone indicators are exported only as a count on the incident. |

Values in a pattern are escaped as STIX string literals (backslash and single quote). The
patterns are built by one pure function, `app/services/stix_export.py::pattern_for(type, value, algo)`.

### 1.4 What is withheld, and why

The export contains only indicators whose `value` is plaintext in the store. Under core v1
§2.3 these are feed, analyst, community-confirmed and sensor values. They are:

- **Scan-derived indicators** (phishing scans, provider checks, e-mail imports, network-windows
  destinations, host detections): withheld. These indicators have only `value_hash`, and
  ETIS keeps no plaintext to export. ETIS also does not export the hashes themselves: an
  unkeyed SHA-256 of a domain or a phone number can be confirmed by anyone who guesses the
  value (core v1 §2.2), so exporting it would publish what the user scanned.
- **Malware file hashes**: withheld. They are stored as SHA-256 of the file's SHA-256, with
  `value` NULL, so the file's own SHA-256 is not available to put in a
  `file:hashes.'SHA-256'` pattern. Q2 asks whether hash-list matches (whose hash is already
  in a public list) should be exportable. A yes would change the malware engine's stored
  value, which is frozen, so it would need a separate, approved change.

The bundle `note` and the command's output report how many indicators were withheld, by
type and reason. In practice the export today carries feed- and analyst-confirmed
indicators of incidents, plus incident structure and ATT&CK context. The design states this
limit plainly rather than weakening the privacy rule.

### 1.5 De-fanged values in the export

The owner asked for de-fanged values. The STIX-native flag for this is the `defanged`
property on observable objects (SCOs, **to verify**, V2). Indicator patterns have no such
flag. A pattern that holds a de-fanged value is syntactically valid but will not match live
traffic in a recipient's tools. The design therefore:

1. writes de-fanged values (rules of §4.2) in every pattern by default;
2. sets `x_etis_pattern_defanged: true` on every such indicator and says so in the bundle
   `note` ("Values are de-fanged for safe handling; re-fang before use in a detection tool");
3. derives every deterministic object id from the **canonical** value, so a later live-value
   export (if Q1 approves one) gives the same ids.

Whether to offer an explicit `--live-values` mode is open question Q1. It is not part of
this design's delivery.

### 1.6 Identifiers

- **SDOs and relationships:** UUIDv5 over `"<table>:<row id>[:<related id>]"` in a namespace
  derived from a per-installation `ETIS_STIX_NAMESPACE` UUID, which `scripts/initialize.py`
  generates into ignored `.env` as it does the pseudonym keys. Re-exports keep ids stable,
  and two ETIS installations never collide.
- **Attack patterns:** MITRE's own `stix_id` (§1.2).
- **Marking definitions:** the fixed TLP ids published with the specification (**to verify**,
  V6).
- **Timestamps:** RFC 3339 UTC with a `Z` suffix and millisecond precision; `spec_version:
  "2.1"` on every object.

### 1.7 Validation without network

Unit tests check the output against a small **committed JSON schema subset**, written by the
team from the specification text. It covers the required properties of the eight object
types used, the id format and the timestamp format. The OASIS `stix2-validator` could be
added as an optional development dependency only if it works fully offline and its licence
allows this (**to verify**, V7). Its use is open question Q6, and it is not a runtime
dependency.

## 2. Recommended action per Finding (FR-14)

### 2.1 Catalogue

One versioned, reviewed file, `backend/app/resources/recommended-actions-v1.json`:

```json
{
  "version": "recommended-actions-v1",
  "entries": {
    "blacklist_exact": {
      "audience": "user",
      "en": "Do not open the link or reply. Delete the message. If you already entered card or account details, call your bank on the number printed on your card.",
      "ar": "<Arabic text, written and reviewed by an Arabic-speaking team member>",
      "status": "draft",
      "reviewed_by": null,
      "reviewed_on": null
    }
  },
  "kind_defaults": { "sms_phishing": { "...": "..." }, "known_bad_hash": { "...": "..." } },
  "fallback": { "audience": "user", "en": "Review this finding before acting on it.", "ar": "…", "status": "draft" }
}
```

- **Key.** The key is the reason code as it appears in `evidence.reasons` (for example
  `blacklist_exact`, `brand_label_reuse`, `hash_list_malicious`, `yara_rule_match`,
  `provider_proof_mismatch`, `payment_destination_change`). `kind_defaults` covers a
  Finding whose reasons have no entry, and `fallback` covers the rest.
- **Fixed text only.** Texts have no placeholders. No indicator, brand, number or URL from
  the Finding is inserted. The schema forbids URLs, e-mail addresses and phone numbers in a
  text, so an action can never send the reader to a contact point that ETIS did not
  verify. The texts tell the reader to use "the number printed on your card" or "the
  official app" instead.
- **`audience`.** `user` texts are for the person who received the message or owns the PC.
  `analyst` texts are for the console operator, for example `model_parity_unverified`:
  "The file model's feature parity is unverified; treat the model layer as advisory."
- **Review.** Each entry starts as `draft`. It becomes `reviewed` only when a team member
  checks the English text and an Arabic-speaking team member writes or checks the Arabic
  text, recorded by role (not by name) in `reviewed_by` with a date. A change to a reviewed
  text resets its status to `draft` and bumps the catalogue `version`. The catalogue is
  part of the code review like any rule table.

### 2.2 Coverage

Every reason code that a registered engine can emit must have an entry, or be listed in an
explicit `no_action` list with a one-line reason (for example `checks_unavailable`). Each
engine module declares its codes in a `REASON_CODES` frozenset, which adds a constant and
changes no behaviour:

| Engine | Where its codes come from today |
| --- | --- |
| `phishing.analyze` | Decisive reasons and supporting signals in `risk_scoring.py` output (e.g. `blacklist_exact`, `blacklist_domain`, `text_high_corroborated`, `text_medium`, `url_model_corroborated`, `brand_claim_from_mobile_number`, the four `BRAND_DECISIVE` techniques). Declared in `phishing_findings.py`; `risk_scoring.py` is not edited. |
| provider claims | `provider_*` codes in `provider_claims.py` (e.g. `provider_sender_outside_set`, `provider_domain_outside_set`, `provider_claim_proof_conflict`). |
| e-mail headers and BEC/payment rules | `email_*`, `reported_arc_*` and `payment_*` codes in `email_headers.py` and `payment_rules.py`. |
| `malware.files` | `REASON_*` constants in `malware/engine.py` (`hash_list_malicious`, `yara_rule_match`, `model_above_threshold`, `model_parity_unverified`, `known_software_conflict`, …). |
| `host.windows`, `network.windows` | Their rule codes (H1–H13, N1–N8 reason codes) when those engines start emitting Findings. Their entries are written in the same step that registers the engine. |

A test (§6, step 6) asserts complete coverage for every registered engine. For phishing,
the test also replays the existing endpoint and probe fixtures and checks that every
emitted reason is in the declared set.

### 2.3 Selection per Finding

A pure function, `recommended_actions(finding) -> list[Action]`:

1. Walk `evidence.reasons` in order. Phishing puts the decisive reason first, and the other
   engines list their primary reason first.
2. Take the first reason that has an entry as the **primary** action, then up to two further
   distinct texts from later reasons as **also** actions (3 at most; identical texts
   appear once).
3. If no reason has an entry, use `kind_defaults[kind]`, and if that is missing, use
   `fallback`.
4. Only `reviewed` entries are shown. A `draft` entry is replaced by the next match or by
   the fallback, unless `ETIS_SHOW_DRAFT_ACTIONS=1` is set for team review. In that case the
   console marks the text "Draft — not reviewed".

Each result carries `{reason_code, audience, en, ar, catalogue_version}`. Actions are
computed when read. They are not stored on the Finding, so a reviewed text change applies
to old Findings without rewriting them, and the catalogue version is shown beside the text.

### 2.4 Where it is shown

- **Incident detail:** each finding row shows its primary action, and the incident header
  shows the primary actions of its highest-severity findings, de-duplicated.
- **Device detail (§3.5):** the actions of the findings that contribute to the score.
- **Language:** the console's current language. The other language is available behind a
  "Show in English / عرض بالعربية" toggle, because the operator and the affected person may
  not read the same language.
- **Scan page:** not in v2. The scan page shows the `/analyze` response, which must not gain
  a field. Showing actions there would need a separate lookup by decisive reason, which is
  open question Q7.

### 2.5 Never automatic

- The catalogue has no field that could be executed: no command, script, URL or rule id
  that a process reads. A schema test rejects extra fields.
- No endpoint performs an action. The API exposes the actions read-only inside
  `GET /incidents/{id}` and `GET /devices/{ref}`, and through `GET /recommended-actions`
  (the catalogue, for the console).
- The console renders actions as plain text. Next to a text it has no "do it", "block",
  "quarantine" or "delete" button, and the only control is the language toggle.
- Malware texts state what ETIS did **not** do, for example "ETIS has not moved, renamed or
  deleted this file." The malware engine never moves files (malware-engine-v1).

## 3. Cross-engine risk score per device

### 3.1 Purpose and non-goals

The score gives the owner a single, explainable view of "how much ETIS has seen on this PC
lately", across the malware, host and network-windows engines. It is **not** a verdict, a
probability or a prediction. No engine, correlation step, incident rule or action reads it,
and it is not trained, calibrated or tuned on data. Its version is `device-risk-v1`.

### 3.2 What a device is

A device is identified by `device_ref`: the host engine's HMAC of the normalised computer
name under `ETIS_HOST_PSEUDONYM_KEY` (host-engine-v1 §6.4). network-windows-v1 §6.5 already
makes its `device_ref` equal to the host engine's `host_ref` for the same PC.

| Engine | Device attribution |
| --- | --- |
| `host.windows` | `evidence.details.host_ref` (set by the engine). |
| `network.windows` | `evidence.details.device_ref` (set by the engine). |
| `malware.files` | The scan command runs on the PC whose files it reads. It computes `device_ref` from the local computer name with the host key and passes it to `record_findings`. The engine and its Finding stay unchanged. If the host key is missing, the scan still runs and its findings have no device. |
| `network.flows` (Zeek, paused) | Not attributed. Its `local_host_ref` is an HMAC of a local IP under a different key and cannot be joined. |
| `phishing.analyze`, provider, e-mail and BEC rules | Not attributed. A submitted message describes a person's inbox, not a device. These findings are listed on the console as "not tied to a device". |

**Storage.** A new table, `finding_devices(finding_id PK/FK → findings ON DELETE CASCADE,
device_ref String(37), attributed_by String(32))`, is filled by `record_findings` from the
details field or from the scan command's argument (migration `008_finding_devices`). The
Finding schema (`finding-v1`) does not change. Findings recorded before v2 have no device
(open question Q8). Device pseudonyms still never pivot incidents (host-engine-v1 §6.6).

An optional owner label per device, for example "Office PC", is open question Q9. Without
it, the console shows the short ref (`hmac:3f9a…`).

### 3.3 Inputs

For one `device_ref`, the score uses every Finding attributed to it with `observed_at` in
the last **30 days** at read time, **except** findings whose incident is resolved
`false_positive` or `benign`. Excluded findings are still listed, with the reason. For each
finding it reads only `engine_name`, `domain`, `kind`, `severity`, `confidence`,
`observed_at` and the incident's resolution. No evidence detail or indicator value is used.

### 3.4 Formula (`device-risk-v1`)

**Step 1 — points per finding**, from a fixed table of severity × confidence:

| severity \ confidence | confirmed | corroborated | single_signal | undetermined |
| --- | --- | --- | --- | --- |
| critical | 10 | 8 | 5 | 3 |
| high | 6 | 5 | 3 | 2 |
| medium | 3 | 2 | 1 | 1 |
| low | 1 | 1 | 0 | 0 |
| info | 0 | 0 | 0 | 0 |

**Step 2 — recency:** findings 0–7 days old count in full. Findings 8–30 days old count half,
rounded up. Older findings are not inputs.

**Step 3 — no inflation by repetition:** for each `(engine_name, kind)` on the device, only
the finding with the most points counts. Others are listed as "repeat — not counted (n)".
One noisy rule therefore cannot raise the score by firing often.

**Step 4 — cross-engine corroboration:** for each **additional** engine domain (`malware`,
`host`, `network`) beyond the first that has a counted finding worth ≥ 3 points in the last
7 days, add 3 points, with at most +6 in total. This is the only cross-engine term. It
expresses that independent engines seeing trouble on the same PC in the same week is
stronger evidence than any one of them.

**Step 5 — sum and band:**

| Points | Band (EN / AR label keys) |
| --- | --- |
| 0 | `none` — no recent findings |
| 1–4 | `low` |
| 5–9 | `elevated` |
| ≥ 10 | `high` |

The number is shown next to the band. The table, the windows, the +3 term and the band
edges are design choices, not fitted values. Q10 asks the team to confirm them. Changing
any of them is a new version (`device-risk-v2`) with a dated note, as for other ETIS rules.

**Worked example (invented).** A PC has a `malware.files` `known_bad_hash` finding (high,
confirmed, 2 days old) = 6, the same kind again 3 days ago (repeat, not counted), and a
`network.windows` `periodic_beaconing` finding (high, corroborated, 1 day old) = 5. The
cross-engine term adds +3 for one additional domain (network) with ≥ 3 points in 7 days.
The total is **14 → high**. If the beaconing incident were resolved `benign`, the total
would be 6 → elevated, and the beaconing line would show "excluded — incident resolved
benign".

### 3.5 Explanation shown to the user

A **Devices** tab (`/devices`) lists devices by band and then by points: short ref (or
label), band chip, points, counted findings, the last finding's time and the engines seen.
The device detail shows:

1. **The total line.** For example: "14 points — high. Computed now from findings of the
   last 30 days (`device-risk-v1`)."
2. **A contribution table** with one row per counted finding: engine, kind, severity,
   confidence, age, points before and after recency, a link to its incident, and its primary
   recommended action (§2).
3. **The cross-engine line**, for example: "+3 — malware and network findings on this device
   in the same week".
4. **Not counted:** repeats, findings older than 30 days (count only) and excluded findings,
   each with its reason.
5. **A fixed "What this score is" text** (AR/EN, reviewed like §2.1): "A count of what ETIS
   engines reported on this device recently, weighted by severity and confidence. It is not
   a probability that the device is compromised, it does not include checks ETIS did not
   run, and a score of 0 does not mean the device is safe."

The API endpoints are `GET /devices` and `GET /devices/{device_ref}`. Both are read-only,
require `verify_api_key`, appear in the proxy allowlist, and return `database_unavailable`
without echoing input.

## 4. De-fanged indicators everywhere in the console

### 4.1 Principle

Storage, hashing, lookups, correlation and STIX ids keep **canonical** values. De-fanging
is applied at the edges where a person reads or copies a value: the console, the STIX export
(§1.5) and the CLI summaries that print a value. `InertValue` stays non-clickable and
left-to-right. De-fanging adds protection against auto-linking by browsers, chat tools and
e-mail clients when the text is copied, and against accidental clicks or pastes.

### 4.2 Rules (`defang-v1`)

| Type | Canonical | Displayed |
| --- | --- | --- |
| `url` | `https://evil.example/a.php?x=1` | `hxxps://evil[.]example/a.php?x=1`. The scheme becomes `http`→`hxxp`, `https`→`hxxps`, `ftp`→`fxp`. Every `.` in the **host** becomes `[.]`; path, query and fragment are unchanged. A `@` in userinfo becomes `[@]`, and `:` before a port stays. |
| `domain` | `evil.example` | `evil[.]example`. IDN hosts are shown in their stored IDNA ASCII (`xn--…`) form, never as Unicode, so lookalike characters are visible. |
| `ip` | `203.0.113.7` / `2001:db8::1` | `203.0.113[.]7` (last dot only, the common convention) / `2001[:]db8[:][:]1` |
| `email` | `payroll@evil.example` | `payroll[@]evil[.]example` |
| `phone` | `+2010…` | Unchanged. The console page sets `<meta name="format-detection" content="telephone=no">` so mobile browsers do not turn numbers into call links (**to verify**, V8). |
| `hash`, pseudonyms | — | Unchanged. |

De-fanging is idempotent: an already de-fanged value is left as is. The rules are a fixed
table, `defang-v1`, committed as `docs/design/defang-cases.json` (input type, canonical,
displayed) and used by both implementations below.

### 4.3 Implementations

- **Backend:** `app/core/defang.py::defang(type, value)`, used by the STIX exporter and CLI
  summaries. The existing `extract_links` refang rule (`hxxp`→`http`, `[.]`→`.`) stays in
  `url_utils.py` and is not changed.
- **Frontend:** `src/api/defang.ts`, and a component
  `<IndicatorValue type value />` that wraps `InertValue` and always de-fangs. `InertValue`
  remains for non-indicator text (commands, model ids, the MITRE reference URL, `path_ref`).
- **Copy:** the copy button next to an indicator copies the de-fanged form.
- **Search input:** the Indicators page accepts both forms. The backend lookup refangs input
  with the same rule as `extract_links` before `normalize`, so `hxxps://evil[.]example`
  and `https://evil.example` hit the same `value_hash`.

### 4.4 Places changed

| Page / component | Value | Today |
| --- | --- | --- |
| `IncidentsPage.tsx` (indicator list) | `value` (feed/analyst) | `InertValue`, plain |
| `IndicatorsPage.tsx` (detail, registered domain, community reports) | `value`, `registered_domain`, `reported_value` | `InertValue`, plain |
| `ThreatFeedPage.tsx` | feed `domain` | monospace cell, plain |
| `ScanPage.tsx` (checked links) | `link.host` | monospace span, plain. The `/analyze` response itself is unchanged; de-fanging happens only in the page. |
| `DevicesPage.tsx` (new, §3.5) | none (pseudonyms only) | — |

A static test (§6, step 9) fails if a page passes an indicator field (`value`, `host`,
`domain`, `registered_domain`, `reported_value`) to `InertValue` or renders it directly
instead of using `IndicatorValue`.

## 5. Data and API changes summary

| Change | Kind |
| --- | --- |
| `finding_devices` table | Migration `008_finding_devices` (explicit `op.create_table`, fresh-vs-upgrade comparison as in core v1 §7.2). Downgrade drops it, and attributions can be rebuilt only for engines that keep the ref in details. |
| `ETIS_STIX_NAMESPACE`, `ETIS_SHOW_DRAFT_ACTIONS` | Settings. The namespace is generated by `scripts/initialize.py` into ignored `.env`. |
| `GET /devices`, `GET /devices/{ref}`, `GET /recommended-actions`; `recommended_actions` added inside `GET /incidents/{id}` finding rows | API additions documented in `docs/api-v2.md`. `/analyze` unchanged. |
| `recommended-actions-v1.json`, `defang-cases.json`, STIX schema subset | Committed, reviewed files. |
| `REASON_CODES` constant per engine module | Declaration only. |

No existing column is changed. No feed table is written. No frozen artifact is touched.

## 6. Step plan (small commits, targeted tests per step)

Every step leaves the suite green. During development on a shared machine, each step runs
**only its targeted tests** (listed). The full pytest run, database initialization, frontend
build and lint required by `CLAUDE.md` run once the machine is free, before the branch is
proposed for merge. No sealed final test is run.

| # | Commit | Content | Targeted tests |
| --- | --- | --- | --- |
| 1 | `feat: defang-v1 rules for backend display` | `app/core/defang.py`, `docs/design/defang-cases.json` | `pytest backend/tests/test_defang.py`: every case in the JSON; idempotence; IDNA shown as ASCII; IPv6; userinfo `@`; path dots unchanged; refang(defang(x)) == x for url/domain/ip/email. |
| 2 | `feat: indicator lookup accepts de-fanged input` | Refang before `normalize` in `routers/indicators.py` | `pytest backend/tests/test_soc_api.py -k lookup`: both forms give the same hash and result; invalid input still returns `invalid_input` without echo. |
| 3 | `feat: STIX 2.1 pattern and object builders` | `app/services/stix_export.py` (pure: `pattern_for`, object builders, id derivation), committed schema subset | `pytest backend/tests/test_stix_export.py -k "pattern or objects or ids"`: pattern per type and escaping; phone gives no pattern; ids stable across runs and different across namespaces; required properties per schema subset; no `confidence` property; TLP marking on every object. |
| 4 | `feat: offline STIX export command` | `data/scripts/export_stix.py`, `ETIS_STIX_NAMESPACE` in initialize, default `var/exports/` | `pytest backend/tests/test_stix_export.py -k "command or privacy or scope"`: invented incidents with feed and scan indicators → scan-derived and malware indicators withheld and counted; no hash-only `value_hash` in the output; no notes, pseudonyms or details (marker-string test); resolved-benign excluded by default; refuses overwrite; `socket.socket` patched to raise and the export still succeeds; deterministic bytes apart from bundle id and timestamp; ATT&CK notice present when an attack pattern is exported. |
| 5 | `feat: recommended-actions-v1 catalogue and schema` | JSON catalogue, loader with strict schema, `REASON_CODES` declarations | `pytest backend/tests/test_recommended_actions.py -k "schema or coverage"`: extra field rejected; URL/e-mail/phone regex rejects a text; both languages present; coverage for every registered engine's `REASON_CODES`, plus phishing replay-fixture reasons ⊆ declared set. |
| 6 | `feat: recommended action selection per finding` | Pure `recommended_actions(finding)`, `recommended_actions` in incident detail, `GET /recommended-actions` | `pytest backend/tests/test_recommended_actions.py -k selection` and `pytest backend/tests/test_soc_api.py -k incident`: decisive first; at most 3 actions, de-duplicated; kind default; fallback; draft hidden unless the flag is set; no endpoint with a write method under `/recommended-actions`. |
| 7 | `feat: device attribution for findings` | Migration 008, `finding_devices`, `record_findings` reads `host_ref`/`device_ref`, malware scan command passes `device_ref` | `pytest backend/tests/test_core_migrations.py -k 008`, `pytest backend/tests/test_correlation.py -k device` and `pytest backend/tests/test_malware_scan_command.py -k device`: fresh-vs-upgrade schema equality; malware finding gets the local device ref; missing host key → no device, scan still succeeds; device refs never create or join incidents; `/analyze` parity test file `test_findings_parity.py` (targeted, it is the gate). |
| 8 | `feat: device-risk-v1 score and devices API` | Pure `device_risk(findings, now)`, routers | `pytest backend/tests/test_device_risk.py`: every cell of the points table; recency boundaries at 7/8 and 30/31 days; repeat rule; cross-engine +3 and +6 cap, not given for a domain below 3 points or older than 7 days; resolved benign/false positive excluded and listed; the worked example of §3.4 gives 14 → high; band edges 0/1/4/5/9/10; `pytest backend/tests/test_soc_api.py -k devices` for auth, no echo, read-only. |
| 9 | `feat: de-fanged indicator display in the console` | `defang.ts`, `IndicatorValue`, pages of §4.4, `format-detection` meta, copy button | `node --experimental-strip-types --test etis-frontend/tests/defang.test.mts` over `defang-cases.json` (Node 22.12 is installed; the flag is **to verify**, V9); static check script for raw indicator rendering; frontend build and `oxlint` on changed files. |
| 10 | `feat: recommended actions and devices console pages` | Incident detail actions, Devices tab, i18n keys AR/EN, proxy allowlist | Frontend build, `oxlint`, an i18n key parity check (every new key in both `ar.json` and `en.json`), `pytest backend/tests/test_proxy_routes.py` for the allowlist; manual RTL and 390-pixel check as recorded today. |
| 11 | `docs: core v2 implementation notes` | README / LOCAL-IMPLEMENTATION status, `docs/api-v2.md`, `docs/engine-authors.md` (declare `REASON_CODES`, add catalogue entries, set device ref) | none (docs only) |

Release check before the action feature is shown by default: every catalogue entry is
`reviewed`, with the Arabic text checked by an Arabic-speaking team member.

## 7. Open questions

| # | Question | Default if unanswered |
| --- | --- | --- |
| Q1 | Should the export offer an explicit `--live-values` mode (real values in patterns, for loading into a detection tool), or stay de-fanged only? | De-fanged only. |
| Q2 | Should malware hash-list matches store and export the file's SHA-256? Such a hash is already public in the list, but the change touches the frozen malware engine and needs separate approval. | Not exported. |
| Q3 | Default TLP marking: AMBER (owner shares deliberately), GREEN, or CLEAR? TLP 1.0 markings are predefined in 2.1, and TLP 2.0 needs the OASIS common objects (**to verify**, V6). | TLP:AMBER (1.0 predefined). |
| Q4 | Use the OASIS incident core extension instead of `x_etis_*` properties? | `x_etis_*`. |
| Q5 | Export campaigns (`campaign` SDO + `attributed-to`/`related-to`)? | Not in v2. |
| Q6 | May `stix2-validator` be a development-only dependency if it is offline and its licence fits? | No. Use the committed schema subset only. |
| Q7 | Show the recommended action on the scan page, through a separate lookup by decisive reason (the `/analyze` response stays unchanged)? | Not in v2. |
| Q8 | Back-attribute existing malware findings to this PC's device? Scans may have read files copied from elsewhere. | No. Only new scans are attributed. |
| Q9 | Allow an owner-typed device label (stored locally, never exported)? | No. Show the short ref only. |
| Q10 | Confirm the points table, the 7/30-day windows, the +3/+6 term and the band edges of §3.4. | As written. |
| Q11 | Please share the FR-12 and FR-14 wording from the requirements list, so the acceptance criteria can be checked against it. | Use the wording in this document. |
| Q12 | Which team member reviews the Arabic action texts, and which reviews the English ones? | Unassigned. Actions stay hidden behind the draft flag until reviewed. |

## 8. To verify (before the step that depends on it)

| # | Fact | Where to read | Step |
| --- | --- | --- | --- |
| V1 | Required common properties per object type (`type`, `spec_version`, `id`, `created`, `modified`) and the bundle shape (no `spec_version` on the bundle in 2.1) | OASIS STIX 2.1 specification | 3 |
| V2 | The `defanged` common property exists on SCOs only | same | 3 |
| V3 | No telephone-number SCO in 2.1 | same | 3 |
| V4 | `confidence` is an optional integer 0–100 on SDOs | same | 3 |
| V5 | Incident core extension: status, identifier and properties | OASIS CTI extension repository | Q4 only |
| V6 | Fixed ids of the predefined TLP 1.0 marking definitions; how TLP 2.0 markings are published | STIX 2.1 specification §7.2 and the OASIS common objects | 3 |
| V7 | `stix2-validator` licence and whether it runs fully offline | its PyPI page and repository | Q6 only |
| V8 | `format-detection` meta behaviour in current mobile Safari / Chrome | browser documentation | 9 |
| V9 | `node --experimental-strip-types --test` works on the installed Node 22.12 without extra packages | Node 22 documentation, local run | 9 |

## Sources

- [Core v1 design](core-v1.md): Finding schema, indicator plaintext rules (§2.3), unkeyed
  hash note (§2.2), categorical confidence (§1.1), stoplist and correlation (§3).
- [Host engine v1](host-engine-v1.md) §6.4, §6.6 and [network-windows v1](network-windows-v1.md)
  §6.5, §6.6: `host_ref`/`device_ref` definition and the rule that pseudonyms never pivot.
- [Malware engine v1](malware-engine-v1.md): hash-only file indicator, frozen v1 rule,
  `path_ref`.
- [Engine authors guide](../engine-authors.md): engine rules this design extends.
- `docs/data-licences.md`: ATT&CK copyright statement required when ATT&CK names are shown
  or exported.
- OASIS, *STIX Version 2.1*, OASIS Standard, 10 June 2021,
  https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html — not re-read for this
  document. Every STIX fact above is marked **to verify** (V1–V6).
